//! Reading the host's own files under /proc and /sys, for the health and network plugins (roadmap section 11.4). Each function takes
//! the text of one file and returns what it holds, so each can be tested on text the kernel writes. Nothing here runs a program.
//!
//! Every value read is the host's claim, as the agent's readings all are: the controller labels it as reported by the agent.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Serialize;

/// The first line of /proc/stat: the time the CPUs spent, (busy, total), in ticks.
pub fn cpu_ticks(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let v: Vec<u64> = parts.filter_map(|p| p.parse().ok()).collect();
    if v.len() < 4 {
        return None;
    }
    let total: u64 = v.iter().take(8).sum();
    // idle and iowait are not busy
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

/// /proc/loadavg: the 1, 5 and 15 minute load.
pub fn load(text: &str) -> Option<[f64; 3]> {
    let v: Vec<f64> = text.split_whitespace().take(3).filter_map(|p| p.parse().ok()).collect();
    (v.len() == 3).then(|| [v[0], v[1], v[2]])
}

/// /proc/meminfo, the lines asked for, in bytes.
pub fn meminfo(text: &str) -> BTreeMap<String, u64> {
    let want = ["MemTotal", "MemAvailable", "SwapTotal", "SwapFree"];
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else { continue };
        if want.contains(&name) {
            if let Some(kib) = rest.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()) {
                out.insert(name.to_string(), kib.saturating_mul(1024));
            }
        }
    }
    out
}

/// /proc/pressure/{cpu,memory,io}: the share of the last ten seconds some task waited, in percent.
pub fn pressure(text: &str) -> Option<f64> {
    let line = text.lines().find(|l| l.starts_with("some "))?;
    line.split_whitespace().find_map(|p| p.strip_prefix("avg10=")).and_then(|v| v.parse().ok())
}

/// One disk's counters from /proc/diskstats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskCounters {
    pub reads: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_ms: u64,
    pub busy_ms: u64,
}

/// /proc/diskstats, for the disks named in `disks` (the host's /sys/block, less loop and RAM devices).
pub fn diskstats(text: &str, disks: &BTreeSet<String>) -> BTreeMap<String, DiskCounters> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 || !disks.contains(f[2]) {
            continue;
        }
        let n = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        out.insert(f[2].to_string(), DiskCounters { reads: n(3), read_ms: n(6), writes: n(7), write_ms: n(10), busy_ms: n(12) });
    }
    out
}

/// What two readings of a disk's counters say: latency per I/O and how busy it was, over `ms` milliseconds.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiskRate {
    pub name: String,
    pub reads: u64,
    pub writes: u64,
    pub read_ms_per_io: Option<f64>,
    pub write_ms_per_io: Option<f64>,
    pub busy_pct: f64,
}

pub fn disk_rate(name: &str, before: &DiskCounters, after: &DiskCounters, ms: u64) -> DiskRate {
    let d = |a: u64, b: u64| b.saturating_sub(a);
    let (r, w) = (d(before.reads, after.reads), d(before.writes, after.writes));
    let per = |t: u64, n: u64| (n > 0).then(|| round2(t as f64 / n as f64));
    DiskRate {
        name: name.to_string(),
        reads: r,
        writes: w,
        read_ms_per_io: per(d(before.read_ms, after.read_ms), r),
        write_ms_per_io: per(d(before.write_ms, after.write_ms), w),
        busy_pct: round2((d(before.busy_ms, after.busy_ms) as f64 * 100.0 / ms.max(1) as f64).min(100.0)),
    }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// One md array from /proc/mdstat.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MdArray {
    pub name: String,
    pub state: String,
    pub level: String,
    pub degraded: bool,
    /// recovery, resync, reshape or check, with how far it is, when one runs.
    pub action: Option<String>,
    pub progress_pct: Option<f64>,
}

pub fn mdstat(text: &str) -> Vec<MdArray> {
    let mut out: Vec<MdArray> = Vec::new();
    for line in text.lines() {
        if let Some((name, rest)) = line.split_once(" : ") {
            let name = name.trim();
            if name.starts_with("md") && !name.contains(' ') {
                let mut words = rest.split_whitespace();
                let state = words.next().unwrap_or("").to_string();
                let level = words.next().filter(|w| w.starts_with("raid") || *w == "linear").unwrap_or("").to_string();
                out.push(MdArray { name: name.to_string(), state, level, degraded: false, action: None, progress_pct: None });
                continue;
            }
        }
        let Some(md) = out.last_mut() else { continue };
        let t = line.trim();
        // "[2/1] [U_]": one of two members is missing
        if let Some(open) = t.rfind('[') {
            let members = &t[open + 1..t.len().saturating_sub(if t.ends_with(']') { 1 } else { 0 })];
            if !members.is_empty() && members.bytes().all(|b| b == b'U' || b == b'_') && members.contains('_') {
                md.degraded = true;
            }
        }
        for action in ["recovery", "resync", "reshape", "check"] {
            if let Some(at) = t.find(&format!("{action} =")) {
                md.action = Some(action.to_string());
                md.progress_pct = t[at + action.len() + 2..].trim().split('%').next().and_then(|p| p.trim().parse().ok());
            }
        }
    }
    out
}

/// A TCP socket from /proc/net/tcp or tcp6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    /// The kernel's state number: 0A is listening, 01 established.
    pub state: u8,
}

fn address(hex: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = hex.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::from(u32::from_str_radix(ip, 16).ok()?.to_le_bytes()),
        32 => {
            // four 32-bit words, each in the host's byte order (little-endian here)
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let v6 = std::net::Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
        }
        _ => return None,
    };
    Some((ip, port))
}

pub fn tcp_sockets(text: &str) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .take(100_000)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, local_port) = address(f.get(1)?)?;
            let (remote, remote_port) = address(f.get(2)?)?;
            Some(Socket { local, local_port, remote, remote_port, state: u8::from_str_radix(f.get(3)?, 16).ok()? })
        })
        .collect()
}

pub const LISTEN: u8 = 0x0A;
pub const ESTABLISHED: u8 = 0x01;

/// The ports something listens on, from both tables.
pub fn listening(sockets: &[Socket]) -> Vec<u16> {
    let set: BTreeSet<u16> = sockets.iter().filter(|s| s.state == LISTEN).map(|s| s.local_port).collect();
    set.into_iter().take(256).collect()
}

/// The share ports: SMB (445, and 139 for NetBIOS) and NFS (2049).
pub const SHARE_PORTS: [(u16, &str); 3] = [(139, "smb"), (445, "smb"), (2049, "nfs")];

/// Who is connected to this host's shares now: (protocol, client address) and how many connections.
pub fn share_clients(sockets: &[Socket]) -> BTreeMap<(String, String), u32> {
    let mut out = BTreeMap::new();
    for s in sockets.iter().filter(|s| s.state == ESTABLISHED) {
        if let Some((_, proto)) = SHARE_PORTS.iter().find(|(p, _)| *p == s.local_port) {
            *out.entry((proto.to_string(), s.remote.to_string())).or_insert(0) += 1;
        }
        if out.len() >= 1024 {
            break;
        }
    }
    out
}

/// One interface's counters from /proc/net/dev.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct IfCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

pub fn net_dev(text: &str) -> BTreeMap<String, IfCounters> {
    let mut out = BTreeMap::new();
    for line in text.lines().skip(2).take(1024) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if v.len() < 12 {
            continue;
        }
        out.insert(name.trim().to_string(), IfCounters { rx_bytes: v[0], rx_packets: v[1], rx_errors: v[2], rx_dropped: v[3], tx_bytes: v[8], tx_packets: v[9], tx_errors: v[10], tx_dropped: v[11] });
    }
    out
}

/// Whether a process name is OpenSSH's server: the listener (`sshd`) or, from OpenSSH 9.8, a session (`sshd-session`).
pub fn is_sshd(comm: &str) -> bool {
    let c = comm.trim();
    c == "sshd" || c == "sshd-session" || c.starts_with("sshd:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_kernel_writes_is_read() {
        assert_eq!(cpu_ticks("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n"), Some((150, 1000)));
        assert_eq!(cpu_ticks("intr 1 2\n"), None);
        assert_eq!(load("0.52 0.41 0.30 1/234 5678\n"), Some([0.52, 0.41, 0.30]));
        let m = meminfo("MemTotal:       16303376 kB\nMemFree:  1 kB\nMemAvailable:   12000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
        assert_eq!(m["MemTotal"], 16303376 * 1024);
        assert!(!m.contains_key("MemFree"));
        assert_eq!(pressure("some avg10=1.50 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"), Some(1.5));
        let disks: BTreeSet<String> = ["sda".to_string()].into();
        let before = diskstats("   8       0 sda 1048 0 58040 5753 200 0 0 400 0 16647 5753 0 0 0 0 0 0\n   8       1 sda1 973 0 46256 5391 0 0 0 0 0 4676 5391\n", &disks);
        assert_eq!(before.len(), 1, "partitions are not disks");
        let after = diskstats("   8       0 sda 1148 0 58040 6753 300 0 0 600 0 17647 5753 0 0 0 0 0 0\n", &disks);
        let r = disk_rate("sda", &before["sda"], &after["sda"], 10_000);
        assert_eq!((r.reads, r.read_ms_per_io, r.write_ms_per_io, r.busy_pct), (100, Some(10.0), Some(2.0), 10.0));
    }

    #[test]
    fn a_degraded_array_and_its_recovery_are_seen() {
        let text = "Personalities : [raid1]\nmd0 : active raid1 sdb1[2] sda1[0]\n      1046528 blocks super 1.2 [2/1] [U_]\n      [====>................]  recovery = 23.5% (246784/1046528) finish=0.1min speed=82261K/sec\n\nmd1 : active raid1 sdd1[1] sdc1[0]\n      1046528 blocks super 1.2 [2/2] [UU]\n\nunused devices: <none>\n";
        let got = mdstat(text);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].name.as_str(), got[0].level.as_str(), got[0].degraded, got[0].action.as_deref(), got[0].progress_pct), ("md0", "raid1", true, Some("recovery"), Some(23.5)));
        assert!(!got[1].degraded && got[1].action.is_none());
    }

    #[test]
    fn sockets_are_read_from_both_tables() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n   1: 0300000A:01BD 0900000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n   2: 0300000A:01BD 0900000A:C351 01 00000000:00000000 00:00000000 00000000     0        0 3 1\n";
        let v6 = "  sl  local_address remote_address st\n   0: 00000000000000000000000000000000:0801 00000000000000000000000000000000:0000 0A 0\n   1: 0000000000000000FFFF00000300000A:0801 0000000000000000FFFF00000800000A:0300 01 0\n";
        let mut s = tcp_sockets(v4);
        s.extend(tcp_sockets(v6));
        assert_eq!(listening(&s), [22, 2049]);
        let clients = share_clients(&s);
        assert_eq!(clients[&("smb".to_string(), "10.0.0.9".to_string())], 2);
        assert_eq!(clients[&("nfs".to_string(), "10.0.0.8".to_string())], 1);
        assert!(tcp_sockets("header\ngarbage line\n").is_empty());
    }

    #[test]
    fn interfaces_and_sshd_are_read() {
        let dev = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0\n  eth0: 5000 50 1 2 0 0 0 0 7000 70 3 4 0 0 0 0\n";
        let got = net_dev(dev);
        assert_eq!(got["eth0"], IfCounters { rx_bytes: 5000, rx_packets: 50, rx_errors: 1, rx_dropped: 2, tx_bytes: 7000, tx_packets: 70, tx_errors: 3, tx_dropped: 4 });
        assert!(is_sshd("sshd\n") && is_sshd("sshd-session") && !is_sshd("sshdx") && !is_sshd("bash"));
    }
}
