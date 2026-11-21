//! The health plugin (roadmap section 11.4): CPU, memory, pressure, disk latency, md arrays and their rebuilds, ZFS pool states,
//! btrfs capacity, and whether the host's SSH server is up.
//!
//! Declares /proc and /sys, read-only, and the host's process table. It reads files there and runs nothing.
//!
//! - `health` every `EVERY` seconds: everything, rates over the last interval.
//! - `ssh` every `SSH_EVERY` seconds when it changed, and with every `health`: whether a process of OpenSSH's server runs and the
//!   ports the host listens on (from the network table of the host's first process). The controller compares them with the SSH
//!   port it knows for the host, so "SSH is down" is said by the agent while the agent and SSH share nothing (roadmap 11.2,
//!   "Either one fails alone").
//!
//! What it does not read: the capacity of filesystems other than btrfs, and the progress of a ZFS scrub, which /proc and /sys do
//! not show. Scans over SSH read those.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use serde_json::{json, Value};
use storageforge_agent::hostread::{self, DiskCounters};
use storageforge_agent::pluginside::Agent;

const EVERY: u64 = 60;
const SSH_EVERY: u64 = 10;

fn read(path: &Path) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(1 << 20).read_to_string(&mut out);
    }
    out
}

fn disks(host: &Path) -> BTreeSet<String> {
    std::fs::read_dir(host.join("sys/block"))
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !["loop", "ram", "zram"].iter().any(|p| n.starts_with(p))).take(512).collect())
        .unwrap_or_default()
}

fn ssh(host: &Path) -> Value {
    let proc = host.join("proc");
    let mut process = false;
    if let Ok(entries) = std::fs::read_dir(&proc) {
        for e in entries.flatten().take(100_000) {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.bytes().all(|b| b.is_ascii_digit()) && hostread::is_sshd(&read(&e.path().join("comm"))) {
                process = true;
                break;
            }
        }
    }
    let mut sockets = hostread::tcp_sockets(&read(&proc.join("1/net/tcp")));
    sockets.extend(hostread::tcp_sockets(&read(&proc.join("1/net/tcp6"))));
    json!({"process": process, "listening": hostread::listening(&sockets), "read": !sockets.is_empty() || proc.join("1/net/tcp").exists()})
}

fn zfs(host: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(pools) = std::fs::read_dir(host.join("proc/spl/kstat/zfs")) {
        for p in pools.flatten().take(256) {
            let state = read(&p.path().join("state"));
            if !state.trim().is_empty() {
                out.push(json!({"pool": p.file_name().to_string_lossy(), "state": state.trim()}));
            }
        }
    }
    out
}

fn btrfs(host: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(fss) = std::fs::read_dir(host.join("sys/fs/btrfs")) {
        for fs in fss.flatten().take(256) {
            let alloc = fs.path().join("allocation");
            if !alloc.is_dir() {
                continue;
            }
            let (mut total, mut used) = (0u64, 0u64);
            for kind in ["data", "metadata", "system"] {
                let n = |f: &str| read(&alloc.join(kind).join(f)).trim().parse::<u64>().unwrap_or(0);
                total += n("total_bytes");
                used += n("bytes_used");
            }
            out.push(json!({"uuid": fs.file_name().to_string_lossy(), "label": read(&fs.path().join("label")).trim(), "allocated": total, "used": used}));
        }
    }
    out
}

fn main() {
    let agent = match Agent::start() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    let host = agent.host.clone();
    let proc = host.join("proc");
    let mut before: Option<(Instant, Option<(u64, u64)>, BTreeMap<String, DiskCounters>)> = None;
    let mut last_ssh = Value::Null;
    let mut beat = 0u64;
    loop {
        let s = ssh(&host);
        if beat % (EVERY / SSH_EVERY) == 0 {
            let names = disks(&host);
            let now = (Instant::now(), hostread::cpu_ticks(&read(&proc.join("stat"))), hostread::diskstats(&read(&proc.join("diskstats")), &names));
            let mut body = json!({
                "load": hostread::load(&read(&proc.join("loadavg"))),
                "memory": hostread::meminfo(&read(&proc.join("meminfo"))),
                "pressure": {"cpu": hostread::pressure(&read(&proc.join("pressure/cpu"))), "memory": hostread::pressure(&read(&proc.join("pressure/memory"))),
                             "io": hostread::pressure(&read(&proc.join("pressure/io")))},
                "md": hostread::mdstat(&read(&proc.join("mdstat"))),
                "zfs": zfs(&host),
                "btrfs": btrfs(&host),
                "ssh": s,
                "uptime": read(&proc.join("uptime")).split_whitespace().next().and_then(|u| u.parse::<f64>().ok()).map(|u| u as u64),
            });
            if let Some((at, cpu, disks_before)) = &before {
                let ms = at.elapsed().as_millis() as u64;
                if let (Some((b0, t0)), Some((b1, t1))) = (cpu, now.1) {
                    let total = t1.saturating_sub(*t0);
                    if total > 0 {
                        body["cpu_busy_pct"] = json!(((b1.saturating_sub(*b0)) as f64 * 1000.0 / total as f64).round() / 10.0);
                    }
                }
                let rates: Vec<_> = now.2.iter().filter_map(|(name, after)| disks_before.get(name).map(|b| hostread::disk_rate(name, b, after, ms))).collect();
                body["disks"] = json!(rates);
            }
            before = Some(now);
            if !agent.data("health", body) {
                return;
            }
            last_ssh = s;
        } else if s != last_ssh {
            if !agent.data("ssh", s.clone()) {
                return;
            }
            last_ssh = s;
        }
        beat += 1;
        if !agent.sleep(SSH_EVERY as f64) {
            return;
        }
    }
}
