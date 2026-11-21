//! The disks plugin (roadmap section 11.4 and PF-04): each disk's SMART health on a schedule, and its errors as they happen.
//!
//! Declares the host's whole disks read-only, `SYS_RAWIO` (an ATA pass-through command that is not a plain read needs it), `/sys`
//! read-only, and the journal's folders and `/etc/machine-id` with the `systemd-journal` group for the kernel's lines. It runs nothing: it asks each disk
//! itself, with the ioctls smartctl uses, and decodes the answers (`smart.rs`).
//!
//! - `smart` at start and every `EVERY` seconds: per disk its health in the shape `smartctl -j -a` prints, which the controller reads
//!   with the same code it reads the SSH collector's report with, or why it could not be read.
//! - `errors` when something changed, looked at every `LOOK` seconds: the kernel's count of each disk's failed commands
//!   (`device/ioerr_cnt`), the errors md counts per member, and the kernel's log lines that say a disk failed, as they are written.
//!
//! What it cannot read: an NVMe disk's health log takes `SYS_ADMIN`, which this plugin does not declare (it is root in effect, and
//! the files plugin's to carry). On a kernel that refuses the command without it, the reading says so and the SSH collector's
//! report stays the source for that disk.

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use storageforge_agent::journal::Reader;
use storageforge_agent::pluginside::Agent;
use storageforge_agent::smart;

const EVERY: u64 = 3600;
const LOOK: u64 = 10;
const MOST_LINES: usize = 50;

fn read(path: &Path) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(64 << 10).read_to_string(&mut out);
    }
    out
}

/// The host's whole disks, as storageforge-agentctl gives them to the container (`/dev/NAME`).
fn disks(host: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(host.join("sys/block"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !["loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd"].iter().any(|p| n.starts_with(p)))
                .filter(|n| n.len() <= 32 && n.bytes().all(|b| b.is_ascii_alphanumeric()))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.truncate(64);
    out
}

#[repr(C)]
struct SgIoHdr {
    interface_id: libc::c_int,
    dxfer_direction: libc::c_int,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut libc::c_void,
    cmdp: *const u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: libc::c_int,
    usr_ptr: *mut libc::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: libc::c_int,
    duration: u32,
    info: u32,
}

const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_NONE: libc::c_int = -1;
const SG_DXFER_FROM_DEV: libc::c_int = -3;

/// One ATA PASS-THROUGH (16) SMART command: `feature` D0h READ DATA, D1h READ THRESHOLDS (a sector in), DAh RETURN STATUS (no data,
/// the registers asked back). Returns the data and the sense bytes.
fn ata_smart(fd: libc::c_int, feature: u8) -> Result<(Vec<u8>, Vec<u8>), String> {
    let data_in = feature != 0xda;
    let mut cdb = [0u8; 16];
    cdb[0] = 0x85;
    cdb[1] = if data_in { 4 << 1 } else { 3 << 1 };
    cdb[2] = if data_in { 0x0e } else { 0x20 };
    cdb[4] = feature;
    cdb[6] = u8::from(data_in);
    cdb[10] = 0x4f;
    cdb[12] = 0xc2;
    cdb[14] = 0xb0;
    let mut data = vec![0u8; if data_in { smart::SECTOR } else { 0 }];
    let mut sense = [0u8; 64];
    let mut h = SgIoHdr {
        interface_id: b'S' as libc::c_int,
        dxfer_direction: if data_in { SG_DXFER_FROM_DEV } else { SG_DXFER_NONE },
        cmd_len: 16,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: data.len() as u32,
        dxferp: if data_in { data.as_mut_ptr().cast() } else { std::ptr::null_mut() },
        cmdp: cdb.as_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: 20_000,
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };
    if unsafe { libc::ioctl(fd, SG_IO as _, &mut h as *mut SgIoHdr) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if h.host_status != 0 || (data_in && h.status != 0) {
        return Err(format!("the disk refused the command (status {}, host {})", h.status, h.host_status));
    }
    Ok((data, sense[..usize::from(h.sb_len_wr).min(sense.len())].to_vec()))
}

#[repr(C)]
#[derive(Default)]
struct NvmeAdminCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xC048_4E41;

/// The SMART / Health Information log page (02h) of an NVMe disk.
fn nvme_health(fd: libc::c_int) -> Result<Vec<u8>, String> {
    let mut log = vec![0u8; smart::SECTOR];
    let mut c = NvmeAdminCmd {
        opcode: 0x02,
        nsid: 0xffff_ffff,
        addr: log.as_mut_ptr() as u64,
        data_len: log.len() as u32,
        cdw10: ((smart::SECTOR as u32 / 4 - 1) << 16) | 0x02,
        timeout_ms: 20_000,
        ..Default::default()
    };
    if unsafe { libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD as _, &mut c as *mut NvmeAdminCmd) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EACCES) || e.raw_os_error() == Some(libc::EPERM) {
            "the kernel lets only SYS_ADMIN read an NVMe disk's health log, which the disks plugin does not declare: the SSH collector reads it".into()
        } else {
            e.to_string()
        });
    }
    Ok(log)
}

fn one_disk(host: &Path, dev_dir: &Path, name: &str) -> Value {
    let sys = host.join("sys/block").join(name);
    let field = |f: &str| read(&sys.join("device").join(f)).trim().to_string();
    let mut v = json!({"dev": name, "model": field("model"), "serial": field("serial"), "firmware": field("firmware_rev"), "rotational": read(&sys.join("queue/rotational")).trim() == "1"});
    let nvme = name.starts_with("nvme");
    v["kind"] = json!(if nvme { "nvme" } else { "ata" });
    let file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(dev_dir.join(name)) {
        Ok(f) => f,
        Err(e) => {
            v["error"] = json!(format!("the disk could not be opened: {e}"));
            return v;
        }
    };
    let fd = file.as_raw_fd();
    let got = if nvme {
        nvme_health(fd).and_then(|log| smart::nvme_json(&log).ok_or_else(|| "the health log was not 512 bytes".to_string()))
    } else {
        ata_smart(fd, 0xd0).and_then(|(data, _)| {
            let thresholds = ata_smart(fd, 0xd1).ok().map(|(t, _)| t);
            let passed = ata_smart(fd, 0xda).ok().and_then(|(_, sense)| smart::ata_status(&sense));
            smart::ata_attributes(&data, thresholds.as_deref()).map(|a| smart::ata_json(&a, passed)).ok_or_else(|| "the disk answered no SMART data (a USB bridge or a virtual disk, perhaps)".to_string())
        })
    };
    match got {
        Ok(j) => v["smartctl"] = j,
        Err(why) => v["error"] = json!(why),
    }
    v
}

fn counters(host: &Path, names: &[String]) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let mut io = BTreeMap::new();
    for n in names {
        if let Some(c) = smart::hex_count(&read(&host.join("sys/block").join(n).join("device/ioerr_cnt"))) {
            io.insert(n.clone(), c);
        }
    }
    let mut md = BTreeMap::new();
    if let Ok(arrays) = std::fs::read_dir(host.join("sys/block")) {
        for a in arrays.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("md")).take(64) {
            if let Ok(members) = std::fs::read_dir(a.path().join("md")) {
                for m in members.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("dev-")).take(64) {
                    if let Ok(n) = read(&m.path().join("errors")).trim().parse::<u64>() {
                        md.insert(format!("{}/{}", a.file_name().to_string_lossy(), m.file_name().to_string_lossy().trim_start_matches("dev-")), n);
                    }
                }
            }
        }
    }
    (io, md)
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
    // the disks are the container's own /dev nodes, which storageforge-agentctl gave it read-only; the tests point it elsewhere
    let dev_dir = if host.join("dev").is_dir() && host != Path::new("/host") { host.join("dev") } else { PathBuf::from("/dev") };
    let machine = std::fs::read_to_string(host.join("etc/machine-id")).map(|t| t.trim().to_string()).unwrap_or_default();
    if machine.len() != 32 || !machine.bytes().all(|b| b.is_ascii_hexdigit()) {
        agent.log("the host's machine id cannot be read: the kernel's lines cannot be found in its journal, and the error counts are read alone");
    }
    // from what is written from now on: what came before, a scan over SSH collected
    let mut journal = Reader::new(["var/log/journal", "run/log/journal"].iter().map(|d| host.join(d).join(&machine)).collect(), None);
    let mut last_counters: Option<(BTreeMap<String, u64>, BTreeMap<String, u64>)> = None;
    let mut since_smart = EVERY;
    loop {
        let names = disks(&host);
        if since_smart >= EVERY {
            let all: Vec<Value> = names.iter().map(|n| one_disk(&host, &dev_dir, n)).collect();
            if !agent.data("smart", json!({"disks": all})) {
                return;
            }
            since_smart = 0;
        }
        let now = counters(&host, &names);
        let mut lines = Vec::new();
        for (entry, _) in journal.poll() {
            if entry.fields.get("_TRANSPORT").map(String::as_str) != Some("kernel") {
                continue;
            }
            let message = entry.fields.get("MESSAGE").cloned().unwrap_or_default();
            if let Some(dev) = smart::disk_error(&message) {
                if lines.len() < MOST_LINES {
                    lines.push(json!({"at": entry.realtime, "dev": dev, "message": message.chars().take(500).collect::<String>()}));
                }
            }
        }
        if !lines.is_empty() || last_counters.as_ref() != Some(&now) {
            let body = json!({"ioerr": now.0, "md": now.1, "lines": lines, "first": last_counters.is_none()});
            if !agent.data("errors", body) {
                return;
            }
            last_counters = Some(now);
        }
        if !agent.sleep(LOOK as f64) {
            return;
        }
        since_smart += LOOK;
    }
}
