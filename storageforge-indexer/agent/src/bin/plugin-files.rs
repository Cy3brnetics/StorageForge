//! The files plugin (roadmap sections 11.4 and 9, "Watchers"): every change to the host's files as it happens, with the process and
//! the account that made it, and how much each account reads, for an index that updates itself, hand edits seen at once and reads
//! out of hours.
//!
//! **It is root on the host in effect**, and says so wherever it is switched on. It declares `SYS_ADMIN` (fanotify on whole
//! filesystems takes it, and with it a process can undo the masks over SSH's keys), `DAC_READ_SEARCH` (to find a changed file by
//! its handle and read its size, whoever owns it) and `SYS_PTRACE` (to reach each filesystem through the host's first process, and
//! to see which program a process runs), with the host's process table and `/proc` read-only. It reads names, sizes, times and
//! who; it opens no file's contents and writes nothing.
//!
//! How: one fanotify group, a mark on each local filesystem of the host (the host's own mount table, reached through
//! `/proc/1/root`), reporting each event as the folder's handle and the name in it. A folder's handle is turned into its path once and
//! kept; the process behind an event is read from `/proc` while it is there.
//!
//! - `changes` every `EVERY` seconds when there were any: up to `MOST_CHANGES` per reading, each path once per action, with its size
//!   and time where it is still there, and how many were left out.
//! - `reads` once a minute: files read (opened and closed without writing) per account, and the folders they were in.
//! - `watching` at start and every ten minutes: the filesystems marked, and those that could not be, with why.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};
use storageforge_agent::pluginside::{now, Agent};

const EVERY: u64 = 5;
const MOST_CHANGES: usize = 500;
const MOST_DIRS: usize = 20_000;
const READ_FOLDERS: usize = 10;

// fanotify, from linux/fanotify.h
const FAN_CLASS_NOTIF: u32 = 0x0;
const FAN_CLOEXEC: u32 = 0x1;
const FAN_NONBLOCK: u32 = 0x2;
const FAN_REPORT_DIR_FID: u32 = 0x400;
const FAN_REPORT_NAME: u32 = 0x800;
const FAN_MARK_ADD: u32 = 0x1;
const FAN_MARK_FILESYSTEM: u32 = 0x100;
const FAN_UNLIMITED_MARKS: u32 = 0x20;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
/// Folder by folder, where a whole filesystem cannot be marked (a btrfs subvolume has an fsid of its own): at most this many in all.
const MOST_DIR_MARKS: usize = 200_000;
const FAN_CLOSE_WRITE: u64 = 0x8;
const FAN_CLOSE_NOWRITE: u64 = 0x10;
const FAN_MOVED_FROM: u64 = 0x40;
const FAN_MOVED_TO: u64 = 0x80;
const FAN_CREATE: u64 = 0x100;
const FAN_DELETE: u64 = 0x200;
const FAN_Q_OVERFLOW: u64 = 0x4000;
const FAN_ONDIR: u64 = 0x4000_0000;
const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
const MASK: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_DELETE | FAN_ONDIR;

/// The filesystems worth watching: where files live. Not /proc, /sys, tmpfs, overlays of containers or network filesystems.
const LOCAL: [&str; 12] = ["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs", "jfs", "vfat", "exfat", "ntfs3"];

fn read(path: &Path) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(4 << 20).read_to_string(&mut out);
    }
    out
}

fn unoctal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// (mount point, filesystem type, major:minor) of each local filesystem in a mount table, once per filesystem, and the mount
/// points of the other btrfs subvolumes of that filesystem. They share one filesystem-wide mark, and an event in any of them must
/// be traced back to the mount it was in.
fn filesystems(mountinfo: &str) -> Vec<(String, String, String, Vec<String>)> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<(String, String, String, Vec<String>)> = Vec::new();
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let (a, b): (Vec<&str>, Vec<&str>) = (left.split(' ').collect(), right.split(' ').collect());
        if a.len() < 5 || b.is_empty() || !LOCAL.contains(&b[0]) {
            continue;
        }
        // btrfs subvolumes share one filesystem and one mark; zfs datasets are each their own
        let key = if b[0] == "btrfs" { b.get(1).unwrap_or(&"").to_string() } else { a[2].to_string() };
        match seen.get(&key) {
            None => {
                seen.insert(key, out.len());
                out.push((unoctal(a[4]), b[0].to_string(), a[2].to_string(), Vec::new()));
            }
            Some(&i) if b[0] == "btrfs" => out[i].3.push(unoctal(a[4])),
            Some(_) => {}
        }
    }
    out.truncate(256);
    out
}

/// Of the mount points a path lies under, the longest one: the mount that path belongs to.
fn longest_mount<'a>(path: &str, mounts: &[&'a str]) -> Option<&'a str> {
    mounts
        .iter()
        .copied()
        .filter(|m| *m == "/" || path == *m || path.strip_prefix(*m).is_some_and(|r| r.starts_with('/')))
        .max_by_key(|m| m.len())
}

/// A filesystem as the host mounts it: each mount point (every btrfs subvolume has one) opened once, to open a handle against.
struct Fs {
    mounts: Vec<(String, libc::c_int)>,
}

struct Watch {
    fd: libc::c_int,
    /// Folders marked one by one, and the filesystems (by device) watched that way, where new folders are marked as they come.
    dir_marks: usize,
    by_folder: std::collections::BTreeSet<u64>,
    /// The filesystems, and by fsid which of them an event is in (a btrfs subvolume has an fsid of its own, so several fsids can name one).
    fses: Vec<Fs>,
    by_fsid: HashMap<[i32; 2], usize>,
    dirs: HashMap<Vec<u8>, String>,
    proc: PathBuf,
    root: PathBuf,
    me: (u32, u32),
}

fn fsid_of(path: &Path) -> Option<[i32; 2]> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    // f_fsid is two ints; libc hides its fields, so they are read as the bytes they are
    let raw: [i32; 2] = unsafe { std::mem::transmute_copy(&s.f_fsid) };
    Some(raw)
}

impl Watch {
    fn mark_all(&mut self, host: &Path) -> (Vec<Value>, Vec<Value>) {
        let (mut marked, mut refused) = (Vec::new(), Vec::new());
        'filesystems: for (target, fstype, _, others) in filesystems(&read(&self.proc.join("1/mountinfo"))) {
            let path = self.root.join(target.trim_start_matches('/'));
            let Ok(c) = CString::new(path.as_os_str().as_bytes()) else { continue };
            let rc = unsafe { libc::fanotify_mark(self.fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, MASK, libc::AT_FDCWD, c.as_ptr()) };
            let mut how = "whole";
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EXDEV) {
                    refused.push(json!({"target": target, "fstype": fstype, "why": e.to_string()}));
                    continue;
                }
                // a btrfs subvolume: its folders are marked one by one, and new ones as they are made. Here each subvolume
                // needs its own pass, because no mark covers the others.
                let mut complete = true;
                let tops = std::iter::once(&target).chain(others.iter());
                for (i, top) in tops.enumerate() {
                    match self.mark_tree(&self.root.join(top.trim_start_matches('/'))) {
                        Ok((_, all)) => complete &= all,
                        Err(why) if i == 0 => {
                            refused.push(json!({"target": target, "fstype": fstype, "why": why}));
                            continue 'filesystems;
                        }
                        Err(_) => complete = false,
                    }
                }
                how = if complete { "by folder" } else { "by folder, in part" };
            }
            // Every mount of the filesystem is opened, so a handle from any subvolume can be traced to the mount it is in.
            let mut fs = Fs { mounts: Vec::new() };
            let mut fsids = Vec::new();
            for top in std::iter::once(&target).chain(others.iter()) {
                let p = self.root.join(top.trim_start_matches('/'));
                let Ok(pc) = CString::new(p.as_os_str().as_bytes()) else { continue };
                let fd = unsafe { libc::open(pc.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
                match (fsid_of(&p), fd >= 0) {
                    (Some(fsid), true) => {
                        fsids.push(fsid);
                        fs.mounts.push((top.clone(), fd));
                    }
                    (_, true) => unsafe {
                        libc::close(fd);
                    },
                    _ => {}
                }
            }
            if fs.mounts.first().is_some_and(|(t, _)| *t == target) {
                self.fses.push(fs);
                for fsid in fsids {
                    self.by_fsid.entry(fsid).or_insert(self.fses.len() - 1);
                }
                marked.push(json!({"target": target, "fstype": fstype, "how": how}));
            } else {
                for (_, fd) in fs.mounts {
                    unsafe { libc::close(fd) };
                }
                refused.push(json!({"target": target, "fstype": fstype, "why": "marked, but its changes cannot be traced back to their paths"}));
            }
        }
        let _ = host;
        (marked, refused)
    }

    /// Marks a folder and every folder under it on the same filesystem. Returns how many, and whether all of them were.
    fn mark_tree(&mut self, top: &Path) -> Result<(usize, bool), String> {
        let dev = std::fs::symlink_metadata(top).map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        let dev = dev.dev();
        let mut stack = vec![top.to_path_buf()];
        let mut n = 0usize;
        while let Some(dir) = stack.pop() {
            if self.dir_marks >= MOST_DIR_MARKS {
                self.by_folder.insert(dev);
                return Ok((n, false));
            }
            if !self.mark_dir(&dir) {
                if n == 0 {
                    return Err(format!("a folder of it cannot be marked either: {}", std::io::Error::last_os_error()));
                }
                continue;
            }
            n += 1;
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    if let Ok(m) = e.path().symlink_metadata() {
                        if m.is_dir() && m.dev() == dev {
                            stack.push(e.path());
                        }
                    }
                }
            }
        }
        self.by_folder.insert(dev);
        Ok((n, true))
    }

    fn mark_dir(&mut self, dir: &Path) -> bool {
        let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else { return false };
        let ok = unsafe { libc::fanotify_mark(self.fd, FAN_MARK_ADD, MASK | FAN_EVENT_ON_CHILD, libc::AT_FDCWD, c.as_ptr()) } == 0;
        if ok {
            self.dir_marks += 1;
        }
        ok
    }

    /// The path of a folder from its handle, as the host names it.
    fn dir_path(&mut self, fsid: [i32; 2], handle: &[u8]) -> Option<String> {
        let mut key = Vec::with_capacity(handle.len() + 8);
        key.extend_from_slice(&fsid[0].to_ne_bytes());
        key.extend_from_slice(&fsid[1].to_ne_bytes());
        key.extend_from_slice(handle);
        if let Some(p) = self.dirs.get(&key) {
            return Some(p.clone());
        }
        let fs = self.fses.get(*self.by_fsid.get(&fsid)?)?;
        let root = self.root.to_string_lossy().into_owned();
        // Tried against each mount of the filesystem (a btrfs subvolume's folders do not lie under another subvolume's
        // mount): the path that lies under the longest mount point is the one that is right.
        let mut found: Vec<(String, &str)> = Vec::new();
        for (target, mount_fd) in &fs.mounts {
            let fd = unsafe { libc::syscall(libc::SYS_open_by_handle_at, *mount_fd, handle.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as libc::c_int;
            if fd < 0 {
                continue;
            }
            let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
            unsafe { libc::close(fd) };
            let Some(link) = link else { continue };
            // reached through the host's first process: the path as the host names it
            let mut p = link.to_string_lossy().into_owned();
            if let Some(rest) = p.strip_prefix(&root) {
                p = if rest.is_empty() { "/".into() } else { rest.to_string() };
            }
            found.push((p, target));
        }
        let mut p = {
            let mut best: Option<&(String, &str)> = None;
            for f in &found {
                if longest_mount(&f.0, &[f.1]).is_some() && best.is_none_or(|b| f.1.len() > b.1.len()) {
                    best = Some(f);
                }
            }
            // none under its own mount (a bind mount of a part of the filesystem): the first answer, as before
            best.or(found.first())?.0.clone()
        };
        if p.is_empty() {
            p = "/".into();
        }
        if self.dirs.len() >= MOST_DIRS {
            self.dirs.clear();
        }
        self.dirs.insert(key, p.clone());
        Some(p)
    }

    fn who(&self, pid: i32) -> (Option<String>, Option<u32>) {
        if pid <= 0 {
            return (None, None);
        }
        let base = self.proc.join(pid.to_string());
        let comm = read(&base.join("comm")).trim().chars().take(64).collect::<String>();
        let uid = read(&base.join("status")).lines().find_map(|l| l.strip_prefix("Uid:").and_then(|r| r.split_whitespace().nth(1)).and_then(|u| u.parse().ok()));
        (Some(comm).filter(|c| !c.is_empty()), uid)
    }
}

#[derive(Default)]
struct Window {
    changes: BTreeMap<(String, &'static str), Value>,
    left_out: u64,
    overflow: u64,
    reads: BTreeMap<u32, (u64, BTreeMap<String, u64>)>,
}

fn action(mask: u64) -> Option<&'static str> {
    Some(if mask & FAN_DELETE != 0 {
        "delete"
    } else if mask & FAN_MOVED_FROM != 0 {
        "moved_from"
    } else if mask & FAN_MOVED_TO != 0 {
        "moved_to"
    } else if mask & FAN_CREATE != 0 {
        "create"
    } else if mask & FAN_CLOSE_WRITE != 0 {
        "write"
    } else {
        return None;
    })
}

/// Whether an event is a folder going away or changing place, which makes cached paths of what is under it wrong.
fn changes_folder_paths(mask: u64) -> bool {
    mask & FAN_ONDIR != 0 && mask & (FAN_MOVED_FROM | FAN_MOVED_TO | FAN_DELETE) != 0
}

fn folder_of(path: &str) -> String {
    // the first three levels: /srv/share/projects, enough to say where someone read
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).take(3).collect();
    format!("/{}", parts.join("/"))
}

fn stat(root: &Path, path: &str) -> Option<Value> {
    let c = CString::new(root.join(path.trim_start_matches('/')).as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(libc::AT_FDCWD, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return None;
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => "dir",
        libc::S_IFLNK => "link",
        libc::S_IFREG => "file",
        _ => "other",
    };
    Some(json!({"size": st.st_size, "mtime": st.st_mtime, "kind": kind, "uid": st.st_uid, "gid": st.st_gid, "mode": st.st_mode & 0o7777}))
}

/// Reads what fanotify has, into the window. Returns false when the group is gone.
fn drain(w: &mut Watch, win: &mut Window, buf: &mut [u8]) -> bool {
    loop {
        let n = unsafe { libc::read(w.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EINTR);
        }
        if n == 0 {
            return true;
        }
        let mut at = 0usize;
        let n = n as usize;
        while at + 24 <= n {
            let event_len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            let meta_len = u16::from_ne_bytes(buf[at + 6..at + 8].try_into().unwrap()) as usize;
            if event_len < 24 || at + event_len > n {
                break;
            }
            let mask = u64::from_ne_bytes(buf[at + 8..at + 16].try_into().unwrap());
            let fd = i32::from_ne_bytes(buf[at + 16..at + 20].try_into().unwrap());
            let pid = i32::from_ne_bytes(buf[at + 20..at + 24].try_into().unwrap());
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
            if mask & FAN_Q_OVERFLOW != 0 {
                win.overflow += 1;
            } else if pid <= 0 || (pid as u32 != w.me.0 && pid as u32 != w.me.1) {
                one_event(w, win, mask, pid, &buf[at + meta_len.max(24)..at + event_len]);
            }
            at += event_len;
        }
    }
}

fn one_event(w: &mut Watch, win: &mut Window, mask: u64, pid: i32, info: &[u8]) {
    // the info record: a header, the fsid, the folder's file handle, then the name
    if info.len() < 4 + 8 + 8 || info[0] != FAN_EVENT_INFO_TYPE_DFID_NAME {
        return;
    }
    let len = u16::from_ne_bytes([info[2], info[3]]) as usize;
    let rec = &info[..len.min(info.len())];
    if rec.len() < 20 {
        return;
    }
    let fsid = [i32::from_ne_bytes(rec[4..8].try_into().unwrap()), i32::from_ne_bytes(rec[8..12].try_into().unwrap())];
    let handle_bytes = u32::from_ne_bytes(rec[12..16].try_into().unwrap()) as usize;
    if 20 + handle_bytes > rec.len() || handle_bytes > 128 {
        return;
    }
    let handle = &rec[12..20 + handle_bytes];
    let name = CStr::from_bytes_until_nul(&rec[20 + handle_bytes..]).map(|c| c.to_string_lossy().into_owned()).unwrap_or_default();
    // A folder that was renamed, moved or deleted keeps its handle but not its path: forget every cached path.
    if changes_folder_paths(mask) {
        w.dirs.clear();
    }
    let Some(dir) = w.dir_path(fsid, handle) else { return };
    let path = if name.is_empty() || name == "." { dir } else if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") };
    if mask & FAN_CLOSE_NOWRITE != 0 && mask & FAN_ONDIR == 0 {
        let (_, uid) = w.who(pid);
        let e = win.reads.entry(uid.unwrap_or(u32::MAX)).or_default();
        e.0 += 1;
        if e.1.len() < 200 || e.1.contains_key(&folder_of(&path)) {
            *e.1.entry(folder_of(&path)).or_default() += 1;
        }
        // fanotify merges queued events of one process and name, so a read may carry a change with it
        if action(mask).is_none() {
            return;
        }
    }
    let Some(act) = action(mask) else { return };
    let key = (path.clone(), act);
    if win.changes.contains_key(&key) {
        return;
    }
    if win.changes.len() >= MOST_CHANGES {
        win.left_out += 1;
        return;
    }
    let (process, uid) = w.who(pid);
    if mask & FAN_ONDIR != 0 && matches!(act, "create" | "moved_to") && !w.by_folder.is_empty() && w.dir_marks < MOST_DIR_MARKS {
        let full = w.root.join(path.trim_start_matches('/'));
        use std::os::unix::fs::MetadataExt;
        if full.symlink_metadata().is_ok_and(|m| w.by_folder.contains(&m.dev())) {
            let _ = w.mark_tree(&full);
        }
    }
    let mut v = json!({"at": now(), "path": path, "action": act, "pid": pid, "process": process, "uid": uid, "dir": mask & FAN_ONDIR != 0});
    if matches!(act, "write" | "create" | "moved_to") {
        if let Some(s) = stat(&w.root, &path) {
            v["stat"] = s;
        }
    }
    win.changes.insert(key, v);
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
    let fd = unsafe { libc::fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_MARKS | FAN_REPORT_DIR_FID | FAN_REPORT_NAME, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32) };
    if fd < 0 {
        let why = std::io::Error::last_os_error();
        agent.data("watching", json!({"filesystems": [], "refused": [], "error": format!("fanotify could not be started: {why} (it takes SYS_ADMIN and Linux 5.9 or later)")}));
        // nothing to watch: wait to be stopped rather than be started again and again
        while agent.sleep(60.0) {}
        return;
    }
    let me = (std::process::id(), unsafe { libc::getppid() } as u32);
    let mut w = Watch { fd, dir_marks: 0, by_folder: Default::default(), fses: Vec::new(), by_fsid: HashMap::new(), dirs: HashMap::new(), root: proc.join("1/root"), proc, me };
    let (marked, refused) = w.mark_all(&host);
    let first = json!({"filesystems": marked, "refused": refused});
    if !agent.data("watching", first.clone()) {
        return;
    }
    let mut buf = vec![0u8; 256 << 10];
    let mut win = Window::default();
    let (mut last_send, mut last_reads, mut last_watching) = (Instant::now(), now() / 60, Instant::now());
    loop {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut pfd, 1, 500) };
        if agent.stopping() || !drain(&mut w, &mut win, &mut buf) {
            return;
        }
        if last_send.elapsed().as_secs() >= EVERY && (!win.changes.is_empty() || win.left_out > 0 || win.overflow > 0) {
            let changes: Vec<Value> = std::mem::take(&mut win.changes).into_values().collect();
            let body = json!({"changes": changes, "left_out": win.left_out, "overflow": win.overflow});
            win.left_out = 0;
            win.overflow = 0;
            if !agent.data("changes", body) {
                return;
            }
            last_send = Instant::now();
        }
        let minute = now() / 60;
        if minute != last_reads {
            if !win.reads.is_empty() {
                let accounts: Vec<Value> = std::mem::take(&mut win.reads)
                    .into_iter()
                    .map(|(uid, (n, folders))| {
                        let mut top: Vec<(String, u64)> = folders.into_iter().collect();
                        top.sort_by(|a, b| b.1.cmp(&a.1));
                        top.truncate(READ_FOLDERS);
                        json!({"uid": if uid == u32::MAX { Value::Null } else { json!(uid) }, "reads": n, "folders": top.into_iter().collect::<BTreeMap<_, _>>()})
                    })
                    .collect();
                if !agent.data("reads", json!({"minute": last_reads, "accounts": accounts})) {
                    return;
                }
            }
            last_reads = minute;
        }
        if last_watching.elapsed().as_secs() >= 600 {
            // the same lists as the first report: what was marked and what was refused does not change until this plugin starts again
            let mut again = first.clone();
            again["again"] = json!(true);
            if !agent.data("watching", again) {
                return;
            }
            last_watching = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_local_filesystem_is_watched_once() {
        let mi = "22 1 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw\n\
                  23 22 0:22 / /proc rw - proc proc rw\n\
                  24 22 0:40 /@home /home rw - btrfs /dev/sda1 rw,subvol=/@home\n\
                  25 22 0:41 /@data /srv/my\\040data rw - btrfs /dev/sda1 rw,subvol=/@data\n\
                  26 22 0:50 / /tank rw - zfs tank rw\n\
                  27 22 0:51 / /tank/a rw - zfs tank/a rw\n\
                  28 22 0:60 / /mnt/nfs rw - nfs4 server:/x rw\n\
                  29 22 0:61 / /run rw - tmpfs tmpfs rw\n";
        let got: Vec<String> = filesystems(mi).into_iter().map(|(t, f, _, o)| format!("{t} {f} {}", o.join(","))).collect();
        assert_eq!(got, ["/ ext4 ", "/home btrfs /srv/my data", "/tank zfs ", "/tank/a zfs "]);
        // an event in a subvolume belongs to the longest mount it lies under
        let mounts = ["/", "/home", "/srv/my data"];
        assert_eq!(longest_mount("/srv/my data/a/b", &mounts), Some("/srv/my data"));
        assert_eq!(longest_mount("/home/u", &mounts), Some("/home"));
        assert_eq!(longest_mount("/homework", &mounts), Some("/"));
        assert_eq!(longest_mount("/home", &["/home/x"]), None);
        assert_eq!(unoctal("/srv/my\\040data"), "/srv/my data");
        assert_eq!(folder_of("/srv/share/projects/2026/a.txt"), "/srv/share/projects");
        assert_eq!(folder_of("/a.txt"), "/a.txt");
        assert_eq!(action(FAN_CLOSE_WRITE), Some("write"));
        assert_eq!(action(FAN_CREATE | FAN_ONDIR), Some("create"));
        assert_eq!(action(FAN_CLOSE_NOWRITE), None);
        // a read merged with a delete is still a delete
        assert_eq!(action(FAN_CLOSE_NOWRITE | FAN_DELETE), Some("delete"));
        assert!(changes_folder_paths(FAN_ONDIR | FAN_MOVED_FROM));
        assert!(changes_folder_paths(FAN_ONDIR | FAN_DELETE));
        assert!(!changes_folder_paths(FAN_MOVED_FROM));
        assert!(!changes_folder_paths(FAN_ONDIR | FAN_CREATE));
    }
}
