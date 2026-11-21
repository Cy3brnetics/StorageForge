//! The scan plugin (roadmap section 11.4): the read-only scans, for a host the controller has no SSH scan access to, as scripts carried
//! in the plugin (decision of 2026-11-16). The script is compiled into this program (`agent/scan/*.scan`), the release key signs the
//! program, and no message from the controller names a script, a path or a command: no code crosses the wire per scan, and the
//! controller can choose this plugin or not, never what it runs.
//!
//! A script is a list of words, each of which reads (see the head of `agent/scan/inventory.scan`): there is no word that runs a
//! program, writes, or follows anything a host says to somewhere it was not told. The image has no shell to run one with anyway.
//!
//! Declares the host's root, `/proc` and `/sys` read-only and the host's process table, with SSH's and StorageForge's secrets masked
//! by storageforge-agentctl as for every plugin. It runs as `sfagent` with no capability, so what an ordinary account cannot read it
//! does not read either.
//!
//! - `inventory` at start and every `EVERY` seconds: the script's output, the sections of the SSH scan's inventory in their form, in
//!   parts of at most `PART` bytes that the controller puts together by `run`.

use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde_json::json;
use storageforge_agent::pluginside::{now, Agent};

const EVERY: u64 = 900;
const PART: usize = 40 << 10;
const MOST_FILE: u64 = 256 << 10;
const MOST_OUTPUT: usize = 2 << 20;
pub const INVENTORY: &str = include_str!("../../scan/inventory.scan");

/// A file's text, if it is a plain file: opened without waiting (a host could put a pipe where a file was), and read up to `most`.
fn open_plain(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a plain file"));
    }
    Ok(f)
}

fn read(path: &Path, most: u64) -> Option<String> {
    let f = open_plain(path).ok()?;
    let mut out = String::new();
    f.take(most).read_to_string(&mut out).ok()?;
    Some(out)
}

fn glob(host: &Path, pattern: &str) -> Vec<PathBuf> {
    let (dir, name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let Some((pre, post)) = name.split_once('*') else { return vec![host.join(pattern.trim_start_matches('/'))] };
    let mut out: Vec<PathBuf> = std::fs::read_dir(host.join(dir.trim_start_matches('/')))
        .map(|d| {
            d.flatten()
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.starts_with(pre) && n.ends_with(post) && n.len() >= pre.len() + post.len()
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.truncate(256);
    out
}

fn host_path(host: &Path, p: &str) -> PathBuf {
    host.join(p.trim_start_matches('/'))
}

fn os_release(host: &Path) -> Option<String> {
    let text = read(&host_path(host, "/etc/os-release"), 64 << 10).or_else(|| read(&host_path(host, "/usr/lib/os-release"), 64 << 10))?;
    text.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim().trim_matches('"').to_string())
}

fn first_line(host: &Path, p: &str) -> String {
    read(&host_path(host, p), 4096).unwrap_or_default().lines().next().unwrap_or("").trim().to_string()
}

fn sys_block(host: &Path) -> String {
    let base = host_path(host, "/sys/block");
    let mut disks = Vec::new();
    let mut names: Vec<String> = std::fs::read_dir(&base).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    names.sort();
    for name in names.into_iter().filter(|n| !["loop", "ram", "zram"].iter().any(|p| n.starts_with(p))).take(256) {
        let dir = base.join(&name);
        let num = |p: &str| first_line(host, &format!("/sys/block/{name}/{p}")).parse::<u64>().unwrap_or(0);
        let text = |p: &str| first_line(host, &format!("/sys/block/{name}/{p}"));
        let kind = if name.starts_with("md") { "raid" } else if name.starts_with("dm-") { "lvm" } else { "disk" };
        let mut parts = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut ps: Vec<String> = entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|p| p.starts_with(&name) && dir.join(p).join("partition").exists()).collect();
            ps.sort();
            for p in ps.into_iter().take(128) {
                let size = first_line(host, &format!("/sys/block/{name}/{p}/size")).parse::<u64>().unwrap_or(0) * 512;
                parts.push(json!({"name": p, "path": format!("/dev/{p}"), "size": size, "type": "part"}));
            }
        }
        disks.push(json!({"name": name, "path": format!("/dev/{name}"), "size": num("size") * 512, "type": kind, "rota": num("queue/rotational") == 1,
                          "model": Some(text("device/model")).filter(|s| !s.is_empty()), "serial": Some(text("device/serial")).filter(|s| !s.is_empty()),
                          "children": if parts.is_empty() { serde_json::Value::Null } else { json!(parts) }}));
    }
    json!({"blockdevices": disks}).to_string()
}

fn passwd(host: &Path) -> Vec<Vec<String>> {
    read(&host_path(host, "/etc/passwd"), 4 << 20).unwrap_or_default().lines().map(|l| l.split(':').map(str::to_string).collect::<Vec<_>>()).filter(|f| f.len() >= 7).collect()
}

fn group(host: &Path) -> Vec<Vec<String>> {
    read(&host_path(host, "/etc/group"), 4 << 20).unwrap_or_default().lines().map(|l| l.split(':').map(str::to_string).collect::<Vec<_>>()).filter(|f| f.len() >= 4).collect()
}

fn ordinary(id: &str) -> bool {
    id.parse::<u32>().is_ok_and(|n| (1000..60000).contains(&n))
}

fn addresses(host: &Path) -> String {
    // the host's own IPv4 addresses, from the kernel's routing trie: the leaves marked "/32 host LOCAL", but loopback
    let trie = read(&host_path(host, "/proc/1/net/fib_trie"), 4 << 20).unwrap_or_default();
    let mut last = "";
    let mut out: Vec<String> = Vec::new();
    for line in trie.lines() {
        let t = line.trim_start_matches([' ', '|', '-', '+']).trim();
        if t.contains("/32 host LOCAL") && !last.starts_with("127.") && !out.iter().any(|a| a == last) && !last.is_empty() {
            out.push(last.to_string());
        } else if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            last = t.split_whitespace().next().unwrap_or("");
        }
    }
    out.join(" ")
}

fn services(host: &Path) -> String {
    let base = host_path(host, "/etc/systemd/system");
    if !base.is_dir() {
        return String::new();
    }
    let mut units = std::collections::BTreeSet::new();
    if let Ok(dirs) = std::fs::read_dir(&base) {
        for d in dirs.flatten().filter(|d| d.file_name().to_string_lossy().ends_with(".wants")).take(256) {
            if let Ok(links) = std::fs::read_dir(d.path()) {
                for l in links.flatten().take(2000) {
                    let n = l.file_name().to_string_lossy().into_owned();
                    if [".service", ".socket", ".timer", ".path"].iter().any(|s| n.ends_with(s)) && !n.contains('@') {
                        units.insert(n);
                    }
                }
            }
        }
    }
    let mut out = String::from("init systemd\n");
    for u in units.into_iter().take(2000) {
        out += &format!("e\t{u}\tenabled\n");
    }
    out
}

fn btrfs(host: &Path) -> String {
    let base = host_path(host, "/sys/fs/btrfs");
    let mut out = String::new();
    let Ok(fss) = std::fs::read_dir(&base) else { return out };
    for fs in fss.flatten().filter(|e| e.file_name().to_string_lossy().contains('-')).take(64) {
        let p = fs.path();
        let profiles = |kind: &str| -> String {
            let mut v: Vec<String> = std::fs::read_dir(p.join("allocation").join(kind)).map(|d| d.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
            v.sort();
            v.join(",")
        };
        let n = |rel: &str| read(&p.join(rel), 64).and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
        let label = read(&p.join("label"), 256).unwrap_or_default().trim().to_string();
        out += &format!("{}\t{}\t{}\t{}\talloc={} datat={} datau={} metat={} metau={} rsv={}\n", fs.file_name().to_string_lossy(), profiles("data"), profiles("metadata"), label,
                        n("allocation/data/disk_total") + n("allocation/metadata/disk_total") + n("allocation/system/disk_total"),
                        n("allocation/data/total_bytes"), n("allocation/data/bytes_used"), n("allocation/metadata/total_bytes"), n("allocation/metadata/bytes_used"), n("allocation/global_rsv_size"));
    }
    out
}

/// Runs a script against the host's paths. Every word reads; a word it does not know is skipped and said.
pub fn run_script(script: &str, host: &Path) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut unknown = Vec::new();
    let b64 = base64::engine::general_purpose::STANDARD;
    for line in script.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if out.len() > MOST_OUTPUT {
            break;
        }
        let mut words = line.split_whitespace();
        let word = words.next().unwrap_or("");
        let args: Vec<&str> = words.collect();
        let mut put = |text: &str| {
            out += text;
            if !text.is_empty() && !text.ends_with('\n') {
                out.push('\n');
            }
        };
        match word {
            "section" => put(&format!("@@{}", args.first().unwrap_or(&""))),
            "cat" => {
                if let Some(t) = args.iter().find_map(|p| read(&host_path(host, p), MOST_FILE)) {
                    put(&t);
                }
            }
            "each" => {
                for p in args.iter().flat_map(|g| glob(host, g)) {
                    if let Some(t) = read(&p, MOST_FILE) {
                        put(&t);
                    }
                }
            }
            "hostname" => put(&first_line(host, "/proc/sys/kernel/hostname")),
            "machineid" => put(&first_line(host, "/etc/machine-id")),
            "ip" => put(&addresses(host)),
            "osname" => put(&os_release(host).unwrap_or_default()),
            "uname" => put(&format!("{} {} {}", first_line(host, "/proc/sys/kernel/ostype"), first_line(host, "/proc/sys/kernel/osrelease"), std::env::consts::ARCH)),
            "arch" => put(&format!("arch\t{}", std::env::consts::ARCH)),
            "lsblk" => put(&sys_block(host)),
            "btrfs" => put(&btrfs(host)),
            "ids" => {
                let mut t = String::new();
                for f in passwd(host).into_iter().filter(|f| ordinary(&f[2])) {
                    t += &format!("u {} {}\n", f[0], f[2]);
                }
                for f in group(host).into_iter().filter(|f| ordinary(&f[2])) {
                    t += &format!("g {} {}\n", f[0], f[2]);
                }
                put(&t);
            }
            "accounts" => {
                let mut t = String::new();
                for f in passwd(host).into_iter().filter(|f| ordinary(&f[2])) {
                    t += &format!("u\t{}\t{}\t{}\t{}\t{}\n", f[0], f[2], f[3], f[5], f[6]);
                }
                for f in group(host).into_iter().filter(|f| !f[3].is_empty() || ordinary(&f[2])) {
                    t += &format!("g\t{}\t{}\t{}\n", f[0], f[2], f[3]);
                }
                put(&t);
            }
            "services" => put(&services(host)),
            "configs" => {
                let mut t = String::new();
                for p in args.iter().flat_map(|g| glob(host, g)) {
                    let shown = format!("/{}", p.strip_prefix(host).unwrap_or(&p).to_string_lossy().trim_start_matches('/'));
                    match open_plain(&p) {
                        Ok(f) => {
                            let mut bytes = Vec::new();
                            let _ = f.take(MOST_FILE).read_to_end(&mut bytes);
                            t += &format!("{shown}\t{}\n", b64.encode(&bytes));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => t += &format!("{shown}\t!\n"),
                        Err(_) => {}
                    }
                }
                put(&t);
            }
            other => unknown.push(other.to_string()),
        }
    }
    (out, unknown)
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
    loop {
        let started = now();
        let (text, unknown) = run_script(INVENTORY, &host);
        if !unknown.is_empty() {
            agent.log(format!("the inventory script has words this program does not know: {}", unknown.join(", ")));
        }
        let mut chunks: Vec<&str> = Vec::new();
        let mut rest = text.as_str();
        while !rest.is_empty() {
            let mut cut = rest.len().min(PART);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            chunks.push(&rest[..cut]);
            rest = &rest[cut..];
        }
        let of = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            if !agent.data("inventory", json!({"script": "inventory", "run": started, "part": i, "of": of, "text": chunk, "took_ms": (now() - started) * 1000})) {
                return;
            }
        }
        if !agent.sleep(EVERY as f64) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_carried_script_uses_only_words_that_read() {
        let dir = std::env::temp_dir().join(format!("sfscan-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        let (out, unknown) = run_script(INVENTORY, &dir);
        assert!(unknown.is_empty(), "{unknown:?}");
        assert!(out.starts_with("@@hostname") && out.trim_end().ends_with("@@end"), "{out}");
        let (_, unknown) = run_script("run /bin/sh\nexec rm\ncat /etc/x", &dir);
        assert_eq!(unknown, ["run", "exec"], "a word that is not one of the reading words is not run");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
