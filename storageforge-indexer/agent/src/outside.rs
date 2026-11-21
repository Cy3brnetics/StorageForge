//! Wipe and stop, from outside (roadmap section 11.3): what storageforge-agentctl's `check` compares, as functions of what it read,
//! so that each comparison can be tested without a runtime.
//!
//! This is the check that counts, since a container that was taken over can lie about itself. It reads nothing the agent says: the
//! runtime's own account of the container (`docker inspect`, `docker diff`, or under plain LXC a hash of its root filesystem), and the
//! files in the agent's state folder, read from the host's side and checked against the manifest and the signatures here.
//!
//! - **The image** the container runs is the one the signed manifest names, by digest, and the image id the runtime has for it.
//! - **Nothing changed in the container** (`docker diff`) but the places the runtime makes for its mounts.
//! - **What it was given** (mounts, capabilities, devices, the host's network and process table, its user, privileged or not) is
//!   what the manifest's plugins declare, as `runtime::container_args` asked for it, and nothing more.
//! - **The plugin files** are the manifest's, each as signed, and nothing else is in the plugin folder.
//! - **The state folder** holds the agent's own files and nothing else, its key is there, and is the one enrolled.
//!
//! Each finding is one sentence. Any finding wipes the agent: the controller revokes its key first, then asks for `wipe`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

use crate::identity::{read_small, KEY_FILE, PUBLIC_FILE};
use crate::manifest::Manifest;
use crate::supervise::SEEN_FILE;
use crate::tunnel::COUNTER_FILE;
use crate::plugin::{self, Anchors};
use crate::runner;
use crate::runtime::{Kind, Spec, NETWORK};
use crate::sig;
use crate::wipe::WIPED_FILE;

/// What the agent may keep in its state folder. Each may also be there as NAME.new for a moment, while it is written whole.
pub const STATE_FILES: [&str; 6] = [KEY_FILE, PUBLIC_FILE, SEEN_FILE, COUNTER_FILE, "resume.json", WIPED_FILE];
pub const PLUGINS_DIR: &str = "plugins";
/// The most entries a folder walk reads before it says so.
const MOST_ENTRIES: usize = 20_000;

/// Paths a runtime makes in a container of its own accord, whatever the image: never a finding when `diff` shows them.
const RUNTIME_MADE: [&str; 9] = ["/dev", "/proc", "/sys", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/.dockerenv", "/run", "/run/.containerenv"];

/// One mount the container should have: where, from where (None for a tmpfs), and whether it may be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub source: Option<String>,
    pub writable: bool,
}

/// The mounts `runtime::container_args` asks Docker or Podman for, by where they are in the container.
pub fn expected_mounts(spec: &Spec) -> BTreeMap<String, Expected> {
    let mut out = BTreeMap::new();
    let bind = |source: &str, writable: bool| Expected { source: Some(source.to_string()), writable };
    out.insert("/etc/storageforge-agent".to_string(), bind(&spec.etc, false));
    out.insert("/var/lib/storageforge-agent/manifest".to_string(), bind(&spec.manifest, false));
    out.insert("/var/lib/storageforge-agent/state".to_string(), bind(&spec.state, true));
    for path in &spec.needs.mounts {
        out.insert(format!("/host{}", path.trim_end_matches('/')), bind(&format!("{}{path}", spec.root), false));
    }
    for file in &spec.mask_files {
        out.insert(format!("/host{file}"), bind("/dev/null", false));
    }
    out.insert("/tmp".to_string(), Expected { source: None, writable: true });
    for dir in &spec.mask_dirs {
        out.insert(format!("/host{dir}"), Expected { source: None, writable: false });
    }
    out
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

fn cap(name: &str) -> String {
    name.trim().to_ascii_uppercase().trim_start_matches("CAP_").to_string()
}

fn same_path(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The agent's process as the host's kernel has it (`/proc/PID/status` on the host, the pid the runtime gave), compared with what it
/// has to be: `sfagent` in every uid and gid, never root, unable to gain privileges, and no capability beyond the declared ones in any
/// set. This is read from the host's side, so an agent that was taken over cannot answer for itself.
pub fn compare_process(spec: &Spec, status: &str) -> Vec<String> {
    let mut out = Vec::new();
    let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')).map(|r| r.trim().to_string()));
    let ids = |name: &str| field(name).map(|v| v.split_whitespace().filter_map(|x| x.parse::<u32>().ok()).collect::<Vec<u32>>()).unwrap_or_default();
    let (uids, gids) = (ids("Uid"), ids("Gid"));
    if uids.len() != 4 || uids.iter().any(|&u| u != spec.uid) {
        out.push(format!("the agent's process runs as uid {}, not as sfagent", runner::plain(&field("Uid").unwrap_or_default())));
    }
    if gids.len() != 4 || gids.iter().any(|&g| g != spec.gid) {
        out.push(format!("the agent's process runs as gid {}, not as sfagent's group", runner::plain(&field("Gid").unwrap_or_default())));
    }
    if field("NoNewPrivs").as_deref() != Some("1") {
        out.push("the agent's process may gain privileges".into());
    }
    let declared = crate::caps::mask_of(&spec.needs.capabilities);
    for set in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        match field(set).and_then(|v| u64::from_str_radix(&v, 16).ok()) {
            Some(held) if held & !declared != 0 => out.push(format!("the agent's process holds capabilities no plugin of the manifest declares ({set} {held:#x})")),
            Some(_) => {}
            None if set == "CapAmb" => {}
            None => out.push(format!("the agent's process has no {set} the kernel reports")),
        }
    }
    out
}

/// What `docker inspect` (or `podman inspect`) printed for the agent's container, compared with what it was made with. `image_id`
/// is the id the runtime has for the manifest's image, by digest, when it could be read.
pub fn compare_inspect(kind: Kind, spec: &Spec, inspected: &Value, image_id: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let c = match inspected {
        Value::Array(items) if items.len() == 1 => &items[0],
        Value::Object(_) => inspected,
        _ => return vec!["the runtime did not describe the agent's container".into()],
    };
    let docker = kind == Kind::Docker;
    let hc = &c["HostConfig"];
    // the image: the name by digest the manifest gives, and the bytes the runtime has under that digest
    let named = c["Config"]["Image"].as_str().or(c["ImageName"].as_str()).unwrap_or("");
    if named != spec.image {
        out.push(format!("the container runs {}, not the image the manifest names", runner::plain(named)));
    }
    if let (Some(want), Some(got)) = (image_id, c["Image"].as_str()) {
        if want.trim_start_matches("sha256:") != got.trim_start_matches("sha256:") {
            out.push("the container's image is not the one the runtime has under the manifest's digest".into());
        }
    }
    if hc["Privileged"].as_bool() == Some(true) {
        out.push("the container is privileged".into());
    }
    if hc["ReadonlyRootfs"].as_bool() == Some(false) {
        out.push("the container's root filesystem can be written".into());
    }
    let user = c["Config"]["User"].as_str().unwrap_or("");
    // a container whose plugins declare a capability starts as root, and the agent gives root up at once (caps.rs): what it runs
    // as is then read from the process itself (`compare_process`)
    if user != crate::runtime::user_of(kind, spec) {
        out.push(format!("the container runs as {}, not as sfagent", runner::plain(if user.is_empty() { "its image's user" } else { user })));
    }
    // capabilities: all dropped, and back only what the plugins declare
    let added: BTreeSet<String> = strings(&hc["CapAdd"]).iter().map(|c| cap(c)).collect();
    let mut wanted: BTreeSet<String> = spec.needs.capabilities.iter().map(|c| cap(c)).collect();
    if crate::runtime::starts_as_root(kind, spec) {
        wanted.extend(crate::runtime::BECOME_CAPS.iter().map(|c| c.to_string()));
    }
    for extra in added.difference(&wanted) {
        out.push(format!("the container holds {extra}, which no plugin of the manifest declares"));
    }
    if docker && !strings(&hc["CapDrop"]).iter().any(|c| cap(c) == "ALL") {
        out.push("the container's capabilities were not all dropped".into());
    }
    if docker && !strings(&hc["SecurityOpt"]).iter().any(|o| o.starts_with("no-new-privileges")) {
        out.push("the container's process may gain privileges".into());
    }
    // the host's network and process table, only when declared
    let net = hc["NetworkMode"].as_str().unwrap_or("");
    let wants_net = spec.needs.namespaces.iter().any(|n| n == "net");
    if net == "host" && !wants_net {
        out.push("the container is on the host's network, which no plugin of the manifest declares".into());
    }
    if docker && !wants_net {
        let want = if spec.tunnel.is_some() { NETWORK } else { "none" };
        if net != want {
            out.push(format!("the container is on network {}, not {want}", runner::plain(net)));
        }
    }
    let pid_host = hc["PidMode"].as_str() == Some("host");
    if pid_host != spec.needs.namespaces.iter().any(|n| n == "pid") {
        out.push(if pid_host { "the container sees the host's processes, which no plugin of the manifest declares".into() } else { "the container does not see the host's processes as a plugin declares".to_string() });
    }
    // devices
    let devices: BTreeSet<String> = hc["Devices"].as_array().map(|a| a.iter().filter_map(|d| d["PathOnHost"].as_str().map(str::to_string)).collect()).unwrap_or_default();
    let want_devices: BTreeSet<String> = spec.devices.iter().cloned().collect();
    for extra in devices.difference(&want_devices) {
        out.push(format!("the container was given the device {}, which no plugin of the manifest declares", runner::plain(extra)));
    }
    // mounts: each where it should be, from where it should be, read-only but the state folder; and none missing
    let expected = expected_mounts(spec);
    let mut seen = BTreeSet::new();
    for m in c["Mounts"].as_array().cloned().unwrap_or_default() {
        let dest = m["Destination"].as_str().unwrap_or("").trim_end_matches('/').to_string();
        let kind_of = m["Type"].as_str().unwrap_or("");
        let Some(want) = expected.iter().find(|(d, _)| same_path(d, &dest)).map(|(_, e)| e) else {
            out.push(format!("the container has a {} mount at {} that the manifest does not account for", runner::plain(kind_of), runner::plain(&dest)));
            continue;
        };
        seen.insert(dest.clone());
        if m["RW"].as_bool() == Some(true) && !want.writable {
            out.push(format!("{} can be written in the container", runner::plain(&dest)));
        }
        match (&want.source, kind_of) {
            (Some(source), "bind") => {
                let got = m["Source"].as_str().unwrap_or("");
                if !same_path(got, source) {
                    out.push(format!("{} in the container is {} on the host, not {source}", runner::plain(&dest), runner::plain(got)));
                }
            }
            (None, "tmpfs") => {}
            (_, other) => out.push(format!("{} in the container is a {} mount, not what it was made with", runner::plain(&dest), runner::plain(other))),
        }
    }
    // Docker keeps --tmpfs mounts apart from the others
    if let Some(tmpfs) = hc["Tmpfs"].as_object() {
        for dest in tmpfs.keys() {
            match expected.iter().find(|(d, _)| same_path(d, dest)) {
                Some((_, e)) if e.source.is_none() => {
                    seen.insert(dest.trim_end_matches('/').to_string());
                }
                _ => out.push(format!("the container has a tmpfs at {} that the manifest does not account for", runner::plain(dest))),
            }
        }
    }
    for (dest, want) in &expected {
        if !seen.contains(dest.as_str()) && (want.source.is_some() || docker) {
            out.push(format!("{dest} is not mounted in the container as it was made: a mask or a folder is missing"));
        }
    }
    out
}

/// What `docker diff` (or `podman diff`) printed: every path changed in the container's own layer that is not a place the runtime
/// made for a mount, or one it makes in every container.
pub fn compare_diff(spec: &Spec, diff: &str) -> Vec<String> {
    let mut allowed: BTreeSet<String> = RUNTIME_MADE.iter().map(|p| p.to_string()).collect();
    for dest in expected_mounts(spec).keys() {
        // the mount point and every folder above it, which the runtime makes when the image has none
        let mut path = dest.as_str();
        loop {
            allowed.insert(path.to_string());
            match path.rfind('/') {
                Some(0) | None => break,
                Some(i) => path = &path[..i],
            }
        }
    }
    let mut out = Vec::new();
    for line in diff.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (change, path) = line.split_once(' ').unwrap_or(("?", line));
        let path = path.trim();
        if change == "D" || !allowed.contains(path.trim_end_matches('/')) {
            out.push(format!("{} in the container was {}", runner::plain(path), match change {
                "A" => "added",
                "C" => "changed",
                "D" => "deleted",
                _ => "touched",
            }));
        }
        if out.len() >= 50 {
            out.push("and more".into());
            break;
        }
    }
    out
}

fn sha256_file(path: &Path, most: u64) -> Option<(String, u64)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > most {
        return None;
    }
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > most {
            return None;
        }
        hash.update(&buf[..n]);
    }
    Some((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), total))
}

/// The plugin folder, read from the host's side: each file of a plugin the manifest names, as signed; nothing else. A plugin whose
/// descriptor is not there yet is on its way through the tunnel, which is a note and not a finding.
pub fn compare_plugins(dir: &Path, m: Option<&Manifest>, anchors: &Anchors) -> (Vec<String>, Vec<String>) {
    let (mut findings, mut notes) = (Vec::new(), Vec::new());
    let entries = m.map(|m| m.plugins.clone()).unwrap_or_default();
    let mut known = BTreeSet::new();
    for e in &entries {
        known.extend([runner::descriptor_file(&e.name), runner::signature_file(&e.name), runner::program_file(&e.name)]);
    }
    if let Ok(listing) = std::fs::read_dir(dir) {
        for item in listing.flatten().take(MOST_ENTRIES) {
            let name = item.file_name().to_string_lossy().into_owned();
            let base = name.strip_suffix(".new").unwrap_or(&name);
            if !known.contains(&name) && !known.contains(base) {
                findings.push(format!("{} is in the agent's plugin folder and no plugin of the manifest accounts for it", runner::plain(&name)));
            } else if !item.file_type().is_ok_and(|t| t.is_file()) {
                findings.push(format!("{} in the agent's plugin folder is not a plain file", runner::plain(&name)));
            }
        }
    }
    for e in &entries {
        let descriptor = read_small(&dir.join(runner::descriptor_file(&e.name)), plugin::MAX_DESCRIPTOR);
        let bytes = match descriptor {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                notes.push(format!("plugin {} has not arrived yet", e.name));
                continue;
            }
            Err(err) => {
                findings.push(format!("plugin {}: its descriptor cannot be read as a plain file ({err})", e.name));
                continue;
            }
        };
        let signature = read_small(&dir.join(runner::signature_file(&e.name)), sig::MAX_SIGNATURE).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
        let d = match Manifest::admit_plugin(e, &bytes, &signature, anchors) {
            Ok(d) => d,
            Err(why) => {
                findings.push(why);
                continue;
            }
        };
        match sha256_file(&dir.join(runner::program_file(&e.name)), plugin::MAX_PROGRAM) {
            Some((sha, size)) if sha == d.sha256 && size == d.size => {}
            Some(_) => findings.push(format!("plugin {}: its program is not the one that was signed", e.name)),
            None if dir.join(runner::program_file(&e.name)).symlink_metadata().is_err() => findings.push(format!("plugin {}: its descriptor is there and its program is not", e.name)),
            None => findings.push(format!("plugin {}: its program is not a plain file of the size its descriptor allows", e.name)),
        }
    }
    (findings, notes)
}

/// The state folder, read from the host's side: the agent's own files and nothing else, its key there, and the one enrolled.
pub fn compare_state(dir: &Path, pinned: &[u8; 32]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(said) = crate::wipe::wiped(dir) {
        let why = said["why"].as_array().map(|w| w.iter().filter_map(Value::as_str).map(runner::plain).collect::<Vec<_>>().join("; ")).unwrap_or_default();
        out.push(format!("the agent wiped itself: {}", if why.is_empty() { "it gave no reason".to_string() } else { why }));
    }
    match std::fs::symlink_metadata(dir.join(KEY_FILE)) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => out.push("the agent's key is not a plain file".into()),
        Err(_) if out.is_empty() => out.push("the agent's key is gone from its state folder".into()),
        Err(_) => {}
    }
    if let Ok(bytes) = read_small(&dir.join(PUBLIC_FILE), 200) {
        if String::from_utf8(bytes).ok().and_then(|l| sig::parse_public_line(&l)) != Some(*pinned) {
            out.push("the agent's state folder holds another key than the one enrolled".into());
        }
    }
    if let Ok(listing) = std::fs::read_dir(dir) {
        for item in listing.flatten().take(MOST_ENTRIES) {
            let name = item.file_name().to_string_lossy().into_owned();
            let base = name.strip_suffix(".new").unwrap_or(&name);
            let is_dir = item.file_type().is_ok_and(|t| t.is_dir());
            let fine = if name == PLUGINS_DIR { is_dir } else { STATE_FILES.contains(&base) && item.file_type().is_ok_and(|t| t.is_file()) };
            if !fine {
                out.push(format!("{} is in the agent's state folder and the agent keeps no such file", runner::plain(&name)));
            }
        }
    }
    out
}

/// A hash of a folder tree: every path, its kind, its mode, and the bytes of every file or the target of every link, in order. Used
/// for a plain LXC container's root filesystem, taken when it is made and compared on every check. None when it is too large.
pub fn tree_hash(root: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let mut hash = Sha256::new();
    let mut stack = vec![std::path::PathBuf::new()];
    let mut seen = 0usize;
    while let Some(rel) = stack.pop() {
        let mut names: Vec<_> = std::fs::read_dir(root.join(&rel)).ok()?.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for name in names.into_iter().rev() {
            seen += 1;
            if seen > MOST_ENTRIES {
                return None;
            }
            let path = rel.join(&name);
            let meta = std::fs::symlink_metadata(root.join(&path)).ok()?;
            hash.update(path.to_string_lossy().as_bytes());
            hash.update([0]);
            hash.update(meta.mode().to_be_bytes());
            if meta.is_dir() {
                stack.push(path);
            } else if meta.file_type().is_symlink() {
                hash.update(std::fs::read_link(root.join(&path)).ok()?.to_string_lossy().as_bytes());
            } else if meta.is_file() {
                hash.update(sha256_file(&root.join(&path), 1 << 30)?.0.as_bytes());
            }
            hash.update([0]);
        }
    }
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::needs::Needs;
    use serde_json::json;

    fn spec() -> Spec {
        Spec {
            image: "registry.example/storageforge-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            uid: 990,
            gid: 990,
            etc: "/etc/storageforge-agent".into(),
            manifest: "/var/lib/storageforge-agent/manifest".into(),
            state: "/var/lib/storageforge-agent/state".into(),
            needs: Needs { mounts: vec!["/var/log/journal".into()], groups: vec!["systemd-journal".into()], ..Needs::default() },
            mask_files: vec!["/etc/shadow".into()],
            mask_dirs: vec!["/var/log/journal/secret".into()],
            ..Spec::default()
        }
    }

    /// What the real Docker says of a container made as `container_args` asks: the shape is taken from `docker inspect`.
    fn inspected(s: &Spec) -> Value {
        json!([{
            "Image": "sha256:1111",
            "Config": {"Image": s.image, "User": "990:990"},
            "HostConfig": {"Privileged": false, "ReadonlyRootfs": true, "CapAdd": null, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                           "NetworkMode": "none", "PidMode": "", "Devices": [], "Tmpfs": {"/tmp": "rw,noexec", "/host/var/log/journal/secret": "ro,size=4k,mode=000"}},
            "Mounts": [
                {"Type": "bind", "Source": "/etc/storageforge-agent", "Destination": "/etc/storageforge-agent", "RW": false},
                {"Type": "bind", "Source": "/var/lib/storageforge-agent/manifest", "Destination": "/var/lib/storageforge-agent/manifest", "RW": false},
                {"Type": "bind", "Source": "/var/lib/storageforge-agent/state", "Destination": "/var/lib/storageforge-agent/state", "RW": true},
                {"Type": "bind", "Source": "/var/log/journal", "Destination": "/host/var/log/journal", "RW": false},
                {"Type": "bind", "Source": "/dev/null", "Destination": "/host/etc/shadow", "RW": false}
            ]
        }])
    }

    #[test]
    fn a_container_as_it_was_made_has_no_finding() {
        let s = spec();
        assert_eq!(compare_inspect(Kind::Docker, &s, &inspected(&s), Some("sha256:1111")), Vec::<String>::new());
        assert_eq!(compare_diff(&s, "A /host\nA /host/var\nA /host/var/log\nA /host/var/log/journal\nA /host/etc\nA /host/etc/shadow\nC /etc\nA /etc/storageforge-agent\nC /var\nA /.dockerenv\n"), Vec::<String>::new());
    }

    #[test]
    fn whatever_was_changed_about_the_container_is_found() {
        let s = spec();
        let changed = |f: &dyn Fn(&mut Value)| {
            let mut v = inspected(&s);
            f(&mut v[0]);
            compare_inspect(Kind::Docker, &s, &v, Some("sha256:1111"))
        };
        let one = |f: &dyn Fn(&mut Value), says: &str| {
            let got = changed(f);
            assert!(got.iter().any(|g| g.contains(says)), "{says}: {got:?}");
        };
        one(&|c| c["Config"]["Image"] = json!("evil.example/agent:latest"), "not the image the manifest names");
        one(&|c| c["Image"] = json!("sha256:2222"), "not the one the runtime has");
        one(&|c| c["HostConfig"]["Privileged"] = json!(true), "privileged");
        one(&|c| c["HostConfig"]["ReadonlyRootfs"] = json!(false), "can be written");
        one(&|c| c["Config"]["User"] = json!("0:0"), "runs as 0:0");
        one(&|c| c["HostConfig"]["CapAdd"] = json!(["CAP_SYS_ADMIN"]), "holds SYS_ADMIN");
        one(&|c| c["HostConfig"]["CapDrop"] = json!([]), "not all dropped");
        one(&|c| c["HostConfig"]["SecurityOpt"] = json!([]), "may gain privileges");
        one(&|c| c["HostConfig"]["NetworkMode"] = json!("host"), "host's network");
        one(&|c| c["HostConfig"]["NetworkMode"] = json!("bridge"), "on network bridge");
        one(&|c| c["HostConfig"]["PidMode"] = json!("host"), "host's processes");
        one(&|c| c["HostConfig"]["Devices"] = json!([{"PathOnHost": "/dev/sda"}]), "device /dev/sda");
        one(&|c| c["Mounts"].as_array_mut().unwrap().push(json!({"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/run/docker.sock", "RW": true})), "does not account for");
        one(&|c| c["Mounts"].as_array_mut().unwrap().push(json!({"Type": "volume", "Source": "/var/lib/docker/volumes/x", "Destination": "/data", "RW": true})), "volume mount at /data");
        one(&|c| c["Mounts"][3]["RW"] = json!(true), "/host/var/log/journal can be written");
        one(&|c| c["Mounts"][3]["Source"] = json!("/"), "is / on the host");
        one(&|c| {
            c["Mounts"].as_array_mut().unwrap().remove(4);
        }, "/host/etc/shadow is not mounted");
        one(&|c| {
            c["HostConfig"]["Tmpfs"].as_object_mut().unwrap().remove("/host/var/log/journal/secret");
        }, "a mask or a folder is missing");
        one(&|c| {
            c["HostConfig"]["Tmpfs"].as_object_mut().unwrap().insert("/var/lib/storageforge-agent/manifest".into(), json!("rw"));
        }, "tmpfs at /var/lib/storageforge-agent/manifest");
        assert!(compare_inspect(Kind::Docker, &s, &json!([]), None)[0].contains("did not describe"));
        // a file written into the container, or one taken out of it
        assert_eq!(compare_diff(&s, "A /usr/bin/sh\nC /usr/bin/storageforge-agent\nD /etc/passwd\nA /host/etc/shadow.d"), [
            "/usr/bin/sh in the container was added", "/usr/bin/storageforge-agent in the container was changed", "/etc/passwd in the container was deleted",
            "/host/etc/shadow.d in the container was added",
        ]);
    }

    #[test]
    fn a_container_that_starts_as_root_to_keep_a_capability_is_checked_by_its_process() {
        let mut s = spec();
        s.needs.capabilities = vec!["SYS_RAWIO".into()];
        let mut v = inspected(&s);
        v[0]["Config"]["User"] = json!("0:990");
        v[0]["HostConfig"]["CapAdd"] = json!(["SYS_RAWIO", "SETUID", "SETGID", "SETPCAP"]);
        assert_eq!(compare_inspect(Kind::Docker, &s, &v, Some("sha256:1111")), Vec::<String>::new());
        v[0]["HostConfig"]["CapAdd"] = json!(["SYS_RAWIO", "SETUID", "SETGID", "SETPCAP", "SYS_ADMIN"]);
        assert!(compare_inspect(Kind::Docker, &s, &v, Some("sha256:1111")).iter().any(|f| f.contains("holds SYS_ADMIN")));
        // and the process, as the host's kernel has it: sfagent, holding SYS_RAWIO (bit 17) and nothing else
        let good = "Name:\tstorageforge-age\nUid:\t990\t990\t990\t990\nGid:\t990\t990\t990\t990\nCapInh:\t0000000000020000\nCapPrm:\t0000000000020000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000020000\nCapAmb:\t0000000000020000\nNoNewPrivs:\t1\n";
        assert_eq!(compare_process(&s, good), Vec::<String>::new());
        let root = good.replace("Uid:\t990\t990\t990\t990", "Uid:\t990\t0\t990\t990");
        assert!(compare_process(&s, &root)[0].contains("not as sfagent"));
        let wider = good.replace("CapBnd:\t0000000000020000", "CapBnd:\t00000000002200c0");
        assert!(compare_process(&s, &wider)[0].contains("CapBnd"));
        let nnp = good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0");
        assert!(compare_process(&s, &nnp)[0].contains("gain privileges"));
        // with no capability declared, holding any is a finding
        assert!(compare_process(&spec(), good).iter().any(|f| f.contains("CapPrm")));
    }

    #[test]
    fn the_state_and_plugin_folders_hold_what_the_agent_keeps_and_nothing_else() {
        let dir = crate::identity::tests::folder("outside-state");
        let key = crate::identity::generate(&dir).unwrap();
        let pinned = key.verifying_key().to_bytes();
        std::fs::create_dir(dir.join(PLUGINS_DIR)).unwrap();
        std::fs::write(dir.join("batch.counter"), "4\n").unwrap();
        std::fs::write(dir.join("batch.counter.new"), "5\n").unwrap();
        assert_eq!(compare_state(&dir, &pinned), Vec::<String>::new());
        std::fs::write(dir.join("payload.sh"), "#!/bin/sh\n").unwrap();
        assert_eq!(compare_state(&dir, &pinned), ["payload.sh is in the agent's state folder and the agent keeps no such file"]);
        std::fs::remove_file(dir.join("payload.sh")).unwrap();
        assert_eq!(compare_state(&dir, &[7; 32]), ["the agent's state folder holds another key than the one enrolled"]);
        std::fs::remove_file(dir.join(KEY_FILE)).unwrap();
        assert_eq!(compare_state(&dir, &pinned), ["the agent's key is gone from its state folder"]);
        crate::wipe::wipe(&dir, &["a stray file".into()], 1).unwrap();
        assert_eq!(compare_state(&dir, &pinned), ["the agent wiped itself: a stray file"]);
        // nothing in a plugin folder with no manifest; a file there with none is a finding
        let plugins = dir.join("p");
        std::fs::create_dir(&plugins).unwrap();
        assert_eq!(compare_plugins(&plugins, None, &Anchors::default()), (vec![], vec![]));
        std::fs::write(plugins.join("logs.plugin"), b"x").unwrap();
        assert_eq!(compare_plugins(&plugins, None, &Anchors::default()).0, ["logs.plugin is in the agent's plugin folder and no plugin of the manifest accounts for it"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tree_hash_changes_with_any_file() {
        let dir = crate::identity::tests::folder("outside-tree");
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::write(dir.join("usr/bin/storageforge-agent"), b"program").unwrap();
        let first = tree_hash(&dir).unwrap();
        assert_eq!(tree_hash(&dir).unwrap(), first);
        std::fs::write(dir.join("usr/bin/sh"), b"").unwrap();
        let second = tree_hash(&dir).unwrap();
        assert_ne!(second, first);
        std::fs::remove_file(dir.join("usr/bin/sh")).unwrap();
        std::fs::write(dir.join("usr/bin/storageforge-agent"), b"programme").unwrap();
        assert_ne!(tree_hash(&dir).unwrap(), first);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
