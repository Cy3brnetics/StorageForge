//! What a plugin may ask of the host: the whole vocabulary, and nothing outside it can be asked for.
//!
//! A plugin's descriptor declares its needs, the host's manifest repeats them, and storageforge-agentctl makes the container
//! with the union of them and nothing more (roadmap section 11.1, "Privileges follow plugins"). There is no word here for a
//! writable mount, a privileged container, a runtime's socket or a path under `/dev` or `/run`, so no descriptor and no
//! manifest can ask for one, whoever signed it.
//!
//! Every list is sorted and without repeats: two needs that mean the same are the same bytes, and are compared with `==`.

use serde::{Deserialize, Serialize};

/// Capabilities a plugin may declare. Any of them takes a rootful runtime.
pub const CAPABILITIES: [&str; 6] = ["DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO"];
/// Device classes a plugin may declare. `disks` is the host's whole disks, read-only.
pub const DEVICES: [&str; 1] = ["disks"];
/// Host namespaces a plugin may share: the network (for the network plugin) and the process table (for health).
pub const NAMESPACES: [&str; 2] = ["net", "pid"];
/// Host groups whose files a plugin may read: the journal's, and `adm` for log files.
pub const GROUPS: [&str; 2] = ["adm", "systemd-journal"];
/// The most mounts one plugin, or one host, may have.
pub const MAX_MOUNTS: usize = 32;

/// Folders no mount may be, be inside, or (through the masks storageforge-agentctl adds) show: SSH's and StorageForge's own
/// secrets, the verifiers' stores, the agent's own state, and what says who may become root (roadmap section 11.2, "No SSH
/// secrets in reach"). `.ssh` folders and SSH host keys are found on the host when the container is made.
pub const MASKED_DIRS: [&str; 6] = ["/etc/sudoers.d", "/etc/storageforge-agent", "/run/storageforge", "/usr/local/lib/storageforge", "/var/lib/storageforge", "/var/lib/storageforge-agent"];
/// Files that are masked the same way.
pub const MASKED_FILES: [&str; 4] = ["/etc/gshadow", "/etc/shadow", "/etc/sudoers", "/etc/security/opasswd"];
/// The only paths under `/run` a plugin may mount: where the journal is kept before it reaches the disk.
pub const RUN_ALLOWED: [&str; 1] = ["/run/log/journal"];

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct Needs {
    /// Host paths, each mounted read-only at `/host` + the path, and only that filesystem: what is mounted below it stays out.
    #[serde(default)]
    pub mounts: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub devices: Vec<String>,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

fn sorted(list: &[String]) -> bool {
    list.windows(2).all(|w| w[0] < w[1])
}

fn from(list: &[String], allowed: &[&str], what: &str) -> Result<(), String> {
    if !sorted(list) {
        return Err(format!("the {what} are not sorted, or one is there twice"));
    }
    match list.iter().find(|x| !allowed.contains(&x.as_str())) {
        Some(x) => Err(format!("{x:?} is not one of the {what} a plugin may ask for")),
        None => Ok(()),
    }
}

/// Whether `path` is `dir` or inside it.
pub fn is_under(path: &str, dir: &str) -> bool {
    path == dir || (path.starts_with(dir) && (dir == "/" || path.as_bytes().get(dir.len()) == Some(&b'/')))
}

/// Whether a host path may be mounted at all, and why not.
pub fn mount_allowed(path: &str) -> Result<(), String> {
    let no = |why: &str| Err(format!("{path:?} cannot be mounted: {why}"));
    if path.is_empty() || path.len() > 255 || !path.starts_with('/') {
        return no("a mount is an absolute path of at most 255 bytes");
    }
    if !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) {
        return no("only letters, digits, / . _ and - are read in a mount");
    }
    if path != "/" && (path.ends_with('/') || path.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..")) {
        return no("it has an empty part, a . or a .., or ends in /");
    }
    if is_under(path, "/dev") {
        return no("devices are declared as devices, not mounted");
    }
    if (is_under(path, "/run") || is_under(path, "/var/run")) && !RUN_ALLOWED.iter().any(|ok| is_under(path, ok)) {
        return no("sockets and secrets live under /run, and only the journal is mounted from there");
    }
    if (is_under(path, "/proc") && path != "/proc") || (is_under(path, "/sys") && path != "/sys") {
        return no("/proc and /sys are mounted whole or not at all");
    }
    if path.split('/').any(|part| part == ".ssh") {
        return no("a .ssh folder is never mounted");
    }
    if let Some(dir) = MASKED_DIRS.iter().find(|dir| is_under(path, dir)) {
        return no(&format!("{dir} is kept from the agent"));
    }
    if MASKED_FILES.contains(&path) || is_under(path, "/etc/ssh") {
        return no("it holds keys or passwords");
    }
    Ok(())
}

impl Needs {
    /// Whether every word is one a plugin may use, in the one order they are written in.
    pub fn check(&self) -> Result<(), String> {
        if self.mounts.len() > MAX_MOUNTS {
            return Err(format!("more than {MAX_MOUNTS} mounts"));
        }
        if !sorted(&self.mounts) {
            return Err("the mounts are not sorted, or one is there twice".into());
        }
        for path in &self.mounts {
            mount_allowed(path)?;
        }
        from(&self.capabilities, &CAPABILITIES, "capabilities")?;
        from(&self.devices, &DEVICES, "devices")?;
        from(&self.namespaces, &NAMESPACES, "namespaces")?;
        from(&self.groups, &GROUPS, "groups")
    }

    /// Everything any of `all` needs, once.
    pub fn union<'a>(all: impl IntoIterator<Item = &'a Needs>) -> Needs {
        let mut out = Needs::default();
        for n in all {
            out.mounts.extend(n.mounts.iter().cloned());
            out.capabilities.extend(n.capabilities.iter().cloned());
            out.devices.extend(n.devices.iter().cloned());
            out.namespaces.extend(n.namespaces.iter().cloned());
            out.groups.extend(n.groups.iter().cloned());
        }
        for list in [&mut out.mounts, &mut out.capabilities, &mut out.devices, &mut out.namespaces, &mut out.groups] {
            list.sort();
            list.dedup();
        }
        out
    }

    /// Whether this takes a runtime that runs as root: a capability or a device cannot be given by a rootless one. The process
    /// inside is `sfagent` either way.
    pub fn rootful(&self) -> bool {
        !self.capabilities.is_empty() || !self.devices.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self == &Needs::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needs(json: &str) -> Result<Needs, String> {
        let n: Needs = serde_json::from_str(json).map_err(|e| e.to_string())?;
        n.check().map(|_| n)
    }

    #[test]
    fn only_the_vocabulary_is_read() {
        assert!(needs("{}").unwrap().is_empty());
        let n = needs(r#"{"mounts":["/etc/machine-id","/var/log/journal"],"capabilities":["SYS_RAWIO"],"devices":["disks"],"namespaces":["net","pid"],"groups":["systemd-journal"]}"#).unwrap();
        assert!(n.rootful());
        assert!(!needs(r#"{"mounts":["/proc","/sys"],"namespaces":["pid"]}"#).unwrap().rootful());
        for bad in [
            r#"{"privileged":true}"#,
            r#"{"mounts":["/var/log","/etc"]}"#,
            r#"{"mounts":["/etc","/etc"]}"#,
            r#"{"capabilities":["SYS_MODULE"]}"#,
            r#"{"capabilities":["ALL"]}"#,
            r#"{"devices":["/dev/sda"]}"#,
            r#"{"namespaces":["ipc"]}"#,
            r#"{"namespaces":["user"]}"#,
            r#"{"groups":["docker"]}"#,
            r#"{"groups":["wheel"]}"#,
            r#"{"mounts":"/"}"#,
        ] {
            assert!(needs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secrets_sockets_and_devices_cannot_be_mounted() {
        for ok in ["/", "/etc", "/proc", "/sys", "/var/log/journal", "/run/log/journal", "/srv/data-1/a_b.c", "/home"] {
            assert!(mount_allowed(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a b", "/a:b", "/a,ro", "/a\n", "/é",
            "/dev", "/dev/sda", "/run", "/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/run/user/1000", "/run/storageforge/secrets",
            "/proc/1/root", "/sys/kernel", "/root/.ssh", "/home/a/.ssh/id_ed25519", "/etc/ssh", "/etc/ssh/ssh_host_ed25519_key",
            "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/sudoers.d/storageforge-deploy", "/usr/local/lib/storageforge", "/usr/local/lib/storageforge/scan.key",
            "/var/lib/storageforge", "/var/lib/storageforge/run/seen", "/var/lib/storageforge-agent", "/var/lib/storageforge-agent/ctl", "/etc/storageforge-agent",
        ] {
            assert!(mount_allowed(bad).is_err(), "{bad}");
        }
        assert!(mount_allowed(&format!("/{}", "a".repeat(255))).is_err());
        // a folder that only begins like a masked one is another folder
        assert!(mount_allowed("/var/lib/storageforge-data").is_ok());
        assert!(mount_allowed("/developer").is_ok());
    }

    #[test]
    fn the_union_is_everything_once_and_still_checks() {
        let a = needs(r#"{"mounts":["/proc"],"namespaces":["pid"]}"#).unwrap();
        let b = needs(r#"{"mounts":["/etc/machine-id","/proc"],"groups":["systemd-journal"]}"#).unwrap();
        let u = Needs::union([&a, &b]);
        assert_eq!(u.mounts, ["/etc/machine-id", "/proc"]);
        assert_eq!(u.namespaces, ["pid"]);
        assert!(u.check().is_ok());
        assert!(Needs::union([]).is_empty());
    }
}
