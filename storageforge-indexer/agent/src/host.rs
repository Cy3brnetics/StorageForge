//! What storageforge-agentctl reads from the host it runs on: its folders, accounts, groups and machine id.
//!
//! Everything is read from files with a size limit, and nothing here runs a command.
//!
//! storageforge-agentctl runs as root, through `sudo`, which empties the environment. Run by anyone else it has no power and is
//! only of use to the unit tests, which give it a folder to treat as `/` (`STORAGEFORGE_AGENTCTL_ROOT`), the name of the user to
//! take for the one behind `sudo` (`STORAGEFORGE_AGENTCTL_USER`) and their own `PATH` of stand-in programs. As root none of the
//! three is read: `storageforge-run` keeps the same rule.

use std::path::{Path, PathBuf};

use crate::identity::read_small;
use crate::needs;

pub const AGENT_USER: &str = "sfagent";
/// The uid and gid the image runs as. On the host `sfagent` has whatever ids the host gave it; a runtime that remaps ids maps
/// the image's to the host's.
pub const IMAGE_ID: u32 = 10003;
/// Groups that are root on the host by another name: whoever is in one can start a container that mounts `/`.
pub const ROOT_GROUPS: [&str; 3] = ["docker", "incus-admin", "lxd"];
/// Groups `sfagent` must not be in either: the above, and the ones `sudo` is usually given to.
pub const AGENT_FORBIDDEN_GROUPS: [&str; 7] = ["admin", "docker", "incus-admin", "lxd", "root", "sudo", "wheel"];
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_ACCOUNTS_FILE: usize = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

#[derive(Debug, Clone)]
pub struct Host {
    /// Empty on a real host. In the unit tests, the folder that stands for `/`.
    pub root: PathBuf,
    /// The user who ran `sudo`, when there is one.
    pub manager: Option<String>,
    /// Where programs are looked for.
    pub path: String,
}

impl Host {
    /// The host as this process sees it, or why it may not act.
    pub fn detect() -> Result<Host, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(Host { root: PathBuf::new(), manager: std::env::var("SUDO_USER").ok().filter(|u| u != "root"), path: PATH.to_string() });
        }
        match std::env::var("STORAGEFORGE_AGENTCTL_ROOT") {
            Ok(root) if root.starts_with('/') && root.len() > 1 => Ok(Host {
                root: PathBuf::from(root),
                manager: std::env::var("STORAGEFORGE_AGENTCTL_USER").ok(),
                path: std::env::var("PATH").unwrap_or_else(|_| PATH.to_string()),
            }),
            _ => Err("storageforge-agentctl runs as root, through sudo".into()),
        }
    }

    /// The host's file at the absolute path `abs`.
    pub fn at(&self, abs: &str) -> PathBuf {
        if self.root.as_os_str().is_empty() {
            PathBuf::from(abs)
        } else {
            self.root.join(abs.trim_start_matches('/'))
        }
    }

    /// Root's: the controller's key, and the operator's own plugin keys.
    pub fn etc(&self) -> PathBuf {
        self.at("/etc/storageforge-agent")
    }

    /// Root's alone (0700): used nonces, the last manifest's counter, the agent's key as pinned, the runtime in use.
    pub fn ctl(&self) -> PathBuf {
        self.at("/var/lib/storageforge-agent/ctl")
    }

    /// Root's, read by the agent: the manifest in use.
    pub fn manifest_dir(&self) -> PathBuf {
        self.at("/var/lib/storageforge-agent/manifest")
    }

    /// The agent's own (0700): the one folder of the host it can write.
    pub fn state_dir(&self) -> PathBuf {
        self.at("/var/lib/storageforge-agent/state")
    }

    pub fn machine_id(&self) -> Option<String> {
        ["/etc/machine-id", "/var/lib/dbus/machine-id"].iter().find_map(|p| {
            let text = String::from_utf8(read_small(&self.at(p), 64).ok()?).ok()?;
            let id = text.trim_end();
            crate::manifest::is_machine(id).then(|| id.to_string())
        })
    }

    fn lines(&self, abs: &str) -> Vec<Vec<String>> {
        let Ok(bytes) = read_small(&self.at(abs), MAX_ACCOUNTS_FILE) else { return Vec::new() };
        String::from_utf8_lossy(&bytes).lines().filter(|l| !l.starts_with('#')).map(|l| l.split(':').map(str::to_string).collect()).collect()
    }

    pub fn users(&self) -> Vec<User> {
        self.lines("/etc/passwd")
            .into_iter()
            .filter_map(|f| Some(User { name: f.first()?.clone(), uid: f.get(2)?.parse().ok()?, gid: f.get(3)?.parse().ok()?, home: f.get(5)?.clone() }))
            .collect()
    }

    pub fn user(&self, name: &str) -> Option<User> {
        self.users().into_iter().find(|u| u.name == name)
    }

    pub fn gid(&self, group: &str) -> Option<u32> {
        self.lines("/etc/group").into_iter().find(|f| f.first().map(String::as_str) == Some(group)).and_then(|f| f.get(2)?.parse().ok())
    }

    /// Every group of `/etc/group` the user is in, with the one their account names. Groups from a directory service are not
    /// seen here: see docs/agent.md, "What it does not check".
    pub fn groups_of(&self, user: &str) -> Vec<String> {
        let primary = self.user(user).map(|u| u.gid);
        let mut out: Vec<String> = self
            .lines("/etc/group")
            .into_iter()
            .filter(|f| f.get(2).and_then(|g| g.parse::<u32>().ok()) == primary && primary.is_some() || f.get(3).is_some_and(|members| members.split(',').any(|m| m == user)))
            .filter_map(|f| f.first().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The first group of `forbidden` the user is in.
    pub fn in_any(&self, user: &str, forbidden: &[&str]) -> Option<String> {
        self.groups_of(user).into_iter().find(|g| forbidden.contains(&g.as_str()))
    }

    /// The program `tool`, where it is installed.
    pub fn find(&self, tool: &str) -> Option<PathBuf> {
        self.path.split(':').filter(|d| d.starts_with('/')).map(|d| Path::new(d).join(tool)).find(|p| p.is_file())
    }

    /// The first free range of 65536 subordinate ids in `/etc/subuid` or `/etc/subgid`, and whether `user` has one already.
    pub fn subids(&self, file: &str, user: &str) -> (bool, u64) {
        let mut has = false;
        let mut free = 100_000u64;
        for f in self.lines(file) {
            if let (Some(name), Some(start), Some(count)) = (f.first(), f.get(1).and_then(|s| s.parse::<u64>().ok()), f.get(2).and_then(|s| s.parse::<u64>().ok())) {
                has |= name == user && count >= 65_536;
                free = free.max(start.saturating_add(count));
            }
        }
        (has, free)
    }

    /// Root's subordinate id range, which an unprivileged LXC container is mapped into.
    pub fn root_subids(&self, file: &str) -> Option<u64> {
        self.lines(file).into_iter().find_map(|f| {
            let (start, count) = (f.get(1)?.parse::<u64>().ok()?, f.get(2)?.parse::<u64>().ok()?);
            (f.first()? == "root" && count >= 65_536).then_some(start)
        })
    }

    /// What has to be hidden inside the mounts a container is given: the fixed list (`needs::MASKED_*`), every `.ssh` folder of
    /// an account, and SSH's host keys. Only what exists, and only what one of `mounts` would show. Returns folders and files.
    pub fn masks(&self, mounts: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
        // A mount shows one filesystem and not what is mounted below it, so a path is shown by the deepest mount above it... or
        // by none. What is hidden is anything under any mount: hiding too much costs nothing.
        let shown = |path: &str| mounts.iter().any(|m| needs::is_under(path, m));
        let mut dirs: Vec<String> = needs::MASKED_DIRS.iter().map(|d| d.to_string()).collect();
        let mut homes: Vec<String> = self.users().into_iter().map(|u| u.home).collect();
        homes.push("/root".into());
        // accounts from a directory service have no line in /etc/passwd and still have a home: every folder directly under
        // /home, and directly under each mount, is taken for one
        for parent in mounts.iter().map(String::as_str).chain(["/home"]) {
            if let Ok(entries) = std::fs::read_dir(self.at(parent)) {
                for entry in entries.flatten().take(4096) {
                    homes.push(format!("{}/{}", parent.trim_end_matches('/'), entry.file_name().to_string_lossy()));
                }
            }
        }
        for home in homes {
            let ssh = format!("{}/.ssh", home.trim_end_matches('/'));
            if !home.starts_with('/') || !shown(&ssh) || !self.at(&ssh).is_dir() {
                continue;
            }
            if !ssh.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) || ssh.contains("/../") {
                // a folder that cannot be named to the runtime cannot be hidden, and then nothing that shows it is mounted
                return Err("an account's home has a name that cannot be masked, and a mount would show its .ssh folder".into());
            }
            dirs.push(ssh);
        }
        let mut files: Vec<String> = needs::MASKED_FILES.iter().map(|f| f.to_string()).collect();
        if let Ok(entries) = std::fs::read_dir(self.at("/etc/ssh")) {
            for name in entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()) {
                if name.starts_with("ssh_host_") && name.ends_with("_key") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                    files.push(format!("/etc/ssh/{name}"));
                }
            }
        }
        dirs.retain(|d| shown(d) && self.at(d).is_dir());
        files.retain(|f| shown(f) && self.at(f).is_file());
        dirs.sort();
        dirs.dedup();
        files.sort();
        files.dedup();
        Ok((dirs, files))
    }

    /// The host's whole disks, as devices: what the `disks` device class means here.
    pub fn disks(&self) -> Vec<String> {
        let mut out: Vec<String> = match std::fs::read_dir(self.at("/sys/block")) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !["loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd"].iter().any(|p| n.starts_with(p)))
                .filter(|n| n.len() <= 32 && n.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map(|n| format!("/dev/{n}"))
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort();
        out.truncate(64);
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fake(name: &str) -> Host {
        let root = std::env::temp_dir().join(format!("sfagentctl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["etc/ssh", "etc/sudoers.d", "root/.ssh", "home/ana/.ssh", "home/ben", "home/from-ldap/.ssh", "srv/data/.ssh", "srv/deep/users/bob/.ssh", "sys/block/sda", "sys/block/nvme0n1", "sys/block/loop0", "sys/block/dm-0", "usr/local/lib/storageforge"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("etc/machine-id"), "0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\nben:x:1001:1001::/home/ben:/bin/sh\nsfagent:x:987:985::/var/lib/storageforge-agent/home:/usr/sbin/nologin\nmgr:x:986:984::/var/lib/storageforge-agent/ctl-home:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/group"), "root:x:0:\ndocker:x:957:ana\nlxd:x:958:\nincus-admin:x:959:ben\nana:x:1000:\nben:x:1001:\nsfagent:x:985:\nmgr:x:984:\nsystemd-journal:x:980:ana\nwheel:x:998:ana,ben\n").unwrap();
        std::fs::write(root.join("etc/shadow"), "root:!::\n").unwrap();
        std::fs::write(root.join("etc/ssh/ssh_host_ed25519_key"), "private").unwrap();
        std::fs::write(root.join("etc/ssh/ssh_host_ed25519_key.pub"), "public").unwrap();
        std::fs::write(root.join("etc/subuid"), "ana:100000:65536\nroot:1000000:65536\n").unwrap();
        Host { root, manager: Some("mgr".into()), path: String::new() }
    }

    #[test]
    fn groups_come_from_the_group_file_and_the_account() {
        let host = fake("groups");
        assert_eq!(host.groups_of("ana"), ["ana", "docker", "systemd-journal", "wheel"]);
        assert_eq!(host.in_any("ana", &ROOT_GROUPS).as_deref(), Some("docker"));
        assert_eq!(host.in_any("ben", &ROOT_GROUPS).as_deref(), Some("incus-admin"));
        assert_eq!(host.in_any("mgr", &ROOT_GROUPS), None);
        assert_eq!(host.in_any("sfagent", &AGENT_FORBIDDEN_GROUPS), None);
        assert_eq!(host.in_any("nobody-here", &ROOT_GROUPS), None);
        assert_eq!(host.gid("systemd-journal"), Some(980));
        assert_eq!(host.user("sfagent").unwrap().uid, 987);
        assert_eq!(host.machine_id().as_deref(), Some("0123456789abcdef0123456789abcdef"));
        std::fs::remove_dir_all(&host.root).unwrap();
    }

    #[test]
    fn what_a_mount_would_show_of_ssh_and_storageforge_is_masked() {
        let host = fake("masks");
        let (dirs, files) = host.masks(&["/".to_string()]).unwrap();
        assert_eq!(dirs, ["/etc/sudoers.d", "/home/ana/.ssh", "/home/from-ldap/.ssh", "/root/.ssh", "/usr/local/lib/storageforge"], "and the home no passwd line names");
        assert_eq!(files, ["/etc/shadow", "/etc/ssh/ssh_host_ed25519_key"]);
        let (dirs, files) = host.masks(&["/etc".to_string()]).unwrap();
        assert_eq!(dirs, ["/etc/sudoers.d"]);
        assert_eq!(files, ["/etc/shadow", "/etc/ssh/ssh_host_ed25519_key"]);
        // a folder directly under a mount is taken for a home; two folders down is not looked at (docs/agent.md says so)
        assert_eq!(host.masks(&["/srv".to_string()]).unwrap(), (vec!["/srv/data/.ssh".to_string()], vec![]));
        assert_eq!(host.masks(&["/srv/deep".to_string()]).unwrap(), (vec![], vec![]));
        assert_eq!(host.masks(&["/var".to_string()]).unwrap(), (vec![], vec![]));
        assert_eq!(host.masks(&[]).unwrap(), (vec![], vec![]));
        // an account whose home cannot be named to a runtime: nothing that would show its .ssh is mounted at all
        std::fs::create_dir_all(host.root.join("home/a b/.ssh")).unwrap();
        let mut passwd = std::fs::read_to_string(host.root.join("etc/passwd")).unwrap();
        passwd.push_str("odd:x:1002:1002::/home/a b:/bin/sh\n");
        std::fs::write(host.root.join("etc/passwd"), passwd).unwrap();
        assert!(host.masks(&["/home".to_string()]).is_err());
        assert!(host.masks(&["/etc".to_string()]).is_ok());
        std::fs::remove_dir_all(&host.root).unwrap();
    }

    #[test]
    fn disks_are_whole_disks_and_subids_are_found() {
        let host = fake("disks");
        assert_eq!(host.disks(), ["/dev/nvme0n1", "/dev/sda"]);
        assert_eq!(host.subids("/etc/subuid", "sfagent"), (false, 1_065_536));
        assert_eq!(host.subids("/etc/subuid", "ana").0, true);
        assert_eq!(host.root_subids("/etc/subuid"), Some(1_000_000));
        assert_eq!(host.root_subids("/etc/subgid"), None);
        std::fs::remove_dir_all(&host.root).unwrap();
    }
}
