//! storageforge-agentctl: the one program the user who manages the agent may run as root (roadmap section 11.1, "Lifecycle over
//! SSH" and "Accounts").
//!
//!   sudo -n /usr/local/sbin/storageforge-agentctl < request        the only way it is run: no arguments, a signed request on stdin
//!   storageforge-agentctl --version
//!
//! It takes one signed request (`request`), does that one agent operation, prints one line of JSON and exits: 0 done, 97 refused
//! (nothing was changed), 1 failed part way. The operations are `preflight`, `enroll`, `apply`, `start`, `stop`, `restart`,
//! `status`, `remove`, `check` and `wipe`, and there is no other: nothing here runs a command, reads a file or makes a mount that a
//! caller chose.
//! It drives Docker, Podman or LXC itself, so the user behind it needs no access to any of them, and it refuses to act at all
//! while that user is in a group that is root by another name (`docker`, `lxd`, `incus-admin`).
//!
//! What it trusts: the controller's key pinned in /etc/storageforge-agent/controller_signers for requests and manifests, the
//! release keys it was built with for plugins, and the operator's own keys in /etc/storageforge-agent/operator_signers. It trusts
//! nothing the agent's container wrote but the public key it reads once, at enrollment.
//!
//! Wipe and stop from outside (roadmap 11.3): `check` compares the running container with the manifest (the image by digest, what
//! changed in the container, its mounts, capabilities and devices, the plugin files and the state folder; `outside.rs`) and says what
//! it found. `wipe` ends the agent's access on this host: its container stopped and left stopped whatever its restart policy, its
//! key and plugin files deleted, and nothing left that `start` or `apply` would take for an enrolled agent.

use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use storageforge_agent::host::{Host, User, AGENT_FORBIDDEN_GROUPS, AGENT_USER, ROOT_GROUPS};
use storageforge_agent::identity::{read_small, write_whole};
use storageforge_agent::manifest::{self, Admitted, Manifest, Seen};
use storageforge_agent::needs::{Needs, GROUPS};
use storageforge_agent::plugin::{self, Anchors};
use storageforge_agent::request::{self, Request, REFUSED};
use storageforge_agent::runtime::{self, Kind, Spec, Step, Tools};
use storageforge_agent::sig::{self, Signers};
use storageforge_agent::supervise::{now, CONTROLLER_SIGNERS, MANIFEST_FILE, MANIFEST_SIGNATURE, OPERATOR_SIGNERS, SEEN_FILE};
use storageforge_agent::{identity, outside, runner, tunnel, wipe, VERSION};

/// What storageforge-agentctl keeps of the container it made: the spec it was made with, which `check` compares against (the masks
/// are found on the host when the container is made, and a folder made since is not in the container yet), and under plain LXC the
/// hash of its root filesystem.
const SPEC_FILE: &str = "spec.json";
const ROOTFS_FILE: &str = "rootfs.sha256";
/// The most of a runtime's answer `check` reads.
const MOST_ANSWER: usize = 1 << 20;

/// Why nothing, or not everything, was done.
struct Stop {
    /// 97: refused, nothing changed. 1: failed while acting.
    exit: i32,
    code: &'static str,
    why: String,
}

fn refuse<T>(code: &'static str, why: impl Into<String>) -> Result<T, Stop> {
    Err(Stop { exit: REFUSED, code, why: why.into() })
}

fn failed(why: impl Into<String>) -> Stop {
    Stop { exit: 1, code: "failed", why: why.into() }
}

struct Ctl {
    host: Host,
    agent: User,
    notes: Vec<String>,
    /// The receiver the agent's tunnel dials, when it has one: the one address its container may reach.
    tunnel: Option<SocketAddr>,
}

impl Ctl {
    fn file(&self, name: &str) -> PathBuf {
        self.host.ctl().join(name)
    }

    fn text(&self, name: &str) -> Option<String> {
        String::from_utf8(read_small(&self.file(name), 4096).ok()?).ok().map(|s| s.trim_end().to_string())
    }

    fn keep(&self, name: &str, text: &str) -> Result<(), Stop> {
        write_whole(&self.file(name), format!("{text}\n").as_bytes(), 0o600).map_err(|e| failed(format!("cannot write {name}: {e}")))
    }

    fn tools(&self) -> Tools {
        let has = |tool: &str| self.host.find(tool).is_some();
        Tools { docker: has("docker"), podman: has("podman"), lxc: has("lxc-create"), incus: has("incus"), pct: has("pct") }
    }

    fn command(&self, argv: &[String], as_agent: bool, env: &[(&str, &str)]) -> Result<Command, String> {
        let mut full: Vec<String> = Vec::new();
        if as_agent {
            // Podman without root: run by sfagent itself, with the runtime folder its lingering session has
            full.extend(["runuser".to_string(), "-u".to_string(), AGENT_USER.to_string(), "--".to_string(), "env".to_string()]);
            full.extend([format!("HOME={}", self.agent.home), format!("XDG_RUNTIME_DIR=/run/user/{}", self.agent.uid), format!("PATH={}", self.host.path)]);
        }
        full.extend(argv.iter().cloned());
        let program = self.host.find(&full[0]).ok_or_else(|| format!("{} is not installed", full[0]))?;
        let mut c = Command::new(program);
        c.args(&full[1..]).env_clear().env("PATH", &self.host.path).env("LC_ALL", "C").envs(env.iter().copied()).current_dir("/").stdin(Stdio::null());
        Ok(c)
    }

    /// Runs a program and returns whether it succeeded and all it printed, up to `MOST_ANSWER`: what `check` reads.
    fn answer(&self, argv: &[String], as_agent: bool) -> Result<(bool, String), String> {
        let out = self.command(argv, as_agent, &[])?.output().map_err(|e| format!("{} could not be run: {e}", argv[0]))?;
        if out.stdout.len() > MOST_ANSWER {
            return Err(format!("{} said more than a description of one container", argv[0]));
        }
        Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
    }

    /// Runs a program and returns whether it succeeded and what it printed, cut to what a log line can carry.
    fn output(&self, argv: &[String], as_agent: bool, env: &[(&str, &str)]) -> Result<(bool, String, String), String> {
        let out = self.command(argv, as_agent, env)?.output().map_err(|e| format!("{} could not be run: {e}", argv[0]))?;
        let cut = |bytes: &[u8]| String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(2000)..]).into_owned();
        Ok((out.status.success(), cut(&out.stdout), cut(&out.stderr)))
    }

    fn act(&mut self, steps: &[Step]) -> Result<(), Stop> {
        for step in steps {
            match step {
                Step::Run { argv, as_agent, note } => {
                    let done = self.output(argv, *as_agent, &[]);
                    let why = match done {
                        Ok((true, ..)) => continue,
                        Ok((false, _, err)) => format!("{} failed: {}", argv[..argv.len().min(3)].join(" "), runner::plain(err.trim())),
                        Err(why) => why,
                    };
                    match note {
                        None => return Err(failed(why)),
                        Some("") => {}
                        Some(note) => self.notes.push(format!("{note} ({why})")),
                    }
                }
                Step::Write { path, content } => write_whole(Path::new(path), content.as_bytes(), 0o644).map_err(|e| failed(format!("cannot write {path}: {e}")))?,
                Step::Append { path, line } => {
                    let old = match read_small(Path::new(path), 1 << 20) {
                        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                        Err(e) => return Err(failed(format!("cannot read {path}: {e}"))),
                    };
                    if !old.lines().any(|l| l == line) {
                        let new = format!("{old}{}{line}\n", if old.is_empty() || old.ends_with('\n') { "" } else { "\n" });
                        write_whole(Path::new(path), new.as_bytes(), 0o644).map_err(|e| failed(format!("cannot write {path}: {e}")))?;
                    }
                }
                Step::Mkdir { path } => std::fs::create_dir_all(path).map_err(|e| failed(format!("cannot make {path}: {e}")))?,
            }
        }
        Ok(())
    }

    /// The folders, as they have to be: root's but the state folder, which is the agent's and nobody else's.
    fn folders(&self) -> Result<(), Stop> {
        let own = |path: &Path, mode: u32, uid: u32, gid: u32| -> Result<(), Stop> {
            std::fs::create_dir_all(path).map_err(|e| failed(format!("cannot make {}: {e}", path.display())))?;
            let meta = std::fs::symlink_metadata(path).map_err(|e| failed(e.to_string()))?;
            if !meta.is_dir() {
                return Err(failed(format!("{} is not a folder", path.display())));
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| failed(format!("cannot set the mode of {}: {e}", path.display())))?;
            if unsafe { libc::geteuid() } == 0 {
                std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| failed(format!("cannot give {} its owner: {e}", path.display())))?;
            }
            Ok(())
        };
        own(&self.host.ctl(), 0o700, 0, 0)?;
        own(&self.host.manifest_dir(), 0o755, 0, 0)?;
        own(&self.host.state_dir(), 0o700, self.agent.uid, self.agent.gid)
    }

    fn vmid(&self) -> Option<u32> {
        if let Some(n) = self.text("vmid").and_then(|t| t.parse().ok()) {
            return Some(n);
        }
        let (ok, out, _) = self.output(&["pvesh".to_string(), "get".to_string(), "/cluster/nextid".to_string()], false, &[]).ok()?;
        let n: u32 = out.trim().trim_matches('"').parse().ok().filter(|n| ok && (100..=999_999_999).contains(n))?;
        self.keep("vmid", &n.to_string()).ok()?;
        Some(n)
    }

    fn spec(&self, kind: Kind, image: &str, needs: &Needs) -> Result<Spec, Stop> {
        let path = |p: PathBuf| p.to_string_lossy().into_owned();
        let (mask_dirs, mask_files) = self.host.masks(&needs.mounts).map_err(|why| Stop { exit: REFUSED, code: "cannot-mask", why })?;
        let mut group_ids = Vec::new();
        for group in &needs.groups {
            match self.host.gid(group) {
                Some(gid) => group_ids.push(gid),
                None => return refuse("no-group", format!("this host has no group {group}, which a plugin reads as")),
            }
        }
        let seccomp = Some("/usr/share/lxc/config/common.seccomp").filter(|p| self.host.at(p).is_file()).map(str::to_string);
        Ok(Spec {
            image: image.to_string(),
            uid: self.agent.uid,
            gid: self.agent.gid,
            root: self.host.root.to_string_lossy().into_owned(),
            etc: path(self.host.etc()),
            manifest: path(self.host.manifest_dir()),
            state: path(self.host.state_dir()),
            ctl: path(self.host.ctl()),
            needs: needs.clone(),
            mask_dirs,
            mask_files,
            group_ids,
            devices: if needs.devices.iter().any(|d| d == "disks") { self.host.disks() } else { Vec::new() },
            subuid: self.host.root_subids("/etc/subuid"),
            subgid: self.host.root_subids("/etc/subgid"),
            vmid: if kind == Kind::Pct { self.vmid() } else { None },
            seccomp,
            docker_major: if kind == Kind::Docker { self.output(&["docker".to_string(), "--version".to_string()], false, &[]).ok().and_then(|(_, out, _)| runtime::docker_major(out.trim())) } else { None },
            tunnel: self.tunnel,
        })
    }

    /// What Podman without root needs of the host before `sfagent` can run a container: ranges of subordinate ids, a session
    /// that outlives its logins, and the groups the plugins read as, and no others.
    fn prepare_rootless(&mut self, needs: &Needs) -> Result<(), Stop> {
        let mut steps = Vec::new();
        for file in ["/etc/subuid", "/etc/subgid"] {
            let (has, free) = self.host.subids(file, AGENT_USER);
            if !has {
                steps.push(Step::Append { path: self.host.at(file).to_string_lossy().into_owned(), line: format!("{AGENT_USER}:{free}:65536") });
            }
        }
        let run = |argv: &[&str], note: &'static str| Step::Run { argv: argv.iter().map(|s| s.to_string()).collect(), as_agent: false, note: Some(note) };
        steps.push(run(&["loginctl", "enable-linger", AGENT_USER], "sfagent's session could not be made to outlive its logins: the agent may not start by itself after a reboot"));
        let member_of = self.host.groups_of(AGENT_USER);
        for group in GROUPS {
            let (wanted, member) = (needs.groups.iter().any(|g| g == group), member_of.iter().any(|g| g == group));
            if wanted && !member {
                steps.push(Step::Run { argv: vec!["gpasswd".into(), "-a".into(), AGENT_USER.into(), group.into()], as_agent: false, note: None });
            } else if !wanted && member {
                // privileges follow plugins: a group no plugin reads as any more is given back
                steps.push(Step::Run { argv: vec!["gpasswd".into(), "-d".into(), AGENT_USER.into(), group.into()], as_agent: false, note: None });
            }
        }
        self.act(&steps)
    }

    /// The runtime these needs take on this host and what it will be told, or why this host cannot give them. Nothing on the
    /// host is changed here: a request that cannot be met is refused whole, before its manifest is accepted.
    fn plan(&self, image: &str, needs: &Needs) -> Result<(Kind, Spec), Stop> {
        let kind = runtime::choose(&self.tools(), needs).map_err(|u| Stop { exit: REFUSED, code: u.code, why: u.why })?;
        let spec = self.spec(kind, image, needs)?;
        match runtime::unserved(kind, &spec) {
            Some(u) => Err(Stop { exit: REFUSED, code: u.code, why: u.why }),
            None => Ok((kind, spec)),
        }
    }

    /// Removes whatever container there is, and makes the one that was planned.
    fn make(&mut self, kind: Kind, spec: &Spec, needs: &Needs) -> Result<Kind, Stop> {
        let image = spec.image.clone();
        self.folders()?;
        if let Some(old) = self.text("runtime").and_then(|t| Kind::parse(&t)) {
            let old_spec = Spec { vmid: self.text("vmid").and_then(|t| t.parse().ok()), root: spec.root.clone(), ..Spec::default() };
            self.act(&runtime::remove(old, &old_spec))?;
        }
        self.act(&runtime::remove(kind, spec))?;
        if kind == Kind::PodmanRootless {
            self.prepare_rootless(needs)?;
        }
        self.keep("runtime", kind.name())?;
        self.keep("image", &image)?;
        self.act(&runtime::pull(kind, spec))?;
        if let Some(to) = spec.tunnel {
            // the firewall rule first, and the network after it: the container never has a way out the rule does not hold
            self.act(&runtime::egress(spec, to))?;
            self.act(&runtime::network(kind))?;
        }
        self.act(&runtime::create(kind, spec))?;
        // what the container was made with, for the check from outside
        let _ = std::fs::remove_file(self.file(ROOTFS_FILE));
        self.keep(SPEC_FILE, &serde_json::to_string(spec).unwrap_or_default())?;
        if kind == Kind::Lxc {
            match outside::tree_hash(&self.host.at(&format!("/var/lib/lxc/{}/rootfs", runtime::NAME))) {
                Some(hash) => self.keep(ROOTFS_FILE, &hash)?,
                None => self.notes.push("the container's root filesystem could not be hashed: the check from outside cannot see files changed in it".into()),
            }
        }
        Ok(kind)
    }

    /// The tunnel pinned on this host: the receiver's address and key, as the last apply that carried one left them.
    fn pinned_tunnel(&self) -> Result<Option<(SocketAddr, [u8; 32])>, Stop> {
        tunnel::load_config(&self.host.etc()).map_err(|why| Stop { exit: REFUSED, code: "tunnel", why })
    }

    /// The tunnel a request carries, checked against the one pinned here: a receiver key that changes is taken only when a person
    /// accepted it, since anyone holding the new key could read what the agent says and hand it plugins to check. Returns the file
    /// to write and the address, or nothing when the request carries none.
    fn requested_tunnel(&self, r: &Request) -> Result<Option<(String, SocketAddr)>, Stop> {
        let Some(t) = &r.tunnel else { return Ok(None) };
        let text = json!({"format": 1, "endpoint": t.endpoint, "key": t.key}).to_string();
        let (_, address, key) = tunnel::Config::parse(text.as_bytes()).map_err(|why| Stop { exit: REFUSED, code: "tunnel", why })?;
        if let Some((_, pinned)) = self.pinned_tunnel()? {
            if pinned != key && !r.accept_new_tunnel_key {
                return refuse("tunnel-key", "this host has another receiver key pinned for its agent's tunnel. A key that changes is taken only when a person accepts it");
            }
        }
        if !self.host.at("/etc/systemd/system").is_dir() {
            return refuse("no-firewall", "this host has no systemd, so the firewall rule that keeps the agent's container from reaching anything but the controller could not be loaded again at boot, before the container starts: the tunnel is not set up here yet");
        }
        if self.host.find("nft").is_none() {
            return refuse("no-firewall", "this host has no nft, and the agent's tunnel is set up only with the firewall rule that keeps its container from reaching anything but the controller: install nftables");
        }
        Ok(Some((text, address)))
    }

    fn pinned_agent(&self) -> Result<[u8; 32], Stop> {
        match self.text("agent.pub").and_then(|line| sig::parse_public_line(&line)) {
            Some(key) => Ok(key),
            None => refuse("not-enrolled", "no agent is enrolled on this host"),
        }
    }

    /// Refuses an image nobody who may vouched for. Before anything is fetched.
    fn image_allowed(&self, image: &str, signature: Option<&str>, anchors: &Anchors) -> Result<(), Stop> {
        plugin::verify_image(image, signature.unwrap_or_default(), anchors).map(|_| ()).map_err(|why| Stop { exit: REFUSED, code: "image", why })
    }

    fn enroll(&mut self, r: &Request, controller: Signers) -> Result<Value, Stop> {
        if self.file("agent.pub").exists() {
            return refuse("enrolled", "an agent is enrolled on this host already: remove it before enrolling another");
        }
        let image = r.image.as_deref().unwrap_or_default();
        self.image_allowed(image, r.image_signature.as_deref(), &self.anchors(controller)?)?;
        if !self.tools().any() {
            if !r.install_podman {
                return refuse("no-runtime", "this host has no container runtime: Podman will be installed when the request says so");
            }
            let has = |tool: &str| self.host.find(tool).is_some();
            let Some((argv, env)) = runtime::install_podman(&has) else {
                return refuse("no-package-manager", "this host has no container runtime and no package manager this program knows to install Podman with");
            };
            match self.output(&argv, false, &env) {
                Ok((true, ..)) => self.notes.push("Podman was installed".into()),
                Ok((false, _, err)) => return Err(failed(format!("Podman could not be installed: {}", runner::plain(err.trim())))),
                Err(why) => return Err(failed(why)),
            }
        }
        self.folders()?;
        // a new enrollment is a new key: nothing of an earlier agent's is kept
        let state = self.host.state_dir();
        for name in [identity::KEY_FILE, identity::PUBLIC_FILE, SEEN_FILE, wipe::WIPED_FILE] {
            let _ = std::fs::remove_file(state.join(name));
        }
        let _ = std::fs::remove_dir_all(state.join("plugins"));
        for name in [MANIFEST_FILE, MANIFEST_SIGNATURE] {
            let _ = std::fs::remove_file(self.host.manifest_dir().join(name));
        }
        let _ = std::fs::remove_file(self.file(SEEN_FILE));
        let (kind, spec) = self.plan(image, &Needs::default())?;
        self.make(kind, &spec, &Needs::default())?;
        // The agent makes its key as it starts. The public half is read from the host's side of its state folder: one small
        // plain file, which is all that is ever taken from what the container wrote.
        let public = state.join(identity::PUBLIC_FILE);
        let mut key = None;
        for _ in 0..150 {
            if let Some(found) = read_small(&public, 200).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|line| sig::parse_public_line(&line)) {
                key = Some(found);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let Some(key) = key else {
            let _ = self.act(&runtime::remove(kind, &spec));
            return Err(failed("the agent's container was made and wrote no key in 30 seconds: it was removed again"));
        };
        let line = format!("{} storageforge-agent", sig::public_line(&key));
        self.keep("agent.pub", &line)?;
        Ok(json!({"public_key": line, "fingerprint": sig::fingerprint(&key), "runtime": kind.name()}))
    }

    fn anchors(&self, controller: Signers) -> Result<Anchors, Stop> {
        let operator = match read_small(&self.host.etc().join(OPERATOR_SIGNERS), sig::MAX_SIGNERS) {
            Ok(bytes) => match Signers::parse(&String::from_utf8_lossy(&bytes)) {
                Ok(signers) => signers,
                Err(why) => return refuse("signers", format!("{OPERATOR_SIGNERS}: {why}")),
            },
            Err(_) => Signers::default(),
        };
        Ok(Anchors { release: plugin::release_signers(), operator, controller })
    }

    /// The manifest in `bytes`, when it is this host's and may be used now.
    fn admit(&self, bytes: &[u8], signature: &str, controller: &Signers, machine: &str) -> Result<(Manifest, String, Admitted), Stop> {
        let m = manifest::verify(bytes, signature, controller).map_err(|why| Stop { exit: REFUSED, code: "manifest", why })?;
        if m.machine != machine {
            return refuse("manifest", "the manifest is for another machine");
        }
        if m.agent != sig::fingerprint(&self.pinned_agent()?) {
            return refuse("manifest", "the manifest is for another agent's key than the one enrolled here");
        }
        let digest = sig::sha256_hex(bytes);
        let seen = match read_small(&self.file(SEEN_FILE), 100) {
            Ok(text) => match std::str::from_utf8(&text).ok().and_then(Seen::parse) {
                Some(seen) => Some(seen),
                None => return refuse("manifest", "the record of the last manifest accepted cannot be read"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return refuse("manifest", format!("cannot read the record of the last manifest accepted: {e}")),
        };
        let admitted = manifest::admit(&m, &digest, seen.as_ref(), now()).map_err(|why| Stop { exit: REFUSED, code: "manifest", why })?;
        Ok((m, digest, admitted))
    }

    fn apply(&mut self, r: &Request, controller: Signers, machine: &str) -> Result<Value, Stop> {
        let (bytes, signature) = (r.manifest.as_deref().unwrap_or_default().as_bytes(), r.manifest_signature.as_deref().unwrap_or_default());
        let (m, digest, admitted) = self.admit(bytes, signature, &controller, machine)?;
        let anchors = self.anchors(controller)?;
        let mut unused: Vec<&request::SignedDescriptor> = r.plugins.iter().collect();
        for entry in &m.plugins {
            let Some(at) = unused.iter().position(|p| sig::sha256_hex(p.descriptor.as_bytes()) == entry.descriptor) else {
                return refuse("plugin", format!("plugin {}: its signed descriptor did not come with the manifest", entry.name));
            };
            let signed = unused.swap_remove(at);
            Manifest::admit_plugin(entry, signed.descriptor.as_bytes(), &signed.signature, &anchors).map_err(|why| Stop { exit: REFUSED, code: "plugin", why })?;
        }
        if !unused.is_empty() {
            return refuse("plugin", "a descriptor came with the request that the manifest does not name");
        }
        self.image_allowed(&m.image, r.image_signature.as_deref(), &anchors)?;
        let needs = m.needs();
        needs.check().map_err(|why| Stop { exit: REFUSED, code: "manifest", why })?;
        let tunnel = self.requested_tunnel(r)?;
        if let Some((_, address)) = &tunnel {
            self.tunnel = Some(*address);
        }
        let (kind, spec) = self.plan(&m.image, &needs)?;
        // everything is checked, and this host can give what is asked; the counter is written down first, so that this manifest
        // or a later one is all that is accepted from here on, whatever becomes of the steps below
        self.folders()?;
        if admitted == Admitted::New {
            self.keep(SEEN_FILE, Seen { counter: m.counter, sha256: digest.clone() }.line().trim_end())?;
        }
        let dir = self.host.manifest_dir();
        // The files of a plugin this manifest takes out go with it: the agent takes anything in its plugin folder that its manifest
        // does not account for as tampering (roadmap 11.3). Only the files of plugins the manifest in force named are taken away;
        // anything else found there stays, for the check from outside to find.
        if let Ok(old) = read_small(&dir.join(MANIFEST_FILE), manifest::MAX_MANIFEST) {
            if let Ok(old) = serde_json::from_slice::<Manifest>(&old) {
                let plugins = self.host.state_dir().join("plugins");
                for gone in old.plugins.iter().filter(|e| plugin::is_name(&e.name) && !m.plugins.iter().any(|n| n.name == e.name)) {
                    for file in [runner::descriptor_file(&gone.name), runner::signature_file(&gone.name), runner::program_file(&gone.name)] {
                        let _ = std::fs::remove_file(plugins.join(&file));
                        let _ = std::fs::remove_file(plugins.join(format!("{file}.new")));
                    }
                }
            }
        }
        write_whole(&dir.join(MANIFEST_SIGNATURE), signature.as_bytes(), 0o644).and_then(|_| write_whole(&dir.join(MANIFEST_FILE), bytes, 0o644)).map_err(|e| failed(format!("cannot write the manifest: {e}")))?;
        if let Some((text, _)) = &tunnel {
            write_whole(&self.host.etc().join(tunnel::TUNNEL_FILE), format!("{text}\n").as_bytes(), 0o644).map_err(|e| failed(format!("cannot write the tunnel file: {e}")))?;
        }
        self.make(kind, &spec, &needs)?;
        Ok(json!({"counter": m.counter, "manifest": digest, "runtime": kind.name(), "plugins": m.plugins.iter().map(|e| e.name.clone()).collect::<Vec<_>>(), "needs": needs, "tunnel": self.tunnel.map(|a| a.to_string())}))
    }

    /// The image and the needs of the manifest in use, read again from the file and checked again; or of an agent that is
    /// enrolled and has no manifest yet.
    fn current(&self, controller: &Signers, machine: &str) -> Result<(String, Needs), Stop> {
        self.pinned_agent()?;
        let dir = self.host.manifest_dir();
        match read_small(&dir.join(MANIFEST_FILE), manifest::MAX_MANIFEST) {
            Ok(bytes) => {
                let signature = read_small(&dir.join(MANIFEST_SIGNATURE), sig::MAX_SIGNATURE).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
                let (m, _, admitted) = self.admit(&bytes, &signature, controller, machine)?;
                if admitted != Admitted::Same {
                    return refuse("manifest", "the manifest on this host is not the one that was accepted last");
                }
                // the image whose signature was checked when this manifest was applied, and no other
                if self.text("image").as_deref() != Some(m.image.as_str()) {
                    return refuse("image", "the manifest names another image than the one that was checked and run here");
                }
                Ok((m.image.clone(), m.needs()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match self.text("image").filter(|i| manifest::is_image(i)) {
                Some(image) => Ok((image, Needs::default())),
                None => refuse("not-enrolled", "no agent is enrolled on this host"),
            },
            Err(e) => Err(failed(format!("cannot read the manifest: {e}"))),
        }
    }

    fn recorded(&self) -> Option<(Kind, Spec)> {
        let kind = Kind::parse(&self.text("runtime")?)?;
        Some((kind, Spec { vmid: self.text("vmid").and_then(|t| t.parse().ok()), root: self.host.root.to_string_lossy().into_owned(), ..Spec::default() }))
    }

    fn status(&self) -> Value {
        let key = self.text("agent.pub").and_then(|line| sig::parse_public_line(&line));
        let seen = read_small(&self.file(SEEN_FILE), 100).ok().and_then(|t| String::from_utf8(t).ok()).and_then(|t| Seen::parse(&t));
        let (mut running, mut image_id, mut runtime) = (false, None, None);
        if let Some((kind, spec)) = self.recorded() {
            runtime = Some(kind.name());
            let (argv, as_agent) = runtime::state_command(kind, &spec);
            if let Ok((ok, out, _)) = self.output(&argv, as_agent, &[]) {
                (running, image_id) = runtime::read_state(kind, ok, &out);
            }
        }
        json!({
            "enrolled": key.is_some(), "fingerprint": key.map(|k| sig::fingerprint(&k)), "runtime": runtime, "running": running,
            "image": self.text("image"), "image_id": image_id, "counter": seen.as_ref().map(|s| s.counter), "manifest": seen.map(|s| s.sha256),
            "runtimes": self.tools().names(), "version": VERSION,
        })
    }

    /// The check from outside (roadmap 11.3): the running container against the manifest, and the agent's folders against what it
    /// keeps. Every finding is a sentence; the controller wipes the agent on any. Nothing here changes anything on the host.
    fn check(&self, controller: &Signers, machine: &str) -> Result<Value, Stop> {
        let pinned = self.pinned_agent()?;
        let anchors = self.anchors(controller.clone())?;
        let (mut findings, mut notes, mut checked) = (Vec::new(), Vec::new(), Vec::new());
        // the manifest in force, as this program accepted it
        let dir = self.host.manifest_dir();
        let mut manifest = None;
        match read_small(&dir.join(MANIFEST_FILE), manifest::MAX_MANIFEST) {
            Ok(bytes) => {
                let signature = read_small(&dir.join(MANIFEST_SIGNATURE), sig::MAX_SIGNATURE).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
                match self.admit(&bytes, &signature, controller, machine) {
                    Ok((m, _, Admitted::Same)) => manifest = Some(m),
                    Ok(_) => findings.push("the manifest on this host is not the one that was accepted last".to_string()),
                    Err(stop) => findings.push(format!("the manifest on this host: {}", stop.why)),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => findings.push(format!("the manifest on this host cannot be read: {e}")),
        }
        checked.push("manifest");
        let recorded_image = self.text("image").unwrap_or_default();
        let image = manifest.as_ref().map(|m| m.image.clone()).unwrap_or_else(|| recorded_image.clone());
        if manifest.is_some() && image != recorded_image {
            findings.push("the manifest names another image than the one that was checked and run here".into());
        }
        let state = self.host.state_dir();
        findings.extend(outside::compare_state(&state, &pinned));
        checked.push("state folder");
        let (found, waiting) = outside::compare_plugins(&state.join(outside::PLUGINS_DIR), manifest.as_ref(), &anchors);
        findings.extend(found);
        notes.extend(waiting);
        checked.push("plugin files");
        let mut running = false;
        if let Some((kind, _)) = self.recorded() {
            let made: Option<Spec> = read_small(&self.file(SPEC_FILE), 1 << 20).ok().and_then(|b| serde_json::from_slice(&b).ok());
            let spec = match made {
                Some(spec) => spec,
                None => {
                    notes.push("what the container was made with was not kept (it was made by an earlier version): compared with what it would be made with now".into());
                    let needs = manifest.as_ref().map(Manifest::needs).unwrap_or_default();
                    self.spec(kind, &image, &needs)?
                }
            };
            if spec.image != image {
                findings.push("the container was made from another image than the manifest names".into());
            }
            let (argv, as_agent) = runtime::state_command(kind, &spec);
            if let Ok((ok, out, _)) = self.output(&argv, as_agent, &[]) {
                running = runtime::read_state(kind, ok, &out).0;
            }
            match kind {
                Kind::Docker | Kind::Podman | Kind::PodmanRootless => {
                    let program = if kind == Kind::Docker { "docker" } else { "podman" };
                    let as_agent = kind == Kind::PodmanRootless;
                    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<String>>();
                    match self.answer(&words(&[program, "inspect", runtime::NAME]), as_agent) {
                        Ok((true, text)) => match serde_json::from_str::<Value>(&text) {
                            Ok(v) => {
                                let id = self.answer(&words(&[program, "image", "inspect", "--format", "{{.Id}}", &spec.image]), as_agent).ok().filter(|(ok, _)| *ok).map(|(_, t)| t.trim().to_string());
                                findings.extend(outside::compare_inspect(kind, &spec, &v, id.as_deref()));
                                checked.push("image, mounts, capabilities and devices");
                            }
                            Err(_) => findings.push(format!("{program} described the agent's container in a form this program does not read")),
                        },
                        Ok((false, _)) => notes.push("the agent's container is not there".into()),
                        Err(why) => notes.push(why),
                    }
                    match self.answer(&words(&[program, "diff", runtime::NAME]), as_agent) {
                        Ok((true, text)) => {
                            findings.extend(outside::compare_diff(&spec, &text));
                            checked.push("files changed in the container");
                        }
                        Ok((false, _)) => {}
                        Err(why) => notes.push(why),
                    }
                }
                Kind::Lxc => match (self.text(ROOTFS_FILE), outside::tree_hash(&self.host.at(&format!("/var/lib/lxc/{}/rootfs", runtime::NAME)))) {
                    (Some(was), Some(now)) if was == now => checked.push("files changed in the container's root filesystem"),
                    (Some(_), Some(_)) => {
                        findings.push("the container's root filesystem changed since it was made".into());
                        checked.push("files changed in the container's root filesystem");
                    }
                    (Some(_), None) => findings.push("the container's root filesystem is gone or cannot be read".into()),
                    (None, _) => notes.push("no hash of the container's root filesystem was taken when it was made".into()),
                },
                Kind::Incus | Kind::Pct => notes.push(format!("under {} the container itself is not compared with the manifest yet: its folders are", kind.name())),
            }
        }
        findings.truncate(100);
        Ok(json!({"clean": findings.is_empty(), "findings": findings, "checked": checked, "running": running, "waiting": notes}))
    }

    /// Ends the agent's access on this host (roadmap 11.3). The controller revoked its key on its own side first. Here: the container
    /// stopped and left stopped, the key and the plugin files deleted as the agent would delete them, why written beside them, and
    /// the key pinned here forgotten, so that `start` and `apply` refuse until an admin enrolls an agent again.
    fn wipe(&mut self, reason: &str) -> Result<Value, Stop> {
        self.pinned_agent()?;
        let mut stopped = false;
        if let Some((kind, spec)) = self.recorded() {
            self.act(&runtime::stop(kind, &spec))?;
            stopped = true;
        }
        let state = self.host.state_dir();
        let why = format!("wiped by the controller: {}", runner::plain(reason));
        if let Err(e) = wipe::wipe(&state, &[why], now()) {
            self.notes.push(e);
        }
        if unsafe { libc::geteuid() } == 0 {
            let _ = std::os::unix::fs::chown(state.join(wipe::WIPED_FILE), Some(self.agent.uid), Some(self.agent.gid));
        }
        let _ = std::fs::remove_file(self.file("agent.pub"));
        Ok(json!({"wiped": true, "stopped": stopped}))
    }

    fn remove(&mut self) -> Result<Value, Stop> {
        let recorded = self.recorded();
        if let Some((kind, spec)) = &recorded {
            self.act(&runtime::remove(*kind, spec))?;
        }
        if self.tunnel.is_some() {
            let root = self.host.root.to_string_lossy().into_owned();
            self.act(&runtime::egress_remove(recorded.as_ref().map(|(k, _)| *k), &root))?;
        }
        let _ = std::fs::remove_file(self.host.etc().join(tunnel::TUNNEL_FILE));
        if self.host.user(AGENT_USER).is_some() {
            let member_of = self.host.groups_of(AGENT_USER);
            for group in GROUPS.iter().filter(|g| member_of.iter().any(|m| m == *g)) {
                self.act(&[Step::Run { argv: vec!["gpasswd".into(), "-d".into(), AGENT_USER.into(), group.to_string()], as_agent: false, note: Some("sfagent could not be taken out of a group") }])?;
            }
        }
        // the key goes with the agent: what is enrolled next is another agent
        let state = self.host.state_dir();
        if let Ok(entries) = std::fs::read_dir(&state) {
            for entry in entries.flatten() {
                let path = entry.path();
                let _ = if entry.file_type().is_ok_and(|t| t.is_dir()) { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            }
        }
        for name in [MANIFEST_FILE, MANIFEST_SIGNATURE] {
            let _ = std::fs::remove_file(self.host.manifest_dir().join(name));
        }
        for name in ["agent.pub", "runtime", "image", "vmid", "lxc.conf", SEEN_FILE, SPEC_FILE, ROOTFS_FILE] {
            let _ = std::fs::remove_file(self.file(name));
        }
        Ok(json!({"removed": true}))
    }
}

fn run() -> Result<Value, Stop> {
    let host = Host::detect().map_err(|why| Stop { exit: REFUSED, code: "not-root", why })?;
    unsafe { libc::umask(0o022) };
    if std::env::args().count() > 1 {
        return refuse("usage", "storageforge-agentctl takes no arguments: a signed request on stdin");
    }
    // the pinned key first, then the signature, and only then is a byte of the request believed
    let controller = match read_small(&host.etc().join(CONTROLLER_SIGNERS), sig::MAX_SIGNERS) {
        Ok(bytes) => Signers::parse(&String::from_utf8_lossy(&bytes)).map_err(|why| Stop { exit: REFUSED, code: "signers", why: format!("{CONTROLLER_SIGNERS}: {why}") })?,
        Err(_) => return refuse("signers", "this host has no controller pinned: the agent's setup has not run here"),
    };
    let Some(machine) = host.machine_id() else { return refuse("machine", "this host has no machine id") };
    let mut stdin = std::io::stdin().lock().take((request::MAX_REQUEST + sig::MAX_SIGNATURE + 64) as u64);
    let (payload, signature) = request::read(&mut stdin).map_err(|why| Stop { exit: REFUSED, code: "request", why })?;
    let r = request::verify(&payload, &signature, &controller, &machine, now()).map_err(|why| Stop { exit: REFUSED, code: "request", why })?;
    request::claim_nonce(&host.ctl().join("seen"), &r.nonce, now()).map_err(|why| Stop { exit: REFUSED, code: "request", why })?;
    // The user behind sudo must not hold the runtime by another road: that group is root on this host, and then the one
    // sudoers line limits nothing.
    if let Some(manager) = &host.manager {
        if let Some(group) = host.in_any(manager, &ROOT_GROUPS) {
            return refuse("root-group", format!("{manager} is in the {group} group, which is root on this host: take that user out of it (gpasswd -d {manager} {group}) and ask again"));
        }
    }
    let Some(agent) = host.user(AGENT_USER) else { return refuse("no-account", "this host has no sfagent account: the agent's setup has not run here") };
    if agent.uid == 0 || agent.gid == 0 {
        return refuse("account", "sfagent is root on this host: the agent never runs as root");
    }
    if let Some(group) = host.in_any(AGENT_USER, &AGENT_FORBIDDEN_GROUPS) {
        return refuse("account", format!("sfagent is in the {group} group on this host: the agent's account is in no group that gives root"));
    }
    let mut ctl = Ctl { host, agent, notes: Vec::new(), tunnel: None };
    // a tunnel file that cannot be read gives no tunnel: the container is then made with no network, never with one unruled
    ctl.tunnel = ctl.pinned_tunnel().ok().flatten().map(|(address, _)| address);
    let mut out = match r.op.as_str() {
        "preflight" => {
            let tools = ctl.tools();
            let would = runtime::choose(&tools, &Needs::default()).map(|k| k.name()).ok();
            json!({"runtimes": tools.names(), "would_use": would, "enrolled": ctl.file("agent.pub").exists(), "version": VERSION, "release_keys": plugin::release_signers().0.len()})
        }
        "enroll" => ctl.enroll(&r, controller)?,
        "apply" => ctl.apply(&r, controller, &machine)?,
        "start" | "restart" => {
            let (image, needs) = ctl.current(&controller, &machine)?;
            let (kind, spec) = ctl.plan(&image, &needs)?;
            ctl.make(kind, &spec, &needs)?;
            json!({"runtime": kind.name()})
        }
        "stop" => {
            ctl.pinned_agent()?;
            match ctl.recorded() {
                Some((kind, spec)) => ctl.act(&runtime::stop(kind, &spec))?,
                None => return refuse("not-enrolled", "no agent's container is recorded on this host"),
            }
            json!({"stopped": true})
        }
        "status" => ctl.status(),
        "remove" => ctl.remove()?,
        "check" => ctl.check(&controller, &machine)?,
        "wipe" => ctl.wipe(r.reason.as_deref().unwrap_or(""))?,
        _ => return refuse("request", "not an agent operation"),
    };
    out["ok"] = json!(true);
    out["op"] = json!(r.op);
    out["notes"] = json!(ctl.notes);
    Ok(out)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") && std::env::args().count() == 2 {
        println!("storageforge-agentctl {VERSION}");
        return;
    }
    match run() {
        Ok(out) => println!("{out}"),
        Err(stop) => {
            println!("{}", json!({"ok": false, "error": stop.code, "why": stop.why}));
            eprintln!("storageforge-agentctl: {}", stop.why);
            std::process::exit(stop.exit);
        }
    }
}
