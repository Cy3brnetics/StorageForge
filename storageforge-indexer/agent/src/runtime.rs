//! The agent's container, as each runtime is asked to make it (roadmap section 11.1, "Runtime" and "LXC").
//!
//! Nothing here runs anything: every function returns the steps, as argument lists and file contents, and storageforge-agentctl
//! carries them out. So what a runtime is asked for can be read in one place and tested without one.
//!
//! What holds on every runtime, whatever the manifest says:
//!
//! - the process is `sfagent`, never root, and cannot gain privileges
//! - the root filesystem is read-only where the runtime can make it so (Docker, Podman, plain LXC)
//! - every capability is dropped but the ones the plugins declare
//! - every host path is mounted read-only, one filesystem at a time, at `/host` + its path, with SSH's and StorageForge's secrets
//!   masked inside it, or the mount is refused where the runtime cannot mask
//! - no runtime's socket is mounted, nesting is off, and an LXC container is unprivileged
//! - there is no network at all unless a plugin declares the host's or the agent has a tunnel to the controller. With a tunnel, the
//!   container is on a bridge of its own (`sfagent0`, Docker and Podman as root) or behind Podman's user-mode network (Podman without
//!   root), and the host's firewall lets it reach the controller's one address and port and nothing else: not the host itself, so
//!   not its `sshd`, and not any other host (`egress_rules`). The rule is matched on the bridge for a bridged container and on
//!   `sfagent`'s uid for everything else, which holds with the host's network too.
//!
//! Docker and Podman are run here against stand-in programs and, in the unit tests of the controller, against the real Docker.
//! The LXC, Incus and Proxmox steps are written from those tools' documentation and have not run against them: lab tier 24.

use crate::host::IMAGE_ID;
use crate::needs::Needs;

/// The container's name, on every runtime that takes one.
pub const NAME: &str = "storageforge-agent";
const INCUS_REMOTE: &str = "storageforge-agent-registry";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Docker,
    /// Podman run by `sfagent` itself: no root runtime is involved at all.
    PodmanRootless,
    Podman,
    Lxc,
    Incus,
    Pct,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Docker => "docker",
            Kind::PodmanRootless => "podman-rootless",
            Kind::Podman => "podman",
            Kind::Lxc => "lxc",
            Kind::Incus => "incus",
            Kind::Pct => "pct",
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        [Kind::Docker, Kind::PodmanRootless, Kind::Podman, Kind::Lxc, Kind::Incus, Kind::Pct].into_iter().find(|k| k.name() == name.trim())
    }

    fn program(self) -> &'static str {
        match self {
            Kind::Docker => "docker",
            Kind::PodmanRootless | Kind::Podman => "podman",
            Kind::Lxc => "lxc-start",
            Kind::Incus => "incus",
            Kind::Pct => "pct",
        }
    }
}

/// Which runtimes the host has.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Tools {
    pub docker: bool,
    pub podman: bool,
    pub lxc: bool,
    pub incus: bool,
    pub pct: bool,
}

impl Tools {
    pub fn any(&self) -> bool {
        self.docker || self.podman || self.lxc || self.incus || self.pct
    }

    pub fn names(&self) -> Vec<&'static str> {
        [(self.docker, "docker"), (self.podman, "podman"), (self.pct, "pct"), (self.incus, "incus"), (self.lxc, "lxc")].iter().filter(|(have, _)| *have).map(|(_, name)| *name).collect()
    }
}

/// What a request cannot be met with. `code` is for the controller, `why` for a person.
#[derive(Debug, PartialEq, Eq)]
pub struct Unserved {
    pub code: &'static str,
    pub why: String,
}

/// The runtime for these needs on a host with these tools. The least that works: Podman without root where no plugin needs
/// more, a root runtime only for capabilities and devices, LXC where the host has LXC and neither of the others.
pub fn choose(tools: &Tools, needs: &Needs) -> Result<Kind, Unserved> {
    if !tools.any() {
        return Err(Unserved { code: "no-runtime", why: "this host has no container runtime: Podman will be installed when the request says so".into() });
    }
    let kind = if needs.rootful() {
        if tools.docker {
            Kind::Docker
        } else if tools.podman {
            Kind::Podman
        } else {
            return Err(Unserved {
                code: "runtime-cannot",
                why: "a plugin needs a capability or a device, which an unprivileged LXC container cannot be given: that plugin takes Docker or Podman on this host".into(),
            });
        }
    } else if tools.podman {
        Kind::PodmanRootless
    } else if tools.docker {
        Kind::Docker
    } else if tools.pct {
        Kind::Pct
    } else if tools.incus {
        Kind::Incus
    } else {
        Kind::Lxc
    };
    Ok(kind)
}

/// Everything a runtime is told to make the container. All paths are the host's.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Spec {
    pub image: String,
    /// `sfagent` on this host.
    pub uid: u32,
    pub gid: u32,
    /// The folder that stands for `/` when files are written: empty on a real host.
    pub root: String,
    pub etc: String,
    pub manifest: String,
    pub state: String,
    /// Where storageforge-agentctl keeps its own files (the LXC configuration is written there).
    pub ctl: String,
    pub needs: Needs,
    /// Folders and files to hide inside the mounts (`Host::masks`).
    pub mask_dirs: Vec<String>,
    pub mask_files: Vec<String>,
    /// The host gids of `needs.groups`.
    pub group_ids: Vec<u32>,
    /// The host devices of `needs.devices`.
    pub devices: Vec<String>,
    /// Root's subordinate id ranges, for LXC.
    pub subuid: Option<u64>,
    pub subgid: Option<u64>,
    /// The container's number on Proxmox VE.
    pub vmid: Option<u32>,
    /// Whether LXC's stock seccomp profile is installed on this host.
    pub seccomp: Option<String>,
    /// Docker's major version, where it could be read: how a mount of one filesystem is spelled changed at 25.
    pub docker_major: Option<u32>,
    /// The controller's receiver, when the agent has a tunnel: the one address the container may reach.
    pub tunnel: Option<std::net::SocketAddr>,
}

/// The bridge, and the network the runtime knows it by, of an agent's container that has a tunnel.
pub const BRIDGE: &str = "sfagent0";
pub const NETWORK: &str = "sfagent";
/// The nftables table the egress rule is in, and the unit that loads it again at boot, before the runtimes start.
pub const EGRESS_TABLE: &str = "storageforge_agent";
pub const EGRESS_UNIT: &str = "storageforge-agent-egress.service";

fn host_net(n: &Needs) -> bool {
    n.namespaces.iter().any(|x| x == "net")
}

/// The host's firewall rule for an agent with a tunnel: `sfagent`'s own sockets (Podman without root, the host's network) and
/// anything that comes off the agent's bridge reach the receiver's address and port, and nothing else. The whole table is made
/// anew each time, so that a rule from an earlier endpoint does not stay behind.
pub fn egress_rules(uid: u32, to: std::net::SocketAddr) -> String {
    let family = if to.is_ipv4() { "ip" } else { "ip6" };
    let (ip, port) = (to.ip(), to.port());
    let mut out = String::from("# Written by storageforge-agentctl. The agent reaches its controller and nothing else.\n");
    out += &format!("table inet {EGRESS_TABLE}\ndelete table inet {EGRESS_TABLE}\ntable inet {EGRESS_TABLE} {{\n");
    out += &format!("\tchain agent_out {{\n\t\ttype filter hook output priority filter - 10; policy accept;\n");
    out += &format!("\t\tmeta skuid {uid} {family} daddr {ip} tcp dport {port} accept\n\t\tmeta skuid {uid} counter drop\n\t}}\n");
    for (chain, hook) in [("agent_fwd", "forward"), ("agent_in", "input")] {
        out += &format!("\tchain {chain} {{\n\t\ttype filter hook {hook} priority filter - 10; policy accept;\n");
        out += &format!("\t\tiifname \"{BRIDGE}\" {family} daddr {ip} tcp dport {port} accept\n\t\tiifname \"{BRIDGE}\" counter drop\n\t}}\n");
    }
    out += "}\n";
    out
}

/// The steps that put the egress rule in place and keep it there across a reboot. A failure to load it stops everything: the
/// container is never made with a network the rule does not hold.
pub fn egress(spec: &Spec, to: std::net::SocketAddr) -> Vec<Step> {
    let file = format!("{}/egress.nft", spec.ctl);
    let mut unit = String::from("[Unit]\nDescription=StorageForge agent: its container reaches the controller and nothing else\nDefaultDependencies=no\n");
    unit += "Before=network-pre.target docker.service podman.service podman-restart.service lxc.service\nWants=network-pre.target\n\n";
    unit += &format!("[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f {file}\n\n[Install]\nWantedBy=multi-user.target\n");
    vec![
        Step::Write { path: file.clone(), content: egress_rules(spec.uid, to) },
        run(&["nft", "-f", &file]),
        Step::Write { path: format!("{}/etc/systemd/system/{EGRESS_UNIT}", spec.root), content: unit },
        Step::Run { argv: words(&["systemctl", "enable", EGRESS_UNIT]), as_agent: false, note: Some("the egress rule could not be set to load at boot: until it is, a reboot leaves the agent's container without it") },
    ]
}

/// The steps that take the egress rule and the agent's bridge away, when the agent is removed.
pub fn egress_remove(kind: Option<Kind>, root: &str) -> Vec<Step> {
    let quiet = |argv: &[&str]| Step::Run { argv: words(argv), as_agent: false, note: Some("") };
    let mut steps = vec![quiet(&["systemctl", "disable", EGRESS_UNIT]), quiet(&["rm", "-f", &format!("{root}/etc/systemd/system/{EGRESS_UNIT}")])];
    match kind {
        Some(Kind::Docker) => steps.push(quiet(&["docker", "network", "rm", NETWORK])),
        Some(Kind::Podman) => steps.push(quiet(&["podman", "network", "rm", NETWORK])),
        _ => {}
    }
    steps.push(quiet(&["nft", "delete", "table", "inet", EGRESS_TABLE]));
    steps
}

/// The steps that make the agent's bridge, for Docker and Podman as root. One that is there already stays.
pub fn network(kind: Kind) -> Vec<Step> {
    let quiet = |argv: &[&str]| Step::Run { argv: words(argv), as_agent: false, note: Some("") };
    match kind {
        Kind::Docker => vec![quiet(&["docker", "network", "create", "--driver", "bridge", "--opt", &format!("com.docker.network.bridge.name={BRIDGE}"), "--opt", "com.docker.network.bridge.enable_icc=false", NETWORK])],
        Kind::Podman => vec![quiet(&["podman", "network", "create", "--interface-name", BRIDGE, "--opt", "isolate=true", NETWORK])],
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Run a program. `as_agent`: as `sfagent`, for Podman without root. `note`: when set, a failure is reported under this
    /// note and the steps go on; when not, a failure stops them.
    Run { argv: Vec<String>, as_agent: bool, note: Option<&'static str> },
    /// Write a file whole.
    Write { path: String, content: String },
    /// Add a line to a file unless it is there.
    Append { path: String, line: String },
    Mkdir { path: String },
}

fn run(argv: &[&str]) -> Step {
    Step::Run { argv: argv.iter().map(|s| s.to_string()).collect(), as_agent: false, note: None }
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| s.to_string()).collect()
}

/// Why `kind` cannot give a container these needs, when it cannot. A plugin a runtime cannot serve is not offered there, with
/// this reason shown (roadmap section 11.1, "LXC").
pub fn unserved(kind: Kind, spec: &Spec) -> Option<Unserved> {
    let no = |why: String| Some(Unserved { code: "runtime-cannot", why });
    let n = &spec.needs;
    if spec.tunnel.is_some() && !host_net(n) && matches!(kind, Kind::Lxc | Kind::Incus | Kind::Pct) {
        return no(format!("the tunnel to the controller is not built for {} yet: its container would need a network of its own, with the host's firewall rule on it", kind.name()));
    }
    match kind {
        Kind::Docker | Kind::Podman => None,
        Kind::PodmanRootless if n.rootful() => no("Podman without root cannot give a capability or a device".into()),
        Kind::PodmanRootless => None,
        Kind::Lxc | Kind::Incus | Kind::Pct => {
            if n.rootful() {
                return no("an unprivileged LXC container cannot be given a capability or a device of the host".into());
            }
            if !n.groups.is_empty() {
                return no(format!("reading as the host's group {} is not built for LXC yet", n.groups.join(", ")));
            }
            if kind == Kind::Lxc && (spec.subuid.is_none() || spec.subgid.is_none()) {
                return no("root has no range of 65536 ids in /etc/subuid and /etc/subgid, which an unprivileged container is mapped into".into());
            }
            if kind != Kind::Lxc && !n.namespaces.is_empty() {
                return no(format!("{} cannot share the host's {} with a container", kind.name(), n.namespaces.join(" and ")));
            }
            if kind != Kind::Lxc && (!spec.mask_dirs.is_empty() || !spec.mask_files.is_empty()) {
                let first = spec.mask_dirs.first().or(spec.mask_files.first()).cloned().unwrap_or_default();
                return no(format!("{} cannot hide {first} inside a mount, so a mount that would show it is not made", kind.name()));
            }
            if kind == Kind::Incus && !spec.image.split('@').next().unwrap_or("").contains('/') {
                return no("Incus takes an image from a registry: registry/name@sha256:...".into());
            }
            if kind == Kind::Pct && spec.vmid.is_none() {
                return no("no container number was given for Proxmox VE".into());
            }
            None
        }
    }
}

/// The arguments of `docker run` or `podman run` for the agent's container.
pub fn container_args(kind: Kind, spec: &Spec) -> Vec<String> {
    let rootless = kind == Kind::PodmanRootless;
    let podman = kind != Kind::Docker;
    let n = &spec.needs;
    let mut a = words(&["run", "-d", "--name", NAME, "--restart", if podman { "always" } else { "unless-stopped" }]);
    a.extend(words(&["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]));
    a.extend(["--user".to_string(), format!("{}:{}", spec.uid, spec.gid)]);
    if rootless {
        // sfagent inside is sfagent outside, and nobody inside is root on the host
        a.extend(words(&["--userns", "keep-id"]));
    } else {
        // limits a rootless runtime can only set where the host delegates the controllers to users, which not every host does
        a.extend(words(&["--pids-limit", "256", "--memory", "256m"]));
    }
    // the host's network when a plugin declares it; with a tunnel the agent's bridge, or Podman's user-mode network without root,
    // where every connection is made by a process of sfagent's and the egress rule holds; else none at all
    match (host_net(n), spec.tunnel.is_some(), rootless) {
        (true, ..) => a.extend(words(&["--network", "host"])),
        (false, true, true) => a.extend(words(&["--network", "pasta"])),
        (false, true, false) => a.extend(words(&["--network", NETWORK])),
        (false, false, _) => a.extend(words(&["--network", "none"])),
    }
    if n.namespaces.iter().any(|x| x == "pid") {
        a.extend(words(&["--pid", "host"]));
    }
    a.extend(words(&["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m"]));
    let ro = if podman { "ro" } else { "readonly" };
    // One filesystem, and not what is mounted below it. Docker 25 named the option anew and Docker 29 refuses the old name; a
    // Docker whose version could not be read is taken for a current one, and an old one then refuses the mount: nothing is
    // ever mounted wider than was asked.
    let one_filesystem = match (podman, spec.docker_major) {
        (true, _) => "bind-nonrecursive",
        (false, Some(major)) if major < 25 => "bind-nonrecursive=true",
        (false, _) => "bind-recursive=disabled",
    };
    a.extend(["--mount".to_string(), format!("type=bind,src={},dst=/etc/storageforge-agent,{ro}", spec.etc)]);
    a.extend(["--mount".to_string(), format!("type=bind,src={},dst=/var/lib/storageforge-agent/manifest,{ro}", spec.manifest)]);
    a.extend(["--mount".to_string(), format!("type=bind,src={},dst=/var/lib/storageforge-agent/state", spec.state)]);
    for path in &n.mounts {
        a.extend(["--mount".to_string(), format!("type=bind,src={}{path},dst=/host{},{ro},{one_filesystem}", spec.root, path.trim_end_matches('/'))]);
    }
    for dir in &spec.mask_dirs {
        a.extend(["--tmpfs".to_string(), format!("/host{dir}:ro,size=4k,mode=000")]);
    }
    for file in &spec.mask_files {
        a.extend(["--mount".to_string(), format!("type=bind,src=/dev/null,dst=/host{file},{ro}")]);
    }
    for cap in &n.capabilities {
        a.extend(["--cap-add".to_string(), cap.clone()]);
    }
    if rootless && !n.groups.is_empty() {
        a.extend(words(&["--group-add", "keep-groups"]));
    } else {
        for gid in &spec.group_ids {
            a.extend(["--group-add".to_string(), gid.to_string()]);
        }
    }
    for device in &spec.devices {
        a.extend(["--device".to_string(), format!("{device}:{device}:r")]);
    }
    a.extend([spec.image.clone(), "run".to_string()]);
    a
}

fn lxc_conf(spec: &Spec) -> String {
    let n = &spec.needs;
    let (subuid, subgid) = (spec.subuid.unwrap_or(0), spec.subgid.unwrap_or(0));
    let rest = 65_536 - u64::from(IMAGE_ID) - 1;
    let mut c = String::from("# Written by storageforge-agentctl for the agent's container, and written again whole whenever its plugins change.\n");
    // unprivileged: every id inside is an id nobody has outside, but sfagent, who is sfagent
    for (kind, base, host) in [("u", subuid, spec.uid), ("g", subgid, spec.gid)] {
        c += &format!("lxc.idmap = {kind} 0 {base} {IMAGE_ID}\n");
        c += &format!("lxc.idmap = {kind} {IMAGE_ID} {host} 1\n");
        c += &format!("lxc.idmap = {kind} {} {} {rest}\n", IMAGE_ID + 1, base + u64::from(IMAGE_ID) + 1);
    }
    c += &format!("lxc.init.cmd = /usr/bin/storageforge-agent run\nlxc.init.uid = {IMAGE_ID}\nlxc.init.gid = {IMAGE_ID}\n");
    c += "lxc.rootfs.options = ro\nlxc.cap.keep = none\nlxc.no_new_privs = 1\n";
    c += "lxc.apparmor.profile = generated\nlxc.apparmor.allow_nesting = 0\n";
    if let Some(profile) = &spec.seccomp {
        c += &format!("lxc.seccomp.profile = {profile}\n");
    }
    c += if n.namespaces.iter().any(|x| x == "net") { "lxc.net.0.type = none\n" } else { "lxc.net.0.type = empty\n" };
    let keep: Vec<&str> = n.namespaces.iter().map(String::as_str).collect();
    if !keep.is_empty() {
        c += &format!("lxc.namespace.keep = {}\n", keep.join(" "));
    }
    c += "lxc.mount.auto = proc:mixed sys:ro\nlxc.tty.max = 0\nlxc.start.auto = 1\n";
    c += "lxc.mount.entry = tmpfs tmp tmpfs rw,noexec,nosuid,nodev,size=16m 0 0\n";
    c += &format!("lxc.mount.entry = {} etc/storageforge-agent none bind,ro 0 0\n", spec.etc);
    c += &format!("lxc.mount.entry = {} var/lib/storageforge-agent/manifest none bind,ro 0 0\n", spec.manifest);
    c += &format!("lxc.mount.entry = {} var/lib/storageforge-agent/state none bind,rw 0 0\n", spec.state);
    for path in &n.mounts {
        // bind, not rbind: this filesystem and not the ones mounted below it
        c += &format!("lxc.mount.entry = {}{path} host{} none bind,ro 0 0\n", spec.root, path.trim_end_matches('/'));
    }
    for dir in &spec.mask_dirs {
        c += &format!("lxc.mount.entry = tmpfs host{dir} tmpfs ro,size=4k,mode=000 0 0\n");
    }
    for file in &spec.mask_files {
        c += &format!("lxc.mount.entry = /dev/null host{file} none bind,ro 0 0\n");
    }
    c
}

fn pct_idmap(spec: &Spec) -> Vec<String> {
    let rest = 65_536 - u64::from(IMAGE_ID) - 1;
    let mut out = Vec::new();
    for (kind, host) in [("u", spec.uid), ("g", spec.gid)] {
        out.push(format!("lxc.idmap: {kind} 0 100000 {IMAGE_ID}"));
        out.push(format!("lxc.idmap: {kind} {IMAGE_ID} {host} 1"));
        out.push(format!("lxc.idmap: {kind} {} {} {rest}", IMAGE_ID + 1, 100_000 + u64::from(IMAGE_ID) + 1));
    }
    out
}

fn digest12(image: &str) -> &str {
    image.rsplit(':').next().map(|d| &d[..d.len().min(12)]).unwrap_or("")
}

/// The steps that fetch the image. Always by digest, so what runs is the image that was scanned and signed.
pub fn pull(kind: Kind, spec: &Spec) -> Vec<Step> {
    let docker_url = format!("docker://{}", spec.image);
    match kind {
        Kind::Docker => vec![run(&["docker", "pull", "--quiet", &spec.image])],
        Kind::Podman => vec![run(&["podman", "pull", "--quiet", &spec.image])],
        Kind::PodmanRootless => vec![Step::Run { argv: words(&["podman", "pull", "--quiet", &spec.image]), as_agent: true, note: None }],
        // lxc-create and incus fetch as they create
        Kind::Lxc | Kind::Incus => Vec::new(),
        Kind::Pct => vec![run(&["skopeo", "copy", "--quiet", &docker_url, &format!("oci-archive:{}/var/lib/vz/template/cache/{NAME}-{}.tar", spec.root, digest12(&spec.image))])],
    }
}

/// The steps that make the container and start it. The caller removed any earlier one, and asked `unserved` first.
pub fn create(kind: Kind, spec: &Spec) -> Vec<Step> {
    let n = &spec.needs;
    match kind {
        Kind::Docker | Kind::Podman | Kind::PodmanRootless => {
            let mut argv = vec![kind.program().to_string()];
            argv.extend(container_args(kind, spec));
            vec![Step::Run { argv, as_agent: kind == Kind::PodmanRootless, note: None }]
        }
        Kind::Lxc => {
            let conf = format!("{}/lxc.conf", spec.ctl);
            let rootfs = format!("{}/var/lib/lxc/{NAME}/rootfs", spec.root);
            let mut steps = vec![
                Step::Write { path: conf.clone(), content: lxc_conf(spec) },
                run(&["lxc-create", "-n", NAME, "-f", &conf, "-t", "oci", "--", "--url", &format!("docker://{}", spec.image)]),
            ];
            // the root filesystem is read-only once it runs, so the places the host's paths are mounted at are made now
            for path in &n.mounts {
                steps.push(Step::Mkdir { path: format!("{rootfs}/host{}", path.trim_end_matches('/')) });
            }
            steps.push(run(&["lxc-start", "-n", NAME, "-d"]));
            steps
        }
        Kind::Incus => {
            let (registry, rest) = spec.image.split_once('/').unwrap_or(("", &spec.image));
            let idmap = format!("raw.idmap=uid {} {IMAGE_ID}\ngid {} {IMAGE_ID}", spec.uid, spec.gid);
            let mut steps = vec![
                Step::Run { argv: words(&["incus", "remote", "add", INCUS_REMOTE, &format!("https://{registry}"), "--protocol=oci"]), as_agent: false, note: Some("the registry was not added to Incus: it is known there already, or it could not be reached") },
                run(&[
                    "incus", "init", &format!("{INCUS_REMOTE}:{rest}"), NAME,
                    "-c", "security.privileged=false", "-c", "security.nesting=false", "-c", "security.idmap.isolated=true", "-c", "boot.autostart=true",
                    "-c", "limits.memory=256MiB", "-c", "limits.processes=256", "-c", &idmap,
                ]),
            ];
            let mut disks = vec![("sf-etc".to_string(), spec.etc.clone(), "/etc/storageforge-agent".to_string(), true), ("sf-manifest".to_string(), spec.manifest.clone(), "/var/lib/storageforge-agent/manifest".to_string(), true), ("sf-state".to_string(), spec.state.clone(), "/var/lib/storageforge-agent/state".to_string(), false)];
            for (i, path) in n.mounts.iter().enumerate() {
                disks.push((format!("sf-host{i}"), format!("{}{path}", spec.root), format!("/host{}", path.trim_end_matches('/')), true));
            }
            for (name, source, path, readonly) in disks {
                let mut argv = words(&["incus", "config", "device", "add", NAME, &name, "disk", &format!("source={source}"), &format!("path={path}"), "recursive=false"]);
                if readonly {
                    argv.push("readonly=true".into());
                }
                steps.push(Step::Run { argv, as_agent: false, note: None });
            }
            steps.push(run(&["incus", "start", NAME]));
            steps
        }
        Kind::Pct => {
            let vmid = spec.vmid.unwrap_or(0).to_string();
            let template = format!("local:vztmpl/{NAME}-{}.tar", digest12(&spec.image));
            let mut argv = words(&["pct", "create", &vmid, &template, "--hostname", NAME, "--unprivileged", "1", "--features", "nesting=0", "--onboot", "1", "--memory", "256", "--swap", "0"]);
            let mut points = vec![(spec.etc.clone(), "/etc/storageforge-agent".to_string(), true), (spec.manifest.clone(), "/var/lib/storageforge-agent/manifest".to_string(), true), (spec.state.clone(), "/var/lib/storageforge-agent/state".to_string(), false)];
            for path in &n.mounts {
                points.push((format!("{}{path}", spec.root), format!("/host{}", path.trim_end_matches('/')), true));
            }
            for (i, (source, path, readonly)) in points.iter().enumerate() {
                argv.extend([format!("--mp{i}"), format!("{source},mp={path}{}", if *readonly { ",ro=1" } else { "" })]);
            }
            let mut steps = vec![
                // Proxmox VE lets root map one id of the host into a container only when /etc/subuid says so
                Step::Append { path: format!("{}/etc/subuid", spec.root), line: format!("root:{}:1", spec.uid) },
                Step::Append { path: format!("{}/etc/subgid", spec.root), line: format!("root:{}:1", spec.gid) },
                Step::Run { argv, as_agent: false, note: None },
            ];
            for line in pct_idmap(spec) {
                steps.push(Step::Append { path: format!("{}/etc/pve/lxc/{vmid}.conf", spec.root), line });
            }
            steps.push(run(&["pct", "start", &vmid]));
            steps
        }
    }
}

/// The steps that stop the container so that nothing starts it again: not its restart policy, and not a reboot.
pub fn stop(kind: Kind, spec: &Spec) -> Vec<Step> {
    let vmid = spec.vmid.unwrap_or(0).to_string();
    let quiet = |argv: &[&str], as_agent: bool| Step::Run { argv: words(argv), as_agent, note: Some("") };
    match kind {
        Kind::Docker => vec![quiet(&["docker", "update", "--restart", "no", NAME], false), quiet(&["docker", "stop", "-t", "10", NAME], false)],
        // Podman starts a container with a restart policy again at boot, so a stopped agent's container is removed. Its state
        // folder on the host stays.
        Kind::Podman | Kind::PodmanRootless => {
            let as_agent = kind == Kind::PodmanRootless;
            vec![quiet(&["podman", "stop", "-t", "10", NAME], as_agent), quiet(&["podman", "rm", "-f", NAME], as_agent)]
        }
        Kind::Lxc => vec![Step::Append { path: format!("{}/var/lib/lxc/{NAME}/config", spec.root), line: "lxc.start.auto = 0".into() }, quiet(&["lxc-stop", "-n", NAME, "-k"], false)],
        Kind::Incus => vec![quiet(&["incus", "config", "set", NAME, "boot.autostart=false"], false), quiet(&["incus", "stop", "--force", NAME], false)],
        Kind::Pct => vec![quiet(&["pct", "set", &vmid, "--onboot", "0"], false), quiet(&["pct", "stop", &vmid], false)],
    }
}

/// The steps that remove the container. Each may fail: there may be none.
pub fn remove(kind: Kind, spec: &Spec) -> Vec<Step> {
    let vmid = spec.vmid.unwrap_or(0).to_string();
    let quiet = |argv: &[&str], as_agent: bool| Step::Run { argv: words(argv), as_agent, note: Some("") };
    match kind {
        Kind::Docker => vec![quiet(&["docker", "rm", "-f", NAME], false)],
        Kind::Podman => vec![quiet(&["podman", "rm", "-f", NAME], false)],
        Kind::PodmanRootless => vec![quiet(&["podman", "rm", "-f", NAME], true)],
        Kind::Lxc => vec![quiet(&["lxc-stop", "-n", NAME, "-k"], false), quiet(&["lxc-destroy", "-n", NAME, "-f"], false)],
        Kind::Incus => vec![quiet(&["incus", "delete", "--force", NAME], false)],
        Kind::Pct => vec![quiet(&["pct", "stop", &vmid], false), quiet(&["pct", "destroy", &vmid, "--purge", "1"], false)],
    }
}

/// The command whose output says whether the container runs, and whether it is run as `sfagent`.
pub fn state_command(kind: Kind, spec: &Spec) -> (Vec<String>, bool) {
    let vmid = spec.vmid.unwrap_or(0).to_string();
    match kind {
        Kind::Docker => (words(&["docker", "inspect", "--format", "{{.State.Running}} {{.Image}}", NAME]), false),
        Kind::Podman => (words(&["podman", "inspect", "--format", "{{.State.Running}} {{.Image}}", NAME]), false),
        Kind::PodmanRootless => (words(&["podman", "inspect", "--format", "{{.State.Running}} {{.Image}}", NAME]), true),
        Kind::Lxc => (words(&["lxc-info", "-n", NAME, "-s", "-H"]), false),
        Kind::Incus => (words(&["incus", "list", &format!("^{NAME}$"), "-f", "csv", "-c", "s"]), false),
        Kind::Pct => (words(&["pct", "status", &vmid]), false),
    }
}

/// What `state_command` printed, read: whether the container runs, and the image's id where the runtime says it.
pub fn read_state(kind: Kind, ok: bool, output: &str) -> (bool, Option<String>) {
    let text = output.trim();
    if !ok || text.len() > 400 {
        return (false, None);
    }
    match kind {
        Kind::Docker | Kind::Podman | Kind::PodmanRootless => {
            let mut parts = text.split(' ');
            let running = parts.next() == Some("true");
            let image = parts.next().filter(|i| i.len() <= 80 && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':')).map(str::to_string);
            (running, image)
        }
        Kind::Lxc | Kind::Incus => (text.eq_ignore_ascii_case("running"), None),
        Kind::Pct => (text == "status: running", None),
    }
}

/// Docker's major version, from what `docker --version` prints ("Docker version 29.1.0, build ...").
pub fn docker_major(output: &str) -> Option<u32> {
    let version = output.strip_prefix("Docker version ")?;
    version.split('.').next()?.parse().ok().filter(|major| (1..1000).contains(major))
}

/// The command that installs Podman with the host's own package manager, for a host that has no runtime. `have` says which
/// package managers are there.
pub fn install_podman(have: &dyn Fn(&str) -> bool) -> Option<(Vec<String>, Vec<(&'static str, &'static str)>)> {
    let none = Vec::new();
    if have("apt-get") {
        Some((words(&["apt-get", "install", "-y", "--no-install-recommends", "podman", "uidmap"]), vec![("DEBIAN_FRONTEND", "noninteractive")]))
    } else if have("dnf") {
        Some((words(&["dnf", "install", "-y", "podman"]), none))
    } else if have("zypper") {
        Some((words(&["zypper", "--non-interactive", "install", "podman"]), none))
    } else if have("pacman") {
        Some((words(&["pacman", "-S", "--noconfirm", "--needed", "podman"]), none))
    } else if have("apk") {
        Some((words(&["apk", "add", "--no-cache", "podman"]), none))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::tests::IMAGE;

    fn spec(needs: &str) -> Spec {
        Spec {
            image: IMAGE.into(),
            uid: 987,
            gid: 985,
            etc: "/etc/storageforge-agent".into(),
            manifest: "/var/lib/storageforge-agent/manifest".into(),
            state: "/var/lib/storageforge-agent/state".into(),
            ctl: "/var/lib/storageforge-agent/ctl".into(),
            needs: serde_json::from_str(needs).unwrap(),
            subuid: Some(1_000_000),
            subgid: Some(1_000_000),
            vmid: Some(912),
            ..Spec::default()
        }
    }

    fn has(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    fn all_argv(steps: &[Step]) -> String {
        steps.iter().map(|s| match s {
            Step::Run { argv, .. } => argv.join(" "),
            Step::Write { path, content } => format!("WRITE {path}\n{content}"),
            Step::Append { path, line } => format!("APPEND {path} {line}"),
            Step::Mkdir { path } => format!("MKDIR {path}"),
        }).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn a_tunnel_gives_the_container_the_way_to_the_controller_and_no_other() {
        let to: std::net::SocketAddr = "192.0.2.10:7843".parse().unwrap();
        let mut s = spec("{}");
        s.tunnel = Some(to);
        assert!(has(&container_args(Kind::Docker, &s), "--network", NETWORK), "its own bridge");
        assert!(has(&container_args(Kind::Podman, &s), "--network", NETWORK));
        assert!(has(&container_args(Kind::PodmanRootless, &s), "--network", "pasta"), "a user-mode network, every connection made as sfagent");
        assert!(has(&container_args(Kind::Docker, &spec("{}")), "--network", "none"), "no tunnel, no network");
        let rules = egress_rules(987, to);
        for line in [
            "meta skuid 987 ip daddr 192.0.2.10 tcp dport 7843 accept",
            "meta skuid 987 counter drop",
            "iifname \"sfagent0\" ip daddr 192.0.2.10 tcp dport 7843 accept",
            "iifname \"sfagent0\" counter drop",
            "type filter hook input",
            "delete table inet storageforge_agent",
        ] {
            assert!(rules.contains(line), "{line}\n{rules}");
        }
        assert!(egress_rules(987, "[2001:db8::1]:7843".parse().unwrap()).contains("ip6 daddr 2001:db8::1 tcp dport 7843 accept"));
        // the rule is loaded before anything else, and a failure to load it stops the steps
        let steps = egress(&s, to);
        assert!(matches!(&steps[1], Step::Run { argv, note: None, .. } if argv[0] == "nft"), "{steps:?}");
        assert!(all_argv(&steps).contains("ExecStart=/usr/sbin/nft -f /var/lib/storageforge-agent/ctl/egress.nft"));
        // LXC has no network of its own for the agent yet: the tunnel is refused there, with the reason
        for kind in [Kind::Lxc, Kind::Incus, Kind::Pct] {
            assert_eq!(unserved(kind, &s).map(|u| u.code), Some("runtime-cannot"), "{kind:?}");
        }
        assert_eq!(unserved(Kind::Docker, &s), None);
    }

    #[test]
    fn the_least_that_works_is_chosen() {
        let basic = Needs::default();
        let disks: Needs = serde_json::from_str(r#"{"capabilities":["SYS_RAWIO"],"devices":["disks"]}"#).unwrap();
        let t = |docker, podman, lxc, incus, pct| Tools { docker, podman, lxc, incus, pct };
        assert_eq!(choose(&t(true, true, true, false, false), &basic), Ok(Kind::PodmanRootless));
        assert_eq!(choose(&t(true, false, true, false, false), &basic), Ok(Kind::Docker));
        assert_eq!(choose(&t(true, true, false, false, false), &disks), Ok(Kind::Docker));
        assert_eq!(choose(&t(false, true, false, false, false), &disks), Ok(Kind::Podman));
        // a Proxmox VE host has pct and the lxc tools, and neither Docker nor Podman: LXC through pct, and Podman is never asked for
        assert_eq!(choose(&t(false, false, true, false, true), &basic), Ok(Kind::Pct));
        assert_eq!(choose(&t(false, false, true, true, false), &basic), Ok(Kind::Incus));
        assert_eq!(choose(&t(false, false, true, false, false), &basic), Ok(Kind::Lxc));
        assert_eq!(choose(&t(false, false, true, false, true), &disks).unwrap_err().code, "runtime-cannot");
        assert_eq!(choose(&Tools::default(), &basic).unwrap_err().code, "no-runtime");
        for kind in [Kind::Docker, Kind::PodmanRootless, Kind::Podman, Kind::Lxc, Kind::Incus, Kind::Pct] {
            assert_eq!(Kind::parse(kind.name()), Some(kind));
        }
        assert_eq!(Kind::parse("containerd"), None);
    }

    #[test]
    fn a_docker_container_has_nothing_it_was_not_given() {
        let a = container_args(Kind::Docker, &spec("{}"));
        for (flag, value) in [("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"), ("--user", "987:985"), ("--network", "none"), ("--restart", "unless-stopped")] {
            assert!(has(&a, flag, value), "{flag} {value}: {a:?}");
        }
        assert!(a.contains(&"--read-only".to_string()));
        assert_eq!(&a[a.len() - 2..], [IMAGE.to_string(), "run".to_string()]);
        let text = a.join(" ");
        for never in ["--privileged", "docker.sock", "--cap-add", "--pid ", "--device", "--group-add", "/host", "SYS_ADMIN", "seccomp=unconfined", "apparmor=unconfined"] {
            assert!(!text.contains(never), "{never}: {text}");
        }
        // the one folder it can write is its own state
        let writable: Vec<&String> = a.iter().filter(|x| x.starts_with("type=bind") && !x.contains("readonly")).collect();
        assert_eq!(writable, ["type=bind,src=/var/lib/storageforge-agent/state,dst=/var/lib/storageforge-agent/state"]);
    }

    #[test]
    fn privileges_are_the_declared_ones_and_mounts_are_read_only_and_masked() {
        let mut s = spec(r#"{"mounts":["/","/proc"],"capabilities":["SYS_ADMIN"],"devices":["disks"],"namespaces":["net","pid"],"groups":["systemd-journal"]}"#);
        s.mask_dirs = vec!["/root/.ssh".into()];
        s.mask_files = vec!["/etc/shadow".into()];
        s.group_ids = vec![980];
        s.devices = vec!["/dev/sda".into()];
        let a = container_args(Kind::Docker, &s);
        for (flag, value) in [
            ("--cap-add", "SYS_ADMIN"), ("--network", "host"), ("--pid", "host"), ("--group-add", "980"), ("--device", "/dev/sda:/dev/sda:r"),
            ("--mount", "type=bind,src=/,dst=/host,readonly,bind-recursive=disabled"),
            ("--mount", "type=bind,src=/proc,dst=/host/proc,readonly,bind-recursive=disabled"),
            ("--tmpfs", "/host/root/.ssh:ro,size=4k,mode=000"),
            ("--mount", "type=bind,src=/dev/null,dst=/host/etc/shadow,readonly"),
            ("--cap-drop", "ALL"), ("--user", "987:985"),
        ] {
            assert!(has(&a, flag, value), "{flag} {value}: {a:?}");
        }
        assert_eq!(a.iter().filter(|x| *x == "--cap-add").count(), 1);
        assert!(a.contains(&"--read-only".to_string()));
        // a Docker from before 25 knows the option by its old name only
        s.docker_major = docker_major("Docker version 24.0.7, build afdd53b");
        assert!(has(&container_args(Kind::Docker, &s), "--mount", "type=bind,src=/,dst=/host,readonly,bind-nonrecursive=true"));
        assert_eq!(docker_major("Docker version 29.10.0, build 1a2b3c"), Some(29));
        assert_eq!(docker_major("podman version 5.0.0"), None);
        assert_eq!(docker_major("Docker version x"), None);
    }

    #[test]
    fn podman_without_root_runs_as_sfagent_and_takes_no_privilege() {
        let s = spec(r#"{"mounts":["/var/log/journal"],"groups":["systemd-journal"]}"#);
        let steps = create(Kind::PodmanRootless, &s);
        let [Step::Run { argv, as_agent: true, note: None }] = &steps[..] else { panic!("{steps:?}") };
        assert_eq!(argv[0], "podman");
        for (flag, value) in [("--userns", "keep-id"), ("--group-add", "keep-groups"), ("--cap-drop", "ALL"), ("--user", "987:985"), ("--restart", "always"), ("--mount", "type=bind,src=/var/log/journal,dst=/host/var/log/journal,ro,bind-nonrecursive")] {
            assert!(has(argv, flag, value), "{flag} {value}: {argv:?}");
        }
        assert!(unserved(Kind::PodmanRootless, &spec(r#"{"capabilities":["SYS_RAWIO"]}"#)).is_some());
        assert!(matches!(&pull(Kind::PodmanRootless, &s)[..], [Step::Run { as_agent: true, .. }]));
    }

    #[test]
    fn an_lxc_container_is_unprivileged_read_only_and_without_nesting() {
        let mut s = spec(r#"{"mounts":["/etc","/proc"],"namespaces":["pid"]}"#);
        s.mask_dirs = vec!["/etc/sudoers.d".into()];
        s.mask_files = vec!["/etc/shadow".into()];
        s.seccomp = Some("/usr/share/lxc/config/common.seccomp".into());
        assert_eq!(unserved(Kind::Lxc, &s), None);
        let text = all_argv(&create(Kind::Lxc, &s));
        for must in [
            "lxc.idmap = u 0 1000000 10003", "lxc.idmap = u 10003 987 1", "lxc.idmap = u 10004 1010004 55532", "lxc.idmap = g 10003 985 1",
            "lxc.rootfs.options = ro", "lxc.cap.keep = none", "lxc.no_new_privs = 1", "lxc.apparmor.allow_nesting = 0", "lxc.apparmor.profile = generated",
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp", "lxc.net.0.type = empty", "lxc.namespace.keep = pid", "lxc.init.uid = 10003",
            "lxc.mount.entry = /etc host/etc none bind,ro 0 0", "lxc.mount.entry = tmpfs host/etc/sudoers.d tmpfs ro,size=4k,mode=000 0 0",
            "lxc.mount.entry = /dev/null host/etc/shadow none bind,ro 0 0",
            &format!("lxc-create -n storageforge-agent -f /var/lib/storageforge-agent/ctl/lxc.conf -t oci -- --url docker://{IMAGE}"),
            "MKDIR /var/lib/lxc/storageforge-agent/rootfs/host/etc", "lxc-start -n storageforge-agent -d",
        ] {
            assert!(text.contains(must), "{must}\n{text}");
        }
        for never in ["rbind", "lxc.cap.drop", "nesting = 1", "unconfined", "lxc.net.0.type = veth"] {
            assert!(!text.contains(never), "{never}");
        }
        // every lxc.mount.entry is read-only but the state folder and /tmp
        let writable: Vec<&str> = text.lines().filter(|l| l.starts_with("lxc.mount.entry") && !l.contains("bind,ro") && !l.contains(" ro,")).collect();
        assert_eq!(writable.len(), 2, "{writable:?}");
        // without a range for root in /etc/subuid there is no unprivileged container, and no privileged one is made instead
        s.subuid = None;
        assert!(unserved(Kind::Lxc, &s).unwrap().why.contains("/etc/subuid"));
    }

    #[test]
    fn incus_and_proxmox_make_it_unprivileged_and_say_what_they_cannot_serve() {
        let s = spec(r#"{"mounts":["/srv/data"]}"#);
        let incus = all_argv(&create(Kind::Incus, &s));
        for must in [
            "incus remote add storageforge-agent-registry https://registry.example --protocol=oci",
            "incus init storageforge-agent-registry:storageforge-agent@sha256:", "security.privileged=false", "security.nesting=false", "security.idmap.isolated=true",
            "raw.idmap=uid 987 10003\ngid 985 10003",
            "incus config device add storageforge-agent sf-host0 disk source=/srv/data path=/host/srv/data recursive=false readonly=true",
            "incus config device add storageforge-agent sf-state disk source=/var/lib/storageforge-agent/state path=/var/lib/storageforge-agent/state recursive=false\n",
        ] {
            assert!(incus.contains(must), "{must}\n{incus}");
        }
        let pct = all_argv(&create(Kind::Pct, &s));
        for must in [
            "pct create 912 local:vztmpl/storageforge-agent-aaaaaaaaaaaa.tar --hostname storageforge-agent --unprivileged 1 --features nesting=0",
            "--mp0 /etc/storageforge-agent,mp=/etc/storageforge-agent,ro=1", "--mp2 /var/lib/storageforge-agent/state,mp=/var/lib/storageforge-agent/state --mp3", "--mp3 /srv/data,mp=/host/srv/data,ro=1",
            "APPEND /etc/subuid root:987:1", "APPEND /etc/pve/lxc/912.conf lxc.idmap: u 10003 987 1", "pct start 912",
        ] {
            assert!(pct.contains(must), "{must}\n{pct}");
        }
        assert!(all_argv(&pull(Kind::Pct, &s)).contains(&format!("skopeo copy --quiet docker://{IMAGE} oci-archive:/var/lib/vz/template/cache/storageforge-agent-aaaaaaaaaaaa.tar")));
        for text in [&incus, &pct] {
            for never in ["privileged=true", "--unprivileged 0", "nesting=1", "nesting=true"] {
                assert!(!text.contains(never), "{never}");
            }
        }
        // what they cannot give is said, not made some other way
        for kind in [Kind::Incus, Kind::Pct] {
            assert!(unserved(kind, &s).is_none());
            assert!(unserved(kind, &spec(r#"{"namespaces":["pid"]}"#)).unwrap().why.contains("cannot share"));
            assert!(unserved(kind, &spec(r#"{"groups":["systemd-journal"]}"#)).is_some());
            assert!(unserved(kind, &spec(r#"{"capabilities":["SYS_ADMIN"]}"#)).unwrap().why.contains("unprivileged"));
            let mut masked = spec(r#"{"mounts":["/etc"]}"#);
            masked.mask_files = vec!["/etc/shadow".into()];
            assert!(unserved(kind, &masked).unwrap().why.contains("cannot hide /etc/shadow"));
        }
        let mut no_number = s.clone();
        no_number.vmid = None;
        assert!(unserved(Kind::Pct, &no_number).is_some());
    }

    #[test]
    fn stopped_means_nothing_starts_it_again() {
        let s = spec("{}");
        assert!(all_argv(&stop(Kind::Docker, &s)).starts_with("docker update --restart no storageforge-agent\ndocker stop"));
        assert!(all_argv(&stop(Kind::PodmanRootless, &s)).contains("podman rm -f storageforge-agent"));
        assert!(all_argv(&stop(Kind::Lxc, &s)).contains("lxc.start.auto = 0"));
        assert!(all_argv(&stop(Kind::Incus, &s)).contains("boot.autostart=false"));
        assert!(all_argv(&stop(Kind::Pct, &s)).contains("pct set 912 --onboot 0"));
        assert_eq!(read_state(Kind::Docker, true, "true sha256:abc\n"), (true, Some("sha256:abc".into())));
        assert_eq!(read_state(Kind::Docker, true, "false sha256:abc\n"), (false, Some("sha256:abc".into())));
        assert_eq!(read_state(Kind::Docker, false, "true sha256:abc"), (false, None));
        assert_eq!(read_state(Kind::Lxc, true, "RUNNING\n").0, true);
        assert_eq!(read_state(Kind::Pct, true, "status: stopped\n").0, false);
        assert_eq!(read_state(Kind::Incus, true, "RUNNING").0, true);
    }

    #[test]
    fn podman_is_installed_with_the_hosts_own_package_manager() {
        assert_eq!(install_podman(&|tool| tool == "dnf").unwrap().0, ["dnf", "install", "-y", "podman"]);
        let (argv, env) = install_podman(&|tool| tool == "apt-get" || tool == "dnf").unwrap();
        assert_eq!(argv[0], "apt-get");
        assert_eq!(env, [("DEBIAN_FRONTEND", "noninteractive")]);
        assert!(install_podman(&|_| false).is_none());
    }
}
