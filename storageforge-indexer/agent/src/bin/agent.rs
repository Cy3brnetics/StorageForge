//! storageforge-agent: the program in the agent's container (roadmap section 11.1).
//!
//!   storageforge-agent run        make the key on first start, then load and run the plugins the manifest names
//!   storageforge-agent check      one pass over the manifest and every plugin, as JSON; exit 0 only when nothing was refused
//!
//! On anything that can only be tampering, at start or on its timer, it deletes its key and stops for good (roadmap 11.3,
//! `wipe.rs`), after giving its last word to the controller through the tunnel if it can.
//!   storageforge-agent pubkey     the agent's public key
//!   storageforge-agent anchors    the release keys this program was built with
//!   storageforge-agent version
//!
//! It runs as `sfagent`, reads the host through read-only mounts, changes nothing on it, and opens one connection: its tunnel to the
//! controller, to the one address storageforge-agentctl wrote in /etc/storageforge-agent/tunnel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;
use storageforge_agent::supervise::{self, Ended, Outbox, Paths};
use storageforge_agent::{identity, plugin, sig, tunnel, wipe, VERSION};

/// The tunnel stops with this; the plugins stop with it or with `PLUGINS_STOP`.
static STOP: AtomicBool = AtomicBool::new(false);
static PLUGINS_STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
/// `--as UID:GID`: the account to become when the container started this program as root to give its plugins capabilities (caps.rs).
static BECOME: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
/// How long a wiped agent waits for its last word to reach the controller before it exits.
const LAST_WORD_SECS: u64 = 20;

fn log(line: String) {
    eprintln!("storageforge-agent: {line}");
}

extern "C" fn on_signal(_: libc::c_int) {
    // As PID 1 of a container a signal with no handler is ignored, and `docker stop` would wait and then kill. Leaving at once
    // is all there is to do: the plugins die with the agent, and nothing here is half written (files are replaced whole).
    unsafe { libc::_exit(0) }
}

fn paths(args: &[String]) -> Result<Paths, String> {
    // The folders are fixed in the container. The flags are for the tests, and for looking at a copy of an agent's folders.
    let mut p = Paths::container();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a folder"))?;
        match flag.as_str() {
            "--etc" => p.etc = value.into(),
            "--manifest" => p.manifest = value.into(),
            "--state" => p.state = value.into(),
            "--host" => storageforge_agent::runner::set_host_root(value),
            "--as" => {
                let (uid, gid) = value.split_once(':').ok_or("--as takes UID:GID")?;
                let ids = (uid.parse::<u32>().map_err(|_| "--as takes UID:GID")?, gid.parse::<u32>().map_err(|_| "--as takes UID:GID")?);
                let _ = BECOME.set(ids);
            }
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(p)
}

/// Ends this agent's access (roadmap 11.3): the plugins are stopped, the key and the plugin files deleted and why written down, the
/// last word put in the outbox for the tunnel, and after it was answered, or `LAST_WORD_SECS`, the agent exits for good.
fn wipe_and_exit(paths: &Paths, why: &[String], outbox: &Outbox, tunnel_up: bool) -> ! {
    PLUGINS_STOP.store(true, Ordering::Relaxed);
    for reason in why {
        log(format!("tampering: {reason}"));
    }
    match wipe::wipe(&paths.state, why, supervise::now()) {
        Ok(()) => log("the agent's key is deleted and it stops for good: only a new enrollment, by an admin, makes another agent here".into()),
        Err(e) => log(format!("wiping did not finish ({e}); the agent stops for good all the same")),
    }
    if tunnel_up {
        let reasons: Vec<String> = why.iter().take(20).map(|w| storageforge_agent::runner::plain(w)).collect();
        outbox.push(plugin::AGENT_NAME, "wipe".into(), json!({"why": reasons}), supervise::now());
        tunnel::LAST_WORD.store(true, Ordering::Relaxed);
        for _ in 0..LAST_WORD_SECS * 4 {
            if tunnel::SAID.load(Ordering::Relaxed) {
                log("the controller has the agent's last word".into());
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    std::process::exit(wipe::EXIT_WIPED);
}

fn run(paths: &Paths) -> i32 {
    if unsafe { libc::geteuid() } == 0 {
        // Started as root only so that the declared capabilities can be kept (caps.rs): root is given up first, before anything
        // is read. Started as root without being told whom to become, it refuses.
        let Some(&(uid, gid)) = BECOME.get() else {
            log("refusing to run as root: the agent runs as sfagent".into());
            return 78;
        };
        match storageforge_agent::caps::become_agent(uid, gid) {
            Ok(kept) => log(format!("gave up root for {uid}:{gid}, keeping for its plugins: {}", if kept.is_empty() { "nothing".to_string() } else { kept.join(", ") })),
            Err(why) => {
                log(format!("refusing to run: {why}"));
                return 78;
            }
        }
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
    // a wiped agent makes no new key and runs nothing, whatever starts it again
    if let Some(said) = wipe::wiped(&paths.state) {
        log(format!("this agent was wiped and does not start again: {said}"));
        return wipe::EXIT_WIPED;
    }
    let program = wipe::own_program();
    let key = match identity::load_or_generate(&paths.state) {
        Ok(key) => key,
        Err(why) => {
            log(why);
            return 78;
        }
    };
    let _ = std::fs::create_dir(paths.plugins());
    let (report, loaded) = supervise::inspect(paths, &key, supervise::now(), true);
    log(format!("version {VERSION}, key {}", report.agent));
    match report.counter {
        Some(counter) => log(format!("manifest {counter}: {} of {} plugins loaded", loaded.len(), report.plugins.len())),
        None if report.problems.is_empty() => log("no manifest yet: enrolled, and nothing to run".into()),
        None => {}
    }
    for problem in &report.problems {
        log(format!("refused: {problem}"));
    }
    let tunnel = match tunnel::load_config(&paths.etc) {
        Ok(t) => t,
        Err(why) => {
            log(format!("no tunnel: {why}"));
            None
        }
    };
    if tunnel.is_none() {
        log("no tunnel to the controller is set up for this agent: what the plugins report is counted and let go".into());
    }
    let outbox = Outbox::new(supervise::OUTBOX_RECORDS);
    let running = report.manifest.clone();
    std::thread::scope(|scope| {
        // The tunnel: batches of what the plugins report go out, the manifest and the plugin files come in. Plugin files of the
        // manifest in force that arrive are loaded by starting the agent again, in place. It starts first, so that an agent that
        // finds tampering at once can still say so before it goes.
        let delivered = tunnel.map(|(address, pinned)| {
            let (outbox, key) = (&outbox, &key);
            scope.spawn(move || {
                let names = tunnel::run(paths, key, address, &pinned, outbox, &STOP, &log);
                if !names.is_empty() {
                    log(format!("plugins delivered through the tunnel: {}; starting again to load them", names.join(", ")));
                    RELOAD.store(true, Ordering::Relaxed);
                }
            })
        });
        let _ = delivered;
        if !report.tamper.is_empty() {
            wipe_and_exit(paths, &report.tamper, &outbox, tunnel.is_some());
        }
        for plugin in &loaded {
            let outbox = &outbox;
            scope.spawn(move || {
                let mut wait = 5;
                while !STOP.load(Ordering::Relaxed) && !PLUGINS_STOP.load(Ordering::Relaxed) {
                    match supervise::serve(plugin, outbox, &PLUGINS_STOP, &log) {
                        Ended::Stopped => return,
                        Ended::Exited => log(format!("plugin {} ended; starting it again in {wait} s", plugin.descriptor.name)),
                        Ended::Failed(why) => log(format!("{why}; trying again in {wait} s")),
                        Ended::Refused(why) => {
                            // it stepped outside the protocol: not started again until the agent is, by a person or a new manifest
                            log(format!("plugin {} was stopped for good: it sent {why}", plugin.descriptor.name));
                            return;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(wait));
                    wait = (wait * 2).min(300);
                }
            });
        }
        // The manifest and the plugin files are checked again on a timer. A manifest that changed means another set of plugins
        // or privileges: the agent starts again with what is there now. It starts itself again in place, so that this holds under
        // every runtime, LXC included, whose container stays down when its one program leaves.
        loop {
            for _ in 0..60 {
                std::thread::sleep(Duration::from_millis(500));
                if RELOAD.load(Ordering::Relaxed) {
                    restart();
                }
            }
            let (again, _) = supervise::inspect(paths, &key, supervise::now(), false);
            let mut tamper = again.tamper.clone();
            if program.is_some() && wipe::own_program() != program {
                tamper.push("the agent's own program changed while it ran".into());
            }
            if !tamper.is_empty() {
                wipe_and_exit(paths, &tamper, &outbox, tunnel.is_some());
            }
            if again.manifest != running || again.problems != report.problems || again.stray != report.stray {
                log("the manifest or the plugin files changed: starting again with what is there now".into());
                restart();
            }
            if tunnel.is_none() {
                let waiting = outbox.drain(supervise::OUTBOX_RECORDS).len();
                if waiting > 0 {
                    log(format!("{waiting} records from plugins, and no tunnel to send them through"));
                }
            }
        }
    })
}

/// Starts this program again in place, with the same arguments: the plugins die with the old image (their parent-death signal),
/// and everything is checked again from the start.
fn restart() -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("/proc/self/exe").args(std::env::args_os().skip(1)).exec();
    log(format!("cannot start again in place ({err}): leaving, for the runtime to start the agent again"));
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("");
    let paths = match paths(args.get(1..).unwrap_or(&[])) {
        Ok(p) => p,
        Err(why) => {
            eprintln!("storageforge-agent: {why}");
            std::process::exit(2);
        }
    };
    let code = match command {
        "run" => run(&paths),
        "check" => match identity::load(&paths.state) {
            Ok(Some(key)) => {
                let (report, _) = supervise::inspect(&paths, &key, supervise::now(), false);
                println!("{}", serde_json::to_string(&report).unwrap_or_default());
                i32::from(!(report.problems.is_empty() && report.stray.is_empty()))
            }
            Ok(None) => {
                eprintln!("storageforge-agent: no key yet: the agent has not started once");
                1
            }
            Err(why) => {
                eprintln!("storageforge-agent: {why}");
                1
            }
        },
        "pubkey" => match identity::load(&paths.state) {
            Ok(Some(key)) => {
                println!("{} storageforge-agent", sig::public_line(&key.verifying_key().to_bytes()));
                0
            }
            _ => {
                eprintln!("storageforge-agent: no key yet");
                1
            }
        },
        "anchors" => {
            let release = plugin::release_signers();
            if release.is_empty() {
                println!("no release key: this program was built to trust none, and runs no official plugin");
            }
            for signer in &release.0 {
                println!("release {} {} {}", signer.name, sig::fingerprint(&signer.key), signer.namespaces.join(","));
            }
            0
        }
        "version" => {
            println!("storageforge-agent {VERSION}");
            0
        }
        _ => {
            eprintln!("usage: storageforge-agent run|check|pubkey|anchors|version");
            2
        }
    };
    std::process::exit(code);
}
