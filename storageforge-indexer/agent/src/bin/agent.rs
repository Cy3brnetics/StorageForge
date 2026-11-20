//! storageforge-agent: the program in the agent's container (roadmap section 11.1).
//!
//!   storageforge-agent run        make the key on first start, then load and run the plugins the manifest names
//!   storageforge-agent check      one pass over the manifest and every plugin, as JSON; exit 0 only when nothing was refused
//!   storageforge-agent pubkey     the agent's public key
//!   storageforge-agent anchors    the release keys this program was built with
//!   storageforge-agent version
//!
//! It runs as `sfagent`, reads the host through read-only mounts, changes nothing on it, and at this stage opens no connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use storageforge_agent::supervise::{self, Ended, Outbox, Paths};
use storageforge_agent::{identity, plugin, sig, VERSION};

static STOP: AtomicBool = AtomicBool::new(false);

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
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(p)
}

fn run(paths: &Paths) -> i32 {
    if unsafe { libc::geteuid() } == 0 {
        log("refusing to run as root: the agent runs as sfagent".into());
        return 78;
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
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
    for name in &report.stray {
        // SEAM (11.3): a file nothing accounts for. Today it is said and not run; wipe and stop decides what else follows.
        log(format!("refused: {name} is in the plugin folder and no plugin of the manifest accounts for it"));
    }
    let outbox = Outbox::new(supervise::OUTBOX_RECORDS);
    let running = report.manifest.clone();
    std::thread::scope(|scope| {
        for plugin in &loaded {
            let outbox = &outbox;
            scope.spawn(move || {
                let mut wait = 5;
                while !STOP.load(Ordering::Relaxed) {
                    match supervise::serve(plugin, outbox, &STOP, &log) {
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
        // or privileges: the agent leaves, and the runtime starts it again with what is there now.
        // SEAM (11.2): Docker and Podman start it again; an LXC container whose one program left stays down. Today every change
        // comes through storageforge-agentctl, which makes the container anew, so nothing depends on that. Plugin files that
        // arrive through the tunnel will: load them in place here, or have storageforge-agentctl asked to restart.
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let (again, _) = supervise::inspect(paths, &key, supervise::now(), false);
            if again.manifest != running || again.problems != report.problems || again.stray != report.stray {
                log("the manifest or the plugin files changed: leaving, to be started again with what is there now".into());
                STOP.store(true, Ordering::Relaxed);
                std::process::exit(0);
            }
            // SEAM (11.2): the tunnel drains the outbox here. With no tunnel yet, what the plugins report is counted and let go.
            let waiting = outbox.drain(supervise::OUTBOX_RECORDS).len();
            if waiting > 0 {
                log(format!("{waiting} records from plugins, and no tunnel to send them through yet"));
            }
        }
    })
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
