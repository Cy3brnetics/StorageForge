//! What the agent does with itself: reads its manifest, loads the plugins it names, runs them, and keeps what they report.
//!
//! This is the part of the agent that exists at this stage (roadmap section 11.1). It opens no socket and no connection: there is
//! no tunnel yet, so nothing leaves the host through the agent. The seams for what comes next are marked `SEAM`:
//!
//! - **11.2, the tunnel and the receiver.** `Outbox::drain` hands over what the plugins reported, each record numbered and
//!   labelled by the agent with the plugin it came from. The tunnel signs batches of them with the agent's key (`sig::NS_BATCH`)
//!   and sends them; nothing else should read the outbox. Plugin files arrive through the tunnel into `Paths::plugins`.
//! - **11.3, wipe and stop.** `inspect` returns everything that does not match the manifest (`Report::problems`, `Report::
//!   stray`). Today the agent refuses the plugin and says so; 11.3 decides when that also means deleting the key and exiting.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;

use crate::identity::{read_small, write_whole};
use crate::manifest::{self, Admitted, Seen};
use crate::plugin::{self, Anchors};
use crate::runner::{self, Hangup, Loaded, Message, Rate};
use crate::sig::{self, Signers};

pub const CONTROLLER_SIGNERS: &str = "controller_signers";
pub const OPERATOR_SIGNERS: &str = "operator_signers";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_SIGNATURE: &str = "manifest.json.sig";
pub const SEEN_FILE: &str = "manifest.seen";
/// How many records the outbox holds before the oldest are dropped, and counted.
pub const OUTBOX_RECORDS: usize = 4096;

/// Where the agent's files are. In the container these are fixed; the tests point them elsewhere.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Read-only, root's: the controller's key pinned at enrollment, and the operator's own plugin keys if any.
    pub etc: PathBuf,
    /// Read-only, root's: the manifest storageforge-agentctl accepted and made the container for.
    pub manifest: PathBuf,
    /// The agent's own: its key, the last counter it accepted, the plugin files.
    pub state: PathBuf,
}

impl Paths {
    pub fn container() -> Paths {
        Paths { etc: "/etc/storageforge-agent".into(), manifest: "/var/lib/storageforge-agent/manifest".into(), state: "/var/lib/storageforge-agent/state".into() }
    }

    pub fn plugins(&self) -> PathBuf {
        self.state.join("plugins")
    }
}

/// The keys this agent trusts: the release keys it was built with, and what is pinned on this host.
pub fn anchors(etc: &Path) -> Result<Anchors, String> {
    let file = |name: &str, needed: bool| -> Result<Signers, String> {
        match read_small(&etc.join(name), sig::MAX_SIGNERS) {
            Ok(bytes) => Signers::parse(std::str::from_utf8(&bytes).map_err(|_| format!("{name} is not text"))?).map_err(|why| format!("{name}: {why}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !needed => Ok(Signers::default()),
            Err(e) => Err(format!("cannot read {name}: {e}")),
        }
    };
    Ok(Anchors { release: plugin::release_signers(), operator: file(OPERATOR_SIGNERS, false)?, controller: file(CONTROLLER_SIGNERS, true)? })
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PluginState {
    pub name: String,
    pub version: Option<String>,
    pub loaded: bool,
    /// Why it was refused, when it was.
    pub why: Option<String>,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The fingerprint of this agent's key.
    pub agent: String,
    /// The counter of the manifest in use, or none when there is no manifest yet or it was refused.
    pub counter: Option<u64>,
    /// The sha256 of the manifest in use.
    pub manifest: Option<String>,
    pub plugins: Vec<PluginState>,
    /// Files in the plugin folder that no plugin of the manifest accounts for.
    pub stray: Vec<String>,
    /// Everything that was refused, in words.
    pub problems: Vec<String>,
}

fn stray_files(dir: &Path, names: &[String]) -> Vec<String> {
    let mut known = Vec::new();
    for name in names {
        known.extend([runner::descriptor_file(name), runner::signature_file(name), runner::program_file(name)]);
    }
    let mut out: Vec<String> = match std::fs::read_dir(dir) {
        Ok(entries) => entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|name| !known.contains(name)).map(|name| runner::plain(&name)).collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out.truncate(100);
    out
}

/// One pass over everything the agent would run: the manifest and every plugin it names, each checked in full. With `record`
/// the counter of a newly accepted manifest is written down, so that an older one is refused from then on.
pub fn inspect(paths: &Paths, key: &SigningKey, now: u64, record: bool) -> (Report, Vec<Loaded>) {
    let mut report = Report { agent: sig::fingerprint(&key.verifying_key().to_bytes()), ..Report::default() };
    let mut loaded = Vec::new();
    let plugins_dir = paths.plugins();
    let anchors = match anchors(&paths.etc) {
        Ok(a) => a,
        Err(why) => {
            report.problems.push(why);
            return (report, loaded);
        }
    };
    let bytes = match read_small(&paths.manifest.join(MANIFEST_FILE), manifest::MAX_MANIFEST) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // no manifest yet: the agent was enrolled and has been given nothing to run. Any plugin file is one too many.
            report.stray = stray_files(&plugins_dir, &[]);
            return (report, loaded);
        }
        Err(e) => {
            report.problems.push(format!("cannot read the manifest: {e}"));
            return (report, loaded);
        }
    };
    let signature = read_small(&paths.manifest.join(MANIFEST_SIGNATURE), sig::MAX_SIGNATURE).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
    let m = match manifest::verify(&bytes, &signature, &anchors.controller) {
        Ok(m) => m,
        Err(why) => {
            report.problems.push(why);
            return (report, loaded);
        }
    };
    if m.agent != report.agent {
        report.problems.push("the manifest is for another agent's key".into());
        return (report, loaded);
    }
    let digest = sig::sha256_hex(&bytes);
    let seen_path = paths.state.join(SEEN_FILE);
    let seen = match read_small(&seen_path, 100) {
        Ok(text) => match std::str::from_utf8(&text).ok().and_then(Seen::parse) {
            Some(seen) => Some(seen),
            None => {
                // a record that cannot be read is not "no record": that would let any old manifest in
                report.problems.push("the record of the last manifest accepted cannot be read".into());
                return (report, loaded);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            report.problems.push(format!("cannot read the record of the last manifest accepted: {e}"));
            return (report, loaded);
        }
    };
    match manifest::admit(&m, &digest, seen.as_ref(), now) {
        Ok(Admitted::Same) => {}
        Ok(Admitted::New) => {
            if record {
                if let Err(e) = write_whole(&seen_path, Seen { counter: m.counter, sha256: digest.clone() }.line().as_bytes(), 0o600) {
                    report.problems.push(format!("cannot record the manifest's counter: {e}"));
                    return (report, loaded);
                }
            }
        }
        Err(why) => {
            report.problems.push(why);
            return (report, loaded);
        }
    }
    report.counter = Some(m.counter);
    report.manifest = Some(digest);
    for entry in &m.plugins {
        match runner::load(&plugins_dir, entry, &anchors) {
            Ok(l) => {
                report.plugins.push(PluginState { name: entry.name.clone(), version: Some(l.descriptor.version.clone()), loaded: true, why: None });
                loaded.push(l);
            }
            Err(why) => {
                report.problems.push(why.clone());
                report.plugins.push(PluginState { name: entry.name.clone(), version: None, loaded: false, why: Some(why) });
            }
        }
    }
    report.stray = stray_files(&plugins_dir, &m.plugins.iter().map(|e| e.name.clone()).collect::<Vec<_>>());
    (report, loaded)
}

/// One thing a plugin reported. `plugin` is which child's pipe it came from, as the agent knows it, never a name the plugin gave.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub at: u64,
    pub plugin: String,
    pub kind: String,
    pub body: Value,
}

struct Queue {
    records: VecDeque<Record>,
    next: u64,
    dropped: u64,
}

/// What the plugins reported and nothing has sent yet. Bounded: when it is full the oldest record goes, and is counted.
pub struct Outbox {
    queue: Mutex<Queue>,
    most: usize,
}

impl Outbox {
    pub fn new(most: usize) -> Outbox {
        Outbox { queue: Mutex::new(Queue { records: VecDeque::new(), next: 1, dropped: 0 }), most: most.max(1) }
    }

    pub fn push(&self, plugin: &str, kind: String, body: Value, at: u64) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let seq = q.next;
        q.next += 1;
        if q.records.len() >= self.most {
            q.records.pop_front();
            q.dropped += 1;
        }
        q.records.push_back(Record { seq, at, plugin: plugin.to_string(), kind, body });
    }

    /// SEAM (11.2): the tunnel takes up to `most` records to sign and send. A gap in `seq` on the other side is what was dropped.
    pub fn drain(&self, most: usize) -> Vec<Record> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let n = most.min(q.records.len());
        q.records.drain(..n).collect()
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).dropped
    }
}

/// How one run of a plugin ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited, or closed its pipe.
    Exited,
    /// It sent what no honest plugin sends, or too much, and was killed.
    Refused(&'static str),
    /// The agent is stopping.
    Stopped,
    /// It could not be started.
    Failed(String),
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Runs a loaded plugin until it ends: says hello, takes what it reports into `outbox`, and kills it the moment it steps outside
/// the protocol. `log` gets lines for the agent's own log.
pub fn serve(loaded: &Loaded, outbox: &Outbox, stop: &AtomicBool, log: &(dyn Fn(String) + Sync)) -> Ended {
    let name = loaded.descriptor.name.clone();
    let mut child = match runner::spawn(loaded) {
        Ok(child) => child,
        Err(e) => return Ended::Failed(format!("plugin {name} could not be started: {e}")),
    };
    let (Some(mut stdin), Some(mut stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Ended::Failed(format!("plugin {name} has no pipes"));
    };
    let pid = child.id() as libc::pid_t;
    let done = AtomicBool::new(false);
    let ended = std::thread::scope(|scope| {
        // what it writes to stderr goes to the log, a line at a time and not without end
        scope.spawn(|| {
            for line in BufReader::new(stderr).split(b'\n').take(1000).flatten() {
                log(format!("plugin {name} stderr: {}", runner::plain(&String::from_utf8_lossy(&line))));
            }
        });
        if runner::send(&mut stdin, &runner::hello(&name)).is_err() {
            let _ = child.kill();
            return Ended::Exited;
        }
        // The agent stopping: the plugin is told, given a second, and killed. Reading below then ends on the closed pipe.
        scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if stop.load(Ordering::Relaxed) {
                    let _ = runner::send(&mut stdin, br#"{"op":"stop"}"#);
                    for _ in 0..10 {
                        if done.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    // still this process's child and not yet waited for, so the pid is its own
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        let mut rate = Rate::new();
        let mut ready = false;
        let ended = loop {
            let message = runner::read_message(&mut stdout);
            if stop.load(Ordering::Relaxed) {
                break Ended::Stopped;
            }
            match message {
                Err(Hangup::Closed) => break Ended::Exited,
                Err(Hangup::Refused(why)) => break Ended::Refused(why),
                Ok(_) if !rate.allow(now()) => break Ended::Refused("more messages in a minute than a plugin may send"),
                Ok(Message::Ready) if !ready => ready = true,
                Ok(Message::Ready) => break Ended::Refused("ready said twice"),
                Ok(_) if !ready => break Ended::Refused("a message before ready"),
                Ok(Message::Log(text)) => log(format!("plugin {name}: {text}")),
                Ok(Message::Data { kind, body }) => outbox.push(&name, kind, body, now()),
            }
        };
        // killed here, inside the scope: the thread reading its stderr ends only when the plugin does
        let _ = child.kill();
        done.store(true, Ordering::Relaxed);
        ended
    });
    let _ = child.wait();
    ended
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_outbox_numbers_everything_and_drops_the_oldest_when_full() {
        let outbox = Outbox::new(3);
        for n in 0..5 {
            outbox.push("heartbeat", "beat".into(), json!({"n": n}), 100 + n);
        }
        assert_eq!((outbox.len(), outbox.dropped()), (3, 2));
        let got = outbox.drain(2);
        assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), [3, 4], "the gap before 3 is what was dropped");
        assert_eq!(got[0].plugin, "heartbeat");
        assert_eq!(outbox.drain(10).len(), 1);
        assert!(outbox.is_empty());
    }
}
