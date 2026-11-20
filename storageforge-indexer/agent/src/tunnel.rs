//! The agent's tunnel to the controller (roadmap section 11.1, "Delivery", and 11.2).
//!
//! One TCP connection to the one address it was given, encrypted and authenticated both ways with Noise IK (`storageforge_wire::
//! noise`): the agent's static key is its own key, the ed25519 key it made at enrollment, used as X25519 (the same scalar, as `age`
//! uses SSH keys), and the controller's is the receiver's key, pinned on this host by storageforge-agentctl from a signed request.
//! The controller knows the agent by that key alone. The agent refuses a controller that does not hold the pinned key before it
//! says a word.
//!
//! ```text
//! /etc/storageforge-agent/tunnel   {"format":1,"endpoint":"192.0.2.10:7843","key":"<base64 of the receiver's X25519 key>"}
//!                                  root's, read-only to the agent: written only by storageforge-agentctl
//! state/batch.counter              the last batch counter used
//! ```
//!
//! What crosses it, as frames of JSON inside the Noise session:
//!
//! ```text
//! controller -> agent   (handshake answer) {"last_counter":N,"session_ends":T}
//! agent -> controller   {"op":"hello","version":V,"run":R,"claims":{...},"manifest":{"counter":C,"sha256":S}|null,"have":[plugins loaded]}
//! controller -> agent   {"op":"manifest","manifest":TEXT|null,"signature":TEXT|null}
//!                       {"op":"plugin","name":N,"descriptor":TEXT,"signature":TEXT}, {"op":"chunk","name":N,"data":B64}..., {"op":"plugin-end","name":N}
//!                       {"op":"ready"}
//! agent -> controller   {"op":"batch","body":TEXT,"signature":SSHSIG}     body: {"counter":N,"run":R,"sent":T,"dropped":D,"records":[...]}
//! controller -> agent   {"op":"ack","counter":N} or {"op":"refused","counter":N,"why":TEXT}
//! controller -> agent   {"op":"bye","why":TEXT}                             the session is over: dial again
//! ```
//!
//! What arrives is checked as everything else here is: the manifest against the controller's pinned signing key, each plugin
//! against its signer, the manifest and its program's hash, before a byte is written to the plugin folder. The tunnel carries no
//! command and no shell, and nothing that arrives through it is run unless it is a signed plugin of the manifest storageforge-
//! agentctl already accepted and made this container for. A manifest that is newer than that one is said and not used: the
//! privileges it takes come only through storageforge-agentctl, over SSH.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use storageforge_wire::noise::{self, NoiseError, Session};
use zeroize::Zeroizing;

use crate::identity::{read_small, write_whole};
use crate::manifest::{self, Manifest};
use crate::plugin;
use crate::runner;
use crate::sig;
use crate::supervise::{self, Outbox, Paths, Record, MANIFEST_FILE};

pub const PROLOGUE: &[u8] = b"storageforge-agent-tunnel-v1";
pub const TUNNEL_FILE: &str = "tunnel";
pub const COUNTER_FILE: &str = "batch.counter";
/// The most a batch's body may be, and the most records it holds.
pub const MAX_BATCH: usize = 512 << 10;
pub const MAX_RECORDS: usize = 512;
/// The most one frame from the controller may be.
pub const MAX_FROM_CONTROLLER: usize = 1 << 20;
/// How much of a program one chunk carries, before base64.
pub const CHUNK: usize = 512 << 10;
/// A batch goes at least this often, empty if there is nothing to say: silence is a signal on the other side.
pub const BEAT_SECS: u64 = 60;
/// How long the agent waits for an answer.
const ANSWER_SECS: u64 = 30;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format: u32,
    /// An address and a port: never a name, so that nothing is looked up and the host's firewall rule can name it.
    pub endpoint: String,
    /// The receiver's X25519 key, base64.
    pub key: String,
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<(Config, SocketAddr, [u8; 32]), String> {
        if bytes.len() > 1024 {
            return Err("the tunnel file is too large".into());
        }
        let c: Config = serde_json::from_slice(bytes).map_err(|e| format!("the tunnel file does not parse: {e}"))?;
        if c.format != 1 {
            return Err(format!("tunnel format {} is not read by this program", c.format));
        }
        let address: SocketAddr = c.endpoint.parse().map_err(|_| "the tunnel's endpoint is not an address and a port".to_string())?;
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err("the tunnel's endpoint is not an address that can be dialled".into());
        }
        let key: [u8; 32] = B64.decode(&c.key).ok().and_then(|k| k.try_into().ok()).ok_or("the tunnel's key is not 32 bytes of base64")?;
        Ok((c, address, key))
    }
}

/// The tunnel this host's agent was given, if any.
pub fn load_config(etc: &Path) -> Result<Option<(SocketAddr, [u8; 32])>, String> {
    match read_small(&etc.join(TUNNEL_FILE), 1024) {
        Ok(bytes) => Config::parse(&bytes).map(|(_, a, k)| Some((a, k))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read the tunnel file: {e}")),
    }
}

/// The agent's key as an X25519 secret: the scalar of its ed25519 key. The controller works out the matching public key from the
/// ed25519 key it pinned at enrollment, so nothing new has to be pinned.
pub fn static_secret(key: &SigningKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key.to_scalar_bytes())
}

pub fn static_public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_montgomery().to_bytes()
}

fn last_counter(state: &Path) -> u64 {
    read_small(&state.join(COUNTER_FILE), 32).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|t| t.trim().parse().ok()).unwrap_or(0)
}

/// A batch: the records, numbered by a counter that only goes up and is written down before the batch is sent, and signed.
#[derive(Debug, Clone)]
pub struct Batch {
    pub counter: u64,
    pub body: String,
    pub signature: String,
}

/// Makes the next batch from what the outbox holds. Records that do not fit go back to the front of the outbox; a single record
/// too large for any batch is dropped and counted there.
pub fn next_batch(state: &Path, key: &SigningKey, outbox: &Outbox, run: u64, floor: u64) -> Result<Batch, String> {
    let mut records = outbox.drain(MAX_RECORDS);
    let counter = last_counter(state).max(floor) + 1;
    loop {
        let body = json!({"counter": counter, "run": run, "sent": supervise::now(), "dropped": outbox.dropped(), "records": records}).to_string();
        if body.len() <= MAX_BATCH {
            write_whole(&state.join(COUNTER_FILE), format!("{counter}\n").as_bytes(), 0o600).map_err(|e| format!("cannot record the batch counter: {e}"))?;
            let signature = sig::sign(key, sig::NS_BATCH, body.as_bytes());
            return Ok(Batch { counter, body, signature });
        }
        if records.len() <= 1 {
            outbox.count_dropped(records.len() as u64);
            records.clear();
            continue;
        }
        let back = records.split_off(records.len() / 2);
        outbox.requeue(back);
    }
}

/// What the agent says of itself when a session starts. All of it is a claim, and the controller treats it as one.
fn hello(paths: &Paths, key: &SigningKey, run: u64) -> Value {
    let (report, loaded) = supervise::inspect(paths, key, supervise::now(), false);
    let machine = read_small(Path::new("/host/etc/machine-id"), 64).ok().and_then(|b| String::from_utf8(b).ok()).map(|t| t.trim().to_string()).filter(|t| manifest::is_machine(t));
    let have: Vec<String> = loaded.iter().map(|l| l.descriptor.name.clone()).collect();
    json!({
        "op": "hello", "version": crate::VERSION, "run": run,
        "claims": {"machine": machine, "problems": report.problems.len(), "stray": report.stray.len()},
        "manifest": report.counter.map(|c| json!({"counter": c, "sha256": report.manifest})),
        "have": have,
    })
}

/// How a delivered manifest stands against the one storageforge-agentctl accepted for this container.
#[derive(Debug, PartialEq, Eq)]
pub enum Standing {
    /// The very one in force: its plugins may be written.
    Current(Manifest),
    /// A later one: said, and not used until storageforge-agentctl makes the container for it.
    Newer(u64),
}

pub fn standing(paths: &Paths, key: &SigningKey, text: &str, signature: &str) -> Result<Standing, String> {
    let anchors = supervise::anchors(&paths.etc)?;
    let m = manifest::verify(text.as_bytes(), signature, &anchors.controller)?;
    if m.agent != sig::fingerprint(&key.verifying_key().to_bytes()) {
        return Err("the delivered manifest is for another agent's key".into());
    }
    let in_force = read_small(&paths.manifest.join(MANIFEST_FILE), manifest::MAX_MANIFEST).ok();
    match in_force {
        Some(bytes) if bytes == text.as_bytes() => Ok(Standing::Current(m)),
        Some(bytes) => {
            let theirs: Manifest = serde_json::from_slice(&bytes).map_err(|_| "the manifest in force does not parse".to_string())?;
            if m.counter > theirs.counter {
                Ok(Standing::Newer(m.counter))
            } else {
                Err(format!("the delivered manifest is an old one: its counter is {} and {} is in force", m.counter, theirs.counter))
            }
        }
        None => Ok(Standing::Newer(m.counter)),
    }
}

/// A plugin arriving: checked against the manifest in force and its signer before its program's first byte is taken.
struct Arriving {
    name: String,
    descriptor: String,
    signature: String,
    size: u64,
    sha256: String,
    hash: Sha256,
    program: Vec<u8>,
}

fn start_plugin(paths: &Paths, m: &Manifest, v: &Value) -> Result<Arriving, String> {
    let (Some(name), Some(descriptor), Some(signature)) = (v["name"].as_str(), v["descriptor"].as_str(), v["signature"].as_str()) else {
        return Err("a plugin came without its name, descriptor and signature".into());
    };
    let entry = m.plugins.iter().find(|e| e.name == name).ok_or_else(|| format!("plugin {}: not in the manifest in force", runner::plain(name)))?;
    let anchors = supervise::anchors(&paths.etc)?;
    let d = Manifest::admit_plugin(entry, descriptor.as_bytes(), signature, &anchors)?;
    if d.arch != plugin::this_arch() {
        return Err(format!("plugin {name}: built for {}", d.arch));
    }
    Ok(Arriving { name: name.to_string(), descriptor: descriptor.to_string(), signature: signature.to_string(), size: d.size, sha256: d.sha256, hash: Sha256::new(), program: Vec::new() })
}

/// Writes a plugin that arrived whole. None when the very same files are there already: then starting again would load nothing
/// new, and the agent goes on (the plugin was refused for another reason, which its log says).
fn finish_plugin(dir: &Path, a: Arriving) -> Result<Option<String>, String> {
    if a.program.len() as u64 != a.size {
        return Err(format!("plugin {}: the program that came is not the size its descriptor says", a.name));
    }
    let got: String = a.hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != a.sha256 {
        return Err(format!("plugin {}: the program that came is not the one that was signed", a.name));
    }
    let same = |file: String, bytes: &[u8]| read_small(&dir.join(file), plugin::MAX_PROGRAM as usize).is_ok_and(|have| have == bytes);
    if same(runner::descriptor_file(&a.name), a.descriptor.as_bytes()) && same(runner::signature_file(&a.name), a.signature.as_bytes()) && same(runner::program_file(&a.name), &a.program) {
        return Ok(None);
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make the plugin folder: {e}"))?;
    // the program first and the descriptor last: until all three are there, the plugin is refused as incomplete, never run half
    write_whole(&dir.join(runner::program_file(&a.name)), &a.program, 0o600)
        .and_then(|_| write_whole(&dir.join(runner::signature_file(&a.name)), a.signature.as_bytes(), 0o600))
        .and_then(|_| write_whole(&dir.join(runner::descriptor_file(&a.name)), a.descriptor.as_bytes(), 0o600))
        .map_err(|e| format!("cannot write plugin {}: {e}", a.name))?;
    Ok(Some(a.name))
}

/// How a session ended.
#[derive(Debug)]
pub enum Over {
    /// The agent is stopping.
    Stopped,
    /// Plugins of the manifest in force were written: the agent loads them by starting again.
    Reload(Vec<String>),
    /// The controller ended the session, or the connection broke; dial again.
    Again(String),
    /// The controller refused this agent, or sent what no honest controller sends.
    Refused(String),
}

fn send(session: &mut Session, conn: &mut TcpStream, v: &Value) -> Result<(), String> {
    session.write(conn, v.to_string().as_bytes()).map_err(|e| format!("the tunnel failed: {e}"))
}

fn receive(session: &mut Session, conn: &mut TcpStream) -> Result<Value, Over> {
    let frame = session.read(conn, MAX_FROM_CONTROLLER).map_err(|e| match e {
        NoiseError::Io(e) => Over::Again(format!("the connection ended: {e}")),
        other => Over::Refused(format!("the controller sent what it should not: {other}")),
    })?;
    match serde_json::from_slice::<Value>(&frame) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err(Over::Refused("the controller sent a frame that is not a JSON object".into())),
    }
}

/// The state that outlives a session: the batch that was sent and not answered yet is sent again, with the same counter and bytes.
pub struct Link {
    pub run: u64,
    pub pending: Option<Batch>,
}

impl Link {
    pub fn new() -> Link {
        let mut run = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut run);
        Link { run: u64::from_be_bytes(run) >> 1, pending: None }
    }
}

impl Default for Link {
    fn default() -> Self {
        Link::new()
    }
}

/// One session: dial, handshake, hello, take the delivery, then send batches until the session ends.
pub fn session(paths: &Paths, key: &SigningKey, address: SocketAddr, pinned: &[u8; 32], outbox: &Outbox, link: &mut Link, stop: &AtomicBool, log: &(dyn Fn(String) + Sync)) -> Over {
    let mut conn = match TcpStream::connect_timeout(&address, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => return Over::Again(format!("cannot reach the controller at {address}: {e}")),
    };
    let _ = conn.set_read_timeout(Some(Duration::from_secs(ANSWER_SECS)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(ANSWER_SECS)));
    let _ = conn.set_nodelay(true);
    let (mut s, welcome) = match noise::initiate(&mut conn, PROLOGUE, &static_secret(key), pinned, b"") {
        Ok(x) => x,
        Err(NoiseError::Io(e)) => return Over::Again(format!("the controller ended the handshake: {e}")),
        Err(e) => return Over::Refused(format!("the controller at {address} did not prove it holds the pinned key: {e}")),
    };
    let welcome: Value = serde_json::from_slice(&welcome).unwrap_or(Value::Null);
    let floor = welcome["last_counter"].as_u64().unwrap_or(0);
    if let Err(why) = send(&mut s, &mut conn, &hello(paths, key, link.run)) {
        return Over::Again(why);
    }
    // the delivery
    let mut in_force: Option<Manifest> = None;
    let mut arriving: Option<Arriving> = None;
    let mut written = Vec::new();
    loop {
        let v = match receive(&mut s, &mut conn) {
            Ok(v) => v,
            Err(over) => return over,
        };
        match v["op"].as_str().unwrap_or("") {
            "manifest" => match (v["manifest"].as_str(), v["signature"].as_str()) {
                (Some(text), Some(signature)) => match standing(paths, key, text, signature) {
                    Ok(Standing::Current(m)) => in_force = Some(m),
                    Ok(Standing::Newer(counter)) => log(format!("the controller has manifest {counter} for this host; it takes effect when storageforge-agentctl applies it")),
                    Err(why) => log(format!("refused the delivered manifest: {why}")),
                },
                _ => {}
            },
            "plugin" => {
                if arriving.is_some() {
                    return Over::Refused("a plugin began before the last one ended".into());
                }
                match in_force.as_ref().map(|m| start_plugin(paths, m, &v)) {
                    Some(Ok(a)) => arriving = Some(a),
                    Some(Err(why)) => return Over::Refused(format!("refused a delivered plugin: {why}")),
                    None => return Over::Refused("a plugin came with no manifest in force to name it".into()),
                }
            }
            "chunk" => {
                let Some(a) = arriving.as_mut().filter(|a| v["name"].as_str() == Some(a.name.as_str())) else {
                    return Over::Refused("a chunk of no plugin that is arriving".into());
                };
                let Some(data) = v["data"].as_str().and_then(|d| B64.decode(d).ok()).filter(|d| d.len() <= CHUNK) else {
                    return Over::Refused("a chunk that is not base64 of the size agreed".into());
                };
                if a.program.len() as u64 + data.len() as u64 > a.size {
                    return Over::Refused(format!("plugin {}: more bytes came than its descriptor says", a.name));
                }
                a.hash.update(&data);
                a.program.extend_from_slice(&data);
            }
            "plugin-end" => match arriving.take().filter(|a| v["name"].as_str() == Some(a.name.as_str())) {
                Some(a) => match finish_plugin(&paths.plugins(), a) {
                    Ok(Some(name)) => written.push(name),
                    Ok(None) => {}
                    Err(why) => return Over::Refused(why),
                },
                None => return Over::Refused("the end of no plugin that is arriving".into()),
            },
            "ready" if arriving.is_none() => break,
            "bye" => return Over::Again(format!("the controller ended the session: {}", runner::plain(v["why"].as_str().unwrap_or("")))),
            _ => return Over::Refused("the controller sent what this agent does not take while a session starts".into()),
        }
    }
    if !written.is_empty() {
        return Over::Reload(written);
    }
    // batches, until the session ends
    let mut last = Instant::now() - Duration::from_secs(BEAT_SECS);
    loop {
        if stop.load(Ordering::Relaxed) {
            return Over::Stopped;
        }
        if link.pending.is_none() {
            if outbox.is_empty() && last.elapsed() < Duration::from_secs(BEAT_SECS) {
                // waiting, and listening meanwhile: the controller may end the session, or the connection may break
                let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
                let peeked = conn.peek(&mut [0u8; 1]);
                let _ = conn.set_read_timeout(Some(Duration::from_secs(ANSWER_SECS)));
                match peeked {
                    Ok(0) => return Over::Again("the controller closed the connection".into()),
                    Ok(_) => {
                        let v = match receive(&mut s, &mut conn) {
                            Ok(v) => v,
                            Err(over) => return over,
                        };
                        return match v["op"].as_str() {
                            Some("bye") => Over::Again(format!("the controller ended the session: {}", runner::plain(v["why"].as_str().unwrap_or("")))),
                            _ => Over::Refused("the controller sent what this agent did not ask for".into()),
                        };
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    Err(e) => return Over::Again(format!("the connection failed: {e}")),
                }
            }
            match next_batch(&paths.state, key, outbox, link.run, floor) {
                Ok(b) => link.pending = Some(b),
                Err(why) => return Over::Refused(why),
            }
        }
        let b = link.pending.clone().expect("a batch is pending");
        if let Err(why) = send(&mut s, &mut conn, &json!({"op": "batch", "body": b.body, "signature": b.signature})) {
            return Over::Again(why);
        }
        last = Instant::now();
        let v = match receive(&mut s, &mut conn) {
            Ok(v) => v,
            Err(over) => return over,
        };
        match (v["op"].as_str().unwrap_or(""), v["counter"].as_u64()) {
            ("ack", Some(c)) if c == b.counter => link.pending = None,
            ("refused", Some(c)) if c == b.counter => {
                // not sent again: the controller said why, and the agent's log keeps it
                log(format!("the controller refused batch {c}: {}", runner::plain(v["why"].as_str().unwrap_or(""))));
                link.pending = None;
            }
            ("bye", _) => return Over::Again(format!("the controller ended the session: {}", runner::plain(v["why"].as_str().unwrap_or("")))),
            _ => return Over::Refused("the controller answered a batch with something else".into()),
        }
    }
}

/// Keeps the tunnel up until `stop`: a session, and when it ends another, waiting longer each time one fails at once. Returns the
/// names of plugins written, when the agent should start again to load them.
pub fn run(paths: &Paths, key: &SigningKey, address: SocketAddr, pinned: &[u8; 32], outbox: &Outbox, stop: &AtomicBool, log: &(dyn Fn(String) + Sync)) -> Vec<String> {
    let mut link = Link::new();
    let mut wait = 1u64;
    while !stop.load(Ordering::Relaxed) {
        let began = Instant::now();
        match session(paths, key, address, pinned, outbox, &mut link, stop, log) {
            Over::Stopped => break,
            Over::Reload(names) => return names,
            Over::Again(why) => log(why),
            Over::Refused(why) => {
                log(why);
                wait = wait.max(60);
            }
        }
        if began.elapsed() > Duration::from_secs(120) {
            wait = 1;
        }
        for _ in 0..wait * 2 {
            if stop.load(Ordering::Relaxed) {
                return Vec::new();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        wait = (wait * 2).min(300);
    }
    Vec::new()
}

/// The records of a batch body, as the controller reads them. Here so that both ends' tests read the same thing.
pub fn records_of(body: &str) -> Vec<Record> {
    serde_json::from_str::<Value>(body).ok().and_then(|v| v["records"].as_array().cloned()).unwrap_or_default().into_iter().filter_map(|r| {
        Some(Record { seq: r["seq"].as_u64()?, at: r["at"].as_u64()?, plugin: r["plugin"].as_str()?.to_string(), kind: r["kind"].as_str()?.to_string(), body: r["body"].clone() })
    }).collect()
}
