//! The agent's tunnel against a controller written here in Rust, over real TCP: the handshake with both keys pinned, the delivery
//! of the manifest and of plugin files and everything about them that must be refused, and batches with their counter and their
//! signature. The controller's own receiver, in Python, meets the real agent in tests/test_agent_tunnel.py.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use storageforge_agent::runner::{descriptor_file, program_file, signature_file};
use storageforge_agent::supervise::{Outbox, Paths};
use storageforge_agent::tunnel::{self, Link, Over};
use storageforge_agent::{identity, plugin, sig};
use storageforge_wire::noise::{self, Session};

const IMAGE: &str = "registry.example/storageforge-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MACHINE: &str = "0123456789abcdef0123456789abcdef";

struct World {
    dir: PathBuf,
    paths: Paths,
    operator: SigningKey,
    controller: SigningKey,
    agent: SigningKey,
    receiver: [u8; 32],
    probe: Vec<u8>,
}

fn probe_program() -> Vec<u8> {
    let path = Path::new(env!("CARGO_BIN_EXE_storageforge-agent")).parent().unwrap().join("examples").join("probe");
    std::fs::read(&path).unwrap_or_else(|e| panic!("the example plugin is not built at {}: {e}", path.display()))
}

fn signers_line(key: &SigningKey, namespaces: &str) -> String {
    format!("test namespaces=\"{namespaces}\" {}\n", sig::public_line(&key.verifying_key().to_bytes()))
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("sfagent-tunnel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths { etc: dir.join("etc"), manifest: dir.join("manifest"), state: dir.join("state") };
        for d in [&paths.etc, &paths.manifest, &paths.plugins()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (operator, controller) = (SigningKey::from_bytes(&[31; 32]), SigningKey::from_bytes(&[32; 32]));
        std::fs::write(paths.etc.join("operator_signers"), signers_line(&operator, sig::NS_PLUGIN)).unwrap();
        std::fs::write(paths.etc.join("controller_signers"), signers_line(&controller, "storageforge-agent-manifest,storageforge-agentctl")).unwrap();
        let agent = identity::generate(&paths.state).unwrap();
        World { dir, paths, operator, controller, agent, receiver: [33; 32], probe: probe_program() }
    }

    fn descriptor(&self, name: &str, program: &[u8]) -> String {
        format!(
            r#"{{"format":1,"name":"{name}","version":"0.5.7","arch":"{}","sha256":"{}","size":{},"protocol":1,"needs":{{}}}}"#,
            plugin::this_arch(),
            sig::sha256_hex(program),
            program.len()
        )
    }

    fn entry(descriptor: &str, name: &str) -> String {
        format!(r#"{{"name":"{name}","descriptor":"{}","signer":"operator","needs":{{}}}}"#, sig::sha256_hex(descriptor.as_bytes()))
    }

    fn manifest_text(&self, counter: u64, entries: &[String]) -> (String, String) {
        let text = format!(
            r#"{{"format":1,"agent":"{}","machine":"{MACHINE}","counter":{counter},"issued":{},"image":"{IMAGE}","plugins":[{}]}}"#,
            sig::fingerprint(&self.agent.verifying_key().to_bytes()),
            storageforge_agent::supervise::now(),
            entries.join(",")
        );
        let signature = sig::sign(&self.controller, sig::NS_MANIFEST, text.as_bytes());
        (text, signature)
    }

    /// Puts a manifest in force, as storageforge-agentctl would.
    fn in_force(&self, text: &str, signature: &str) {
        std::fs::write(self.paths.manifest.join("manifest.json"), text).unwrap();
        std::fs::write(self.paths.manifest.join("manifest.json.sig"), signature).unwrap();
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A controller for one connection: the handshake as the receiver, then `script` with the session.
fn controller(receiver: [u8; 32], agent_pub: [u8; 32], script: impl FnOnce(&mut Session, &mut TcpStream) + Send + 'static) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_secs(20))).unwrap();
        let Ok((mut s, _)) = noise::respond(&mut conn, tunnel::PROLOGUE, &receiver, |k| *k == agent_pub, |_, _| json!({"last_counter": 0}).to_string().into_bytes()) else { return };
        script(&mut s, &mut conn);
    });
    (address, handle)
}

fn read(s: &mut Session, conn: &mut TcpStream) -> Value {
    serde_json::from_slice(&s.read(conn, 1 << 20).unwrap()).unwrap()
}

fn write(s: &mut Session, conn: &mut TcpStream, v: Value) {
    s.write(conn, v.to_string().as_bytes()).unwrap();
}

fn send_plugin(s: &mut Session, conn: &mut TcpStream, name: &str, descriptor: &str, signature: &str, program: &[u8]) {
    write(s, conn, json!({"op": "plugin", "name": name, "descriptor": descriptor, "signature": signature}));
    for chunk in program.chunks(tunnel::CHUNK) {
        write(s, conn, json!({"op": "chunk", "name": name, "data": B64.encode(chunk)}));
    }
    write(s, conn, json!({"op": "plugin-end", "name": name}));
}

fn session(w: &World, address: SocketAddr, outbox: &Outbox, link: &mut Link) -> (Over, Vec<String>) {
    let lines = Mutex::new(Vec::new());
    let log = |line: String| lines.lock().unwrap().push(line);
    let stop = AtomicBool::new(false);
    let over = tunnel::session(&w.paths, &w.agent, address, &noise::public_of(&w.receiver), outbox, link, &stop, &log);
    (over, lines.into_inner().unwrap())
}

#[test]
fn plugins_of_the_manifest_in_force_arrive_checked_and_the_agent_starts_again_for_them() {
    let w = World::new("deliver");
    let descriptor = w.descriptor("probe", &w.probe);
    let signature = sig::sign(&w.operator, sig::NS_PLUGIN, descriptor.as_bytes());
    let (text, msig) = w.manifest_text(3, &[World::entry(&descriptor, "probe")]);
    w.in_force(&text, &msig);
    let (d, s2, p, t, m) = (descriptor.clone(), signature.clone(), w.probe.clone(), text.clone(), msig.clone());
    let (address, server) = controller(w.receiver, tunnel::static_public(&w.agent), move |s, conn| {
        let hello = read(s, conn);
        assert_eq!(hello["op"], "hello");
        assert_eq!(hello["manifest"]["counter"], 3, "the agent says which manifest it runs");
        assert_eq!(hello["have"], json!([]), "and that it has no plugin loaded yet");
        write(s, conn, json!({"op": "manifest", "manifest": t, "signature": m}));
        send_plugin(s, conn, "probe", &d, &s2, &p);
        write(s, conn, json!({"op": "ready"}));
    });
    let outbox = Outbox::new(16);
    let (over, lines) = session(&w, address, &outbox, &mut Link::new());
    server.join().unwrap();
    assert!(matches!(&over, Over::Reload(names) if names == &["probe".to_string()]), "{over:?} {lines:?}");
    let dir = w.paths.plugins();
    assert_eq!(std::fs::read(dir.join(program_file("probe"))).unwrap(), w.probe);
    assert_eq!(std::fs::read_to_string(dir.join(descriptor_file("probe"))).unwrap(), descriptor);
    assert_eq!(std::fs::read_to_string(dir.join(signature_file("probe"))).unwrap(), signature);
    let (report, loaded) = storageforge_agent::supervise::inspect(&w.paths, &w.agent, storageforge_agent::supervise::now(), true);
    assert!(report.problems.is_empty(), "{report:?}");
    assert_eq!(loaded.len(), 1, "what arrived is what loads");
}

#[test]
fn what_does_not_match_the_manifest_or_its_signer_is_not_written() {
    let w = World::new("refuse");
    let descriptor = w.descriptor("probe", &w.probe);
    let good = sig::sign(&w.operator, sig::NS_PLUGIN, descriptor.as_bytes());
    let (text, msig) = w.manifest_text(3, &[World::entry(&descriptor, "probe")]);
    w.in_force(&text, &msig);
    let other_descriptor = w.descriptor("other", &w.probe);
    let other_sig = sig::sign(&w.operator, sig::NS_PLUGIN, other_descriptor.as_bytes());
    let mut changed = w.probe.clone();
    changed[100] ^= 1;
    let by_controller = sig::sign(&w.controller, sig::NS_PLUGIN, descriptor.as_bytes());
    let cases: Vec<(&str, String, String, Vec<u8>)> = vec![
        ("a plugin the manifest does not name", other_descriptor, other_sig, w.probe.clone()),
        ("a program that is not the one signed", descriptor.clone(), good.clone(), changed),
        ("a descriptor signed by the controller, which signs no code", descriptor.clone(), by_controller, w.probe.clone()),
        ("more bytes than the descriptor says", descriptor.clone(), good.clone(), [w.probe.clone(), b"extra".to_vec()].concat()),
    ];
    for (what, d, s, p) in cases {
        let name = serde_json::from_str::<Value>(&d).unwrap()["name"].as_str().unwrap().to_string();
        let (t, m) = (text.clone(), msig.clone());
        let (address, server) = controller(w.receiver, tunnel::static_public(&w.agent), move |sess, conn| {
            read(sess, conn);
            write(sess, conn, json!({"op": "manifest", "manifest": t, "signature": m}));
            write(sess, conn, json!({"op": "plugin", "name": name, "descriptor": d, "signature": s}));
            for chunk in p.chunks(tunnel::CHUNK) {
                if sess.write(conn, json!({"op": "chunk", "name": name, "data": B64.encode(chunk)}).to_string().as_bytes()).is_err() {
                    return;
                }
            }
            let _ = sess.write(conn, json!({"op": "plugin-end", "name": name}).to_string().as_bytes());
            let _ = sess.write(conn, json!({"op": "ready"}).to_string().as_bytes());
        });
        let (over, _) = session(&w, address, &Outbox::new(4), &mut Link::new());
        server.join().unwrap();
        assert!(matches!(over, Over::Refused(_)), "{what}: {over:?}");
        assert_eq!(std::fs::read_dir(w.paths.plugins()).unwrap().count(), 0, "{what}: nothing was written");
    }
}

#[test]
fn a_newer_manifest_is_said_and_takes_nothing_and_an_older_one_is_refused() {
    let w = World::new("newer");
    let descriptor = w.descriptor("probe", &w.probe);
    let signature = sig::sign(&w.operator, sig::NS_PLUGIN, descriptor.as_bytes());
    let (in_force, sig_in_force) = w.manifest_text(5, &[]);
    w.in_force(&in_force, &sig_in_force);
    for (counter, says) in [(6, "takes effect when storageforge-agentctl applies it"), (4, "an old one")] {
        let (text, msig) = w.manifest_text(counter, &[World::entry(&descriptor, "probe")]);
        let (d, s) = (descriptor.clone(), signature.clone());
        let p = w.probe.clone();
        let (address, server) = controller(w.receiver, tunnel::static_public(&w.agent), move |sess, conn| {
            read(sess, conn);
            write(sess, conn, json!({"op": "manifest", "manifest": text, "signature": msig}));
            // its plugin: refused, since the manifest in force does not name it and the newer one is not in force
            let _ = sess.write(conn, json!({"op": "plugin", "name": "probe", "descriptor": d, "signature": s}).to_string().as_bytes());
            let _ = p;
        });
        let (over, lines) = session(&w, address, &Outbox::new(4), &mut Link::new());
        server.join().unwrap();
        assert!(lines.iter().any(|l| l.contains(says)), "{counter}: {lines:?}");
        assert!(matches!(over, Over::Refused(_)), "{over:?}");
        assert_eq!(std::fs::read_dir(w.paths.plugins()).unwrap().count(), 0);
    }
}

#[test]
fn a_controller_without_the_pinned_key_hears_nothing() {
    let w = World::new("impostor");
    let (address, server) = controller([44; 32], tunnel::static_public(&w.agent), |_, _| panic!("no session with the wrong key"));
    let (over, _) = session(&w, address, &Outbox::new(4), &mut Link::new());
    server.join().unwrap();
    // whoever sits at the address without the key cannot make the second message: the agent hears only a hang-up, and says nothing
    assert!(matches!(over, Over::Again(ref why) if why.contains("handshake")), "{over:?}");
}

#[test]
fn batches_are_signed_counted_and_sent_again_until_answered() {
    let w = World::new("batches");
    let agent_key = w.agent.verifying_key().to_bytes();
    let outbox = Outbox::new(16);
    for n in 0..3 {
        outbox.push("probe", "reading".into(), json!({"n": n}), 100 + n);
    }
    let mut link = Link::new();
    // the first controller takes the batch and never answers: the connection ends
    let (address, server) = controller(w.receiver, tunnel::static_public(&w.agent), move |s, conn| {
        read(s, conn);
        write(s, conn, json!({"op": "manifest", "manifest": null, "signature": null}));
        write(s, conn, json!({"op": "ready"}));
        let batch = read(s, conn);
        assert_eq!(batch["op"], "batch");
    });
    let (over, _) = session(&w, address, &outbox, &mut link);
    server.join().unwrap();
    assert!(matches!(over, Over::Again(_)), "{over:?}");
    let first = link.pending.clone().expect("the unanswered batch is kept");
    assert_eq!(first.counter, 1);
    assert_eq!(std::fs::read_to_string(w.paths.state.join(tunnel::COUNTER_FILE)).unwrap().trim(), "1", "written down before it was sent");
    // the next one gets the same batch, with the same counter and bytes, and answers it; then an empty one follows
    let body = first.body.clone();
    let (address, server) = controller(w.receiver, tunnel::static_public(&w.agent), move |s, conn| {
        read(s, conn);
        write(s, conn, json!({"op": "ready"}));
        let again = read(s, conn);
        assert_eq!(again["body"].as_str().unwrap(), body, "the same bytes again");
        let signers = sig::Signers(vec![sig::Signer { name: "agent".into(), namespaces: vec![sig::NS_BATCH.into()], key: agent_key }]);
        sig::verify(&signers, sig::NS_BATCH, body.as_bytes(), again["signature"].as_str().unwrap()).expect("signed with the agent's key");
        let records = tunnel::records_of(&body);
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2, 3]);
        write(s, conn, json!({"op": "ack", "counter": 1}));
        // the agent is waiting for more to say, and hears the session end at once
        write(s, conn, json!({"op": "bye", "why": "the session is over"}));
    });
    let (over, _) = session(&w, address, &outbox, &mut link);
    server.join().unwrap();
    assert!(matches!(over, Over::Again(ref why) if why.contains("session is over")), "{over:?}");
    assert!(link.pending.is_none());
}

#[test]
fn the_counter_never_goes_below_what_the_controller_last_took() {
    let w = World::new("floor");
    let outbox = Outbox::new(4);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (receiver, agent_pub) = (w.receiver, tunnel::static_public(&w.agent));
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let (mut s, _) = noise::respond(&mut conn, tunnel::PROLOGUE, &receiver, |k| *k == agent_pub, |_, _| json!({"last_counter": 41}).to_string().into_bytes()).unwrap();
        read(&mut s, &mut conn);
        write(&mut s, &mut conn, json!({"op": "ready"}));
        let batch = read(&mut s, &mut conn);
        let body: Value = serde_json::from_str(batch["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["counter"], 42, "an agent whose own count was lost goes on above the controller's");
    });
    let (over, _) = session(&w, address, &outbox, &mut Link::new());
    server.join().unwrap();
    assert!(matches!(over, Over::Again(_)), "{over:?}");
}

#[test]
fn the_tunnel_file_names_an_address_never_a_name() {
    assert!(tunnel::Config::parse(format!(r#"{{"format":1,"endpoint":"192.0.2.10:7843","key":"{}"}}"#, B64.encode([1u8; 32])).as_bytes()).is_ok());
    for bad in [
        format!(r#"{{"format":1,"endpoint":"forge.example:7843","key":"{}"}}"#, B64.encode([1u8; 32])),
        format!(r#"{{"format":1,"endpoint":"0.0.0.0:7843","key":"{}"}}"#, B64.encode([1u8; 32])),
        format!(r#"{{"format":1,"endpoint":"192.0.2.10:0","key":"{}"}}"#, B64.encode([1u8; 32])),
        r#"{"format":1,"endpoint":"192.0.2.10:7843","key":"c2hvcnQ="}"#.to_string(),
        format!(r#"{{"format":1,"endpoint":"192.0.2.10:7843","key":"{}","shell":"/bin/sh"}}"#, B64.encode([1u8; 32])),
    ] {
        assert!(tunnel::Config::parse(bad.as_bytes()).is_err(), "{bad}");
    }
}
