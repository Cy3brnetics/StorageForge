//! The agent against real files and a real plugin process: the manifest and the plugin files on disk, the plugin started from
//! the bytes that were checked, and everything 11.6 says must be refused, refused.
//!
//! The plugin is `examples/probe.rs`, built by cargo beside the tests. The plugins here are signed by an operator key, which a
//! host reads from a file; a release key is compiled in, and the controller's unit tests build the programs with one of their
//! own to cover that road (tests/test_agent.py).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use storageforge_agent::runner::{descriptor_file, program_file, signature_file};
use storageforge_agent::supervise::{self, Ended, Outbox, Paths};
use storageforge_agent::{identity, plugin, sig};

const IMAGE: &str = "registry.example/storageforge-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MACHINE: &str = "0123456789abcdef0123456789abcdef";

struct World {
    dir: PathBuf,
    paths: Paths,
    operator: SigningKey,
    controller: SigningKey,
    agent: SigningKey,
    probe: Vec<u8>,
}

fn probe_program() -> Vec<u8> {
    // cargo puts examples beside the programs it built for this test
    let path = Path::new(env!("CARGO_BIN_EXE_storageforge-agent")).parent().unwrap().join("examples").join("probe");
    std::fs::read(&path).unwrap_or_else(|e| panic!("the example plugin is not built at {}: {e}", path.display()))
}

fn signers_line(key: &SigningKey, namespaces: &str) -> String {
    format!("test namespaces=\"{namespaces}\" {}\n", sig::public_line(&key.verifying_key().to_bytes()))
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("sfagent-it-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths { etc: dir.join("etc"), manifest: dir.join("manifest"), state: dir.join("state") };
        for d in [&paths.etc, &paths.manifest, &paths.plugins()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (operator, controller) = (SigningKey::from_bytes(&[21; 32]), SigningKey::from_bytes(&[22; 32]));
        std::fs::write(paths.etc.join("operator_signers"), signers_line(&operator, sig::NS_PLUGIN)).unwrap();
        std::fs::write(paths.etc.join("controller_signers"), signers_line(&controller, "storageforge-agent-manifest,storageforge-agentctl")).unwrap();
        let agent = identity::generate(&paths.state).unwrap();
        World { dir, paths, operator, controller, agent, probe: probe_program() }
    }

    /// Puts a plugin's three files in the plugin folder, signed by `key`, and returns the manifest's entry for it.
    fn plugin(&self, name: &str, needs: &str, key: &SigningKey) -> String {
        let descriptor = format!(
            r#"{{"format":1,"name":"{name}","version":"0.5.7","arch":"{}","sha256":"{}","size":{},"protocol":1,"needs":{needs}}}"#,
            plugin::this_arch(),
            sig::sha256_hex(&self.probe),
            self.probe.len()
        );
        let dir = self.paths.plugins();
        std::fs::write(dir.join(descriptor_file(name)), &descriptor).unwrap();
        std::fs::write(dir.join(signature_file(name)), sig::sign(key, sig::NS_PLUGIN, descriptor.as_bytes())).unwrap();
        std::fs::write(dir.join(program_file(name)), &self.probe).unwrap();
        format!(r#"{{"name":"{name}","descriptor":"{}","signer":"operator","needs":{needs}}}"#, sig::sha256_hex(descriptor.as_bytes()))
    }

    fn manifest(&self, counter: u64, issued: u64, entries: &[String]) {
        let text = format!(
            r#"{{"format":1,"agent":"{}","machine":"{MACHINE}","counter":{counter},"issued":{issued},"image":"{IMAGE}","plugins":[{}]}}"#,
            sig::fingerprint(&self.agent.verifying_key().to_bytes()),
            entries.join(",")
        );
        std::fs::write(self.paths.manifest.join("manifest.json"), &text).unwrap();
        std::fs::write(self.paths.manifest.join("manifest.json.sig"), sig::sign(&self.controller, sig::NS_MANIFEST, text.as_bytes())).unwrap();
    }

    fn inspect(&self, record: bool) -> (supervise::Report, Vec<storageforge_agent::runner::Loaded>) {
        supervise::inspect(&self.paths, &self.agent, supervise::now(), record)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn file(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

#[test]
fn an_enrolled_agent_with_no_manifest_runs_nothing() {
    let w = World::new("idle");
    let (report, loaded) = w.inspect(true);
    assert!(report.problems.is_empty() && report.counter.is_none() && loaded.is_empty(), "{report:?}");
    // and a plugin put there with no manifest to name it is a stray file, not a plugin
    w.plugin("probe", "{}", &w.operator);
    let (report, loaded) = w.inspect(true);
    assert!(loaded.is_empty());
    assert_eq!(report.stray, ["probe.plugin", "probe.plugin.json", "probe.plugin.sig"]);
}

#[test]
fn a_signed_plugin_in_the_manifest_runs_with_nothing_it_did_not_declare() {
    let w = World::new("runs");
    let entry = w.plugin("probe", "{}", &w.operator);
    w.manifest(1, supervise::now(), &[entry]);
    let (report, loaded) = w.inspect(true);
    assert!(report.problems.is_empty() && report.stray.is_empty(), "{report:?}");
    assert_eq!((report.counter, loaded.len()), (Some(1), 1));
    // the program runs from the copy that was hashed: taking the file away, or changing it, changes nothing for what was loaded
    std::fs::write(file(&w.paths.plugins(), "probe.plugin"), b"#!/bin/sh\necho not the program\n").unwrap();
    let outbox = Outbox::new(16);
    let stop = AtomicBool::new(false);
    let lines = Mutex::new(Vec::new());
    let log = |line: String| lines.lock().unwrap().push(line);
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| supervise::serve(&loaded[0], &outbox, &stop, &log));
        for _ in 0..200 {
            if !outbox.is_empty() && lines.lock().unwrap().len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        // the plugin waits for the agent: told to stop, it ends, and so does serving it
        stop.store(true, Ordering::Relaxed);
        assert_eq!(serving.join().unwrap(), Ended::Stopped);
        let records = outbox.drain(16);
        assert_eq!(records.len(), 1, "{:?}", lines.lock().unwrap());
        let r = &records[0];
        assert_eq!((r.seq, r.plugin.as_str(), r.kind.as_str()), (1, "probe", "probe"));
        assert_eq!(r.body["env"], 0, "an empty environment");
        assert_eq!(r.body["args"], 1, "no arguments");
        assert_eq!(r.body["no_new_privs"], true);
        assert!(r.body["fds"].as_u64().unwrap() <= 4, "stdin, stdout, stderr and the folder being listed: {}", r.body["fds"]);
        assert_eq!(r.body["uid"], unsafe { libc::geteuid() }.to_string());
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("plugin probe: probe is up") && said.contains("plugin probe stderr: a line on stderr"), "{said}");
    });
}

#[test]
fn a_plugin_that_steps_outside_the_protocol_is_stopped() {
    let w = World::new("rude");
    let entries = [w.plugin("early", "{}", &w.operator), w.plugin("quit", "{}", &w.operator), w.plugin("rude", "{}", &w.operator)];
    w.manifest(1, supervise::now(), &entries);
    let (report, loaded) = w.inspect(true);
    assert_eq!(loaded.len(), 3, "{report:?}");
    let outbox = Outbox::new(16);
    let stop = AtomicBool::new(false);
    let log = |_: String| {};
    assert_eq!(supervise::serve(&loaded[0], &outbox, &stop, &log), Ended::Refused("a message before ready"));
    assert_eq!(supervise::serve(&loaded[1], &outbox, &stop, &log), Ended::Exited);
    assert_eq!(supervise::serve(&loaded[2], &outbox, &stop, &log), Ended::Refused("a message that is not ready, data or log"));
    assert!(outbox.is_empty(), "nothing a refused plugin said was kept");
}

#[test]
fn what_the_manifest_does_not_account_for_is_refused() {
    let w = World::new("refused");
    let now = supervise::now();
    let good = w.plugin("probe", "{}", &w.operator);
    let why = |w: &World| w.inspect(false).0.problems.join(" | ");

    // a plugin whose program changed after it was signed
    w.manifest(1, now, &[good.clone()]);
    assert!(w.inspect(false).0.problems.is_empty());
    let mut changed = w.probe.clone();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(file(&w.paths.plugins(), "probe.plugin"), &changed).unwrap();
    assert!(why(&w).contains("not the one that was signed"), "{}", why(&w));
    changed.push(0);
    std::fs::write(file(&w.paths.plugins(), "probe.plugin"), &changed).unwrap();
    assert!(why(&w).contains("not a plain file of the size"), "{}", why(&w));
    std::fs::write(file(&w.paths.plugins(), "probe.plugin"), &w.probe).unwrap();

    // a program that is a link to another file, even the same bytes
    std::fs::write(w.dir.join("elsewhere"), &w.probe).unwrap();
    std::fs::remove_file(file(&w.paths.plugins(), "probe.plugin")).unwrap();
    std::os::unix::fs::symlink(w.dir.join("elsewhere"), file(&w.paths.plugins(), "probe.plugin")).unwrap();
    assert!(why(&w).contains("not in the plugin folder as a plain file"), "{}", why(&w));
    std::fs::remove_file(file(&w.paths.plugins(), "probe.plugin")).unwrap();
    std::fs::write(file(&w.paths.plugins(), "probe.plugin"), &w.probe).unwrap();
    assert!(w.inspect(false).0.problems.is_empty());

    // an unsigned plugin, and one signed by a key this host does not trust for plugins: the controller's own
    std::fs::write(file(&w.paths.plugins(), "probe.plugin.sig"), "").unwrap();
    assert!(why(&w).contains("not signed by an operator key"), "{}", why(&w));
    let entry = w.plugin("probe", "{}", &w.controller);
    w.manifest(1, now, &[entry]);
    assert!(why(&w).contains("not signed by an operator key"), "{}", why(&w));

    // a plugin that is signed and is not in the manifest
    w.plugin("probe", "{}", &w.operator);
    w.plugin("extra", "{}", &w.operator);
    w.manifest(1, now, &[good.clone()]);
    let (report, loaded) = w.inspect(false);
    assert_eq!(loaded.len(), 1);
    assert_eq!(report.stray, ["extra.plugin", "extra.plugin.json", "extra.plugin.sig"]);

    // a manifest that gives a plugin more than its signed descriptor declares
    w.manifest(1, now, &[good.replace(r#""needs":{}"#, r#""needs":{"mounts":["/"]}"#)]);
    assert!(why(&w).contains("other privileges than its signed descriptor declares"), "{}", why(&w));

    // a manifest signed by the operator's key, by the agent's own, or not at all
    w.manifest(1, now, &[good.clone()]);
    let text = std::fs::read(w.paths.manifest.join("manifest.json")).unwrap();
    for key in [&w.operator, &w.agent] {
        std::fs::write(w.paths.manifest.join("manifest.json.sig"), sig::sign(key, sig::NS_MANIFEST, &text)).unwrap();
        assert!(why(&w).contains("not signed by this host's controller"), "{}", why(&w));
    }
    std::fs::remove_file(w.paths.manifest.join("manifest.json.sig")).unwrap();
    assert!(why(&w).contains("not signed by this host's controller"));

    // a manifest for another agent's key
    let other = World::new("refused-other");
    other.manifest(1, now, &[]);
    for name in ["manifest.json", "manifest.json.sig"] {
        std::fs::copy(other.paths.manifest.join(name), w.paths.manifest.join(name)).unwrap();
    }
    assert!(why(&w).contains("another agent's key"), "{}", why(&w));
}

#[test]
fn an_old_manifest_played_back_is_refused() {
    let w = World::new("replay");
    let now = supervise::now();
    let entry = w.plugin("probe", "{}", &w.operator);
    w.manifest(4, now, &[entry.clone()]);
    let old = (std::fs::read(w.paths.manifest.join("manifest.json")).unwrap(), std::fs::read(w.paths.manifest.join("manifest.json.sig")).unwrap());
    // looking does not record: only the running agent writes the counter down
    assert_eq!(w.inspect(false).0.counter, Some(4));
    assert!(!w.paths.state.join("manifest.seen").exists());
    assert_eq!(w.inspect(true).0.counter, Some(4));
    assert_eq!(w.inspect(true).0.counter, Some(4), "the same one again is a restart");
    w.manifest(5, now, &[]);
    assert_eq!(w.inspect(true).0.counter, Some(5));
    // the earlier manifest, with its good signature, put back
    std::fs::write(w.paths.manifest.join("manifest.json"), &old.0).unwrap();
    std::fs::write(w.paths.manifest.join("manifest.json.sig"), &old.1).unwrap();
    let (report, loaded) = w.inspect(true);
    assert!(loaded.is_empty() && report.counter.is_none());
    assert!(report.problems[0].contains("old one played back"), "{:?}", report.problems);
    // a later counter on a manifest that was signed long ago
    w.manifest(6, now - 3600, &[]);
    assert!(w.inspect(true).0.problems[0].contains("not signed a moment ago"));
    // and a record that was damaged is not taken for no record
    std::fs::write(w.paths.state.join("manifest.seen"), "garbage").unwrap();
    w.manifest(7, now, &[]);
    assert!(w.inspect(true).0.problems[0].contains("cannot be read"));
}
