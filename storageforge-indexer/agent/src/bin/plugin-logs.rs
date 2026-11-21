//! The logs plugin (roadmap sections 11.4 and 3, phase 2): the host's journal, pushed line by line as it is written.
//!
//! Declares the journal's folders and /etc/machine-id, read-only, and reads as the `systemd-journal` group. It reads the journal
//! files itself (`journal.rs`): the agent's image holds no journalctl.
//!
//! Where it starts: where it left off in this run of the agent (the agent's hello), or else where the controller says it has the
//! host's lines up to (the receiver's `resume`, after the agent started again, after a reboot say), or, when the controller has
//! none, with what is written from now on: an SSH scan has collected what came before.
//!
//! What it sends: `lines` readings, each up to `MOST_LINES` lines and `MOST_BYTES`, each line the fields a scan collects
//! (never `_CMDLINE`), its journal cursor (the same journalctl gives, so a line pushed and the same line scanned are one), and
//! `skipped`: how many debug entries were left out just before it, so that the controller can tell those from lines deleted on the
//! host when it reads the numbers (`__SEQNUM`). Each reading carries `cursor`, where to resume after it.
//!
//! It reads at its own pace: when the agent's outbox holds its share, the agent stops reading this plugin's pipe and the plugin
//! waits, with the journal on disk, instead of losing lines.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Map, Value};
use storageforge_agent::journal::{Entry, Reader, Resume, POLL_ENTRIES};
use storageforge_agent::pluginside::{now, Agent};

const MOST_LINES: usize = 200;
const MOST_BYTES: usize = 48 << 10;
const MESSAGE_BYTES: usize = 4000;
/// How long it waits for the controller's word on where to start, when the agent has none.
const RESUME_WAIT: Duration = Duration::from_secs(120);

fn resume_of(v: &Value) -> Option<Resume> {
    let s = v["s"].as_str().filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))?;
    Some(Resume { seqnum_id: s.to_string(), seqnum: v["i"].as_u64()?, realtime: v["t"].as_u64().unwrap_or(0) })
}

fn cut(text: &str, most: usize) -> String {
    if text.len() <= most {
        return text.to_string();
    }
    let mut end = most;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn line(e: &Entry, skipped: u64) -> Value {
    let mut m = Map::new();
    for (name, value) in &e.fields {
        let v = if name == "MESSAGE" { cut(value, MESSAGE_BYTES) } else { cut(value, 200) };
        m.insert(name.clone(), Value::String(v));
    }
    m.insert("__CURSOR".into(), json!(e.cursor()));
    m.insert("__SEQNUM".into(), json!(e.seqnum.to_string()));
    m.insert("__SEQNUM_ID".into(), json!(e.seqnum_id));
    m.insert("__REALTIME_TIMESTAMP".into(), json!(e.realtime.to_string()));
    m.insert("skipped".into(), json!(skipped));
    if e.unread > 0 {
        m.insert("unread".into(), json!(e.unread));
    }
    Value::Object(m)
}

fn main() {
    let agent = match Agent::start() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    let host = agent.host.clone();
    let machine = std::fs::read_to_string(host.join("etc/machine-id")).map(|t| t.trim().to_string()).unwrap_or_default();
    if machine.len() != 32 || !machine.bytes().all(|b| b.is_ascii_hexdigit()) {
        agent.log("the host's machine id cannot be read: its journal cannot be found");
        while agent.sleep(60.0) {}
        return;
    }
    let dirs: Vec<PathBuf> = ["var/log/journal", "run/log/journal"].iter().map(|d| host.join(d).join(&machine)).collect();
    // where to start
    let start = match agent.resume.as_ref().and_then(resume_of) {
        Some(r) => Some(r),
        None => {
            let mut said = None;
            let until = std::time::Instant::now() + RESUME_WAIT;
            while said.is_none() && std::time::Instant::now() < until && !agent.stopping() {
                if let Some(v) = agent.next(Duration::from_millis(500)) {
                    if v["op"] == "resume" {
                        said = Some(v["cursor"].clone());
                    }
                }
            }
            match said {
                Some(c) if c.is_object() => resume_of(&c),
                Some(_) => {
                    agent.log("the controller has no line of this host's journal yet: reading from what is written now");
                    None
                }
                None => {
                    agent.log("no word from the controller on where to start: reading from what is written now");
                    None
                }
            }
        }
    };
    if let Some(r) = &start {
        agent.log(format!("reading the journal from after entry {} of {}", r.seqnum, &r.seqnum_id[..8]));
    }
    let mut reader = Reader::new(dirs, start);
    let (mut skipped, mut sent, mut said_at) = (0u64, 0u64, now());
    let mut lines: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    let mut cursor = Value::Null;
    loop {
        if agent.stopping() {
            return;
        }
        // a late word from the controller is not followed: this run is reading already
        while agent.next(Duration::from_millis(0)).is_some() {}
        let got = reader.poll();
        let full = got.len() >= POLL_ENTRIES;
        for (e, _missing) in got {
            cursor = json!({"s": e.seqnum_id, "i": e.seqnum, "t": e.realtime});
            if e.priority() >= 7 {
                skipped += 1;
                continue;
            }
            let l = line(&e, skipped);
            skipped = 0;
            bytes += l.to_string().len();
            lines.push(l);
            if lines.len() >= MOST_LINES || bytes >= MOST_BYTES {
                sent += lines.len() as u64;
                if !agent.data("lines", json!({"lines": std::mem::take(&mut lines), "cursor": cursor})) {
                    return;
                }
                bytes = 0;
            }
        }
        if !lines.is_empty() {
            sent += lines.len() as u64;
            if !agent.data("lines", json!({"lines": std::mem::take(&mut lines), "cursor": cursor})) {
                return;
            }
            bytes = 0;
            // the cursor sent covers the debug entries after the last line: the controller counts from it
            skipped = 0;
        }
        if now() >= said_at + 600 {
            agent.log(format!("{sent} lines sent in the last ten minutes from {} journal files; {} could not be read", reader.files(), reader.unreadable));
            sent = 0;
            said_at = now();
        }
        if !full && !agent.sleep(1.0) {
            return;
        }
    }
}
