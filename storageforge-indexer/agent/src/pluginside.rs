//! The plugin's side of the protocol on its pipes (`runner` is the agent's side), shared by the official plugins in `src/bin/plugin-*`.
//!
//! ```text
//! agent  -> plugin   {"op":"hello","protocol":1,"name":"NAME","host":"/host","resume":CURSOR|null}   first, once
//! plugin -> agent    {"op":"ready"}
//! plugin -> agent    {"op":"data","kind":"KIND","body":{...}}, {"op":"log","text":"..."}
//! agent  -> plugin   {"op":"resume","cursor":CURSOR|null}     where the controller has this plugin's readings up to, once a session opened
//! agent  -> plugin   {"op":"stop"}
//! ```
//!
//! A plugin that resumes (the logs plugin) puts its position in its readings as `cursor`; the agent keeps the newest one and hands it
//! back in `hello` when the plugin is started again, and the controller's receiver gives back the last one it stored when the agent
//! starts again (after a reboot, say), so nothing is read twice and nothing is skipped.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use storageforge_wire::{read_frame, write_frame};

use crate::runner::MAX_MESSAGE;

/// What a plugin knows of the agent: how to say things to it, and what it said.
pub struct Agent {
    out: Mutex<std::io::Stdout>,
    stop: Arc<AtomicBool>,
    from_agent: Receiver<Value>,
    /// Where the host's paths are mounted.
    pub host: PathBuf,
    /// The cursor the agent handed over in `hello`: where this plugin left off in this run of the agent.
    pub resume: Option<Value>,
}

impl Agent {
    /// Reads the agent's hello and answers ready. Then a thread reads what else the agent sends.
    pub fn start() -> Result<Agent, String> {
        let mut stdin = std::io::stdin();
        let hello = read_frame(&mut stdin, 2, MAX_MESSAGE).map_err(|e| format!("no hello from the agent: {e:?}"))?;
        let hello: Value = serde_json::from_slice(&hello).map_err(|_| "the hello is not JSON".to_string())?;
        if hello["op"] != "hello" {
            return Err("the agent did not begin with hello".into());
        }
        let host = PathBuf::from(hello["host"].as_str().unwrap_or("/host"));
        let resume = Some(hello["resume"].clone()).filter(|v| v.is_object());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let flag = stop.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            while let Ok(frame) = read_frame(&mut stdin, 2, MAX_MESSAGE) {
                let Ok(v) = serde_json::from_slice::<Value>(&frame) else { break };
                if v["op"] == "stop" {
                    break;
                }
                if tx.send(v).is_err() {
                    break;
                }
            }
            // the agent said stop, or went away: either way this plugin is done
            flag.store(true, Ordering::Relaxed);
        });
        let agent = Agent { out: Mutex::new(std::io::stdout()), stop, from_agent: rx, host, resume };
        agent.send(&json!({"op": "ready"}))?;
        Ok(agent)
    }

    fn send(&self, v: &Value) -> Result<(), String> {
        let bytes = v.to_string();
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        write_frame(&mut *out, bytes.as_bytes()).and_then(|_| out.flush()).map_err(|e| format!("the agent went away: {e}"))
    }

    /// One reading. False when the agent is gone, which ends the plugin.
    pub fn data(&self, kind: &str, body: Value) -> bool {
        self.send(&json!({"op": "data", "kind": kind, "body": body})).is_ok()
    }

    /// A line for the agent's log.
    pub fn log(&self, text: impl Into<String>) {
        let _ = self.send(&json!({"op": "log", "text": text.into()}));
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// The next message the agent sends (a resume), waiting at most `wait`.
    pub fn next(&self, wait: Duration) -> Option<Value> {
        match self.from_agent.recv_timeout(wait) {
            Ok(v) => Some(v),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Sleeps `secs`, a little at a time, and says whether the plugin should go on.
    pub fn sleep(&self, secs: f64) -> bool {
        let until = std::time::Instant::now() + Duration::from_secs_f64(secs);
        while std::time::Instant::now() < until {
            if self.stopping() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100).min(until.saturating_duration_since(std::time::Instant::now())));
        }
        !self.stopping()
    }
}

/// The seconds since 1970.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
