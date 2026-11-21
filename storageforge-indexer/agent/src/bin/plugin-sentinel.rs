//! The sentinel plugin (roadmap section 11.4, "Sentinel reports"): the sentinel's events through the agent, as they are written. The
//! sentinel itself stays on the host (security.py, secscripts.py), because its local actions need the host's root; it writes each event
//! to its own file, reports it over HTTPS where it can, and writes it to the journal, where this plugin reads it.
//!
//! Declares the journal's folders and `/etc/machine-id` read-only, and reads as the `systemd-journal` group: what the logs plugin
//! declares, and nothing more.
//!
//! It takes only lines the sentinel could have written: `SYSLOG_IDENTIFIER=storageforge-sentinel` from a process of root's (`_UID`,
//! which journald sets and no process can), each an `ev` line of the sentinel's own form. Anyone may log under any name, but only root
//! as root, and root holds the host anyway. The controller reads them as the host's claim, through the same checks and limits as the
//! sentinel's own reports (security.ingest_events), and an event an agent carried is never a witness for an action on another host.
//!
//! - `events` within `EVERY` seconds of an event: the lines, as the sentinel wrote them.
//!
//! It reads from what is written from its start on. An event written while the agent was down reaches the controller through the
//! sentinel's own report or the next scan, which carry the same file; the event's id makes it one event whichever way it came.

use std::path::PathBuf;

use serde_json::json;
use storageforge_agent::journal::Reader;
use storageforge_agent::pluginside::Agent;

const EVERY: f64 = 2.0;
const MOST_LINES: usize = 200;
const IDENT: &str = "storageforge-sentinel";

/// Whether a journal entry is a line the sentinel wrote: its name, root's, and of the sentinel's form.
pub fn is_sentinel(fields: &std::collections::BTreeMap<String, String>) -> Option<String> {
    if fields.get("SYSLOG_IDENTIFIER").map(String::as_str) != Some(IDENT) || fields.get("_UID").map(String::as_str) != Some("0") {
        return None;
    }
    let m = fields.get("MESSAGE")?;
    let parts: Vec<&str> = m.split('\t').collect();
    (parts.len() == 6 && parts[0] == "ev" && m.len() <= 16 << 10).then(|| m.clone())
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
    let mut reader = Reader::new(dirs, None);
    loop {
        let mut lines = Vec::new();
        for (entry, _) in reader.poll() {
            if let Some(line) = is_sentinel(&entry.fields) {
                if lines.len() < MOST_LINES {
                    lines.push(line);
                }
            }
        }
        if !lines.is_empty() && !agent.data("events", json!({"lines": lines})) {
            return;
        }
        if !agent.sleep(EVERY) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_root_under_the_sentinels_name_in_its_form_is_taken() {
        let ev = "ev\t0b6f2c1e-4c2a-4f7e-9a51-1d2e3f4a5b6c\tcanary_tripped\t1795000000\tYQ==\tYg==";
        let entry = |ident: &str, uid: &str, msg: &str| -> std::collections::BTreeMap<String, String> {
            [("SYSLOG_IDENTIFIER", ident), ("_UID", uid), ("MESSAGE", msg)].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        assert_eq!(is_sentinel(&entry(IDENT, "0", ev)), Some(ev.to_string()));
        assert_eq!(is_sentinel(&entry(IDENT, "1000", ev)), None, "an account that is not root logging under the name");
        assert_eq!(is_sentinel(&entry("sshd", "0", ev)), None);
        assert_eq!(is_sentinel(&entry(IDENT, "0", "hello")), None);
    }
}
