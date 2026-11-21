//! Wipe and stop, from inside (roadmap section 11.3).
//!
//! At start and on a timer the agent checks its manifest and every plugin file against it (`supervise::inspect`), and the program
//! it runs against what it was when it started. Anything that can only be tampering (`Report::tamper`) ends its access: the agent
//! deletes its key from its state folder, writes down why in `wiped`, gives its last word to the controller if its tunnel is up
//! (one record, under the name `agent`, kind `wipe`, signed with the key it still holds in memory), and exits. It does not start
//! again: an agent that finds `wiped` in its state folder exits at once, makes no new key and runs nothing, whatever its runtime's
//! restart policy does. Only a new enrollment, which an admin starts, makes another agent there.
//!
//! What this protects against is the host's files being changed under an honest agent. An agent whose own process was taken over
//! can skip all of this, which is why the check that counts is the one from outside, over SSH (storageforge-agentctl's `check`),
//! and why the controller revokes the key on its own side first, which nobody on the host can undo.
//!
//! ```text
//! state/wiped    {"at":1794960000,"why":["plugin logs: its program is not the one that was signed"]}
//! ```

use std::path::Path;

use serde_json::{json, Value};

use crate::identity::{read_small, write_whole, KEY_FILE, PUBLIC_FILE};

pub const WIPED_FILE: &str = "wiped";
/// What the agent exits with once it has wiped itself, and on every start after.
pub const EXIT_WIPED: i32 = 79;
/// The most reasons written down.
const MOST_REASONS: usize = 20;

/// Deletes the agent's key and its plugin files, and writes down why. The key the caller holds in memory is all that is left of it,
/// and it goes when the process does.
pub fn wipe(state: &Path, why: &[String], now: u64) -> Result<(), String> {
    let reasons: Vec<String> = why.iter().take(MOST_REASONS).map(|w| crate::runner::plain(w)).collect();
    // the marker first: should anything below fail, the agent still never starts again with this key
    let marker = json!({"at": now, "why": reasons}).to_string();
    let marked = write_whole(&state.join(WIPED_FILE), marker.as_bytes(), 0o600);
    let mut failed = Vec::new();
    for name in [KEY_FILE, PUBLIC_FILE] {
        match std::fs::remove_file(state.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failed.push(format!("cannot delete {name}: {e}")),
        }
    }
    let _ = std::fs::remove_dir_all(state.join("plugins"));
    if let Err(e) = marked {
        failed.push(format!("cannot write down why: {e}"));
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// Why this agent was wiped, if it was: what its marker says, cut to what a log line carries.
pub fn wiped(state: &Path) -> Option<Value> {
    match read_small(&state.join(WIPED_FILE), 16 << 10) {
        Ok(bytes) => Some(serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| json!({"why": ["the record of why is unreadable"]}))),
        // a marker that is there and cannot be read (a link, a folder, too large) still means wiped
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some(json!({"why": [format!("the record of why cannot be read: {e}")]})),
        Err(_) => None,
    }
}

/// The sha256 of the program this process runs, read through /proc: what it started as is compared with what it is on the timer.
pub fn own_program() -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open("/proc/self/exe").ok()?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wipe_takes_the_key_and_the_plugins_and_says_why() {
        let dir = crate::identity::tests::folder("wipe");
        let key = crate::identity::generate(&dir).unwrap();
        std::fs::create_dir_all(dir.join("plugins")).unwrap();
        std::fs::write(dir.join("plugins/logs.plugin"), b"x").unwrap();
        assert!(wiped(&dir).is_none());
        wipe(&dir, &["plugin logs: its program is not the one that was signed\u{1b}[31m".to_string()], 1794960000).unwrap();
        assert!(!dir.join(KEY_FILE).exists() && !dir.join(PUBLIC_FILE).exists() && !dir.join("plugins").exists());
        let said = wiped(&dir).unwrap();
        assert_eq!(said["at"], 1794960000);
        assert_eq!(said["why"][0], "plugin logs: its program is not the one that was signed?[31m");
        // the key is gone from disk: loading finds none, and the agent refuses to make another while the marker is there
        assert!(crate::identity::load(&dir).unwrap().is_none());
        drop(key);
        // a marker that is not a plain file still counts
        std::fs::remove_file(dir.join(WIPED_FILE)).unwrap();
        std::fs::create_dir(dir.join(WIPED_FILE)).unwrap();
        assert!(wiped(&dir).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_program_can_be_hashed() {
        assert_eq!(own_program().map(|h| h.len()), Some(64));
    }
}
