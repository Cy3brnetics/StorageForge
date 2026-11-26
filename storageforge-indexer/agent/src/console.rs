//! A console on a monitoring-only host (decision of 2026-11-16): SSH turned on for that session through storageforge-agentctl, and off
//! again after. Never a shell in the agent: the agent has no part in it, and carries no shell, command or SSH session.
//!
//! `console-open` puts one public key, made by the controller for that session alone, in the account's own `authorized_keys`, as a line
//! sshd itself stops taking after a few minutes (`expiry-time`), with no forwarding of any kind (`restrict,pty`), marked with the
//! session's grant. `console-close` takes the line out. Every request to storageforge-agentctl also takes out every grant whose time
//! is past, so a console the controller never closed is closed by the next request, and sshd refused its key long before.
//!
//! **Only the accounts this host's own admin listed** in `/etc/storageforge-agent/console_users`, by hand, one name a line, may be logged
//! in as. Without that file there is no console on this host. No request writes that file, so a controller that was taken over can
//! open a console only where a person on the host said it may, and only as the accounts they named. The agent's two accounts are never
//! one of them.
//!
//! The account's file is written by a child that has become that account, so a link or a file the account controls reaches nothing
//! the account could not reach by itself.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::host::{Host, User, AGENT_USER};

pub const CONSOLE_USERS: &str = "console_users";
pub const GRANTS_DIR: &str = "console";
/// How long the key may be used to log in. The session itself goes on after it; only the login has to fall inside.
pub const MAX_MINUTES: u32 = 10;
const MANAGER: &str = "storageforge-agentctl";
const MARK: &str = "storageforge-console:";

pub fn is_grant(g: &str) -> bool {
    g.len() == 32 && g.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An OpenSSH ed25519 public key line, `ssh-ed25519 BASE64`, and nothing else.
pub fn is_key(k: &str) -> bool {
    let mut w = k.split(' ');
    matches!((w.next(), w.next(), w.next()), (Some("ssh-ed25519"), Some(b), None) if b.len() == 68 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/'))
}

pub fn is_account(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && u.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) && !u.starts_with('-')
}

/// The accounts this host's admin allowed a console to log in as.
pub fn allowed(host: &Host) -> Result<Vec<String>, String> {
    let path = host.etc().join(CONSOLE_USERS);
    let text = match crate::identity::read_small(&path, 4096) {
        Ok(t) => String::from_utf8_lossy(&t).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("this host allows no console: its admin lists the accounts a console may log in as in {}, one a line", path.display()))
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && is_account(l) && *l != AGENT_USER && *l != MANAGER).map(str::to_string).collect())
}

/// `expiry-time` as sshd reads it, in UTC: YYYYMMDDHHMMZ.
pub fn expiry(at: u64) -> String {
    let t = at as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&t, &mut tm) };
    format!("{:04}{:02}{:02}{:02}{:02}Z", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
}

pub fn line(key: &str, grant: &str, until: u64) -> String {
    format!("restrict,pty,expiry-time=\"{}\" {key} {MARK}{grant}", expiry(until))
}

/// The file's lines but the ones of `grant` (or, with None, of every grant in `expired`).
pub fn without(text: &str, drop: &dyn Fn(&str) -> bool) -> String {
    let mut out = String::new();
    for l in text.lines() {
        let grant = l.rsplit_once(MARK).map(|(_, g)| g.trim());
        if grant.is_some_and(|g| is_grant(g) && drop(g)) {
            continue;
        }
        out += l;
        out.push('\n');
    }
    out
}

/// Runs `f` on the account's `authorized_keys`, as that account, in a child: f gets the old text and gives the new.
fn as_account(host: &Host, user: &User, f: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let home = host.at(&user.home);
    let root = unsafe { libc::geteuid() } == 0;
    if !root && user.uid != unsafe { libc::geteuid() } {
        // only the unit tests run this as an ordinary account, against a folder that stands for a host: as that account alone
        return Err(format!("not root, and not {}", user.name));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // the child: becomes the account, then touches only what the account may
        let code = (|| -> Result<(), ()> {
            unsafe {
                if root && (libc::setgroups(0, std::ptr::null()) != 0 || libc::setresgid(user.gid, user.gid, user.gid) != 0 || libc::setresuid(user.uid, user.uid, user.uid) != 0) {
                    return Err(());
                }
                libc::umask(0o077);
            }
            if unsafe { libc::geteuid() } == 0 && user.uid != 0 {
                return Err(());
            }
            let dir = home.join(".ssh");
            if !dir.exists() {
                std::fs::create_dir(&dir).map_err(|_| ())?;
            }
            let path = dir.join("authorized_keys");
            let mut old = String::new();
            // Only a missing file may be replaced: a symlink or unreadable file holds keys that must not be overwritten.
            match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path) {
                Ok(file) => {
                    let meta = file.metadata().map_err(|_| ())?;
                    if !meta.is_file() || meta.len() > 1 << 20 {
                        return Err(());
                    }
                    file.take(1 << 20).read_to_string(&mut old).map_err(|_| ())?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(()),
            }
            let Some(new) = f(&old) else { return Ok(()) };
            let tmp = dir.join(format!(".authorized_keys.storageforge-{}", std::process::id()));
            let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp).map_err(|_| ())?;
            out.write_all(new.as_bytes()).and_then(|_| out.sync_all()).map_err(|_| ())?;
            std::fs::rename(&tmp, &path).map_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })
        })();
        unsafe { libc::_exit(i32::from(code.is_err())) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(format!("the key could not be written for {} in its own folder (as {}, which owns it)", user.name, user.name))
    }
}

/// A grant as storageforge-agentctl keeps it: the account and until when.
fn grant_file(ctl: &Path, grant: &str) -> PathBuf {
    ctl.join(GRANTS_DIR).join(grant)
}

pub fn open(host: &Host, ctl: &Path, user: &str, key: &str, grant: &str, minutes: u32, now: u64) -> Result<u64, String> {
    if !is_account(user) || !is_key(key) || !is_grant(grant) || minutes == 0 || minutes > MAX_MINUTES {
        return Err("a console is opened for an account, with one ed25519 key, a grant and a few minutes".into());
    }
    if !allowed(host)?.iter().any(|a| a == user) {
        return Err(format!("{user} is not one of the accounts this host's admin allowed a console to log in as"));
    }
    let account = host.user(user).ok_or_else(|| format!("this host has no account {user}"))?;
    let until = now + u64::from(minutes) * 60;
    std::fs::create_dir_all(ctl.join(GRANTS_DIR)).map_err(|e| e.to_string())?;
    crate::identity::write_whole(&grant_file(ctl, grant), format!("{user} {until}\n").as_bytes(), 0o600).map_err(|e| e.to_string())?;
    let entry = line(key, grant, until);
    as_account(host, &account, &|old| {
        let mut new = without(old, &|g| g == grant);
        if !new.is_empty() && !new.ends_with('\n') {
            new.push('\n');
        }
        new += &entry;
        new.push('\n');
        Some(new)
    })?;
    Ok(until)
}

pub fn close(host: &Host, ctl: &Path, grant: &str) -> Result<bool, String> {
    if !is_grant(grant) {
        return Err("not a grant".into());
    }
    let Ok(text) = crate::identity::read_small(&grant_file(ctl, grant), 256) else { return Ok(false) };
    let text = String::from_utf8_lossy(&text).into_owned();
    let user = text.split_whitespace().next().unwrap_or("");
    if let Some(account) = host.user(user) {
        as_account(host, &account, &|old| if old.contains(&format!("{MARK}{grant}")) { Some(without(old, &|g| g == grant)) } else { None })?;
    }
    let _ = std::fs::remove_file(grant_file(ctl, grant));
    Ok(true)
}

/// Closes every grant whose time is past. Done on every request, so that a console the controller never closed does not stay open.
pub fn sweep(host: &Host, ctl: &Path, now: u64) -> Vec<String> {
    let mut closed = Vec::new();
    let Ok(entries) = std::fs::read_dir(ctl.join(GRANTS_DIR)) else { return closed };
    for e in entries.flatten() {
        let grant = e.file_name().to_string_lossy().into_owned();
        let until = crate::identity::read_small(&e.path(), 256).ok().and_then(|t| String::from_utf8_lossy(&t).split_whitespace().nth(1).and_then(|u| u.parse::<u64>().ok()));
        if is_grant(&grant) && until.is_none_or(|u| u + 60 < now) && close(host, ctl, &grant).is_ok() {
            closed.push(grant);
        }
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_sshd_stops_taking_and_that_forwards_nothing() {
        let key = format!("ssh-ed25519 {}", "A".repeat(68));
        assert!(is_key(&key));
        assert!(!is_key(&format!("{key} comment")) && !is_key("ssh-rsa AAAA") && !is_key(&format!("command=\"sh\" {key}")));
        let l = line(&key, &"ab".repeat(16), 1_795_000_000);
        assert_eq!(l, format!("restrict,pty,expiry-time=\"202611181106Z\" {key} storageforge-console:{}", "ab".repeat(16)));
        let text = format!("ssh-ed25519 BBB ana@laptop\n{l}\n# storageforge-console:{}\n", "cd".repeat(16));
        assert_eq!(without(&text, &|g| g == "ab".repeat(16)), format!("ssh-ed25519 BBB ana@laptop\n# storageforge-console:{}\n", "cd".repeat(16)));
        for bad in ["", "-x", "a b", "a/b", "root\n"] {
            assert!(!is_account(bad), "{bad:?}");
        }
    }
}
