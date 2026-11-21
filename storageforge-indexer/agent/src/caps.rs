//! Capabilities for a plugin that declares one (roadmap section 11.1, "Runtime": the disks and files plugins).
//!
//! Docker and Podman as root give a process that is not root no capability it can use: what `--cap-add` names lands in the bounding
//! set only, and none in the effective, permitted or ambient sets. So a container whose plugins declare a capability is started as
//! root with `--cap-drop ALL`, the declared capabilities and the three it takes to stop being root (`SETUID`, `SETGID`, `SETPCAP`),
//! and the agent's first act, before it reads a byte of anything, is `become_agent`: it gives up root for `sfagent` and keeps the
//! declared capabilities, and nothing else, in the sets a child can inherit (permitted, inheritable, ambient). The three it needed
//! leave the bounding set, so neither it nor anything it starts can have them again, and the securebits are locked so that no
//! later `setuid` gives root's capabilities back.
//!
//! The agent itself holds them in none of its effective set. The runner gives each plugin only its own declared ones
//! (`limit_ambient`), so the health plugin does not run with the files plugin's `SYS_ADMIN`.

use crate::needs::CAPABILITIES;

/// The kernel's number for each capability a plugin may declare.
pub fn number(name: &str) -> Option<u32> {
    Some(match name {
        "DAC_READ_SEARCH" => 2,
        "NET_ADMIN" => 12,
        "NET_RAW" => 13,
        "SYS_RAWIO" => 17,
        "SYS_PTRACE" => 19,
        "SYS_ADMIN" => 21,
        _ => return None,
    })
}

const SETGID: u32 = 6;
const SETUID: u32 = 7;
const SETPCAP: u32 = 8;
const LAST_CAP: u32 = 63;
// securebits: no root magic for uid 0, no fixup of capabilities on setuid, keep-caps off, each one locked
const SECBITS_LOCKED: libc::c_ulong = 0x01 | 0x02 | 0x04 | 0x08 | 0x20;

fn bit(n: u32) -> u64 {
    1u64 << n
}

/// The mask of the declared capabilities' numbers.
pub fn mask_of(names: &[String]) -> u64 {
    names.iter().filter_map(|n| number(n)).fold(0, |m, n| m | bit(n))
}

/// The capabilities a plugin may declare, as a mask: anything else is never kept.
pub fn allowed_mask() -> u64 {
    CAPABILITIES.iter().filter_map(|n| number(n)).fold(0, |m, n| m | bit(n))
}

#[repr(C)]
struct Header {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const VERSION_3: u32 = 0x2008_0522;

/// (effective, permitted, inheritable) of this thread.
pub fn get() -> Result<(u64, u64, u64), String> {
    let mut h = Header { version: VERSION_3, pid: 0 };
    let mut d = [Data::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut Header, d.as_mut_ptr()) } != 0 {
        return Err(format!("capget: {}", std::io::Error::last_os_error()));
    }
    let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    Ok((join(d[0].effective, d[1].effective), join(d[0].permitted, d[1].permitted), join(d[0].inheritable, d[1].inheritable)))
}

fn set(effective: u64, permitted: u64, inheritable: u64) -> Result<(), String> {
    let mut h = Header { version: VERSION_3, pid: 0 };
    let split = |v: u64| (v as u32, (v >> 32) as u32);
    let (e0, e1) = split(effective);
    let (p0, p1) = split(permitted);
    let (i0, i1) = split(inheritable);
    let d = [Data { effective: e0, permitted: p0, inheritable: i0 }, Data { effective: e1, permitted: p1, inheritable: i1 }];
    if unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut Header, d.as_ptr()) } != 0 {
        return Err(format!("capset: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The bounding set of this thread.
pub fn bounding() -> u64 {
    (0..=LAST_CAP).filter(|&c| unsafe { libc::prctl(libc::PR_CAPBSET_READ, c as libc::c_ulong, 0, 0, 0) } == 1).fold(0, |m, c| m | bit(c))
}

/// The ambient set of this thread.
pub fn ambient() -> u64 {
    (0..=LAST_CAP)
        .filter(|&c| unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong, c as libc::c_ulong, 0, 0) } == 1)
        .fold(0, |m, c| m | bit(c))
}

/// What a bounding set holds beyond the declared capabilities and the three it takes to give up root: anything there means the
/// container was not made the way storageforge-agentctl makes it, and the agent does not start.
pub fn unexpected(bounding: u64) -> u64 {
    bounding & !(allowed_mask() | bit(SETUID) | bit(SETGID) | bit(SETPCAP))
}

fn must(rc: libc::c_int, what: &str) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what}: {}", std::io::Error::last_os_error()))
    }
}

/// Gives up root for `uid`:`gid`, keeping the declared capabilities this container was given (its bounding set, less the three it
/// takes to do this) for its plugins and nothing else. Returns the names kept. On any failure the agent does not start.
pub fn become_agent(uid: u32, gid: u32) -> Result<Vec<String>, String> {
    if uid == 0 || gid == 0 {
        return Err("the agent's account is never root".into());
    }
    let bounding = bounding();
    if unexpected(bounding) != 0 {
        return Err(format!("the container was given capabilities no plugin may declare ({:#x})", unexpected(bounding)));
    }
    let keep = bounding & allowed_mask();
    unsafe {
        // the groups the runtime gave, but root's
        let mut groups = vec![0 as libc::gid_t; 64];
        let n = libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr());
        if n < 0 {
            return Err(format!("getgroups: {}", std::io::Error::last_os_error()));
        }
        groups.truncate(n as usize);
        groups.retain(|&g| g != 0);
        must(libc::setgroups(groups.len(), groups.as_ptr()), "setgroups")?;
        must(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0), "keepcaps")?;
        must(libc::setresgid(gid, gid, gid), "setresgid")?;
        must(libc::setresuid(uid, uid, uid), "setresuid")?;
    }
    // permitted was kept across setuid; SETPCAP is made effective once more, to change the bounding set and the securebits
    let (_, permitted, _) = get()?;
    set(bit(SETPCAP), permitted, 0)?;
    unsafe {
        must(libc::prctl(libc::PR_SET_SECUREBITS, SECBITS_LOCKED, 0, 0, 0), "securebits")?;
        for c in [SETUID, SETGID, SETPCAP] {
            must(libc::prctl(libc::PR_CAPBSET_DROP, c as libc::c_ulong, 0, 0, 0), "dropping from the bounding set")?;
        }
    }
    set(0, keep, keep)?;
    for c in (0..=LAST_CAP).filter(|&c| keep & bit(c) != 0) {
        must(unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong, c as libc::c_ulong, 0, 0) }, "raising an ambient capability")?;
    }
    if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } == 0 || unsafe { libc::getgid() } == 0 {
        return Err("still root after giving it up".into());
    }
    Ok(CAPABILITIES.iter().filter(|n| number(n).is_some_and(|c| keep & bit(c) != 0)).map(|n| n.to_string()).collect())
}

/// In a child between fork and exec: leaves in the ambient set only what `declared` names. Only calls that are safe there.
pub fn limit_ambient(declared: u64) -> std::io::Result<()> {
    for c in 0..=LAST_CAP {
        if declared & bit(c) == 0 {
            // a capability that is not set, or that the kernel does not know, is fine to lower
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_LOWER as libc::c_ulong, c as libc::c_ulong, 0, 0) };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_vocabulary_has_numbers() {
        for name in CAPABILITIES {
            assert!(number(name).is_some(), "{name}");
        }
        assert_eq!(number("SYS_MODULE"), None);
        assert_eq!(mask_of(&["SYS_RAWIO".into(), "SYS_ADMIN".into(), "NONSENSE".into()]), bit(17) | bit(21));
    }

    #[test]
    fn a_bounding_set_with_more_than_was_declared_stops_the_agent() {
        let made = bit(17) | bit(SETUID) | bit(SETGID) | bit(SETPCAP);
        assert_eq!(unexpected(made), 0);
        assert_eq!(unexpected(made | bit(16)), bit(16), "SYS_MODULE is never given");
        assert_eq!(unexpected(made | bit(0)), bit(0), "nor CHOWN");
    }

    #[test]
    fn a_process_that_is_not_root_cannot_become_anyone() {
        if unsafe { libc::geteuid() } != 0 {
            assert!(become_agent(12345, 12345).is_err());
        }
        assert!(become_agent(0, 5).is_err());
    }
}
