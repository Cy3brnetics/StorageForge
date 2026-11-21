//! The agent's own key (roadmap section 11.1, "Enrollment", and 11.2, "Its own key, used for nothing else").
//!
//! An ed25519 key the agent makes itself the first time it starts, in its state folder. The private half never leaves that
//! folder: storageforge-agentctl reads the public half from the host's side of it during enrollment, over the SSH connection
//! the controller already pinned, and the controller pins it. It is no SSH key of the host's, and nothing but the agent's own
//! reports is ever signed with it (`sig::NS_BATCH`).
//!
//! ```text
//! agent_key       64 hex digits, the seed, mode 0600
//! agent_key.pub   ssh-ed25519 AAAA... storageforge-agent
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::sig;

pub const KEY_FILE: &str = "agent_key";
pub const PUBLIC_FILE: &str = "agent_key.pub";

/// A small regular file, read whole. Not followed if it is a link, and not read if it is larger than `most`: the folder may
/// belong to someone else than the reader.
pub fn read_small(path: &Path, most: usize) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > most as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file of the size expected"));
    }
    let mut out = Vec::with_capacity(meta.len() as usize);
    file.take(most as u64 + 1).read_to_end(&mut out)?;
    if out.len() > most {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "larger than expected"));
    }
    Ok(out)
}

/// Writes `bytes` to `path` so that a reader sees the old file or the new one, never half of one.
pub fn write_whole(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = std::path::PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let b = text.trim_end().as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Makes the key. Refuses when there is one: a key is replaced only by removing the agent and enrolling it again.
pub fn generate(state: &Path) -> Result<SigningKey, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(seed.as_mut());
    let key = SigningKey::from_bytes(&seed);
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state.join(KEY_FILE))
        .map_err(|e| format!("cannot make the agent's key in {}: {e}", state.display()))?;
    let text = Zeroizing::new(hex(seed.as_ref()) + "\n");
    file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| format!("cannot write the agent's key: {e}"))?;
    let line = format!("{} storageforge-agent\n", sig::public_line(&key.verifying_key().to_bytes()));
    write_whole(&state.join(PUBLIC_FILE), line.as_bytes(), 0o644).map_err(|e| format!("cannot write the agent's public key: {e}"))?;
    Ok(key)
}

/// The key in `state`, when it is there and nobody else can read it.
pub fn load(state: &Path) -> Result<Option<SigningKey>, String> {
    let path = state.join(KEY_FILE);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot look at the agent's key: {e}")),
    };
    if !meta.is_file() || meta.mode() & 0o077 != 0 {
        return Err("the agent's key is not a file only its owner can read".into());
    }
    let text = Zeroizing::new(read_small(&path, 80).map_err(|e| format!("cannot read the agent's key: {e}"))?);
    let seed = Zeroizing::new(std::str::from_utf8(&text).ok().and_then(unhex).ok_or("the agent's key file is not a key")?);
    Ok(Some(SigningKey::from_bytes(&seed)))
}

/// The key, made now if this is the first start.
pub fn load_or_generate(state: &Path) -> Result<SigningKey, String> {
    match load(state)? {
        Some(key) => Ok(key),
        None => generate(state),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub fn folder(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sfagent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_key_is_made_once_and_kept_private() {
        let dir = folder("identity");
        assert!(load(&dir).unwrap().is_none());
        let key = load_or_generate(&dir).unwrap();
        assert_eq!(std::fs::metadata(dir.join(KEY_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_or_generate(&dir).unwrap().to_bytes(), key.to_bytes());
        assert!(generate(&dir).is_err(), "a second key is never made over the first");
        let public = std::fs::read_to_string(dir.join(PUBLIC_FILE)).unwrap();
        assert_eq!(sig::parse_public_line(&public), Some(key.verifying_key().to_bytes()));
        // a key others can read is not used
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_link_or_a_large_file_is_not_read() {
        let dir = folder("small");
        std::fs::write(dir.join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        assert!(read_small(&dir.join("link"), 10).is_err());
        assert_eq!(read_small(&dir.join("real"), 10).unwrap(), b"x");
        std::fs::write(dir.join("large"), vec![0u8; 11]).unwrap();
        assert!(read_small(&dir.join("large"), 10).is_err());
        assert!(read_small(&dir, 10).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
