//! A signed request to storageforge-agentctl (roadmap section 11.1, "Lifecycle over SSH").
//!
//! What arrives on stdin, as `storageforge-run` takes its requests:
//!
//! ```text
//! STORAGEFORGE-AGENTCTL 1\n
//! <length of the request in bytes>\n
//! <length of the signature in bytes>\n
//! <the request: JSON><the signature: SSH, namespace "storageforge-agentctl">
//! ```
//!
//! The request names its operation, this machine, when it was signed and a nonce:
//!
//! ```text
//! {"op":"apply","machine":"<machine-id>","issued":1794960000,"nonce":"<32 hex>", ...}
//! ```
//!
//! It is acted on only when the controller pinned on this host signed it, for this machine, in the last ten minutes, and its
//! nonce was never used here. The signature is checked before the request is parsed. There is no operation that runs a command
//! of the caller's, takes a path of the caller's, or reads anything from the caller but what is listed in `Request`.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::Deserialize;

use crate::manifest::{is_image, is_machine};
use crate::sig::{self, Signers};

pub const MAGIC: &str = "STORAGEFORGE-AGENTCTL 1";
/// The most a request may be: a manifest and the descriptors of all its plugins fit several times.
pub const MAX_REQUEST: usize = 1 << 20;
/// How old a request may be, and how far ahead of this host's clock, in seconds. The same as `storageforge-run`.
pub const MAX_AGE: u64 = 600;
pub const MAX_AHEAD: u64 = 300;
/// What storageforge-agentctl exits with for a request it would not act on. The same as `storageforge-run`.
pub const REFUSED: i32 = 97;
/// The operations there are. Nothing else is one.
/// `check` compares the running container with the manifest from outside (roadmap 11.3); `wipe` ends an agent's access there:
/// its key deleted, its container stopped and left stopped.
/// `console-open` and `console-close`: SSH turned on for one console session on a monitoring-only host, and off again (console.rs).
pub const OPS: [&str; 12] = ["preflight", "enroll", "apply", "start", "stop", "restart", "status", "remove", "check", "wipe", "console-open", "console-close"];
/// The most a wipe's reason may be.
pub const MAX_REASON: usize = 500;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedDescriptor {
    pub descriptor: String,
    pub signature: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub op: String,
    pub machine: String,
    pub issued: u64,
    pub nonce: String,
    /// `enroll`: the image to start the agent from, by digest. Later the manifest names it.
    #[serde(default)]
    pub image: Option<String>,
    /// `enroll` and `apply`: the signature of the image's digest, made by a release key or an operator's (`plugin::verify_image`).
    #[serde(default)]
    pub image_signature: Option<String>,
    /// `enroll`: install Podman when the host has no runtime. Set only after the user was told.
    #[serde(default)]
    pub install_podman: bool,
    /// `apply`: the manifest's bytes and the controller's signature of them.
    #[serde(default)]
    pub manifest: Option<String>,
    #[serde(default)]
    pub manifest_signature: Option<String>,
    /// `apply`: the signed descriptor of every plugin the manifest names, so that the needs can be checked here against the
    /// signer's own words. The programs themselves do not come this way.
    #[serde(default)]
    pub plugins: Vec<SignedDescriptor>,
    /// `apply`: the controller's receiver, which the agent's tunnel dials and pins (`tunnel::Config`). Without it the tunnel this
    /// host has stays as it is.
    #[serde(default)]
    pub tunnel: Option<TunnelRequest>,
    /// `apply`: a receiver key other than the one pinned here is taken, because a person accepted it.
    #[serde(default)]
    pub accept_new_tunnel_key: bool,
    /// `wipe`: why, in words, kept beside what is left of the agent on the host.
    #[serde(default)]
    pub reason: Option<String>,
    /// `console-open` and `console-close`: the session's grant, and to open it the account, the session's public key and the minutes
    /// the key may be used to log in.
    #[serde(default)]
    pub console: Option<ConsoleRequest>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsoleRequest {
    pub grant: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub minutes: Option<u32>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelRequest {
    pub endpoint: String,
    pub key: String,
}

fn line(from: &mut impl Read, most: usize) -> Result<String, String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        from.read_exact(&mut byte).map_err(|_| "the request ended early")?;
        if byte[0] == b'\n' {
            return String::from_utf8(out).map_err(|_| "the request's head is not text".into());
        }
        if out.len() >= most {
            return Err("the request's head is too long".into());
        }
        out.push(byte[0]);
    }
}

fn length(text: &str, most: usize) -> Result<usize, String> {
    if text.is_empty() || text.len() > 8 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("a length in the request's head is not a number".into());
    }
    let n: usize = text.parse().map_err(|_| "a length in the request's head is not a number")?;
    if n == 0 || n > most {
        return Err("the request is larger than a request may be".into());
    }
    Ok(n)
}

/// The request's bytes and its signature, read from stdin. Nothing is allocated before the lengths are known to be in range.
pub fn read(from: &mut impl Read) -> Result<(Vec<u8>, String), String> {
    if line(from, 32)? != MAGIC {
        return Err("not a StorageForge agent request".into());
    }
    let payload_len = length(&line(from, 8)?, MAX_REQUEST)?;
    let signature_len = length(&line(from, 8)?, sig::MAX_SIGNATURE)?;
    let mut payload = vec![0u8; payload_len];
    from.read_exact(&mut payload).map_err(|_| "the request ended early")?;
    let mut signature = vec![0u8; signature_len];
    from.read_exact(&mut signature).map_err(|_| "the request ended early")?;
    Ok((payload, String::from_utf8(signature).map_err(|_| "the signature is not text")?))
}

/// The request in `payload`, when this host's controller signed it for this machine a moment ago. The nonce is not claimed here.
pub fn verify(payload: &[u8], signature: &str, controller: &Signers, machine: &str, now: u64) -> Result<Request, String> {
    sig::verify(controller, sig::NS_AGENTCTL, payload, signature).map_err(|e| format!("the request is not signed by this host's controller: {e}"))?;
    let r: Request = serde_json::from_slice(payload).map_err(|e| format!("the request does not parse: {e}"))?;
    if !OPS.contains(&r.op.as_str()) {
        return Err("the request asks for something that is not an agent operation".into());
    }
    if !is_machine(&r.machine) || r.machine != machine {
        return Err("the request was signed for another machine".into());
    }
    if r.issued + MAX_AGE < now || r.issued > now + MAX_AHEAD {
        return Err(format!("the request is too old, or the clocks differ (issued {}, now {now})", r.issued));
    }
    if r.nonce.len() != 32 || !r.nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("the request's nonce is not 32 hex digits".into());
    }
    if r.image.as_deref().is_some_and(|i| !is_image(i)) {
        return Err("the image is not named by its digest (name@sha256:...)".into());
    }
    // each operation takes its own fields and no others: a field that would be ignored is a request nobody meant to send
    let (image, manifest) = (r.image.is_some(), r.manifest.is_some() || r.manifest_signature.is_some() || !r.plugins.is_empty());
    let signed_image = r.image_signature.as_deref().is_some_and(|s| !s.is_empty() && s.len() <= sig::MAX_SIGNATURE);
    if r.reason.as_deref().is_some_and(|w| w.len() > MAX_REASON) {
        return Err("the reason is longer than a reason may be".into());
    }
    let reason = r.reason.is_some();
    let console = r.console.as_ref();
    let fits = match r.op.as_str() {
        _ if reason && r.op != "wipe" => false,
        _ if console.is_some() && !r.op.starts_with("console-") => false,
        "console-open" => !image && !manifest && r.image_signature.is_none() && r.tunnel.is_none()
            && console.is_some_and(|c| c.user.is_some() && c.key.is_some() && c.minutes.is_some()),
        "console-close" => !image && !manifest && r.image_signature.is_none() && r.tunnel.is_none()
            && console.is_some_and(|c| c.user.is_none() && c.key.is_none() && c.minutes.is_none()),
        "enroll" => image && signed_image && !manifest,
        "apply" => !image && signed_image && !r.install_podman && r.manifest.is_some() && r.manifest_signature.is_some() && (r.tunnel.is_some() || !r.accept_new_tunnel_key),
        _ => !image && !manifest && !r.install_podman && r.image_signature.is_none() && r.tunnel.is_none() && !r.accept_new_tunnel_key,
    };
    if !fits {
        return Err(format!("the request does not carry what {} takes, or carries more", r.op));
    }
    Ok(r)
}

/// Marks `nonce` as used, in `dir`. Fails when it was used before: a request runs once. Marks older than a day are removed,
/// which is safe because a request that old is refused for its age.
pub fn claim_nonce(dir: &Path, nonce: &str, now: u64) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot keep the used nonces: {e}"))?;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let old = entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).is_some_and(|t| t.as_secs() + 86_400 < now);
            if old {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(nonce))
        .map(|_| ())
        .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { "this request was already used".to_string() } else { format!("cannot record the request's nonce: {e}") })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::tests::{IMAGE, MACHINE};
    use ed25519_dalek::SigningKey;

    pub fn wrap(payload: &[u8], signature: &str) -> Vec<u8> {
        let mut out = format!("{MAGIC}\n{}\n{}\n", payload.len(), signature.len()).into_bytes();
        out.extend_from_slice(payload);
        out.extend_from_slice(signature.as_bytes());
        out
    }

    fn controller() -> (SigningKey, Signers) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signers = Signers::parse(&format!("controller namespaces=\"storageforge-agentctl,storageforge-agent-manifest\" {}", sig::public_line(&key.verifying_key().to_bytes()))).unwrap();
        (key, signers)
    }

    fn body(op: &str, issued: u64, more: &str) -> String {
        format!(r#"{{"op":"{op}","machine":"{MACHINE}","issued":{issued},"nonce":"{}"{more}}}"#, "ab".repeat(16))
    }

    #[test]
    fn the_head_is_read_with_limits() {
        let good = wrap(b"{}", "sig");
        assert_eq!(read(&mut &good[..]).unwrap(), (b"{}".to_vec(), "sig".to_string()));
        for bad in [
            &b"STORAGEFORGE-RUN 1\n2\n3\n{}sig"[..],
            b"STORAGEFORGE-AGENTCTL 1\n99999999\n3\n{}sig",
            b"STORAGEFORGE-AGENTCTL 1\n2\n99999\n{}sig",
            b"STORAGEFORGE-AGENTCTL 1\n-2\n3\n{}sig",
            b"STORAGEFORGE-AGENTCTL 1\n0\n3\nsig",
            b"STORAGEFORGE-AGENTCTL 1\n2\n3\n{}s",
            b"STORAGEFORGE-AGENTCTL 1\n2",
            b"",
            &[b'A'; 200][..],
        ] {
            assert!(read(&mut &bad[..]).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_request_is_for_this_machine_now_and_signed_by_the_controller() {
        let (key, signers) = controller();
        let now = 1_000_000;
        let check = |text: &str, key: &SigningKey, namespace: &str| verify(text.as_bytes(), &sig::sign(key, namespace, text.as_bytes()), &signers, MACHINE, now);
        assert_eq!(check(&body("status", now, ""), &key, sig::NS_AGENTCTL).unwrap().op, "status");
        assert!(check(&body("enroll", now, &format!(r#","image":"{IMAGE}","image_signature":"s","install_podman":true"#)), &key, sig::NS_AGENTCTL).unwrap().install_podman);
        // another key, or the controller's signature made for a manifest or a deploy
        assert!(check(&body("status", now, ""), &SigningKey::from_bytes(&[8; 32]), sig::NS_AGENTCTL).is_err());
        assert!(check(&body("status", now, ""), &key, sig::NS_MANIFEST).is_err());
        assert!(check(&body("status", now, ""), &key, "storageforge-deploy").is_err());
        // old, from the future, for another machine, with a nonce that is none
        assert!(check(&body("status", now - MAX_AGE - 1, ""), &key, sig::NS_AGENTCTL).is_err());
        assert!(check(&body("status", now + MAX_AHEAD + 1, ""), &key, sig::NS_AGENTCTL).is_err());
        assert!(check(&body("status", now, "").replace(MACHINE, &"f".repeat(32)), &key, sig::NS_AGENTCTL).unwrap_err().contains("another machine"));
        assert!(check(&body("status", now, "").replace(&"ab".repeat(16), "../../etc/passwd"), &key, sig::NS_AGENTCTL).is_err());
    }

    #[test]
    fn only_agent_operations_with_only_their_own_fields() {
        let (key, signers) = controller();
        let now = 1_000_000;
        let check = |text: &str| verify(text.as_bytes(), &sig::sign(&key, sig::NS_AGENTCTL, text.as_bytes()), &signers, MACHINE, now);
        for op in ["run", "exec", "shell", "docker", "", "Apply"] {
            assert!(check(&body(op, now, "")).unwrap_err().contains("not an agent operation"), "{op}");
        }
        for more in [r#","command":"id""#, r#","argv":["sh"]"#, r#","script":"true""#, r#","path":"/etc/shadow""#, r#","runtime":"docker""#, r#","privileged":true"#] {
            assert!(check(&body("status", now, more)).unwrap_err().contains("does not parse"), "{more}");
        }
        assert!(check(&body("enroll", now, "")).is_err(), "enroll without an image");
        assert!(check(&body("enroll", now, r#","image":"storageforge-agent:latest""#)).unwrap_err().contains("digest"));
        assert!(check(&body("stop", now, &format!(r#","image":"{IMAGE}""#))).is_err(), "stop takes nothing");
        assert!(check(&body("apply", now, r#","manifest":"{}""#)).is_err(), "apply without the manifest's signature");
        assert!(check(&body("apply", now, r#","manifest":"{}","manifest_signature":"x","image_signature":"s","install_podman":true"#)).is_err());
        assert!(check(&body("apply", now, r#","manifest":"{}","manifest_signature":"x""#)).is_err(), "apply without the image's signature");
        assert!(check(&body("enroll", now, &format!(r#","image":"{IMAGE}""#))).is_err(), "enroll without the image's signature");
        assert!(check(&body("status", now, r#","image_signature":"s""#)).is_err());
        assert!(check(&body("apply", now, r#","manifest":"{}","manifest_signature":"x","image_signature":"s""#)).is_ok());
        // the check from outside takes nothing; a wipe takes its reason and nothing else
        assert!(check(&body("check", now, "")).is_ok());
        assert!(check(&body("wipe", now, r#","reason":"files changed in the container""#)).is_ok());
        assert!(check(&body("status", now, r#","reason":"x""#)).is_err());
        assert!(check(&body("wipe", now, &format!(r#","reason":"{}""#, "x".repeat(MAX_REASON + 1)))).is_err());
        assert!(check(&body("check", now, &format!(r#","image":"{IMAGE}""#))).is_err());
    }

    #[test]
    fn a_nonce_is_used_once() {
        let dir = std::env::temp_dir().join(format!("sfagentctl-nonce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nonce = "0".repeat(32);
        assert!(claim_nonce(&dir, &nonce, 1000).is_ok());
        assert_eq!(claim_nonce(&dir, &nonce, 1000).unwrap_err(), "this request was already used");
        assert!(claim_nonce(&dir, &"1".repeat(32), 1000).is_ok());
        // a day and more later (by the clock handed in) the old marks go, and a request that old is refused for its age anyway
        assert!(claim_nonce(&dir, &"2".repeat(32), u64::MAX / 2).is_ok());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
