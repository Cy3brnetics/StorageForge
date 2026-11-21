//! The plugin format (roadmap sections 11.1 and 11.4).
//!
//! A plugin is three files:
//!
//! ```text
//! NAME.plugin.json   the descriptor: name, version, architecture, the program's sha256 and size, the protocol, what it needs
//! NAME.plugin.sig    an SSH signature of the descriptor's bytes, namespace "storageforge-plugin"
//! NAME.plugin        the program: one static executable
//! ```
//!
//! The signature covers the descriptor and the descriptor names the program by its hash, so one signature covers both, and it is
//! made with `ssh-keygen -Y sign -n storageforge-plugin -f KEY NAME.plugin.json` (then renamed from `.json.sig`). An official
//! plugin is signed by a release key, which is compiled into the agent. An operator's own is signed by a key the operator put in
//! `/etc/storageforge-agent/operator_signers` on that host, by hand: the controller never holds it and cannot add one.
//!
//! A descriptor says what the plugin needs and cannot be made to say more by whoever carries it: the manifest has to repeat the
//! same needs, and storageforge-agentctl reads the signed descriptor itself before it gives a container anything.

use serde::{Deserialize, Serialize};

use crate::needs::Needs;
use crate::sig::{self, Signers};

pub const FORMAT: u32 = 1;
/// The protocol the agent speaks to a plugin over its pipes (see `runner`).
pub const PROTOCOL: u32 = 1;
pub const MAX_DESCRIPTOR: usize = 16 << 10;
pub const MAX_PROGRAM: u64 = 32 << 20;
pub const MAX_PLUGINS: usize = 32;
/// The name the agent's own records go under (its last word when it wipes itself). No plugin may have it, so no plugin can speak
/// as the agent.
pub const AGENT_NAME: &str = "agent";

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: u32,
    pub name: String,
    pub version: String,
    /// `x86_64` or `aarch64`: the machine the program was built for.
    pub arch: String,
    /// The program's sha256, lower-case hex.
    pub sha256: String,
    /// The program's size in bytes.
    pub size: u64,
    pub protocol: u32,
    #[serde(default)]
    pub needs: Needs,
}

/// Who signed a plugin, as the manifest says it.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SignedBy {
    Release,
    Operator,
}

/// The keys a program trusts, and for what.
#[derive(Debug, Clone, Default)]
pub struct Anchors {
    /// Compiled in (`build.rs`): official plugins.
    pub release: Signers,
    /// `/etc/storageforge-agent/operator_signers`, put there by the operator: their own plugins.
    pub operator: Signers,
    /// `/etc/storageforge-agent/controller_signers`, pinned at enrollment: manifests and requests.
    pub controller: Signers,
}

/// The release signers this program was built with.
pub fn release_signers() -> Signers {
    // A file that does not parse is a build that trusts nobody, and `anchors` shows it: never a build that trusts by accident.
    Signers::parse(include_str!(concat!(env!("OUT_DIR"), "/release_signers"))).unwrap_or_default()
}

/// Whether `name` is a plugin's name: a lower-case letter, then up to 31 lower-case letters, digits or `-`.
pub fn is_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The machine this program was built for, as a descriptor names it.
pub fn this_arch() -> &'static str {
    std::env::consts::ARCH
}

/// Reads a descriptor's bytes. No signature is checked here: see `verify`.
pub fn read(bytes: &[u8]) -> Result<Descriptor, String> {
    if bytes.len() > MAX_DESCRIPTOR {
        return Err("the descriptor is too large".into());
    }
    let d: Descriptor = serde_json::from_slice(bytes).map_err(|e| format!("the descriptor does not parse: {e}"))?;
    if d.format != FORMAT {
        return Err(format!("descriptor format {} is not read by this program, which reads {FORMAT}", d.format));
    }
    if !is_name(&d.name) {
        return Err("the plugin's name is not a lower-case letter and then letters, digits and -".into());
    }
    if d.name == AGENT_NAME {
        return Err("agent is the agent's own name, never a plugin's".into());
    }
    if d.version.is_empty() || d.version.len() > 32 || !d.version.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b)) {
        return Err("the plugin's version is not letters, digits, . + and -".into());
    }
    if d.arch != "x86_64" && d.arch != "aarch64" {
        return Err("the plugin's architecture is x86_64 or aarch64".into());
    }
    if !sig::is_sha256(&d.sha256) {
        return Err("the program's sha256 is not 64 lower-case hex digits".into());
    }
    if d.size == 0 || d.size > MAX_PROGRAM {
        return Err(format!("a program is 1 to {MAX_PROGRAM} bytes"));
    }
    if d.protocol != PROTOCOL {
        return Err(format!("plugin protocol {} is not spoken by this program, which speaks {PROTOCOL}", d.protocol));
    }
    d.needs.check()?;
    Ok(d)
}

/// A descriptor whose signature was made by a key of the kind the manifest names. The signature is checked before a byte of the
/// descriptor is parsed.
pub fn verify(bytes: &[u8], signature: &str, by: SignedBy, anchors: &Anchors) -> Result<Descriptor, String> {
    if bytes.len() > MAX_DESCRIPTOR {
        return Err("the descriptor is too large".into());
    }
    let (signers, who) = match by {
        SignedBy::Release => (&anchors.release, "a release key"),
        SignedBy::Operator => (&anchors.operator, "an operator key of this host"),
    };
    sig::verify(signers, sig::NS_PLUGIN, bytes, signature).map_err(|e| format!("the plugin is not signed by {who}: {e}"))?;
    read(bytes)
}

/// Whether the image named by digest in `image` (`name@sha256:...`) is one a release key signed, or a key the operator put on
/// this host. What is signed is the digest and a newline, `sha256:<64 hex>\n`, in the namespace "storageforge-agent-image":
///
/// ```text
/// echo sha256:... > digest && ssh-keygen -Y sign -n storageforge-agent-image -f KEY digest
/// ```
///
/// The controller names the image and carries this signature, and cannot make one: so the program in the container is one the
/// release key vouched for, as its plugins are, and a controller that was taken over cannot have another image run with the
/// privileges a signed plugin declares.
pub fn verify_image(image: &str, signature: &str, anchors: &Anchors) -> Result<SignedBy, String> {
    let Some((_, digest)) = image.split_once('@') else { return Err("the image is not named by its digest".into()) };
    let message = format!("{digest}\n");
    if sig::verify(&anchors.release, sig::NS_IMAGE, message.as_bytes(), signature).is_ok() {
        return Ok(SignedBy::Release);
    }
    match sig::verify(&anchors.operator, sig::NS_IMAGE, message.as_bytes(), signature) {
        Ok(_) => Ok(SignedBy::Operator),
        Err(e) => Err(format!("the image is not signed by a release key or by an operator key of this host: {e}")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    pub fn descriptor(name: &str, program: &[u8], needs: &str) -> Vec<u8> {
        format!(
            r#"{{"format":1,"name":"{name}","version":"0.5.7","arch":"{}","sha256":"{}","size":{},"protocol":1,"needs":{needs}}}"#,
            this_arch(),
            sig::sha256_hex(program),
            program.len()
        )
        .into_bytes()
    }

    pub fn anchors(release: &SigningKey, operator: &SigningKey, controller: &SigningKey) -> Anchors {
        let line = |k: &SigningKey, ns: &str| Signers::parse(&format!("k namespaces=\"{ns}\" {}", sig::public_line(&k.verifying_key().to_bytes()))).unwrap();
        let code = "storageforge-plugin,storageforge-agent-image";
        Anchors { release: line(release, code), operator: line(operator, code), controller: line(controller, "storageforge-agent-manifest,storageforge-agentctl") }
    }

    #[test]
    fn an_image_runs_only_when_its_digest_was_signed_for_that() {
        let (release, operator, controller) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]), SigningKey::from_bytes(&[3; 32]));
        let a = anchors(&release, &operator, &controller);
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = format!("registry.example/storageforge-agent@{digest}");
        let signed = |key: &SigningKey, namespace: &str, text: &str| sig::sign(key, namespace, text.as_bytes());
        let line = format!("{digest}\n");
        assert_eq!(verify_image(&image, &signed(&release, sig::NS_IMAGE, &line), &a), Ok(SignedBy::Release));
        assert_eq!(verify_image(&image, &signed(&operator, sig::NS_IMAGE, &line), &a), Ok(SignedBy::Operator));
        // the same image under another name is the same bytes, and the signature is of the bytes
        assert!(verify_image(&format!("mirror.example/x@{digest}"), &signed(&release, sig::NS_IMAGE, &line), &a).is_ok());
        // the controller cannot vouch for an image, and a signature made for a plugin is not one for an image
        assert!(verify_image(&image, &signed(&controller, sig::NS_IMAGE, &line), &a).is_err());
        assert!(verify_image(&image, &signed(&release, sig::NS_PLUGIN, &line), &a).is_err());
        // another digest, the digest without its newline, no signature, a tag
        assert!(verify_image(&format!("registry.example/storageforge-agent@sha256:{}", "b".repeat(64)), &signed(&release, sig::NS_IMAGE, &line), &a).is_err());
        assert!(verify_image(&image, &signed(&release, sig::NS_IMAGE, &digest), &a).is_err());
        assert!(verify_image(&image, "", &a).is_err());
        assert!(verify_image("storageforge-agent:latest", &signed(&release, sig::NS_IMAGE, &line), &a).is_err());
        // a build that trusts no release key runs no image but an operator's own
        let none = Anchors { release: Signers::default(), ..a };
        assert!(verify_image(&image, &signed(&release, sig::NS_IMAGE, &line), &none).is_err());
        assert!(verify_image(&image, &signed(&operator, sig::NS_IMAGE, &line), &none).is_ok());
    }

    #[test]
    fn a_descriptor_is_read_only_whole_and_only_as_written() {
        let good = descriptor("heartbeat", b"program", "{}");
        let d = read(&good).unwrap();
        assert_eq!((d.name.as_str(), d.size), ("heartbeat", 7));
        let text = String::from_utf8(good).unwrap();
        for (from, to) in [
            ("\"format\":1", "\"format\":2"),
            ("\"protocol\":1", "\"protocol\":9"),
            ("heartbeat", "Heartbeat"),
            ("heartbeat", "../etc"),
            ("heartbeat", ""),
            ("\"0.5.7\"", "\"0.5.7 beta\""),
            ("\"size\":7", "\"size\":0"),
            ("\"size\":7", "\"size\":99999999999"),
            ("\"needs\":{}", "\"needs\":{\"mounts\":[\"/dev/sda\"]}"),
            ("\"needs\":{}", "\"needs\":{},\"run_as\":\"root\""),
            (this_arch(), "riscv64"),
        ] {
            assert!(read(text.replacen(from, to, 1).as_bytes()).is_err(), "{from} -> {to}");
        }
        assert!(read(&vec![b' '; MAX_DESCRIPTOR + 1]).is_err());
        assert!(read(b"[]").is_err());
    }

    #[test]
    fn a_plugin_is_official_only_when_a_release_key_signed_it() {
        let (release, operator, controller) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]), SigningKey::from_bytes(&[3; 32]));
        let a = anchors(&release, &operator, &controller);
        let bytes = descriptor("heartbeat", b"program", "{}");
        let by_release = sig::sign(&release, sig::NS_PLUGIN, &bytes);
        let by_operator = sig::sign(&operator, sig::NS_PLUGIN, &bytes);
        let by_controller = sig::sign(&controller, sig::NS_PLUGIN, &bytes);
        assert!(verify(&bytes, &by_release, SignedBy::Release, &a).is_ok());
        assert!(verify(&bytes, &by_operator, SignedBy::Operator, &a).is_ok());
        assert!(verify(&bytes, &by_operator, SignedBy::Release, &a).is_err());
        assert!(verify(&bytes, &by_release, SignedBy::Operator, &a).is_err());
        // the controller's key signs manifests, never code
        assert!(verify(&bytes, &by_controller, SignedBy::Release, &a).is_err());
        assert!(verify(&bytes, &by_controller, SignedBy::Operator, &a).is_err());
        // one byte of the descriptor changed after it was signed
        let mut changed = bytes.clone();
        let at = changed.len() - 2;
        changed.insert(at, b' ');
        assert!(verify(&changed, &by_release, SignedBy::Release, &a).is_err());
        // a host whose operator trusts no key of their own runs no operator plugin
        let none = Anchors { operator: Signers::default(), ..a };
        assert!(verify(&bytes, &by_operator, SignedBy::Operator, &none).is_err());
    }
}
