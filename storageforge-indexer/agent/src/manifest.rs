//! The host's manifest (roadmap section 11.1, "The host's manifest").
//!
//! Which plugins, at which hashes, with which needs, for this one host, signed by the controller with the time and a counter:
//!
//! ```text
//! manifest.json      {"format":1,"agent":"SHA256:...","machine":"<machine-id>","counter":7,"issued":1794960000,
//!                     "image":"registry/storageforge-agent@sha256:...",
//!                     "plugins":[{"name":"heartbeat","descriptor":"<sha256 of its descriptor>","signer":"release","needs":{}}]}
//! manifest.json.sig  an SSH signature of those bytes, namespace "storageforge-agent-manifest"
//! ```
//!
//! `agent` is the fingerprint of the key the agent made at enrollment and `machine` the host's machine id, so a manifest is of
//! use on one host only. The counter only goes up: a manifest with a lower one than the last accepted is an old one played
//! back, and is refused; the same counter is accepted again only with the same bytes, which is a restart. A manifest seen for
//! the first time must also have been issued a moment ago.
//!
//! The controller's signature says which plugins, and no more than that: it cannot make a plugin official (`plugin::verify`), and
//! it cannot give one more than its signed descriptor declares, because the needs here have to equal the descriptor's.

use serde::{Deserialize, Serialize};

use crate::needs::Needs;
use crate::plugin::{self, Descriptor, SignedBy};
use crate::sig::{self, Signers};

pub const FORMAT: u32 = 1;
pub const MAX_MANIFEST: usize = 64 << 10;
/// How old a manifest may be when it is seen for the first time, and how far ahead of this host's clock, in seconds.
pub const FRESH_BEHIND: u64 = 900;
pub const FRESH_AHEAD: u64 = 300;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    /// The sha256 of the plugin's descriptor file.
    pub descriptor: String,
    pub signer: SignedBy,
    #[serde(default)]
    pub needs: Needs,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    /// The fingerprint of the agent's key (`SHA256:...`).
    pub agent: String,
    /// The host's machine id: 32 hex digits.
    pub machine: String,
    pub counter: u64,
    /// When it was signed, in seconds since 1970.
    pub issued: u64,
    /// The image the container is made from, by digest.
    pub image: String,
    pub plugins: Vec<Entry>,
}

/// Whether `text` is an image named by its digest: `registry/name@sha256:<64 hex>`. A tag alone is never accepted, since a tag
/// can be moved to other bytes.
pub fn is_image(text: &str) -> bool {
    let Some((name, digest)) = text.split_once("@sha256:") else { return false };
    let b = name.as_bytes();
    sig::is_sha256(digest)
        && !b.is_empty()
        && b.len() <= 200
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._:/-".contains(c))
        && !name.contains("..")
        && !name.contains("//")
}

pub fn is_machine(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_fingerprint(text: &str) -> bool {
    text.strip_prefix("SHA256:").is_some_and(|b| b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/'))
}

/// The manifest in `bytes`, when the controller signed them. The signature is checked before anything is parsed.
pub fn verify(bytes: &[u8], signature: &str, controller: &Signers) -> Result<Manifest, String> {
    if bytes.len() > MAX_MANIFEST {
        return Err("the manifest is too large".into());
    }
    sig::verify(controller, sig::NS_MANIFEST, bytes, signature).map_err(|e| format!("the manifest is not signed by this host's controller: {e}"))?;
    let m: Manifest = serde_json::from_slice(bytes).map_err(|e| format!("the manifest does not parse: {e}"))?;
    if m.format != FORMAT {
        return Err(format!("manifest format {} is not read by this program, which reads {FORMAT}", m.format));
    }
    if !is_fingerprint(&m.agent) || !is_machine(&m.machine) {
        return Err("the manifest does not name an agent key and a machine".into());
    }
    if m.counter == 0 {
        return Err("a manifest's counter starts at 1".into());
    }
    if !is_image(&m.image) {
        return Err("the manifest's image is not named by its digest (name@sha256:...)".into());
    }
    if m.plugins.len() > plugin::MAX_PLUGINS {
        return Err(format!("more than {} plugins", plugin::MAX_PLUGINS));
    }
    for (i, e) in m.plugins.iter().enumerate() {
        if !plugin::is_name(&e.name) || !sig::is_sha256(&e.descriptor) {
            return Err("a plugin in the manifest has no proper name or descriptor hash".into());
        }
        if i > 0 && m.plugins[i - 1].name >= e.name {
            return Err("the manifest's plugins are not sorted by name, or one is there twice".into());
        }
        e.needs.check().map_err(|why| format!("plugin {}: {why}", e.name))?;
    }
    Ok(m)
}

impl Manifest {
    /// What the container needs: the union of the plugins' needs, and nothing more.
    pub fn needs(&self) -> Needs {
        Needs::union(self.plugins.iter().map(|e| &e.needs))
    }

    /// Whether the signed descriptor in `bytes` is the one `entry` names, signed by the kind of key it names, asking for exactly
    /// what it says. This is the check that keeps a controller from giving a plugin more than its signer declared.
    pub fn admit_plugin(entry: &Entry, bytes: &[u8], signature: &str, anchors: &plugin::Anchors) -> Result<Descriptor, String> {
        if sig::sha256_hex(bytes) != entry.descriptor {
            return Err(format!("plugin {}: the descriptor is not the one the manifest names", entry.name));
        }
        let d = plugin::verify(bytes, signature, entry.signer, anchors).map_err(|why| format!("plugin {}: {why}", entry.name))?;
        if d.name != entry.name {
            return Err(format!("plugin {}: its descriptor is for {}", entry.name, d.name));
        }
        if d.needs != entry.needs {
            return Err(format!("plugin {}: the manifest gives it other privileges than its signed descriptor declares", entry.name));
        }
        Ok(d)
    }
}

/// The last manifest accepted: its counter and the sha256 of its bytes. Kept in a file as `COUNTER SHA256\n`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seen {
    pub counter: u64,
    pub sha256: String,
}

impl Seen {
    pub fn parse(text: &str) -> Option<Seen> {
        let (counter, sha256) = text.trim_end().split_once(' ')?;
        (text.len() <= 100 && sig::is_sha256(sha256)).then_some(())?;
        Some(Seen { counter: counter.parse().ok()?, sha256: sha256.to_string() })
    }

    pub fn line(&self) -> String {
        format!("{} {}\n", self.counter, self.sha256)
    }
}

/// How a manifest stands against the last one accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admitted {
    /// A later one, issued a moment ago: it replaces the last, and the caller records it.
    New,
    /// The very one accepted last: a restart.
    Same,
}

/// Whether `m` (whose bytes hash to `sha256`) may be used, given the last manifest accepted and this host's clock.
pub fn admit(m: &Manifest, sha256: &str, seen: Option<&Seen>, now: u64) -> Result<Admitted, String> {
    if let Some(seen) = seen {
        if m.counter < seen.counter {
            return Err(format!("the manifest is an old one played back: its counter is {} and {} was accepted already", m.counter, seen.counter));
        }
        if m.counter == seen.counter {
            return if sha256 == seen.sha256 { Ok(Admitted::Same) } else { Err(format!("another manifest was accepted with counter {} already", m.counter)) };
        }
    }
    if m.issued + FRESH_BEHIND < now || m.issued > now + FRESH_AHEAD {
        return Err(format!("the manifest was not signed a moment ago (issued {}, now {now}): it is an old one, or the clocks differ", m.issued));
    }
    Ok(Admitted::New)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::plugin::tests::{anchors, descriptor};
    use ed25519_dalek::SigningKey;

    pub const IMAGE: &str = "registry.example/storageforge-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub const MACHINE: &str = "0123456789abcdef0123456789abcdef";

    pub fn manifest(agent: &SigningKey, counter: u64, issued: u64, plugins: &str) -> Vec<u8> {
        format!(
            r#"{{"format":1,"agent":"{}","machine":"{MACHINE}","counter":{counter},"issued":{issued},"image":"{IMAGE}","plugins":[{plugins}]}}"#,
            sig::fingerprint(&agent.verifying_key().to_bytes())
        )
        .into_bytes()
    }

    fn keys() -> (SigningKey, SigningKey, SigningKey, SigningKey) {
        (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]), SigningKey::from_bytes(&[3; 32]), SigningKey::from_bytes(&[4; 32]))
    }

    #[test]
    fn only_the_controller_signs_a_manifest() {
        let (release, operator, controller, agent) = keys();
        let a = anchors(&release, &operator, &controller);
        let bytes = manifest(&agent, 1, 1000, "");
        assert_eq!(verify(&bytes, &sig::sign(&controller, sig::NS_MANIFEST, &bytes), &a.controller).unwrap().counter, 1);
        // not the release key, not the agent itself, and not the controller's signature made for a request
        for (key, namespace) in [(&release, sig::NS_MANIFEST), (&agent, sig::NS_MANIFEST), (&controller, sig::NS_AGENTCTL)] {
            assert!(verify(&bytes, &sig::sign(key, namespace, &bytes), &a.controller).is_err());
        }
    }

    #[test]
    fn a_signed_manifest_is_still_read_strictly() {
        let (release, operator, controller, agent) = keys();
        let a = anchors(&release, &operator, &controller);
        let good = String::from_utf8(manifest(&agent, 1, 1000, r#"{"name":"a","descriptor":"DD","signer":"release","needs":{}},{"name":"b","descriptor":"DD","signer":"operator"}"#)).unwrap().replace("DD", &"d".repeat(64));
        let signed = |text: &str| verify(text.as_bytes(), &sig::sign(&controller, sig::NS_MANIFEST, text.as_bytes()), &a.controller);
        assert_eq!(signed(&good).unwrap().plugins.len(), 2);
        for (from, to) in [
            ("\"format\":1", "\"format\":2"),
            ("\"counter\":1", "\"counter\":0"),
            ("\"counter\":1", "\"counter\":-1"),
            (MACHINE, "not-a-machine"),
            ("SHA256:", "MD5:"),
            ("@sha256:", ":latest"),
            ("registry.example", "Registry.example"),
            ("registry.example", "--privileged"),
            ("\"name\":\"b\"", "\"name\":\"a\""),
            ("\"signer\":\"release\"", "\"signer\":\"controller\""),
            ("\"needs\":{}", "\"needs\":{\"capabilities\":[\"SYS_MODULE\"]}"),
            ("\"plugins\":[", "\"network\":\"host\",\"plugins\":["),
        ] {
            assert!(signed(&good.replacen(from, to, 1)).is_err(), "{from} -> {to}");
        }
    }

    #[test]
    fn the_counter_only_goes_up_and_a_new_manifest_is_fresh() {
        let (.., agent) = keys();
        let at = |counter, issued| serde_json::from_slice::<Manifest>(&manifest(&agent, counter, issued, "")).unwrap();
        let now = 1_000_000;
        assert_eq!(admit(&at(1, now), "a", None, now), Ok(Admitted::New));
        let seen = Seen { counter: 5, sha256: "a".repeat(64) };
        assert_eq!(admit(&at(6, now - 10), "x", Some(&seen), now), Ok(Admitted::New));
        // the same one again is a restart, whenever it happens
        assert_eq!(admit(&at(5, now - 999_999), &seen.sha256, Some(&seen), now), Ok(Admitted::Same));
        // an older one played back, and another manifest under a counter that was used
        assert!(admit(&at(4, now), "x", Some(&seen), now).unwrap_err().contains("played back"));
        assert!(admit(&at(5, now), "x", Some(&seen), now).is_err());
        // a new counter on a manifest signed long ago, or in the future
        assert!(admit(&at(6, now - FRESH_BEHIND - 1), "x", Some(&seen), now).is_err());
        assert!(admit(&at(6, now + FRESH_AHEAD + 1), "x", Some(&seen), now).is_err());
        assert_eq!(Seen::parse(&seen.line()), Some(seen));
        assert_eq!(Seen::parse("5 abc\n"), None);
        assert_eq!(Seen::parse("x"), None);
    }

    #[test]
    fn a_manifest_cannot_give_a_plugin_more_than_its_signer_declared() {
        let (release, operator, controller, _) = keys();
        let a = anchors(&release, &operator, &controller);
        let bytes = descriptor("health", b"program", r#"{"mounts":["/proc"],"namespaces":["pid"]}"#);
        let signature = sig::sign(&release, sig::NS_PLUGIN, &bytes);
        let entry = |needs: &str, signer: &str, name: &str| -> Entry {
            serde_json::from_str(&format!(r#"{{"name":"{name}","descriptor":"{}","signer":"{signer}","needs":{needs}}}"#, sig::sha256_hex(&bytes))).unwrap()
        };
        let same = r#"{"mounts":["/proc"],"namespaces":["pid"]}"#;
        assert!(Manifest::admit_plugin(&entry(same, "release", "health"), &bytes, &signature, &a).is_ok());
        let more = Manifest::admit_plugin(&entry(r#"{"mounts":["/","/proc"],"capabilities":["SYS_ADMIN"],"namespaces":["pid"]}"#, "release", "health"), &bytes, &signature, &a);
        assert!(more.unwrap_err().contains("other privileges"));
        // fewer is refused too: the plugin would run without what it was built to have, and nobody signed that
        assert!(Manifest::admit_plugin(&entry("{}", "release", "health"), &bytes, &signature, &a).is_err());
        assert!(Manifest::admit_plugin(&entry(same, "operator", "health"), &bytes, &signature, &a).is_err());
        assert!(Manifest::admit_plugin(&entry(same, "release", "other"), &bytes, &signature, &a).is_err());
        let another = descriptor("health", b"another program", same);
        assert!(Manifest::admit_plugin(&entry(same, "release", "health"), &another, &sig::sign(&release, sig::NS_PLUGIN, &another), &a).unwrap_err().contains("not the one the manifest names"));
    }

    #[test]
    fn an_image_is_named_by_its_digest() {
        assert!(is_image(IMAGE));
        assert!(is_image(&format!("localhost:5000/a/b@sha256:{}", "0".repeat(64))));
        for bad in ["storageforge-agent:latest", "storageforge-agent", "@sha256:00", &format!("a@sha256:{}", "g".repeat(64)), &format!("-v/:/host@sha256:{}", "0".repeat(64)), &format!("a b@sha256:{}", "0".repeat(64)), &format!("a/../b@sha256:{}", "0".repeat(64))] {
            assert!(!is_image(bad), "{bad}");
        }
    }
}
