//! SSH signatures (OpenSSH's PROTOCOL.sshsig), made and checked here without `ssh-keygen` or OpenSSL.
//!
//! Everything StorageForge signs is signed this way, with an SSH key and a namespace that says what the signature is for:
//! release tags, the enclave image, signed deploys. So what the agent checks can be made with `ssh-keygen -Y sign` by whoever
//! holds the release key, and what the agent signs can be checked with `ssh-keygen -Y verify`.
//!
//! Only ed25519, only the hashes OpenSSH itself uses (sha512, sha256), and a namespace always: a signature made for one use is
//! worth nothing for another. A signers file is OpenSSH's allowed-signers format, and a line that does not name its namespaces is
//! refused, since "any namespace" is never what is meant here.

use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NOPAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

/// A plugin's descriptor, signed by the release key or by an operator's own.
pub const NS_PLUGIN: &str = "storageforge-plugin";
/// A host's manifest, signed by the controller.
pub const NS_MANIFEST: &str = "storageforge-agent-manifest";
/// A request to storageforge-agentctl, signed by the controller.
pub const NS_AGENTCTL: &str = "storageforge-agentctl";
/// What the agent sends, signed with its own key. The receiver of roadmap section 11.2 checks it.
pub const NS_BATCH: &str = "storageforge-agent-batch";

/// The most an armored signature may be. One of ed25519 is about 300 bytes.
pub const MAX_SIGNATURE: usize = 4096;
/// The most a signers file may be.
pub const MAX_SIGNERS: usize = 64 << 10;
const KEY_TYPE: &[u8] = b"ssh-ed25519";
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

/// One line of a signers file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub name: String,
    pub namespaces: Vec<String>,
    pub key: [u8; 32],
}

/// A signers file: who may sign, and for what.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signers(pub Vec<Signer>);

impl Signers {
    /// Reads an allowed-signers file. Empty lines and `#` comments are skipped; any other line that is not
    /// `name namespaces="a,b" ssh-ed25519 KEY [comment]` is an error, so a file with a line this program does not understand
    /// trusts nobody rather than somebody else than was meant.
    pub fn parse(text: &str) -> Result<Signers, String> {
        if text.len() > MAX_SIGNERS {
            return Err("the signers file is too large".into());
        }
        let mut out = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = |why: &str| format!("signers line {}: {why}", n + 1);
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 4 {
                return Err(bad("it is not: name namespaces=\"...\" ssh-ed25519 KEY"));
            }
            let name = words[0];
            if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b)) {
                return Err(bad("the name is not letters, digits, . _ @ and -"));
            }
            let Some(list) = words[1].strip_prefix("namespaces=\"").and_then(|s| s.strip_suffix('"')) else {
                return Err(bad("it has to name its namespaces, and no other option is read"));
            };
            let namespaces: Vec<String> = list.split(',').map(str::to_string).collect();
            if namespaces.iter().any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) {
                return Err(bad("a namespace is lower-case letters, digits and -"));
            }
            if words[2].as_bytes() != KEY_TYPE {
                return Err(bad("only ssh-ed25519 keys are read"));
            }
            let key = key_from_blob(&B64.decode(words[3]).map_err(|_| bad("the key is not base64"))?).ok_or_else(|| bad("the key is not an ed25519 public key"))?;
            out.push(Signer { name: name.to_string(), namespaces, key });
        }
        Ok(Signers(out))
    }

    /// The signer that holds `key` and may sign for `namespace`.
    pub fn allows(&self, key: &[u8; 32], namespace: &str) -> Option<&Signer> {
        self.0.iter().find(|s| &s.key == key && s.namespaces.iter().any(|n| n == namespace))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why a signature was refused. The text is for a log; nothing in it comes from the signature itself.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused(pub &'static str);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A reader of SSH's length-prefixed strings that never reads past the end.
struct Blob<'a>(&'a [u8]);

impl<'a> Blob<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        self.take(n)
    }
}

fn key_blob(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(51);
    put(&mut out, KEY_TYPE);
    put(&mut out, key);
    out
}

fn key_from_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut b = Blob(blob);
    if b.string()? != KEY_TYPE {
        return None;
    }
    let key: [u8; 32] = b.string()?.try_into().ok()?;
    b.0.is_empty().then_some(key)
}

/// `ssh-ed25519 AAAA...`, the public key as OpenSSH writes it.
pub fn public_line(key: &[u8; 32]) -> String {
    format!("ssh-ed25519 {}", B64.encode(key_blob(key)))
}

/// The key of a public key line. A comment after the key is allowed and ignored.
pub fn parse_public_line(line: &str) -> Option<[u8; 32]> {
    if line.len() > 512 {
        return None;
    }
    let mut words = line.split_whitespace();
    if words.next()?.as_bytes() != KEY_TYPE {
        return None;
    }
    key_from_blob(&B64.decode(words.next()?).ok()?)
}

/// `SHA256:...`, the fingerprint `ssh-keygen -l` shows.
pub fn fingerprint(key: &[u8; 32]) -> String {
    format!("SHA256:{}", B64_NOPAD.encode(Sha256::digest(key_blob(key))))
}

fn signed_data(namespace: &str, hash_name: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"SSHSIG");
    put(&mut out, namespace.as_bytes());
    put(&mut out, b"");
    put(&mut out, hash_name);
    put(&mut out, digest);
    out
}

/// Checks an armored SSH signature of `message`, made for `namespace` by one of `signers`. Returns who signed.
pub fn verify<'a>(signers: &'a Signers, namespace: &str, message: &[u8], armored: &str) -> Result<&'a Signer, Refused> {
    if armored.len() > MAX_SIGNATURE {
        return Err(Refused("the signature is too large"));
    }
    let body = armored.trim();
    let body = body.strip_prefix(BEGIN).and_then(|s| s.strip_suffix(END)).ok_or(Refused("it is not an SSH signature"))?;
    let b64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let raw = B64.decode(b64).map_err(|_| Refused("the signature is not base64"))?;
    let mut b = Blob(&raw);
    let bad = Refused("the signature is malformed");
    if b.take(6) != Some(b"SSHSIG") || b.take(4) != Some(&[0, 0, 0, 1]) {
        return Err(bad);
    }
    let (Some(key_part), Some(their_namespace), Some(reserved), Some(hash_name), Some(sig_part)) = (b.string(), b.string(), b.string(), b.string(), b.string()) else {
        return Err(bad);
    };
    if !b.0.is_empty() || !reserved.is_empty() {
        return Err(bad);
    }
    if their_namespace != namespace.as_bytes() {
        return Err(Refused("the signature was made for another use"));
    }
    let key = key_from_blob(key_part).ok_or(Refused("the signing key is not ed25519"))?;
    let signer = signers.allows(&key, namespace).ok_or(Refused("the signing key is not one that is trusted for this"))?;
    let digest: Vec<u8> = match hash_name {
        b"sha512" => Sha512::digest(message).to_vec(),
        b"sha256" => Sha256::digest(message).to_vec(),
        _ => return Err(Refused("the signature names a hash that is not read")),
    };
    let mut s = Blob(sig_part);
    if s.string() != Some(KEY_TYPE) {
        return Err(Refused("the signature is not ed25519"));
    }
    let sig: [u8; 64] = s.string().and_then(|x| x.try_into().ok()).ok_or(Refused("the signature is malformed"))?;
    if !s.0.is_empty() {
        return Err(Refused("the signature is malformed"));
    }
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| Refused("the signing key is not a point on the curve"))?;
    verifying
        .verify_strict(&signed_data(namespace, hash_name, &digest), &Signature::from_bytes(&sig))
        .map_err(|_| Refused("the signature does not verify"))?;
    Ok(signer)
}

/// An armored SSH signature of `message` for `namespace`, as `ssh-keygen -Y sign` writes it (sha512).
pub fn sign(key: &SigningKey, namespace: &str, message: &[u8]) -> String {
    let public = key.verifying_key().to_bytes();
    let signature = key.sign(&signed_data(namespace, b"sha512", &Sha512::digest(message)));
    let mut sig_part = Vec::with_capacity(83);
    put(&mut sig_part, KEY_TYPE);
    put(&mut sig_part, &signature.to_bytes());
    let mut blob = Vec::with_capacity(256);
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put(&mut blob, &key_blob(&public));
    put(&mut blob, namespace.as_bytes());
    put(&mut blob, b"");
    put(&mut blob, b"sha512");
    put(&mut blob, &sig_part);
    let b64 = B64.encode(blob);
    let mut out = String::from(BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// The lower-case hex sha256 of `bytes`: how a manifest names a descriptor and a descriptor names its program.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `text` is a lower-case hex sha256.
pub fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signers(k: &SigningKey, namespaces: &str) -> Signers {
        Signers::parse(&format!("someone namespaces=\"{namespaces}\" {}\n", public_line(&k.verifying_key().to_bytes()))).unwrap()
    }

    #[test]
    fn a_signature_verifies_for_its_namespace_and_key_only() {
        let k = key(1);
        let sig = sign(&k, NS_PLUGIN, b"the message");
        let trusted = signers(&k, NS_PLUGIN);
        assert_eq!(verify(&trusted, NS_PLUGIN, b"the message", &sig).unwrap().name, "someone");
        assert_eq!(verify(&trusted, NS_PLUGIN, b"another message", &sig), Err(Refused("the signature does not verify")));
        assert_eq!(verify(&trusted, NS_MANIFEST, b"the message", &sig), Err(Refused("the signature was made for another use")));
        assert_eq!(verify(&signers(&key(2), NS_PLUGIN), NS_PLUGIN, b"the message", &sig), Err(Refused("the signing key is not one that is trusted for this")));
        // a key trusted for manifests is not trusted for plugins
        let other = sign(&k, NS_MANIFEST, b"the message");
        assert!(verify(&trusted, NS_MANIFEST, b"the message", &other).is_err());
        assert!(verify(&Signers::default(), NS_PLUGIN, b"the message", &sig).is_err());
    }

    #[test]
    fn what_no_honest_signer_sends_is_refused_without_a_panic() {
        let k = key(3);
        let trusted = signers(&k, NS_PLUGIN);
        let good = sign(&k, NS_PLUGIN, b"m");
        for bad in ["", "hello", BEGIN, &format!("{BEGIN}\n!!!\n{END}"), &format!("{BEGIN}\nAAAA\n{END}"), &"A".repeat(MAX_SIGNATURE + 1)] {
            assert!(verify(&trusted, NS_PLUGIN, b"m", bad).is_err(), "{bad:?}");
        }
        // every prefix of a good signature's bytes, armored again: cut anywhere, it is refused and nothing is read past the end
        let b64: String = good.lines().filter(|l| !l.starts_with("-----")).collect();
        let raw = B64.decode(b64).unwrap();
        for cut in 0..raw.len() {
            let armored = format!("{BEGIN}\n{}\n{END}\n", B64.encode(&raw[..cut]));
            assert!(verify(&trusted, NS_PLUGIN, b"m", &armored).is_err(), "cut at {cut}");
        }
        // and a byte added after the end
        let mut longer = raw.clone();
        longer.push(0);
        assert!(verify(&trusted, NS_PLUGIN, b"m", &format!("{BEGIN}\n{}\n{END}\n", B64.encode(longer))).is_err());
    }

    #[test]
    fn a_signers_line_must_name_its_namespaces() {
        let line = public_line(&key(4).verifying_key().to_bytes());
        assert!(Signers::parse(&format!("someone {line}")).is_err());
        assert!(Signers::parse(&format!("someone cert-authority {line}")).is_err());
        assert!(Signers::parse(&format!("someone namespaces=\"a\" ssh-rsa {}", line.split(' ').nth(1).unwrap())).is_err());
        assert!(Signers::parse("someone namespaces=\"a\" ssh-ed25519 AAAA").is_err());
        let s = Signers::parse(&format!("# a comment\n\nsomeone namespaces=\"a,b-c\" {line} a comment\n")).unwrap();
        assert_eq!(s.0[0].namespaces, ["a", "b-c"]);
        assert!(Signers::parse("").unwrap().is_empty());
    }

    #[test]
    fn a_public_line_reads_back() {
        let public = key(5).verifying_key().to_bytes();
        assert_eq!(parse_public_line(&format!("{} storageforge-agent", public_line(&public))), Some(public));
        assert_eq!(parse_public_line("ssh-rsa AAAA"), None);
        assert!(fingerprint(&public).starts_with("SHA256:"));
        assert_eq!(fingerprint(&public).len(), 7 + 43);
    }
}
