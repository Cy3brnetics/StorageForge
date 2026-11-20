//! StorageForge's key enclave (roadmap section 14).
//!
//! The one program of a micro VM whose only devices are vsock and a read-only initramfs. It holds the vault's KEK, derived here from
//! the vault secret, and nothing else that lasts: every ciphertext stays in the controller's database and comes with the request that
//! needs it. So the stored format does not change, a restarted enclave knows nothing until it is unlocked, and what the web app holds
//! is ciphertexts and a socket that answers a few narrow questions.
//!
//! The wire: a 4-byte big-endian length, then that many bytes of JSON, one request and one answer at a time, one connection at a time.
//! Bytes inside JSON are base64. A frame over MAX_FRAME, JSON that does not parse, or an unknown operation ends the connection and
//! counts as a bad request; BAD_LIMIT of them lock the enclave down, which wipes the KEK and refuses everything but `status` and
//! `unlock` until someone unlocks again. No operation returns a private key or the KEK.
//!
//! The channel: every connection begins with a Noise handshake (Noise_NX_25519_AESGCM_SHA256) against the enclave's static key,
//! and everything after it is encrypted under the keys the handshake made. The static key is made as the program starts and is
//! gone when it stops. Whoever started the enclave pins the key it shows at first contact, and every later client refuses an
//! enclave that shows another: so what crosses the socket cannot be read by something else on the host, and the vault secret is
//! never sent to something that only sits where the enclave should be. The handshake proves the enclave to the client, not the
//! client to the enclave: anyone who can open the socket can still ask, under the same limits.
//!
//! What a plaintext key does here: it is decrypted, used for one signature, and zeroed. Its envelope is the vault's own
//! (vault.py): KEK wraps a DEK with AES-256-GCM under `storageforge:dek:<uuid>`, the DEK encrypts the OpenSSH private key under
//! `storageforge:key:<uuid>`, so a ciphertext moved to another row does not authenticate here either.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use ssh_key::private::PrivateKey;
use ssh_key::{Algorithm, EcdsaCurve, LineEnding};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL: u32 = 3;
const NOISE_NAME: &[u8; 28] = b"Noise_NX_25519_AESGCM_SHA256";
const NOISE_PROLOGUE: &[u8] = b"storageforge-enclave-v3";
/// The vsock port the enclave listens on inside its VM.
const VSOCK_PORT: u32 = 7000;
const MAX_FRAME: usize = 1 << 20;
const MAX_SIGN_DATA: usize = 256 << 10;
const BAD_LIMIT: u32 = 5;
// One connection is served at a time, so one that goes quiet is dropped: a client that holds its connection open cannot hold the others out.
const IDLE_SECS: i64 = 5;
const VERIFIER: &[u8] = b"storageforge-vault-v1";
// Argon2id costs the enclave may be asked for: enough to be worth something, and never so much that one request stalls it for good.
const KDF_MEMORY_KIB: std::ops::RangeInclusive<u32> = 8 * 1024..=1024 * 1024;
const KDF_TIME: std::ops::RangeInclusive<u32> = 1..=10;
const KDF_LANES: std::ops::RangeInclusive<u32> = 1..=16;
// Signatures per key per minute, and unlock attempts per minute. The limits live here, where the web app cannot change them.
const SIGN_PER_MINUTE: f64 = 600.0;
const UNLOCK_PER_MINUTE: f64 = 6.0;
/// A secret that has to leave (a device password, a step's secret) leaves at most this often per secret.
const RELEASE_PER_MINUTE: f64 = 60.0;
const MAX_SECRET: usize = 64 << 10;
const MAX_KEY: usize = 32 << 10;
// Step-up (roadmap section 14, "Step-up checked inside"). A person proves who they are to the enclave itself, with a password whose
// hash it holds or a FIDO2 assertion against a public key it holds, and gets a session token that is good for this long. The
// tokens rotate by themselves: none lives longer, none survives a lock or a restart, and the web app cannot make one.
const STEPUP_SECS: u64 = 300;
const STEPUP_PER_MINUTE: f64 = 5.0;
const CHALLENGE_SECS: u64 = 120;
const MAX_TOKENS: usize = 64;
const MAX_CHALLENGES: usize = 16;
const MAX_FIDO_KEYS: usize = 8;
// The password hash the enclave holds: Argon2id at 19 MiB and two passes, checked at most STEPUP_PER_MINUTE times a minute a person.
const PW_MEMORY_KIB: u32 = 19 * 1024;
const PW_TIME: u32 = 2;
const PW_MIN: usize = 12;
/// Limits per kind of task, a minute: every signature says what kind of task it is for, and each kind has its own allowance on top
/// of the one per key. The kind is the web app's word, so it cannot be used to get more out of a key than the key's own limit
/// gives; what it does is keep one kind of work (a console, a runaway job) from using up what the others need, and show in the
/// counts which kind asked for what. A kind that is not listed counts as `other`.
const TASKS: [(&str, f64); 9] = [("scan", 1200.0), ("deploy", 600.0), ("console", 120.0), ("device", 300.0), ("access", 60.0), ("rotate", 120.0), ("git", 300.0), ("sign", 300.0), ("other", 120.0)];
/// Secrets released a minute for one kind of step or platform, and an hour altogether.
const RELEASE_PER_KIND_PER_MINUTE: f64 = 120.0;
const RELEASES_PER_HOUR: f64 = 600.0;
const MAX_RELEASE_KINDS: usize = 64;
/// How many names a secret's policy may hold in each of its lists.
const MAX_POLICY_NAMES: usize = 32;
/// Entries of the audit log taken in at once when the enclave catches up with what others wrote.
const MAX_ADVANCE: usize = 512;

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// X25519: a scalar times a point, and the point of a scalar. A result of all zeros is a point of small order: refused.
fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let out = Zeroizing::new(curve25519_dalek::montgomery::MontgomeryPoint(*point).mul_clamped(*scalar).to_bytes());
    if out.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        None
    } else {
        Some(out)
    }
}

fn x25519_public(scalar: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*scalar).to_bytes()
}

/// The Noise handshake's state, as the specification names it: the hash of everything said so far, the chaining key, and the
/// key the next part of the handshake is encrypted under.
struct Noise {
    h: [u8; 32],
    ck: Zeroizing<[u8; 32]>,
    k: Option<Zeroizing<[u8; 32]>>,
    n: u64,
}

impl Noise {
    fn new() -> Self {
        let mut h = [0u8; 32];
        h[..NOISE_NAME.len()].copy_from_slice(NOISE_NAME);
        let mut noise = Noise { h, ck: Zeroizing::new(h), k: None, n: 0 };
        noise.mix_hash(NOISE_PROLOGUE);
        noise
    }

    fn mix_hash(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.h = Sha256::new().chain_update(self.h).chain_update(data).finalize().into();
    }

    /// HKDF as Noise uses it, for two outputs.
    fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let temp = Zeroizing::new(hmac256(ck, &[ikm]));
        let one = Zeroizing::new(hmac256(temp.as_ref(), &[&[1u8]]));
        let two = Zeroizing::new(hmac256(temp.as_ref(), &[one.as_ref(), &[2u8]]));
        (one, two)
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = Self::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let out = match &self.k {
            Some(k) => {
                let out = Channel::seal_with(k, self.n, &self.h, plain)?;
                self.n += 1;
                out
            }
            None => plain.to_vec(),
        };
        self.mix_hash(&out);
        Some(out)
    }
}

/// One direction of a connection after the handshake: a key and a count of the messages it has encrypted.
struct Channel {
    key: Zeroizing<[u8; 32]>,
    n: u64,
}

impl Channel {
    fn nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    fn seal_with(key: &[u8; 32], n: u64, aad: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
        Aes256Gcm::new_from_slice(key).ok()?.encrypt(Nonce::from_slice(&Self::nonce(n)), Payload { msg: plain, aad }).ok()
    }

    fn seal(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let out = Self::seal_with(&self.key, self.n, &[], plain)?;
        self.n += 1;
        Some(out)
    }

    fn open(&mut self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let plain = Aes256Gcm::new_from_slice(self.key.as_ref()).ok()?.decrypt(Nonce::from_slice(&Self::nonce(self.n)), Payload { msg: sealed, aad: &[] }).ok()?;
        self.n += 1;
        Some(Zeroizing::new(plain))
    }
}

/// A token bucket: `per_minute` a minute, with one minute saved up.
struct Bucket {
    tokens: f64,
    at: Instant,
    per_minute: f64,
    /// The most that is ever saved up.
    most: f64,
}

impl Bucket {
    fn new(per_minute: f64) -> Self {
        Bucket { tokens: per_minute, at: Instant::now(), per_minute, most: per_minute }
    }
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.per_minute / 60.0).min(self.most);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct State {
    kek: Option<Zeroizing<[u8; 32]>>,
    audit: Option<Zeroizing<Vec<u8>>>,
    bad: u32,
    lockdown: bool,
    unlocks: Bucket,
    signs: HashMap<String, Bucket>,
    /// The KEK the vault is being moved to, while a rotation of the vault secret is under way.
    next: Option<Zeroizing<[u8; 32]>>,
    releases: HashMap<String, Bucket>,
    released: u64,
    /// Whether this process's memory is locked, and whether it is the micro VM's only program: status says both, so the web app can
    /// tell the enclave from a test double of it.
    memory_locked: bool,
    pid1: bool,
    signed: u64,
    refused: u64,
    /// Whether making or rotating a key needs a step-up token. It turns on when a step-up record is enrolled or shown, or when
    /// whoever unlocks asks for it, and stays on until the VM restarts: a lock or a lock-down does not turn it off.
    stepup_required: bool,
    tokens: HashMap<String, Token>,
    challenges: HashMap<String, Instant>,
    stepups: HashMap<String, Bucket>,
    stepup_ok: u64,
    stepup_failed: u64,
    token_secs: u64,
    chain: Chain,
    /// Per kind of task: its allowance, what it signed and what it was refused.
    tasks: HashMap<&'static str, (Bucket, u64, u64)>,
    release_kinds: HashMap<String, Bucket>,
    release_hour: Bucket,
    /// Requests whose ciphertext or secret did not authenticate, and requests that came without the step-up they needed: what
    /// someone trying things looks like from inside.
    auth_failed: u64,
    stepup_missing: u64,
    policy_refused: u64,
    started: Instant,
    /// The vault secret and, where the vault has a second lock, the host's share: held from unlock to lock, here and nowhere
    /// else, so that the KEK can be derived again under a new salt on a schedule without anyone handing the secret over again.
    held: Option<Held>,
    next_held: Option<Held>,
    /// The enclave's own key for the channel, made as it starts: its public half is what a client pins.
    static_secret: Zeroizing<[u8; 32]>,
    static_public: [u8; 32],
    handshakes: u64,
}

struct Held {
    secret: Zeroizing<Vec<u8>>,
    share: Option<Zeroizing<Vec<u8>>>,
}

/// The head of the audit chain, as the enclave last signed it (roadmap section 14, "The audit log's key"). It is kept here, in
/// memory the database's owner cannot reach, so a log that was cut short in the database no longer ends where the enclave says.
#[derive(Default)]
struct Chain {
    /// The hash of the entry signed last, and of the one before it.
    head: Option<String>,
    prior: Option<String>,
    /// Whether the entry signed last was one the enclave made itself, for a release.
    head_release: bool,
    appended: u64,
    taken_in: u64,
    /// Entries that were signed and then not written: the next entry followed the one before them.
    unwritten: u64,
    releases_unwritten: u64,
    /// An entry was offered that follows neither the head nor the one before it, and the log has not been shown to lead there.
    behind: bool,
}

impl Chain {
    /// A new entry `hash` that says it follows `prev`. Refused when the enclave has signed past `prev`: the caller shows how
    /// the log got from the head to `prev` (`advance`), or the log was cut.
    fn append(&mut self, prev: &str, hash: &str, release: bool) -> Result<(), Refusal> {
        if self.head.as_deref().is_some_and(|h| h != prev) {
            if self.prior.as_deref() != Some(prev) {
                self.behind = true;
                return no("chain", "the audit log does not end where the enclave last signed it");
            }
            // what was signed last never reached the log: a write that failed, or an entry that was held back
            self.unwritten += 1;
            if self.head_release {
                self.releases_unwritten += 1;
            }
        }
        self.prior = Some(prev.to_string());
        self.head = Some(hash.to_string());
        self.head_release = release;
        self.appended += 1;
        self.behind = false;
        Ok(())
    }

    fn status(&self) -> Value {
        json!({"head": self.head, "prior": self.prior, "head_release": self.head_release, "appended": self.appended, "taken_in": self.taken_in,
               "unwritten": self.unwritten, "releases_unwritten": self.releases_unwritten, "behind": self.behind})
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A name in a secret's policy or in what a release is for: a step kind, a host, a platform. Only what needs no escaping in
/// JSON, so the audit entry made here is byte for byte the one the controller would write.
fn policy_name(text: &str) -> bool {
    !text.is_empty() && text.len() <= 253 && text.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// A policy as it is sealed with its secret and stored beside it: sorted, with nothing in it but names. Returns the text and
/// what it says.
struct Policy {
    steps: Vec<String>,
    hosts: Vec<String>,
    platforms: Vec<String>,
    sensitive: bool,
}

impl Policy {
    fn names(v: &Value, name: &str) -> Result<Vec<String>, Refusal> {
        let mut out = Vec::new();
        match v.get(name) {
            None | Some(Value::Null) => {}
            Some(Value::Array(list)) if list.len() <= MAX_POLICY_NAMES => {
                for item in list {
                    match item.as_str() {
                        Some(t) if policy_name(t) => out.push(t.to_string()),
                        _ => return bad(format!("{name} holds names of letters, digits, dot, dash, colon and underscore")),
                    }
                }
            }
            _ => return bad(format!("{name} is a list of at most {MAX_POLICY_NAMES} names")),
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn read(v: &Value) -> Result<Policy, Refusal> {
        if !v.is_object() {
            return bad("a policy is an object");
        }
        let sensitive = match v.get("sensitive") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            _ => return bad("sensitive is true or false"),
        };
        Ok(Policy { steps: Self::names(v, "steps")?, hosts: Self::names(v, "hosts")?, platforms: Self::names(v, "platforms")?, sensitive })
    }

    fn text(&self) -> String {
        json!({"hosts": self.hosts, "platforms": self.platforms, "sensitive": self.sensitive, "steps": self.steps}).to_string()
    }

    /// The policy stored beside a secret, as text. It has to be the text it was sealed with, to the byte: it is in the
    /// ciphertext's associated data.
    fn stored(v: &Value) -> Result<Option<(String, Policy)>, Refusal> {
        match v.get("policy") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) if text.len() <= 64 << 10 => {
                let Ok(parsed) = serde_json::from_str::<Value>(text) else { return bad("policy is not JSON") };
                let policy = Self::read(&parsed)?;
                if policy.text() != *text {
                    return no("auth", "that is not the policy this secret was sealed with");
                }
                Ok(Some((text.clone(), policy)))
            }
            _ => bad("policy is the text stored beside the secret"),
        }
    }

    fn allows(&self, step: &str, host: &str, platform: &str) -> Result<(), Refusal> {
        for (list, named, what) in [(&self.steps, step, "step"), (&self.hosts, host, "host"), (&self.platforms, platform, "platform")] {
            if !list.is_empty() && !list.iter().any(|n| n == named) {
                return no("policy", format!("this secret is not released for that {what}: its policy names {}", list.join(", ")));
            }
        }
        Ok(())
    }
}

/// A session token: who proved themselves, and until when it counts.
struct Token {
    user: String,
    until: Instant,
}

/// What the enclave holds about one person, sealed under the KEK and kept in the controller's database like every other ciphertext.
#[derive(Deserialize)]
struct Record {
    user: String,
    salt: String,
    hash: String,
    #[serde(default)]
    fido: Vec<FidoKey>,
    #[serde(default)]
    rp: String,
    #[serde(default)]
    origin: String,
}

#[derive(Deserialize)]
struct FidoKey {
    id: String,
    key: String,
}

/// An account name as users.py takes one.
fn user_name(v: &Value, name: &str) -> Result<String, Refusal> {
    match v.get(name).and_then(Value::as_str) {
        Some(u) if !u.is_empty() && u.len() <= 64 && u.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-') => Ok(u.to_string()),
        _ => bad(format!("{name} is not an account name")),
    }
}

fn text(v: &Value, name: &str, most: usize) -> Result<String, Refusal> {
    match v.get(name).and_then(Value::as_str) {
        Some(t) if t.len() <= most && t.bytes().all(|c| (0x20..0x7f).contains(&c)) => Ok(t.to_string()),
        None => Ok(String::new()),
        _ => bad(format!("{name} is at most {most} printable characters")),
    }
}

fn random_hex(n: usize) -> String {
    use rand_core::RngCore;
    let mut raw = Zeroizing::new(vec![0u8; n]);
    rand_core::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash of a step-up password, as the enclave keeps it.
fn password_hash(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let params = argon2::Params::new(PW_MEMORY_KIB, PW_TIME, 1, Some(32)).or_else(|_| no("crypto", "Argon2id refuses the password costs"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    let mut blocks: Vec<argon2::Block> = Vec::new();
    if blocks.try_reserve_exact(params.block_count()).is_err() {
        return no("crypto", "not enough memory in the enclave to check a password");
    }
    blocks.resize(params.block_count(), argon2::Block::default());
    let done = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params).hash_password_into_with_memory(password, salt, out.as_mut(), &mut blocks);
    for b in blocks.iter_mut() {
        *b = argon2::Block::default();
    }
    done.or_else(|_| no("crypto", "Argon2id failed on the password"))?;
    Ok(out)
}

/// An ECDSA signature as a FIDO2 token sends it (DER: a sequence of two integers), as the two 32-byte numbers. Read here, in one
/// pass and bounded by what is there, so that no DER library is in the enclave.
fn der_signature(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    fn int(b: &[u8]) -> Option<([u8; 32], &[u8])> {
        if b.len() < 2 || b[0] != 0x02 {
            return None;
        }
        let n = b[1] as usize;
        if n == 0 || n > 33 || b.len() < 2 + n {
            return None;
        }
        let mut digits = &b[2..2 + n];
        if digits.len() == 33 {
            if digits[0] != 0 {
                return None;
            }
            digits = &digits[1..];
        }
        let mut out = [0u8; 32];
        out[32 - digits.len()..].copy_from_slice(digits);
        Some((out, &b[2 + n..]))
    }
    if der.len() < 8 || der.len() > 72 || der[0] != 0x30 || der[1] as usize != der.len() - 2 {
        return None;
    }
    let (r, rest) = int(&der[2..])?;
    let (s, rest) = int(rest)?;
    if rest.is_empty() {
        Some((r, s))
    } else {
        None
    }
}

fn b64url(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// Why a request was refused. `Bad` is a request no honest client sends: it counts towards the lock-down and ends the connection.
enum Refusal {
    Bad(String),
    No(&'static str, String),
}

type Answer = Result<Value, Refusal>;

fn bad<T>(why: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::Bad(why.into()))
}

fn no<T>(code: &'static str, why: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::No(code, why.into()))
}

fn bytes(v: &Value, name: &str, most: usize) -> Result<Vec<u8>, Refusal> {
    let text = match v.get(name).and_then(Value::as_str) {
        Some(t) => t,
        None => return bad(format!("{name} is missing")),
    };
    if text.len() > most * 4 / 3 + 4 {
        return bad(format!("{name} is too long"));
    }
    match B64.decode(text) {
        Ok(b) if b.len() <= most => Ok(b),
        _ => bad(format!("{name} is not base64 of at most {most} bytes")),
    }
}

fn nonce(v: &Value, name: &str) -> Result<[u8; 12], Refusal> {
    let b = bytes(v, name, 12)?;
    <[u8; 12]>::try_from(b.as_slice()).or_else(|_| bad(format!("{name} is not 12 bytes")))
}

/// A row's uuid as the vault makes it: 32 hex digits. It goes into the associated data, so nothing else may.
fn uuid(v: &Value) -> Result<String, Refusal> {
    match v.get("uuid").and_then(Value::as_str) {
        Some(u) if u.len() == 32 && u.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) => Ok(u.to_string()),
        _ => bad("uuid is not 32 lower-case hex digits"),
    }
}

/// A private key as the enclave holds it for the length of one signature.
enum Secret {
    Ed25519(Zeroizing<[u8; 32]>),
    P256(Zeroizing<Vec<u8>>),
    P384(Zeroizing<Vec<u8>>),
    Rsa { n: Vec<u8>, e: Vec<u8>, d: Zeroizing<Vec<u8>>, p: Zeroizing<Vec<u8>>, q: Zeroizing<Vec<u8>> },
}

/// The fields of an SSH wire blob, read in order. Every read is bounded by what is left, so a length that lies ends the parse.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// A number, without the zero byte SSH puts before one whose top bit is set.
    fn mpint(&mut self) -> Option<&'a [u8]> {
        let mut b = self.string()?;
        while b.len() > 1 && b[0] == 0 {
            b = &b[1..];
        }
        Some(b)
    }
}

fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A number as SSH writes it: no leading zeros, and one zero byte before a top bit that is set.
fn ssh_mpint(out: &mut Vec<u8>, mut bytes: &[u8]) {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        out.extend_from_slice(&(bytes.len() as u32 + 1).to_be_bytes());
        out.push(0);
    } else {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// A number left-padded with zeros to `size` bytes, or None when it is longer: the fixed width a curve's scalar is given in.
fn padded(bytes: &[u8], size: usize) -> Option<Zeroizing<Vec<u8>>> {
    if bytes.len() > size {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; size]);
    out[size - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

/// An unencrypted OpenSSH private key (the `openssh-key-v1` container, PROTOCOL.key), read here and not by a library: the vault stores
/// what Python's `cryptography` wrote, whose line width and number widths two parsers took three different ways. Returns the key and
/// its public half in SSH wire form. Anything it does not expect is None: one key, no passphrase, ed25519, ECDSA P-256 or P-384, or RSA.
fn parse_openssh(pem: &[u8]) -> Option<(Secret, Vec<u8>)> {
    let text = std::str::from_utf8(pem).ok()?;
    let mut body = Zeroizing::new(String::with_capacity(text.len()));
    let (mut began, mut ended) = (false, false);
    for line in text.lines().map(str::trim) {
        match line {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => began = true,
            "-----END OPENSSH PRIVATE KEY-----" => ended = true,
            _ if began && !ended => body.push_str(line),
            _ => {}
        }
    }
    if !began || !ended {
        return None;
    }
    let blob = Zeroizing::new(B64.decode(body.as_bytes()).ok()?);
    let mut w = Wire(&blob);
    if w.take(15)? != b"openssh-key-v1\0" || w.string()? != b"none" || w.string()? != b"none" || !w.string()?.is_empty() || w.u32()? != 1 {
        return None;
    }
    let public = w.string()?.to_vec();
    let mut w = Wire(w.string()?);
    if w.u32()? != w.u32()? {
        return None; // the two check numbers differ: not decrypted, or not a key
    }
    let kind = w.string()?;
    let secret = match kind {
        b"ssh-ed25519" => {
            let (pk, sk) = (w.string()?, w.string()?);
            if pk.len() != 32 || sk.len() != 64 || &sk[32..] != pk {
                return None;
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&sk[..32]);
            Secret::Ed25519(seed)
        }
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" => {
            let (curve, _point, d) = (w.string()?, w.string()?, w.mpint()?);
            match (kind, curve) {
                (b"ecdsa-sha2-nistp256", b"nistp256") => Secret::P256(padded(d, 32)?),
                (b"ecdsa-sha2-nistp384", b"nistp384") => Secret::P384(padded(d, 48)?),
                _ => return None,
            }
        }
        b"ssh-rsa" => {
            let (n, e, d, _iqmp, p, q) = (w.mpint()?, w.mpint()?, w.mpint()?, w.mpint()?, w.mpint()?, w.mpint()?);
            Secret::Rsa { n: n.to_vec(), e: e.to_vec(), d: Zeroizing::new(d.to_vec()), p: Zeroizing::new(p.to_vec()), q: Zeroizing::new(q.to_vec()) }
        }
        _ => return None,
    };
    // the public half stored beside it must be this key's: its type, at the least
    if Wire(&public).string()? != kind {
        return None;
    }
    Some((secret, public))
}

/// One signature in SSH wire form: a string naming the algorithm, then a string holding the signature.
fn sign_with(secret: &Secret, data: &[u8], flags: u64) -> Option<Vec<u8>> {
    use signature::{SignatureEncoding, Signer};
    let (name, sig): (&[u8], Vec<u8>) = match secret {
        Secret::Ed25519(seed) => (b"ssh-ed25519", ed25519_dalek::SigningKey::from_bytes(seed).try_sign(data).ok()?.to_bytes().to_vec()),
        Secret::P256(d) => {
            let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(d).ok()?.try_sign(data).ok()?;
            let (r, s) = sig.split_bytes();
            let mut both = Vec::new();
            ssh_mpint(&mut both, &r);
            ssh_mpint(&mut both, &s);
            (b"ecdsa-sha2-nistp256", both)
        }
        Secret::P384(d) => {
            let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(d).ok()?.try_sign(data).ok()?;
            let (r, s) = sig.split_bytes();
            let mut both = Vec::new();
            ssh_mpint(&mut both, &r);
            ssh_mpint(&mut both, &s);
            (b"ecdsa-sha2-nistp384", both)
        }
        // an RSA key signs with the hash the agent protocol's flags ask for, SHA-512 when they ask for neither or both: never SHA-1
        Secret::Rsa { n, e, d, p, q } => {
            let big = |b: &[u8]| rsa::BigUint::from_bytes_be(b);
            let private = rsa::RsaPrivateKey::from_components(big(n), big(e), big(d), vec![big(p), big(q)]).ok()?;
            if flags & 2 != 0 && flags & 4 == 0 {
                (b"rsa-sha2-256", rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private).try_sign(data).ok()?.to_vec())
            } else {
                (b"rsa-sha2-512", rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private).try_sign(data).ok()?.to_vec())
            }
        }
    };
    let mut wire = Vec::with_capacity(sig.len() + name.len() + 8);
    ssh_string(&mut wire, name);
    ssh_string(&mut wire, &sig);
    Some(wire)
}

fn open(key: &[u8], nonce: &[u8; 12], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let cipher = Aes256Gcm::new_from_slice(key).or_else(|_| no("crypto", "the key is not 32 bytes"))?;
    match cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: blob, aad }) {
        Ok(plain) => Ok(Zeroizing::new(plain)),
        Err(_) => no("auth", "authentication failed: wrong secret, or a ciphertext that was changed or moved"),
    }
}

fn seal(key: &[u8], plain: &[u8], aad: &[u8]) -> Result<([u8; 12], Vec<u8>), Refusal> {
    use rand_core::RngCore;
    let mut n = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut n);
    let cipher = Aes256Gcm::new_from_slice(key).or_else(|_| no("crypto", "the key is not 32 bytes"))?;
    match cipher.encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad }) {
        Ok(ct) => Ok((n, ct)),
        Err(_) => no("crypto", "encryption failed"),
    }
}

impl State {
    fn new(memory_locked: bool) -> Self {
        use rand_core::RngCore;
        let mut static_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(static_secret.as_mut());
        let static_public = x25519_public(&static_secret);
        State {
            static_secret,
            static_public,
            handshakes: 0,
            memory_locked,
            pid1: std::process::id() == 1,
            kek: None,
            audit: None,
            bad: 0,
            lockdown: false,
            unlocks: Bucket::new(UNLOCK_PER_MINUTE),
            signs: HashMap::new(),
            next: None,
            releases: HashMap::new(),
            released: 0,
            signed: 0,
            refused: 0,
            stepup_required: false,
            tokens: HashMap::new(),
            challenges: HashMap::new(),
            stepups: HashMap::new(),
            stepup_ok: 0,
            stepup_failed: 0,
            token_secs: STEPUP_SECS,
            chain: Chain::default(),
            tasks: HashMap::new(),
            release_kinds: HashMap::new(),
            // an hour's allowance, refilled evenly: Bucket counts by the minute
            release_hour: Bucket { tokens: RELEASES_PER_HOUR, at: Instant::now(), per_minute: RELEASES_PER_HOUR / 60.0, most: RELEASES_PER_HOUR },
            auth_failed: 0,
            stepup_missing: 0,
            policy_refused: 0,
            started: Instant::now(),
            held: None,
            next_held: None,
        }
    }

    fn wipe(&mut self) {
        self.kek = None; // Zeroizing clears it as it goes
        self.audit = None;
        self.next = None;
        self.held = None;
        self.next_held = None;
        self.signs.clear();
        self.releases.clear();
        self.tokens.clear(); // a token does not outlive the keys it was good for
        self.challenges.clear();
    }

    fn kek(&self) -> Result<&[u8; 32], Refusal> {
        match &self.kek {
            Some(k) => Ok(k),
            None => no("locked", "the enclave is locked"),
        }
    }

    fn status(&self) -> Value {
        json!({"ok": true, "protocol": PROTOCOL, "version": env!("CARGO_PKG_VERSION"), "state": if self.lockdown { "lockdown" } else if self.kek.is_some() { "unlocked" } else { "locked" },
               "bad_requests": self.bad, "bad_limit": BAD_LIMIT, "signed": self.signed, "refused": self.refused, "released": self.released, "rotating": self.next.is_some(),
               "memory_locked": self.memory_locked, "pid1": self.pid1,
               "chain": self.chain.status(),
               "auth_failed": self.auth_failed, "stepup_missing": self.stepup_missing, "policy_refused": self.policy_refused, "uptime": self.started.elapsed().as_secs(),
               "second_lock": self.held.as_ref().is_some_and(|h| h.share.is_some()),
               "channel": {"noise": "Noise_NX_25519_AESGCM_SHA256", "key": B64.encode(self.static_public), "handshakes": self.handshakes},
               "tasks": self.tasks.iter().map(|(name, (_, signed, refused))| (name.to_string(), json!({"signed": signed, "refused": refused}))).collect::<serde_json::Map<String, Value>>(),
               "stepup": {"required": self.stepup_required, "ok": self.stepup_ok, "failed": self.stepup_failed, "tokens": self.tokens.len(), "token_seconds": self.token_secs},
               "limits": {"sign_per_key_per_minute": SIGN_PER_MINUTE, "unlock_per_minute": UNLOCK_PER_MINUTE, "release_per_secret_per_minute": RELEASE_PER_MINUTE, "stepup_per_person_per_minute": STEPUP_PER_MINUTE,
                          "release_per_kind_per_minute": RELEASE_PER_KIND_PER_MINUTE, "releases_per_hour": RELEASES_PER_HOUR,
                          "sign_per_task_per_minute": TASKS.iter().map(|(name, limit)| (name.to_string(), json!(limit))).collect::<serde_json::Map<String, Value>>(),
                          "max_frame": MAX_FRAME, "max_sign_data": MAX_SIGN_DATA}})
    }

    /// A KEK from a secret, a salt and Argon2id costs, as vault.py derives it. Counted against the unlock limit: it is the costly
    /// thing to ask for, and the only place a guess at the secret can be tried. With `share` it is the KEK of a vault with a
    /// second lock: the host's share is mixed in, so the secret alone derives a key that opens nothing.
    fn derive(&mut self, v: &Value) -> Result<(Zeroizing<[u8; 32]>, Held), Refusal> {
        if !self.unlocks.take() {
            return no("rate", "too many unlock attempts: wait a minute");
        }
        let secret = Zeroizing::new(bytes(v, "secret", 4096)?);
        let share = match v.get("share") {
            None | Some(Value::Null) => None,
            Some(_) => Some(Zeroizing::new(bytes(v, "share", 64)?)),
        };
        let kek = Self::kdf(&secret, share.as_ref().map(|s| s.as_slice()), v)?;
        Ok((kek, Held { secret, share }))
    }

    fn kdf(secret: &[u8], share: Option<&[u8]>, v: &Value) -> Result<Zeroizing<[u8; 32]>, Refusal> {
        let salt = bytes(v, "salt", 64)?;
        let num = |name: &str| v.get(name).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
        let (Some(t), Some(m), Some(p)) = (num("time_cost"), num("memory_kib"), num("lanes")) else {
            return bad("time_cost, memory_kib and lanes are whole numbers");
        };
        if secret.len() < 32 || salt.len() < 8 || !KDF_TIME.contains(&t) || !KDF_MEMORY_KIB.contains(&m) || !KDF_LANES.contains(&p) || share.is_some_and(|s| s.len() != 32) {
            return bad("the secret, the salt, the share or the Argon2id costs are outside what the enclave takes");
        }
        let params = argon2::Params::new(m, t, p, Some(32)).or_else(|_| bad("Argon2id refuses those costs"))?;
        let mut kek = Zeroizing::new([0u8; 32]);
        // the memory Argon2id works in is asked for here, so that not having it is an answer and not the end of the process
        let mut blocks: Vec<argon2::Block> = Vec::new();
        if blocks.try_reserve_exact(params.block_count()).is_err() {
            return no("crypto", "not enough memory in the enclave for those Argon2id costs");
        }
        blocks.resize(params.block_count(), argon2::Block::default());
        let derived = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params).hash_password_into_with_memory(secret, &salt, kek.as_mut(), &mut blocks);
        for b in blocks.iter_mut() {
            *b = argon2::Block::default();
        }
        derived.or_else(|_| no("crypto", "Argon2id failed with those costs"))?;
        if let Some(share) = share {
            // the second lock: HMAC-SHA256 keyed with the host's share over a label and the secret's key. vault.py's second_lock_mix
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(share).or_else(|_| no("crypto", "the share is unusable"))?;
            mac.update(b"storageforge:second-lock:v1\0");
            mac.update(kek.as_ref());
            kek.copy_from_slice(&mac.finalize().into_bytes());
        }
        Ok(kek)
    }

    /// The vault secret arrives once, here. The KEK is derived as vault.py derives it, proved against the stored verifier, and kept;
    /// the audit MAC key is unwrapped and kept. The secret is zeroed before this returns, whatever happened.
    fn unlock(&mut self, v: &Value) -> Answer {
        let (kek, held) = self.derive(v)?;
        let (vn, vct, an, act) = (nonce(v, "verifier_nonce")?, bytes(v, "verifier", 256)?, nonce(v, "audit_key_nonce")?, bytes(v, "audit_key_wrapped", 256)?);
        let wrong = if held.share.is_some() { "wrong vault secret, or not the share of the machine this vault is locked to: the stored verifier did not authenticate" } else { "wrong vault secret: the stored verifier did not authenticate" };
        let check = open(kek.as_ref(), &vn, &vct, b"storageforge:verifier").or_else(|_| no("auth", wrong))?;
        if check.ct_eq(VERIFIER).unwrap_u8() != 1 {
            return no("auth", "wrong vault secret: the stored verifier did not authenticate");
        }
        let audit = open(kek.as_ref(), &an, &act, b"storageforge:audit-key")?;
        // Whoever unlocks may ask for step-up, and showing one enrolled record turns it on: the records are sealed under this KEK,
        // so one that opens was made by this enclave's vault. Leaving them out cannot turn it off again before a restart.
        if v.get("stepup").and_then(Value::as_str) == Some("required") {
            self.stepup_required = true;
        }
        if let Some(records) = v.get("records").and_then(Value::as_array) {
            if records.len() > 64 {
                return bad("at most 64 step-up records are shown at unlock");
            }
            if records.iter().any(|r| Self::open_record(kek.as_ref(), r).is_ok()) {
                self.stepup_required = true;
            }
        }
        // A lock-down is lifted by a person. Where step-up is on, the enclave checks that person itself: the secret alone, which
        // a starter also holds, does not lift it.
        if self.lockdown && self.stepup_required {
            match v.get("proof") {
                Some(proof) => {
                    self.check_proof(proof, kek.as_ref())?;
                }
                None => return no("stepup", "the enclave is locked down: unlocking it takes the vault secret and a step-up it checks itself, a password or a security key"),
            }
        }
        self.kek = Some(kek);
        self.audit = Some(audit);
        self.held = Some(held);
        self.lockdown = false; // only a person with the secret lifts a lock-down
        self.bad = 0;
        Ok(json!({"ok": true, "state": "unlocked", "stepup": self.stepup_required}))
    }

    /// One person's step-up record, opened under `kek`. The envelope is the vault's: a DEK wrapped under the KEK, and the record
    /// under the DEK with associated data that names its purpose and row.
    fn open_record(kek: &[u8], r: &Value) -> Result<Record, Refusal> {
        let id = uuid(r)?;
        let dek = open(kek, &nonce(r, "dek_nonce")?, &bytes(r, "wrapped_dek", 128)?, format!("storageforge:dek:{id}").as_bytes())?;
        let plain = open(&dek, &nonce(r, "nonce")?, &bytes(r, "ciphertext", 16 << 10)?, format!("storageforge:stepup:{id}").as_bytes())?;
        serde_json::from_slice::<Record>(&plain).or_else(|_| no("auth", "that is not a step-up record"))
    }

    /// The proof of one person, checked here: `user`, their `record`, and a `password` or a `fido` assertion. Limited per person,
    /// and every failure is counted. Returns the account name.
    fn check_proof(&mut self, v: &Value, kek: &[u8]) -> Result<String, Refusal> {
        let user = user_name(v, "user")?;
        let Some(sealed) = v.get("record") else { return bad("record is missing") };
        if !self.stepups.entry(user.clone()).or_insert_with(|| Bucket::new(STEPUP_PER_MINUTE)).take() {
            self.refused += 1;
            return no("rate", "too many step-up attempts for this account: wait a minute");
        }
        let record = Self::open_record(kek, sealed)?;
        self.stepup_required = true;
        let ok = if record.user != user {
            false
        } else if v.get("password").is_some() {
            let password = Zeroizing::new(bytes(v, "password", 1024)?);
            let (Ok(salt), Ok(want)) = (B64.decode(&record.salt), B64.decode(&record.hash)) else { return no("auth", "that is not a step-up record") };
            password_hash(&password, &salt)?.ct_eq(want.as_slice()).unwrap_u8() == 1
        } else if let Some(f) = v.get("fido") {
            self.fido_ok(&record, f)?
        } else {
            return bad("a proof is a password or a fido assertion");
        };
        if !ok {
            self.stepup_failed += 1;
            return no("auth", "the step-up did not check out: wrong password, or a security key the enclave does not hold");
        }
        self.stepup_ok += 1;
        Ok(user)
    }

    /// A FIDO2 assertion, checked as webauthn.py checks one, against a public key the record holds and a challenge the enclave
    /// itself gave out and has not seen answered. The web app can neither make the challenge nor use an answer twice.
    fn fido_ok(&mut self, record: &Record, f: &Value) -> Result<bool, Refusal> {
        use signature::Verifier;
        let (Some(id), auth, client, sig) = (f.get("id").and_then(Value::as_str), bytes(f, "authenticator_data", 1024)?, bytes(f, "client_data", 4096)?, bytes(f, "signature", 80)?) else {
            return bad("a fido assertion has id, authenticator_data, client_data and signature");
        };
        let Ok(data) = serde_json::from_slice::<Value>(&client) else { return Ok(false) };
        let Some(challenge) = data.get("challenge").and_then(Value::as_str) else { return Ok(false) };
        // used up whatever follows: an assertion is tried once
        let fresh = matches!(self.challenges.remove(challenge), Some(until) if Instant::now() < until);
        if !fresh || data.get("type").and_then(Value::as_str) != Some("webauthn.get") || data.get("origin").and_then(Value::as_str) != Some(record.origin.as_str()) {
            return Ok(false);
        }
        use sha2::Digest;
        if auth.len() < 37 || auth[..32] != Sha256::digest(record.rp.as_bytes())[..] || auth[32] & 1 == 0 {
            return Ok(false);
        }
        let Some(key) = record.fido.iter().find(|k| k.id == id).and_then(|k| b64url(&k.key)) else { return Ok(false) };
        let (Ok(key), Some((r, s))) = (p256::ecdsa::VerifyingKey::from_sec1_bytes(&key), der_signature(&sig)) else { return Ok(false) };
        let Ok(sig) = p256::ecdsa::Signature::from_scalars(r, s) else { return Ok(false) };
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        Ok(key.verify(&signed, &sig).is_ok())
    }

    /// Whether this request carries what the vault secret's holder would: the secret itself, derived and compared with the KEK
    /// in use. A command run by whoever holds the secret needs no person beside it.
    fn holds_secret(&mut self, v: &Value) -> Result<bool, Refusal> {
        let kek = *self.kek()?;
        let (derived, _) = self.derive(v)?;
        Ok(derived.ct_eq(&kek).unwrap_u8() == 1)
    }

    fn issue(&mut self, user: String) -> Value {
        let now = Instant::now();
        self.tokens.retain(|_, t| t.until > now);
        if self.tokens.len() >= MAX_TOKENS {
            // the oldest goes: a flood of step-ups cannot grow this without bound
            if let Some(oldest) = self.tokens.iter().min_by_key(|(_, t)| t.until).map(|(k, _)| k.clone()) {
                self.tokens.remove(&oldest);
            }
        }
        let token = random_hex(32);
        self.tokens.insert(token.clone(), Token { user: user.clone(), until: now + Duration::from_secs(self.token_secs) });
        json!({"ok": true, "token": token, "seconds": self.token_secs, "user": user})
    }

    /// A step-up: a person's proof, or the vault secret from whoever holds it, exchanged for a session token.
    fn stepup(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        if v.get("secret").is_some() {
            if !self.holds_secret(v)? {
                self.stepup_failed += 1;
                return no("auth", "that is not the vault secret");
            }
            self.stepup_ok += 1;
            return Ok(self.issue("vault-secret".to_string()));
        }
        let user = self.check_proof(v, &kek)?;
        Ok(self.issue(user))
    }

    /// A challenge for a FIDO2 assertion: random, good once and for CHALLENGE_SECS.
    fn challenge(&mut self) -> Answer {
        self.kek()?;
        let now = Instant::now();
        self.challenges.retain(|_, until| *until > now);
        if self.challenges.len() >= MAX_CHALLENGES {
            self.refused += 1;
            return no("rate", "too many step-up challenges are waiting for an answer");
        }
        use rand_core::RngCore;
        let mut raw = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut raw);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        self.challenges.insert(challenge.clone(), now + Duration::from_secs(CHALLENGE_SECS));
        Ok(json!({"ok": true, "challenge": challenge, "seconds": CHALLENGE_SECS}))
    }

    /// The token of a step-up, where one is needed: for making or rotating a key once step-up is on, and always for what is
    /// marked sensitive. Returns who it was.
    fn token_user(&mut self, v: &Value) -> Result<String, Refusal> {
        let now = Instant::now();
        self.tokens.retain(|_, t| t.until > now);
        match v.get("token").and_then(Value::as_str).and_then(|t| self.tokens.get(t)) {
            Some(t) => Ok(t.user.clone()),
            None => no("stepup", "this needs a step-up the enclave checks itself: a password or a security key, typed within the last few minutes"),
        }
    }

    fn need_stepup(&mut self, v: &Value) -> Result<(), Refusal> {
        if self.stepup_required {
            self.token_user(v)?;
        }
        Ok(())
    }

    /// A person's step-up record, made here: the hash of their password, and the public keys of their FIDO2 tokens. The first
    /// one needs nothing, since until then there is no step-up to pass. After that it takes a token, or the vault secret.
    fn stepup_enroll(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        let (id, user) = (uuid(v)?, user_name(v, "user")?);
        if self.stepup_required {
            let by_secret = v.get("secret").is_some() && self.holds_secret(v)?;
            if !by_secret {
                self.token_user(v)?;
            }
        }
        let password = Zeroizing::new(bytes(v, "password", 1024)?);
        if password.len() < PW_MIN {
            return no("auth", "a step-up password is at least 12 characters");
        }
        let (rp, origin) = (text(v, "rp", 253)?, text(v, "origin", 300)?);
        let mut keys = Vec::new();
        if let Some(list) = v.get("fido").and_then(Value::as_array) {
            if list.len() > MAX_FIDO_KEYS {
                return bad("at most 8 security keys a person");
            }
            for k in list {
                let (Some(kid), Some(key)) = (k.get("id").and_then(Value::as_str), k.get("key").and_then(Value::as_str)) else { return bad("a security key has an id and a key") };
                if kid.len() > 1400 || !b64url(key).is_some_and(|b| p256::ecdsa::VerifyingKey::from_sec1_bytes(&b).is_ok()) {
                    return no("key", "a security key is a P-256 public key");
                }
                keys.push(json!({"id": kid, "key": key}));
            }
        }
        use rand_core::RngCore;
        let mut salt = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut salt);
        let hash = password_hash(&password, &salt)?;
        let record = Zeroizing::new(json!({"user": user, "salt": B64.encode(salt), "hash": B64.encode(*hash), "fido": keys, "rp": rp, "origin": origin}).to_string());
        let mut dek = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(dek.as_mut());
        let (dn, wd) = seal(&kek, dek.as_ref(), format!("storageforge:dek:{id}").as_bytes())?;
        let (n, ct) = seal(dek.as_ref(), record.as_bytes(), format!("storageforge:stepup:{id}").as_bytes())?;
        self.stepup_required = true;
        Ok(json!({"ok": true, "dek_nonce": B64.encode(dn), "wrapped_dek": B64.encode(wd), "nonce": B64.encode(n), "ciphertext": B64.encode(ct), "keys": keys.len()}))
    }

    /// The private key of one row, decrypted for the length of one call, with its public half.
    fn private(&self, v: &Value) -> Result<(String, Secret, Vec<u8>), Refusal> {
        let id = uuid(v)?;
        let dek = open(self.kek()?, &nonce(v, "dek_nonce")?, &bytes(v, "wrapped_dek", 128)?, format!("storageforge:dek:{id}").as_bytes())?;
        let pem = open(&dek, &nonce(v, "key_nonce")?, &bytes(v, "ciphertext", 32 << 10)?, format!("storageforge:key:{id}").as_bytes())?;
        match parse_openssh(&pem) {
            Some((secret, public)) => Ok((id, secret, public)),
            None => no("key", "what decrypted is not an OpenSSH private key the enclave signs with"),
        }
    }

    /// One signature, as an SSH agent gives it: the wire form of the signature (a string naming the algorithm, then the signature),
    /// and of the public key that made it. `flags` are the agent protocol's: 2 asks an RSA key for rsa-sha2-256, 4 for rsa-sha2-512.
    fn sign(&mut self, v: &Value) -> Answer {
        self.kek()?;
        let data = bytes(v, "data", MAX_SIGN_DATA)?;
        let flags = v.get("flags").and_then(Value::as_u64).unwrap_or(0);
        let (id, secret, public) = self.private(v)?;
        let asked = v.get("task").and_then(Value::as_str).unwrap_or("other");
        let (task, limit) = TASKS.iter().find(|(name, _)| *name == asked).copied().unwrap_or(("other", 120.0));
        let kind = self.tasks.entry(task).or_insert_with(|| (Bucket::new(limit), 0, 0));
        if !kind.0.take() {
            kind.2 += 1;
            self.refused += 1;
            return no("rate", format!("{task} tasks have signed as often as the enclave allows that kind in a minute"));
        }
        if !self.signs.entry(id).or_insert_with(|| Bucket::new(SIGN_PER_MINUTE)).take() {
            kind.2 += 1;
            self.refused += 1;
            return no("rate", "this key has signed as often as the enclave allows in a minute");
        }
        let Some(wire) = sign_with(&secret, &data, flags) else { return no("key", "that key cannot sign") };
        kind.1 += 1;
        self.signed += 1;
        Ok(json!({"ok": true, "signature": B64.encode(wire), "public": B64.encode(public)}))
    }

    /// A new key, made here. What leaves is its public half and the same two ciphertexts the vault stores: the private half never does.
    fn generate(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        self.need_stepup(v)?;
        let id = uuid(v)?;
        let algorithm = match v.get("kind").and_then(Value::as_str) {
            Some("ed25519") => Algorithm::Ed25519,
            Some("ecdsa") => Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            _ => return bad("kind is ed25519 or ecdsa"),
        };
        let comment = v.get("comment").and_then(Value::as_str).unwrap_or("");
        if comment.len() > 200 || comment.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return bad("the comment is at most 200 printable characters");
        }
        let mut key = PrivateKey::random(&mut rand_core::OsRng, algorithm).or_else(|_| no("crypto", "the key could not be made"))?;
        key.set_comment(comment);
        let pem = key.to_openssh(LineEnding::LF).or_else(|_| no("crypto", "the key could not be written"))?;
        let public = key.public_key().to_openssh().or_else(|_| no("crypto", "the public key could not be written"))?;
        use rand_core::RngCore;
        let mut dek = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(dek.as_mut());
        let (dn, wd) = seal(&kek, dek.as_ref(), format!("storageforge:dek:{id}").as_bytes())?;
        let (kn, ct) = seal(dek.as_ref(), pem.as_bytes(), format!("storageforge:key:{id}").as_bytes())?;
        Ok(json!({"ok": true, "public_key": public, "dek_nonce": B64.encode(dn), "wrapped_dek": B64.encode(wd), "key_nonce": B64.encode(kn), "ciphertext": B64.encode(ct)}))
    }

    /// A key that was made elsewhere, taken in: checked to be one the enclave can sign with, then sealed as the vault seals one.
    /// It came through the web app to get here, which is why a site can be set to take only keys made inside (`generate`).
    fn import(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        self.need_stepup(v)?;
        let id = uuid(v)?;
        let pem = Zeroizing::new(bytes(v, "private", MAX_KEY)?);
        let Some((secret, public)) = parse_openssh(&pem) else {
            return no("key", "not an unencrypted OpenSSH private key of a kind the enclave signs with");
        };
        if let Secret::Rsa { n, .. } = &secret {
            if n.len() < 384 {
                return no("key", "an RSA key shorter than 3072 bits is too weak");
            }
        }
        if sign_with(&secret, b"storageforge import check", 0).is_none() {
            return no("key", "that key cannot sign");
        }
        use rand_core::RngCore;
        let mut dek = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(dek.as_mut());
        let (dn, wd) = seal(&kek, dek.as_ref(), format!("storageforge:dek:{id}").as_bytes())?;
        let (kn, ct) = seal(dek.as_ref(), &pem, format!("storageforge:key:{id}").as_bytes())?;
        Ok(json!({"ok": true, "public": B64.encode(public), "dek_nonce": B64.encode(dn), "wrapped_dek": B64.encode(wd), "key_nonce": B64.encode(kn), "ciphertext": B64.encode(ct)}))
    }

    /// The one kind of thing that is sealed to be given back: a secret something outside has to use (a device password, a step's
    /// secret). Its associated data names the purpose, so nothing sealed as a key can be asked for as one of these.
    fn purpose(v: &Value) -> Result<&'static str, Refusal> {
        match v.get("purpose").and_then(Value::as_str) {
            Some("credential") => Ok("credential"),
            _ => bad("purpose is credential"),
        }
    }

    fn seal_secret(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        let (id, purpose) = (uuid(v)?, Self::purpose(v)?);
        let plain = Zeroizing::new(bytes(v, "plaintext", MAX_SECRET)?);
        if plain.is_empty() {
            return bad("plaintext is empty");
        }
        // A policy says what the secret may be released for, and whether releasing it takes a step-up. It is written into the
        // associated data, so the policy stored beside the secret cannot be changed or left out without the secret failing to open.
        let policy = match v.get("policy") {
            None | Some(Value::Null) => None,
            Some(p) => Some(Policy::read(p)?.text()),
        };
        let aad = match &policy {
            Some(text) => format!("storageforge:{purpose}:{id}:{text}"),
            None => format!("storageforge:{purpose}:{id}"),
        };
        use rand_core::RngCore;
        let mut dek = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(dek.as_mut());
        let (dn, wd) = seal(&kek, dek.as_ref(), format!("storageforge:dek:{id}").as_bytes())?;
        let (n, ct) = seal(dek.as_ref(), &plain, aad.as_bytes())?;
        Ok(json!({"ok": true, "dek_nonce": B64.encode(dn), "wrapped_dek": B64.encode(wd), "nonce": B64.encode(n), "ciphertext": B64.encode(ct), "policy": policy}))
    }

    /// A secret that has to leave, released for a named request: this secret, for this step, this host or this platform. What
    /// its policy does not name is refused; what is marked sensitive takes a step-up token; any one secret leaves at most
    /// RELEASE_PER_MINUTE times a minute. Each release is written up here, as an entry of the audit log signed into the chain
    /// before the secret is handed over: the controller stores the entry, and a log without it no longer ends where the enclave
    /// says it does.
    fn release(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        let Some(key) = self.audit.clone() else { return no("locked", "the enclave is locked") };
        let (id, purpose) = (uuid(v)?, Self::purpose(v)?);
        let (dn, wd, n, ct) = (nonce(v, "dek_nonce")?, bytes(v, "wrapped_dek", 128)?, nonce(v, "nonce")?, bytes(v, "ciphertext", MAX_SECRET + 16)?);
        let named = v.get("for").filter(|f| f.is_object());
        let name = |field: &str| -> Result<String, Refusal> {
            match named.and_then(|f| f.get(field)) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(t)) if t.is_empty() || policy_name(t) => Ok(t.clone()),
                _ => bad(format!("for.{field} is a name of letters, digits, dot, dash, colon and underscore")),
            }
        };
        let (step, host, platform) = (name("step")?, name("host")?, name("platform")?);
        if step.is_empty() && host.is_empty() && platform.is_empty() {
            return bad("a release names what it is for: a step, a host or a platform");
        }
        let (Some(ts), Some(prev)) = (v.get("audit").and_then(|a| a.get("ts")).and_then(Value::as_u64), v.get("audit").and_then(|a| a.get("prev")).and_then(Value::as_str)) else {
            return bad("a release comes with the time and the last entry of the audit log it will be written after");
        };
        if !is_hash(prev) {
            return bad("audit.prev is 64 hex digits");
        }
        let stored = Policy::stored(v)?;
        let (aad, sensitive) = match &stored {
            Some((text, policy)) => (format!("storageforge:{purpose}:{id}:{text}"), policy.sensitive),
            None => (format!("storageforge:{purpose}:{id}"), false),
        };
        // opened before anything is decided: only a policy that authenticates with its secret is a policy
        let dek = open(&kek, &dn, &wd, format!("storageforge:dek:{id}").as_bytes())?;
        let plain = open(&dek, &n, &ct, aad.as_bytes())?;
        if let Some((_, policy)) = &stored {
            if let Err(refusal) = policy.allows(&step, &host, &platform) {
                self.policy_refused += 1;
                return Err(refusal);
            }
        }
        let who = if sensitive { self.token_user(v)? } else { String::new() };
        if self.chain.head.as_deref().is_some_and(|h| h != prev) && self.chain.prior.as_deref() != Some(prev) {
            self.chain.behind = true;
            return no("chain", "the audit log does not end where the enclave last signed it");
        }
        if !self.releases.entry(id.clone()).or_insert_with(|| Bucket::new(RELEASE_PER_MINUTE)).take() {
            self.refused += 1;
            return no("rate", "this secret has been released as often as the enclave allows in a minute");
        }
        // per kind of task: the step it is for, else the platform, else that it is for a host
        let kind = if !step.is_empty() { format!("step:{step}") } else if !platform.is_empty() { format!("platform:{platform}") } else { "host".to_string() };
        let kind = if self.release_kinds.contains_key(&kind) || self.release_kinds.len() < MAX_RELEASE_KINDS { kind } else { "other".to_string() };
        if !self.release_kinds.entry(kind).or_insert_with(|| Bucket::new(RELEASE_PER_KIND_PER_MINUTE)).take() {
            self.refused += 1;
            return no("rate", "secrets for that kind of task have been released as often as the enclave allows in a minute");
        }
        if !self.release_hour.take() {
            self.refused += 1;
            return no("rate", "as many secrets have been released as the enclave allows in an hour");
        }
        // The entry, as vault.py's AuditLog would write and later check it: the same fields in the same order, and the detail as
        // the text that is stored. Every name in it needs no escaping, so serde's text is Python's.
        let detail = json!({"for": {"host": host, "platform": platform, "step": step}, "n": self.released + 1, "secret": id, "sensitive": sensitive, "who": who}).to_string();
        let target = if host.is_empty() { Value::Null } else { Value::String(host.clone()) };
        let payload = json!([ts, "enclave", "enclave.release", target, Value::Null, "ok", detail]).to_string();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).or_else(|_| no("crypto", "the MAC key is unusable"))?;
        mac.update(prev.as_bytes());
        mac.update(payload.as_bytes());
        let hash = hex(&mac.finalize().into_bytes());
        self.chain.append(prev, &hash, true)?;
        self.released += 1;
        Ok(json!({"ok": true, "plaintext": B64.encode(&*plain),
                  "audit": {"ts": ts, "actor": "enclave", "action": "enclave.release", "host": target, "outcome": "ok", "detail_json": detail, "prev": prev, "hash": hash}}))
    }

    /// Rotating the vault secret, first step: the KEK of the new secret is derived and held beside the current one, and the
    /// verifier and the audit key come back wrapped under it for the vault to store. Nothing changes until `rotate-commit`.
    fn rotate_begin(&mut self, v: &Value) -> Answer {
        self.kek()?;
        let Some(audit) = self.audit.clone() else { return no("locked", "the enclave is locked") };
        // `rekey`: the same secret and share under a new salt, from what is held here. It gives nobody anything they did not have:
        // the vault opens with the same secret afterwards. So it takes no step-up and can run on a schedule. Anything else is a
        // rotation to a new secret or a change of the second lock, and takes one.
        let (next, held) = if v.get("rekey").and_then(Value::as_bool) == Some(true) {
            let Some(h) = &self.held else { return no("locked", "the enclave is locked") };
            if !self.unlocks.take() {
                return no("rate", "too many derivations: wait a minute");
            }
            let again = Held { secret: h.secret.clone(), share: h.share.clone() };
            (Self::kdf(&again.secret, again.share.as_ref().map(|s| s.as_slice()), v)?, again)
        } else {
            self.need_stepup(v)?;
            self.derive(v)?
        };
        self.next_held = Some(held);
        let (vn, vct) = seal(next.as_ref(), VERIFIER, b"storageforge:verifier")?;
        let (an, act) = seal(next.as_ref(), &audit, b"storageforge:audit-key")?;
        self.next = Some(next);
        Ok(json!({"ok": true, "verifier_nonce": B64.encode(vn), "verifier": B64.encode(vct), "audit_key_nonce": B64.encode(an), "audit_key_wrapped": B64.encode(act)}))
    }

    /// One row's DEK, opened under the current KEK and sealed under the next. The DEK itself is never outside.
    fn rewrap(&mut self, v: &Value) -> Answer {
        let kek = *self.kek()?;
        let Some(next) = self.next.clone() else { return no("state", "no rotation is under way") };
        let id = uuid(v)?;
        let aad = format!("storageforge:dek:{id}");
        let dek = open(&kek, &nonce(v, "dek_nonce")?, &bytes(v, "wrapped_dek", 128)?, aad.as_bytes())?;
        let (dn, wd) = seal(next.as_ref(), &dek, aad.as_bytes())?;
        Ok(json!({"ok": true, "dek_nonce": B64.encode(dn), "wrapped_dek": B64.encode(wd)}))
    }

    fn rotate_end(&mut self, commit: bool) -> Answer {
        self.kek()?;
        let Some(next) = self.next.take() else { return no("state", "no rotation is under way") };
        let held = self.next_held.take();
        if commit {
            self.kek = Some(next);
            self.held = held;
        }
        Ok(json!({"ok": true, "state": "unlocked", "rotated": commit}))
    }

    fn chain_mac(key: &[u8], prev: &str, payload: &str) -> Result<String, Refusal> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).or_else(|_| no("crypto", "the MAC key is unusable"))?;
        mac.update(prev.as_bytes());
        mac.update(payload.as_bytes());
        Ok(hex(&mac.finalize().into_bytes()))
    }

    /// The audit chain's MAC, as vault.py's AuditLog computes it: HMAC-SHA256 over the previous entry's hash and the entry's payload.
    /// With `append` the entry is about to be written: it becomes the head the enclave remembers, and it has to follow the head
    /// there is. Without it nothing is remembered: that is how a chain is verified.
    fn mac(&mut self, v: &Value) -> Answer {
        self.kek()?;
        let Some(key) = self.audit.clone() else { return no("locked", "the enclave is locked") };
        let (Some(prev), Some(payload)) = (v.get("prev").and_then(Value::as_str), v.get("payload").and_then(Value::as_str)) else {
            return bad("prev and payload are text");
        };
        if prev.len() != 64 || !prev.bytes().all(|c| c.is_ascii_hexdigit()) {
            return bad("prev is 64 hex digits");
        }
        let out = Self::chain_mac(&key, prev, payload)?;
        if let Some(want) = v.get("expect").and_then(Value::as_str) {
            return Ok(json!({"ok": true, "matches": out.as_bytes().ct_eq(want.as_bytes()).unwrap_u8() == 1}));
        }
        if v.get("append").and_then(Value::as_bool) == Some(true) {
            self.chain.append(prev, &out, false)?;
        }
        Ok(json!({"ok": true, "mac": out}))
    }

    /// The enclave catches up with entries others wrote after its head: a command beside the server with an enclave of its own,
    /// or entries chained without the key while this one was locked. Each has to follow the one before it, from the head on,
    /// with the MAC or the plain hash the log says it has. A log that was cut short cannot be led from the head to its new end.
    fn advance(&mut self, v: &Value) -> Answer {
        self.kek()?;
        let Some(key) = self.audit.clone() else { return no("locked", "the enclave is locked") };
        let (Some(from), Some(entries)) = (v.get("from").and_then(Value::as_str), v.get("entries").and_then(Value::as_array)) else {
            return bad("from is a hash and entries is a list");
        };
        if !is_hash(from) || entries.len() > MAX_ADVANCE {
            return bad("from is 64 hex digits, and at most 512 entries come at once");
        }
        let from_prior = self.chain.head.as_deref() != Some(from) && self.chain.prior.as_deref() == Some(from);
        if self.chain.head.is_some() && self.chain.head.as_deref() != Some(from) && !from_prior {
            self.chain.behind = true;
            return no("chain", "those entries do not start where the enclave last signed the audit log");
        }
        let mut at = from.to_string();
        for entry in entries {
            let (Some(alg), Some(payload), Some(hash)) = (entry.get(0).and_then(Value::as_str), entry.get(1).and_then(Value::as_str), entry.get(2).and_then(Value::as_str)) else {
                return bad("an entry is its algorithm, its payload and its hash");
            };
            use sha2::Digest;
            let want = match alg {
                "hmac-sha256" => Self::chain_mac(&key, &at, payload)?,
                "sha256" => hex(&Sha256::digest([at.as_bytes(), payload.as_bytes()].concat())),
                _ => return bad("an entry is chained with hmac-sha256 or sha256"),
            };
            if want.as_bytes().ct_eq(hash.as_bytes()).unwrap_u8() != 1 {
                self.chain.behind = true;
                return no("chain", "an entry does not follow the one before it: the audit log was changed");
            }
            at = hash.to_string();
        }
        if !entries.is_empty() || self.chain.head.is_none() {
            if from_prior {
                // what was signed last is not in the log, and the log went on from the entry before it
                self.chain.unwritten += 1;
                if self.chain.head_release {
                    self.chain.releases_unwritten += 1;
                }
            }
            self.chain.prior = Some(from.to_string());
            self.chain.head = Some(at);
            self.chain.head_release = false;
            self.chain.taken_in += entries.len() as u64;
        }
        self.chain.behind = false;
        Ok(json!({"ok": true, "chain": self.chain.status()}))
    }

    /// A person accepts the log as it is now, after looking at why it no longer ends where the enclave signed it: the head is
    /// set to `head`. Once step-up is on this takes a token, so the web app cannot do it for them.
    fn chain_accept(&mut self, v: &Value) -> Answer {
        self.kek()?;
        self.need_stepup(v)?;
        match v.get("head").and_then(Value::as_str) {
            Some(head) if is_hash(head) => {
                self.chain = Chain { head: Some(head.to_string()), ..Chain::default() };
                Ok(json!({"ok": true, "chain": self.chain.status()}))
            }
            _ => bad("head is 64 hex digits"),
        }
    }

    fn answer(&mut self, v: &Value) -> Answer {
        #[derive(Deserialize)]
        struct Op {
            op: String,
        }
        let Ok(Op { op }) = Op::deserialize(v) else { return bad("a request is an object with an op") };
        if self.lockdown && op != "status" && op != "unlock" {
            return no("lockdown", "the enclave is locked down after repeated bad requests: unlock it again");
        }
        match op.as_str() {
            "status" => Ok(self.status()),
            "unlock" => self.unlock(v),
            "lock" => {
                self.wipe();
                Ok(json!({"ok": true, "state": "locked"}))
            }
            "stepup" => self.stepup(v),
            "stepup-enroll" => self.stepup_enroll(v),
            "challenge" => self.challenge(),
            "sign" => self.sign(v),
            "generate" => self.generate(v),
            "import" => self.import(v),
            "seal" => self.seal_secret(v),
            "release" => self.release(v),
            "rotate-begin" => self.rotate_begin(v),
            "rewrap" => self.rewrap(v),
            "rotate-commit" => self.rotate_end(true),
            "rotate-abort" => self.rotate_end(false),
            "mac" => self.mac(v),
            "advance" => self.advance(v),
            "chain-accept" => self.chain_accept(v),
            _ => bad("unknown op"),
        }
    }

    fn count_bad(&mut self) {
        self.bad += 1;
        if self.bad >= BAD_LIMIT {
            self.wipe();
            self.lockdown = true;
        }
    }

    /// The responder's side of Noise NX: the client's ephemeral key comes in, and back go the enclave's ephemeral key, its static
    /// key (encrypted) and the proof that it holds the static secret. Returns the two directions of the channel, or None for a
    /// first frame no honest client sends.
    fn handshake(&mut self, conn: &mut (impl Read + Write)) -> Option<(Channel, Channel)> {
        let mut head = [0u8; 4];
        conn.read_exact(&mut head).ok()?;
        if u32::from_be_bytes(head) != 32 {
            self.count_bad(); // not a handshake: a client from before the channel, or something that is no client at all
            return None;
        }
        let mut theirs = [0u8; 32];
        conn.read_exact(&mut theirs).ok()?;
        use rand_core::RngCore;
        let mut ephemeral = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(ephemeral.as_mut());
        let mut noise = Noise::new();
        noise.mix_hash(&theirs); // -> e
        noise.mix_hash(&[]); //    and its empty payload
        let ours = x25519_public(&ephemeral);
        noise.mix_hash(&ours); // <- e
        let (Some(ee), Some(es)) = (x25519(&ephemeral, &theirs), x25519(&self.static_secret, &theirs)) else {
            self.count_bad();
            return None;
        };
        noise.mix_key(ee.as_ref()); //  ee
        let sealed_static = noise.encrypt_and_hash(&self.static_public)?; //  s
        noise.mix_key(es.as_ref()); //  es
        let sealed_payload = noise.encrypt_and_hash(&[])?;
        let mut reply = Vec::with_capacity(96);
        reply.extend_from_slice(&ours);
        reply.extend_from_slice(&sealed_static);
        reply.extend_from_slice(&sealed_payload);
        conn.write_all(&(reply.len() as u32).to_be_bytes()).ok()?;
        conn.write_all(&reply).ok()?;
        let (to_us, to_them) = Noise::hkdf(&noise.ck, &[]);
        self.handshakes += 1;
        Some((Channel { key: to_us, n: 0 }, Channel { key: to_them, n: 0 }))
    }

    /// One connection: the handshake, then requests answered in order until it closes, sends something no honest client sends,
    /// or goes quiet. Every frame after the handshake is encrypted, both ways.
    fn serve(&mut self, mut conn: impl Read + Write) {
        let Some((mut rx, mut tx)) = self.handshake(&mut conn) else { return };
        loop {
            let mut head = [0u8; 4];
            if conn.read_exact(&mut head).is_err() {
                return;
            }
            let len = u32::from_be_bytes(head) as usize;
            if len < 16 || len > MAX_FRAME + 16 {
                self.count_bad();
                return;
            }
            let mut sealed = vec![0u8; len];
            if conn.read_exact(&mut sealed).is_err() {
                return;
            }
            let Some(body) = rx.open(&sealed) else {
                self.count_bad(); // changed on the way, or not encrypted for this connection
                return;
            };
            if body.is_empty() {
                self.count_bad();
                return;
            }
            let (reply, hang_up) = match serde_json::from_slice::<Value>(&body) {
                Ok(mut v) => {
                    let got = self.answer(&v);
                    for name in ["secret", "share", "private", "plaintext", "password", "token"] {
                        if let Some(s) = v.get_mut(name).and_then(|s| if let Value::String(s) = s { Some(s) } else { None }) {
                            s.zeroize();
                        }
                    }
                    if let Some(Value::String(s)) = v.get_mut("proof").and_then(|p| p.get_mut("password")) {
                        s.zeroize();
                    }
                    match got {
                        Ok(r) => (r, false),
                        Err(Refusal::No(code, why)) => {
                            match code {
                                "auth" => self.auth_failed += 1,
                                "stepup" => self.stepup_missing += 1,
                                _ => {}
                            }
                            (json!({"ok": false, "error": code, "why": why}), false)
                        }
                        Err(Refusal::Bad(why)) => {
                            self.count_bad();
                            (json!({"ok": false, "error": "bad-request", "why": why}), true)
                        }
                    }
                }
                Err(_) => {
                    self.count_bad();
                    (json!({"ok": false, "error": "bad-request", "why": "not JSON"}), true)
                }
            };
            let text = Zeroizing::new(reply.to_string()); // a released secret is in it
            let Some(out) = tx.seal(text.as_bytes()) else { return };
            if conn.write_all(&(out.len() as u32).to_be_bytes()).is_err() || conn.write_all(&out).is_err() || hang_up {
                return;
            }
        }
    }
}

/// A connection that says nothing for IDLE_SECS is given up on.
fn impatient(fd: i32) {
    let tv = libc::timeval { tv_sec: IDLE_SECS, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t);
    }
}

/// A listening AF_VSOCK socket on `port`, for any peer. The micro VM has no other way in or out.
fn vsock_listen(port: u32) -> std::io::Result<i32> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t) < 0 || libc::listen(fd, 1) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd)
    }
}

/// Nothing this process holds may reach a disk or another process: its memory is locked, it leaves no core, and it cannot be traced.
fn harden() -> bool {
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit { rlim_cur: 0, rlim_max: 0 });
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        // In the micro VM this is PID 1 and may lock everything it will ever hold. A process on a developer's machine has a small
        // lock limit, and locking what it cannot would fail every later allocation: it says so and goes on unlocked, as a test double.
        let pid1 = std::process::id() == 1;
        if pid1 {
            // the kernel starts PID 1 with the small default; it is root, and takes the limit away from itself
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY });
        }
        let mut limit: libc::rlimit = std::mem::zeroed();
        let unlimited = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) == 0 && limit.rlim_cur == libc::RLIM_INFINITY;
        let locked = unlimited && libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0;
        if !locked && pid1 {
            // in its own VM there is no excuse: it stops, the kernel halts with it, and the supervisor sees a VM that did not come up
            eprintln!("enclave: cannot lock memory: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        if !locked {
            eprintln!("enclave: memory is not locked here (no leave to lock it): fine for a test, wrong for the enclave's own VM");
        }
        locked
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut state = State::new(harden());
    // As PID 1 of the micro VM there is no command line to speak of: the kernel starts /init with none, and the port is this one.
    let pid1 = [String::new(), "--vsock".to_string(), VSOCK_PORT.to_string()];
    let args = if std::process::id() == 1 && args.len() < 3 { pid1.to_vec() } else { args };
    match (args.get(1).map(String::as_str), args.get(2)) {
        // in the micro VM: PID 1, with nothing to return to. A listener that cannot be made is a halt, which the supervisor sees
        (Some("--vsock"), Some(port)) => {
            let port: u32 = port.parse().unwrap_or(0);
            let fd = vsock_listen(port).unwrap_or_else(|e| {
                eprintln!("enclave: no vsock listener on port {port}: {e}");
                std::process::exit(1)
            });
            loop {
                let conn = unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
                if conn < 0 {
                    continue;
                }
                impatient(conn);
                use std::os::fd::FromRawFd;
                state.serve(unsafe { std::fs::File::from_raw_fd(conn) });
            }
        }
        // on a developer's machine and in the unit tests: the same program and the same wire, over a socket file
        (Some("--unix"), Some(path)) => {
            // only here, for the tests of what happens when a token runs out: in its VM the program takes no arguments at all
            if let (Some("--token-seconds"), Some(n)) = (args.get(3).map(String::as_str), args.get(4).and_then(|n| n.parse::<u64>().ok())) {
                state.token_secs = n.clamp(1, STEPUP_SECS);
            }
            let _ = std::fs::remove_file(path);
            let listener = std::os::unix::net::UnixListener::bind(path).unwrap_or_else(|e| {
                eprintln!("enclave: cannot listen on {path}: {e}");
                std::process::exit(1)
            });
            for conn in listener.incoming().flatten() {
                use std::os::fd::AsRawFd;
                impatient(conn.as_raw_fd());
                state.serve(conn);
            }
        }
        _ => {
            eprintln!("usage: storageforge-enclave --vsock PORT | --unix PATH [--token-seconds N]");
            std::process::exit(2);
        }
    }
}
