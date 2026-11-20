//! The agent's tunnel: Noise IK over the framing above (roadmap section 11.1, "Delivery", and 11.2, "Its own tunnel").
//!
//! `Noise_IK_25519_AESGCM_SHA256`, as the Noise specification (revision 34) defines it, with the same primitives the key enclave's
//! channel uses (X25519, AES-256-GCM, SHA-256, its HKDF), so the two are read and audited the same way:
//!
//! ```text
//! <- s                       the agent knows the controller's static key before it dials: pinned at enrollment
//! ...
//! -> e, es, s, ss            the agent's ephemeral key, then its static key, encrypted
//! <- e, ee, se               the controller's ephemeral key: from here both sides have proved they hold their static secrets
//! ```
//!
//! The responder learns who the initiator is from the static key in the first message and nothing else: `respond` hands that key
//! to the caller's `admit` before any more work is done, and a key that is not admitted ends the handshake. Every frame after the
//! handshake is sealed under keys of this connection alone, with a count that never repeats, so a frame cannot be replayed into
//! another connection or played twice in this one.
//!
//! A peer that sends what no honest peer sends (a frame of the wrong size, a point of small order, a frame that does not open)
//! ends the conversation: these functions return an error and the caller hangs up.

use std::io::{self, Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{read_frame, write_frame, FrameError, MAX_FRAME};

pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_AESGCM_SHA256";
/// The size of an AES-GCM tag.
pub const TAG: usize = 16;
/// The most a handshake message may carry as its payload.
pub const MAX_HANDSHAKE_PAYLOAD: usize = 4096;
/// The most a sealed frame may be: a frame of `MAX_FRAME` and its tag.
pub const MAX_SEALED: usize = MAX_FRAME + TAG;

/// Why a handshake or a frame failed. Every one ends the conversation.
#[derive(Debug)]
pub enum NoiseError {
    /// The stream ended or failed.
    Io(io::Error),
    /// A frame of a size no honest peer sends.
    Size(usize),
    /// A point of small order, a frame that does not open, or a nonce that would repeat.
    Bad(&'static str),
    /// The responder's `admit` did not accept the initiator's static key.
    Refused,
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoiseError::Io(e) => write!(f, "the connection ended or failed: {e}"),
            NoiseError::Size(n) => write!(f, "a frame of {n} bytes is outside what is accepted"),
            NoiseError::Bad(why) => write!(f, "{why}"),
            NoiseError::Refused => write!(f, "the key is not one this end accepts"),
        }
    }
}

impl std::error::Error for NoiseError {}

impl From<FrameError> for NoiseError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(e) => NoiseError::Io(e),
            FrameError::Size(n) => NoiseError::Size(n),
        }
    }
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// X25519. A result of all zeros is a point of small order and is refused, as the enclave refuses it.
pub fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, NoiseError> {
    let out = Zeroizing::new(curve25519_dalek::montgomery::MontgomeryPoint(*public).mul_clamped(*secret).to_bytes());
    if out.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        return Err(NoiseError::Bad("a key of small order"));
    }
    Ok(out)
}

/// The public half of an X25519 secret.
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// A fresh X25519 secret.
pub fn generate() -> Zeroizing<[u8; 32]> {
    use rand_core::RngCore;
    let mut secret = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(secret.as_mut());
    secret
}

fn nonce(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_be_bytes());
    out
}

/// One direction of a connection: a key, and the count of frames it has sealed or opened.
pub struct Cipher {
    key: Zeroizing<[u8; 32]>,
    n: u64,
}

impl Cipher {
    fn new(key: Zeroizing<[u8; 32]>) -> Cipher {
        Cipher { key, n: 0 }
    }

    fn next(&mut self) -> Result<u64, NoiseError> {
        // 2^64-1 is reserved by the specification; a connection never gets near it, and if it did it ends rather than repeat
        if self.n == u64::MAX {
            return Err(NoiseError::Bad("the connection has used every nonce"));
        }
        let n = self.n;
        self.n += 1;
        Ok(n)
    }

    fn seal_ad(&mut self, ad: &[u8], plain: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let n = self.next()?;
        Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| NoiseError::Bad("no key"))?
            .encrypt(Nonce::from_slice(&nonce(n)), Payload { msg: plain, aad: ad })
            .map_err(|_| NoiseError::Bad("cannot seal"))
    }

    fn open_ad(&mut self, ad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, NoiseError> {
        let n = self.next()?;
        Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| NoiseError::Bad("no key"))?
            .decrypt(Nonce::from_slice(&nonce(n)), Payload { msg: sealed, aad: ad })
            .map(Zeroizing::new)
            .map_err(|_| NoiseError::Bad("a frame that does not open: changed on the way, or not sealed for this connection"))
    }

    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.seal_ad(&[], plain)
    }

    pub fn open(&mut self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, NoiseError> {
        self.open_ad(&[], sealed)
    }
}

/// The handshake's state, as the specification names its parts.
struct Symmetric {
    h: [u8; 32],
    ck: Zeroizing<[u8; 32]>,
    k: Option<Cipher>,
}

impl Symmetric {
    fn new(prologue: &[u8]) -> Symmetric {
        let mut h = [0u8; 32];
        h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
        let mut s = Symmetric { h, ck: Zeroizing::new(h), k: None };
        s.mix_hash(prologue);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = Sha256::new().chain_update(self.h).chain_update(data).finalize().into();
    }

    fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let temp = Zeroizing::new(hmac256(ck, &[ikm]));
        let one = Zeroizing::new(hmac256(temp.as_ref(), &[&[1u8]]));
        let two = Zeroizing::new(hmac256(temp.as_ref(), &[one.as_ref(), &[2u8]]));
        (one, two)
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = Self::hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(Cipher::new(k));
    }

    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let h = self.h;
        let out = match &mut self.k {
            Some(k) => k.seal_ad(&h, plain)?,
            None => plain.to_vec(),
        };
        self.mix_hash(&out);
        Ok(out)
    }

    fn decrypt_and_hash(&mut self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, NoiseError> {
        let h = self.h;
        let out = match &mut self.k {
            Some(k) => k.open_ad(&h, sealed)?,
            None => Zeroizing::new(sealed.to_vec()),
        };
        self.mix_hash(sealed);
        Ok(out)
    }

    /// The two keys of the connection: the initiator sends with the first.
    fn split(&self) -> (Cipher, Cipher) {
        let (one, two) = Self::hkdf(&self.ck, &[]);
        (Cipher::new(one), Cipher::new(two))
    }
}

/// A connection after the handshake.
pub struct Session {
    pub send: Cipher,
    pub recv: Cipher,
    /// The handshake hash: the same on both ends, and on no other connection.
    pub hash: [u8; 32],
    /// The other end's static key.
    pub remote: [u8; 32],
}

impl Session {
    /// Seals `plain` and writes it as one frame.
    pub fn write(&mut self, conn: &mut impl Write, plain: &[u8]) -> Result<(), NoiseError> {
        if plain.len() > MAX_FRAME {
            return Err(NoiseError::Size(plain.len()));
        }
        let sealed = self.send.seal(plain)?;
        write_frame(conn, &sealed).map_err(NoiseError::Io)
    }

    /// Reads one frame of at most `most` bytes once opened, and opens it.
    pub fn read(&mut self, conn: &mut impl Read, most: usize) -> Result<Zeroizing<Vec<u8>>, NoiseError> {
        let sealed = read_frame(conn, TAG, most.min(MAX_FRAME) + TAG)?;
        self.recv.open(&sealed)
    }
}

fn exact<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// The initiator's side: the agent. `local` is its static secret, `remote` the responder's static key it pinned. Returns the
/// connection and the payload of the responder's message.
pub fn initiate(conn: &mut (impl Read + Write), prologue: &[u8], local: &[u8; 32], remote: &[u8; 32], payload: &[u8]) -> Result<(Session, Zeroizing<Vec<u8>>), NoiseError> {
    initiate_with(conn, prologue, local, remote, payload, &generate())
}

fn initiate_with(conn: &mut (impl Read + Write), prologue: &[u8], local: &[u8; 32], remote: &[u8; 32], payload: &[u8], ephemeral: &[u8; 32]) -> Result<(Session, Zeroizing<Vec<u8>>), NoiseError> {
    if payload.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(NoiseError::Size(payload.len()));
    }
    let mut s = Symmetric::new(prologue);
    s.mix_hash(remote); //                                   <- s
    let e_pub = public_of(ephemeral);
    let mut first = Vec::with_capacity(96 + payload.len());
    first.extend_from_slice(&e_pub); //                      -> e
    s.mix_hash(&e_pub);
    s.mix_key(dh(ephemeral, remote)?.as_ref()); //           es
    first.extend(s.encrypt_and_hash(&public_of(local))?); // s
    s.mix_key(dh(local, remote)?.as_ref()); //               ss
    first.extend(s.encrypt_and_hash(payload)?);
    write_frame(conn, &first).map_err(NoiseError::Io)?;
    let reply = read_frame(conn, 32 + TAG, 32 + TAG + MAX_HANDSHAKE_PAYLOAD)?;
    let re: [u8; 32] = exact(&reply);
    s.mix_hash(&re); //                                      <- e
    s.mix_key(dh(ephemeral, &re)?.as_ref()); //              ee
    s.mix_key(dh(local, &re)?.as_ref()); //                  se
    let theirs = s.decrypt_and_hash(&reply[32..])?;
    let (send, recv) = s.split();
    Ok((Session { send, recv, hash: s.h, remote: *remote }, theirs))
}

/// The responder's side: the controller's receiver. `admit` is shown the initiator's static key as soon as it is known, and the
/// handshake goes on only if it says yes. `payload` is what to answer with, given that key and the initiator's payload.
pub fn respond(
    conn: &mut (impl Read + Write),
    prologue: &[u8],
    local: &[u8; 32],
    admit: impl FnOnce(&[u8; 32]) -> bool,
    payload: impl FnOnce(&[u8; 32], &[u8]) -> Vec<u8>,
) -> Result<(Session, Zeroizing<Vec<u8>>), NoiseError> {
    let first = read_frame(conn, 32 + 48 + TAG, 32 + 48 + TAG + MAX_HANDSHAKE_PAYLOAD)?;
    let mut s = Symmetric::new(prologue);
    s.mix_hash(&public_of(local)); //                        <- s
    let re: [u8; 32] = exact(&first);
    s.mix_hash(&re); //                                      -> e
    s.mix_key(dh(local, &re)?.as_ref()); //                  es
    let rs: [u8; 32] = exact(&s.decrypt_and_hash(&first[32..80])?); // s
    if !admit(&rs) {
        return Err(NoiseError::Refused);
    }
    s.mix_key(dh(local, &rs)?.as_ref()); //                  ss
    let theirs = s.decrypt_and_hash(&first[80..])?;
    let answer = payload(&rs, &theirs);
    if answer.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(NoiseError::Size(answer.len()));
    }
    let ephemeral = generate();
    let e_pub = public_of(&ephemeral);
    s.mix_hash(&e_pub); //                                   <- e
    s.mix_key(dh(&ephemeral, &re)?.as_ref()); //             ee
    s.mix_key(dh(&ephemeral, &rs)?.as_ref()); //             se
    let mut reply = e_pub.to_vec();
    reply.extend(s.encrypt_and_hash(&answer)?);
    write_frame(conn, &reply).map_err(NoiseError::Io)?;
    let (recv, send) = s.split();
    Ok((Session { send, recv, hash: s.h, remote: rs }, theirs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    const PROLOGUE: &[u8] = b"test-prologue";

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn both_ends_agree_and_each_knows_the_other() {
        let (agent, controller) = (generate(), generate());
        let controller_pub = public_of(&controller);
        let agent_pub = public_of(&agent);
        let (mut a, mut b) = pair();
        let server = std::thread::spawn(move || {
            let (mut session, got) = respond(&mut b, PROLOGUE, &controller, |k| *k == agent_pub, |_, p| [p, b" back"].concat()).unwrap();
            assert_eq!(&got[..], b"hello");
            assert_eq!(session.remote, agent_pub, "the responder learns the initiator from its key");
            let frame = session.read(&mut b, 100).unwrap();
            session.write(&mut b, &[&frame[..], b"!"].concat()).unwrap();
            session.hash
        });
        let (mut session, answer) = initiate(&mut a, PROLOGUE, &agent, &controller_pub, b"hello").unwrap();
        assert_eq!(&answer[..], b"hello back");
        session.write(&mut a, b"ping").unwrap();
        assert_eq!(&session.read(&mut a, 100).unwrap()[..], b"ping!");
        assert_eq!(session.hash, server.join().unwrap(), "the same handshake hash on both ends");
    }

    #[test]
    fn a_key_not_admitted_ends_the_handshake_before_the_reply() {
        let (agent, controller) = (generate(), generate());
        let controller_pub = public_of(&controller);
        let (mut a, mut b) = pair();
        let server = std::thread::spawn(move || respond(&mut b, PROLOGUE, &controller, |_| false, |_, _| Vec::new()).err());
        assert!(initiate(&mut a, PROLOGUE, &agent, &controller_pub, b"").is_err(), "no reply comes");
        assert!(matches!(server.join().unwrap(), Some(NoiseError::Refused)));
    }

    #[test]
    fn a_controller_that_is_not_the_pinned_one_cannot_answer() {
        let (agent, controller, other) = (generate(), generate(), generate());
        let pinned = public_of(&controller);
        let (mut a, mut b) = pair();
        // whoever sits at the address holds another key: it cannot even read who the agent is
        let server = std::thread::spawn(move || respond(&mut b, PROLOGUE, &other, |_| true, |_, _| Vec::new()).err());
        assert!(initiate(&mut a, PROLOGUE, &agent, &pinned, b"").is_err());
        assert!(matches!(server.join().unwrap(), Some(NoiseError::Bad(_))));
    }

    #[test]
    fn another_prologue_does_not_meet() {
        let (agent, controller) = (generate(), generate());
        let pinned = public_of(&controller);
        let (mut a, mut b) = pair();
        let server = std::thread::spawn(move || respond(&mut b, b"other", &controller, |_| true, |_, _| Vec::new()).err());
        assert!(initiate(&mut a, PROLOGUE, &agent, &pinned, b"").is_err());
        assert!(server.join().unwrap().is_some());
    }

    #[test]
    fn a_frame_changed_replayed_or_reordered_does_not_open() {
        let (agent, controller) = (generate(), generate());
        let controller_pub = public_of(&controller);
        let (mut a, mut b) = pair();
        let server = std::thread::spawn(move || respond(&mut b, PROLOGUE, &controller, |_| true, |_, _| Vec::new()).unwrap().0);
        let (mut mine, _) = initiate(&mut a, PROLOGUE, &agent, &controller_pub, b"").unwrap();
        let mut theirs = server.join().unwrap();
        let one = mine.send.seal(b"one").unwrap();
        let two = mine.send.seal(b"two").unwrap();
        assert!(theirs.recv.open(&two).is_err(), "out of order");
        let mut theirs2 = theirs; // the count moved on: the same frame cannot be opened again either
        assert!(theirs2.recv.open(&one).is_err());
        let mut changed = one.clone();
        changed[0] ^= 1;
        assert!(theirs2.recv.open(&changed).is_err());
    }

    #[test]
    fn a_small_order_point_is_refused() {
        let secret = generate();
        assert!(dh(&secret, &[0u8; 32]).is_err());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(dh(&secret, &one).is_err());
    }

    #[test]
    fn a_handshake_frame_of_the_wrong_size_is_refused_unread() {
        let controller = generate();
        let (mut a, mut b) = pair();
        write_frame(&mut a, &[0u8; 10]).unwrap();
        assert!(matches!(respond(&mut b, PROLOGUE, &controller, |_| true, |_, _| Vec::new()), Err(NoiseError::Size(10))));
    }

    /// The same handshake with fixed keys gives the same bytes and hash every time: what the controller's Python side is checked
    /// against (tests/test_agent_tunnel.py repeats these numbers).
    #[test]
    fn fixed_keys_give_fixed_bytes() {
        struct Tape(Vec<u8>, std::io::Cursor<Vec<u8>>);
        impl Read for Tape {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.1.read(buf)
            }
        }
        impl Write for Tape {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (agent, controller, eph) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut first = Tape(Vec::new(), std::io::Cursor::new(Vec::new()));
        let _ = initiate_with(&mut first, b"storageforge-agent-tunnel-v1", &agent, &public_of(&controller), b"hi", &eph);
        let digest: String = Sha256::digest(&first.0).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(first.0.len(), 4 + 32 + 48 + 2 + TAG);
        // printed so that the Python side can repeat it
        eprintln!("first message sha256 {digest}");
        assert_eq!(digest, include_str!("noise_vector.txt").trim());
    }
}
