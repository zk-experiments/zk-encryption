//! Pairwise handshake plus symmetric ratchet (PROTOCOL.md §§4–5).
//!
//! - The receiver publishes one long-term key pair: a Grumpkin key V and an
//!   ML-KEM-768 ek, whose pre-expansion the sender commits to with Poseidon2.
//! - Handshake, carried by the sender's first transfer: DH with V and a
//!   lattice encryption of m give the transcript-bound root
//!   S_0 = H(ROOT, m, Z, E, ct_commit, pq_commit), Z = e·V. The public tag
//!   H(TAG, Z, pq_commit) lets the receiver recognise its handshakes with one
//!   scalar multiplication.
//! - Every transfer t (the handshake is t = 0): C_t = H(COMMIT, S_t) and, per
//!   payload, the duplex keyed by (H(key_domain, S_t, ctx), C_t) bound to ctx.
//!   Then S_{t+1} = H(RATCHET, S_t).

use crate::duplex::Duplex;
use crate::grumpkin::Point;
use crate::lattice::{Ciphertext, EK_BYTES, Kpke, MlKemKeys, Noise, PqKey};
use crate::poseidon::{Poseidon, Rng};
use crate::{Error, Fr};

/// What an envelope app of size N seals (the frozen circuits instantiate 6).
pub type Payload<const N: usize> = [Fr; N];
use ark_ff::Zero;
use std::collections::HashMap;

/// The ratchet's hashes.
pub struct Ratchet;

impl Ratchet {
    fn d(label: &str) -> Fr {
        Poseidon::domain(&format!("pq-ratchet/{label}/v1"))
    }

    /// The key domain of the DG1 payload.
    /// The payload domain of DG1's envelope (`"pq-ratchet/key-payload/v1"`),
    /// pinned by the `channel/envelope` family.
    pub fn key_payload() -> Fr {
        Self::d("key-payload")
    }

    pub fn key_note() -> Fr {
        Self::d("key-note")
    }

    /// H(TAG, Z.x, Z.y, pq_commit): the handshake's recognition tag.
    pub fn tag(shared: Point, pq_commitment: Fr) -> Fr {
        Poseidon::hash(&[Self::d("tag"), shared.x, shared.y, pq_commitment])
    }

    /// S_0 = H(ROOT, m halves, Z, E, ct_commit, pq_commit).
    pub fn root(
        m: &[u8; 32],
        shared: Point,
        ephemeral: Point,
        ct_commitment: Fr,
        pq_commitment: Fr,
    ) -> Fr {
        let h = PqKey::halves(m);
        Poseidon::hash(&[
            Self::d("root"),
            h[0],
            h[1],
            shared.x,
            shared.y,
            ephemeral.x,
            ephemeral.y,
            ct_commitment,
            pq_commitment,
        ])
    }

    /// S_{t+1} = H(RATCHET, S_t).
    pub fn next(s: Fr) -> Fr {
        Poseidon::hash(&[Self::d("ratchet"), s])
    }

    /// C_t = H(COMMIT, S_t).
    pub fn commit(s: Fr) -> Fr {
        Poseidon::hash(&[Self::d("commit"), s])
    }

    /// The payload key H(key_domain, S_t, ctx).
    /// K = H(KEY, S_t, ctx, domain): one derivation domain
    /// (`"pq-ratchet/key/v1"`); `domain` is the payload's, pinned by the
    /// envelope app's family (`key_payload`, `key_note`).
    pub fn key(domain: Fr, s: Fr, ctx: Fr) -> Fr {
        Poseidon::hash(&[Self::d("key"), s, ctx, domain])
    }

    /// (C_t, the duplex under H(KEY, S_t, ctx, domain) keyed with (key, C_t), bound to ctx).
    pub fn seal(domain: Fr, s: Fr, ctx: Fr, plaintext: &[Fr]) -> Result<(Fr, Vec<Fr>), Error> {
        let c = Self::commit(s);
        Ok((
            c,
            Duplex::seal(Self::key(domain, s, ctx), c, Fr::zero(), ctx, plaintext)?,
        ))
    }

    pub fn open(domain: Fr, s: Fr, c: Fr, ctx: Fr, ciphertext: &[Fr]) -> Result<Vec<Fr>, Error> {
        Duplex::open(Self::key(domain, s, ctx), c, Fr::zero(), ctx, ciphertext)
    }

    /// A hiding commitment to a payload, `H("pq-channel/payload/v1/<N>", salt,
    /// payload)`: the link between the app that owns the payload and the
    /// envelope app of that size (`PayloadCommitment<N>` in noir-zk's link
    /// vocabulary).
    pub fn payload_commitment<const N: usize>(salt: Fr, payload: &Payload<N>) -> Fr {
        let mut v = vec![
            Poseidon::domain(&format!("pq-channel/payload/v1/{N}")),
            salt,
        ];
        v.extend_from_slice(payload);
        Poseidon::hash(&v)
    }

    /// An envelope app's sealing: (C_t, ciphertext) of `payload` under chain
    /// key `s` and the app's key domain (`key_payload` for DG1's envelope,
    /// `key_note` for the note's: two payloads under one chain key never
    /// share a keystream).
    pub fn seal_payload<const N: usize>(
        key: Fr,
        s: Fr,
        ctx: Fr,
        payload: &Payload<N>,
    ) -> Result<(Fr, [Fr; N]), Error> {
        let (c, ct) = Self::seal(key, s, ctx, payload)?;
        Ok((c, ct.try_into().expect("N fields")))
    }

    /// Opens an envelope app's ciphertext.
    pub fn open_payload<const N: usize>(
        key: Fr,
        s: Fr,
        c_t: Fr,
        ctx: Fr,
        ciphertext: &[Fr; N],
    ) -> Result<Payload<N>, Error> {
        Ok(Self::open(key, s, c_t, ctx, ciphertext)?
            .try_into()
            .expect("N fields"))
    }
}

/// What the receiver publishes, as the sender uses it (ek expanded).
#[derive(Debug, Clone)]
pub struct ReceiverPublic {
    pub grumpkin: Point,
    /// The ML-KEM-768 encapsulation key as published (what a sender persists).
    pub ek: [u8; EK_BYTES],
    pub pq: PqKey,
    pub pq_commitment: Fr,
}

impl ReceiverPublic {
    pub fn from_published(grumpkin: Point, ek: &[u8; EK_BYTES]) -> Result<Self, Error> {
        if !grumpkin.is_valid() {
            return Err(Error::NotOnCurve);
        }
        let pq = PqKey::expand(ek)?;
        Ok(Self {
            grumpkin,
            ek: *ek,
            pq_commitment: pq.commitment(),
            pq,
        })
    }
}

/// The receiver's long-term secrets and their public bundle material.
pub struct ReceiverKeys {
    pub(crate) v: Fr,
    pub(crate) keys: MlKemKeys,
    pub public: ReceiverPublic,
}

impl ReceiverKeys {
    pub fn generate() -> Self {
        Self::from_secrets(Rng::field(), MlKemKeys::generate())
    }

    pub fn from_secrets(v: Fr, keys: MlKemKeys) -> Self {
        let grumpkin = Point::generator_mul(v).expect("nonzero secret");
        let public =
            ReceiverPublic::from_published(grumpkin, &keys.ek).expect("a fresh ML-KEM key expands");
        Self { v, keys, public }
    }

    pub fn ek(&self) -> &[u8; EK_BYTES] {
        &self.keys.ek
    }

    /// The Grumpkin secret and the ML-KEM seed, for persistence.
    pub fn secrets(&self) -> (Fr, [u8; 64]) {
        (self.v, self.keys.seed)
    }

    /// The cheap scan (PROTOCOL.md §4 receiver step 1): Z' = v·E and the tag.
    pub fn recognises(&self, ephemeral: Point, tag: Fr) -> bool {
        ephemeral
            .mul(self.v)
            .is_ok_and(|z| Ratchet::tag(z, self.public.pq_commitment) == tag)
    }

    /// Receiver steps 1–4: tag, ciphertext commitment, decryption, root
    /// checked against C_0. Returns S_0.
    pub fn handshake_root(
        &self,
        ephemeral: Point,
        tag: Fr,
        ct_commitment: Fr,
        c0: Fr,
        ct: &Ciphertext,
    ) -> Result<Fr, Error> {
        let shared = ephemeral.mul(self.v)?;
        if Ratchet::tag(shared, self.public.pq_commitment) != tag {
            return Err(Error::NotForUs);
        }
        if ct.commitment() != ct_commitment {
            return Err(Error::CiphertextMismatch);
        }
        let m = Kpke::decrypt(&self.keys.dk, ct);
        let s0 = Ratchet::root(
            &m,
            shared,
            ephemeral,
            ct_commitment,
            self.public.pq_commitment,
        );
        if Ratchet::commit(s0) != c0 {
            return Err(Error::HandshakeMismatch);
        }
        Ok(s0)
    }
}

/// The handshake's KEM half: what a sender computes against a receiver's
/// bundle (or a throwaway one, on a uniform ratchet transfer).
#[derive(Debug, Clone)]
pub struct Handshake {
    pub ephemeral: Point,
    pub tag: Fr,
    pub ct_commitment: Fr,
    /// S_0.
    pub root: Fr,
    /// The carried ciphertext (u, v).
    pub ct: Ciphertext,
}

impl Handshake {
    pub fn new(to: &ReceiverPublic, e: Fr, noise: &Noise, m: &[u8; 32]) -> Result<Self, Error> {
        let shared = to.grumpkin.mul(e)?;
        let ephemeral = Point::generator_mul(e)?;
        let ct = Kpke::encrypt(&to.pq, noise, m)?;
        let ct_commitment = ct.commitment();
        Ok(Self {
            ephemeral,
            tag: Ratchet::tag(shared, to.pq_commitment),
            ct_commitment,
            root: Ratchet::root(m, shared, ephemeral, ct_commitment, to.pq_commitment),
            ct,
        })
    }
}

/// The sender's chain state: the next index and its chain key. Earlier keys
/// are overwritten (forward secrecy); an index is never reused.
#[derive(Debug, Clone)]
pub struct SenderChain {
    pub(crate) t: u64,
    pub(crate) s: Fr,
}

impl SenderChain {
    /// The state after a handshake with root `s0`: the next transfer is t = 1.
    pub fn after_handshake(s0: Fr) -> Self {
        Self {
            t: 1,
            s: Ratchet::next(s0),
        }
    }

    pub fn index(&self) -> u64 {
        self.t
    }

    /// Returns (t, S_t) for the next transfer and advances the chain.
    pub fn advance(&mut self) -> (u64, Fr) {
        let out = (self.t, self.s);
        self.s = Ratchet::next(self.s);
        self.t += 1;
        out
    }
}

/// The receiver's side of one channel: chain keys for indices it hasn't
/// seen, looked up by C_t, up to `window` beyond the highest index received.
#[derive(Debug, Clone)]
pub struct Session {
    pub(crate) next_t: u64,
    pub(crate) next_s: Fr,
    pub(crate) window: u64,
    pub(crate) highest: u64,
    /// How many skipped keys (indices below `highest`, not yet received) are
    /// kept; the oldest beyond that are deleted (PROTOCOL.md R7).
    pub(crate) max_skipped: usize,
    pub(crate) keys: HashMap<Fr, (u64, Fr)>,
}

impl Session {
    /// From the root, holding the next `window` chain keys and at most
    /// `window` skipped keys.
    pub fn start(s0: Fr, window: u64) -> Self {
        Self::start_with(s0, window, window as usize)
    }

    pub fn start_with(s0: Fr, window: u64, max_skipped: usize) -> Self {
        let mut session = Session {
            next_t: 1,
            next_s: Ratchet::next(s0),
            window,
            highest: 0,
            max_skipped,
            keys: HashMap::new(),
        };
        session.fill(window);
        session
    }

    fn fill(&mut self, upto: u64) {
        while self.next_t <= upto {
            self.keys
                .insert(Ratchet::commit(self.next_s), (self.next_t, self.next_s));
            self.next_s = Ratchet::next(self.next_s);
            self.next_t += 1;
        }
    }

    fn expire(&mut self) {
        let mut old: Vec<(u64, Fr)> = self
            .keys
            .iter()
            .filter(|(_, (t, _))| *t < self.highest)
            .map(|(c, (t, _))| (*t, *c))
            .collect();
        old.sort();
        for (_, c) in old.iter().take(old.len().saturating_sub(self.max_skipped)) {
            self.keys.remove(c);
        }
    }

    /// The chain key (t, S_t) that C_t commits to, if held; nothing changes.
    pub fn peek(&self, c: Fr) -> Option<(u64, Fr)> {
        self.keys.get(&c).copied()
    }

    /// Consumes the chain key C_t commits to, extends the window and expires
    /// old skipped keys.
    pub fn take(&mut self, c: Fr) -> Result<(u64, Fr), Error> {
        let (t, s) = self.keys.remove(&c).ok_or(Error::UnknownCommitment)?;
        self.highest = self.highest.max(t);
        self.fill(t + self.window);
        self.expire();
        Ok((t, s))
    }

    /// Chain keys held (skipped or ahead).
    pub fn held(&self) -> usize {
        self.keys.len()
    }

    /// Skipped keys held: indices below the highest received.
    pub fn skipped(&self) -> usize {
        self.keys
            .values()
            .filter(|(t, _)| *t < self.highest)
            .count()
    }

    /// Also holds the next `n` chain keys beyond the window (PROTOCOL.md §5 step 5).
    pub fn resync(&mut self, n: u64) {
        self.fill(self.next_t - 1 + n);
    }
}
