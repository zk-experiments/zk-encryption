//! The sender's state for one channel (one receiver): the accepted bundle,
//! and after the handshake the chain (PROTOCOL.md §§4–6).
//!
//! Persist the `Sender` after `handshake` or `advance` and *before*
//! broadcasting the transfer they were used for (S3): a state restored from
//! before them reuses a chain index, which links two transfers and makes
//! the second unopenable. Never restore from a backup (S4); start a new
//! channel instead.

use crate::bundle::{Accepted, Bundle, BundleError};
use crate::emit::{Kem, NoteOpening};
use crate::lattice::Noise;
use crate::poseidon::Rng;
use crate::ratchet::{Handshake, Ratchet, ReceiverKeys, ReceiverPublic, SenderChain};
use crate::{Error, Fr};

/// The KEM half of a transfer's witness: the receiver's key it ran against
/// (the real one on a handshake, a throwaway one on a ratchet transfer), the
/// randomness, and what it produced.
#[derive(Clone, Debug)]
pub struct KemWitness {
    pub receiver: ReceiverPublic,
    pub e: Fr,
    pub m: [u8; 32],
    pub noise: Noise,
    pub handshake: Handshake,
}

impl KemWitness {
    /// A KEM to `receiver` with fresh CSPRNG randomness.
    pub fn new(receiver: &ReceiverPublic) -> Result<Self, Error> {
        let (e, m, noise) = (Rng::field(), Rng::bytes(), Noise::random());
        let handshake = Handshake::new(receiver, e, &noise, &m)?;
        Ok(Self {
            receiver: receiver.clone(),
            e,
            m,
            noise,
            handshake,
        })
    }

    /// The extData fields.
    pub fn kem(&self) -> Kem {
        let h = &self.handshake;
        Kem {
            ephemeral: h.ephemeral,
            tag: h.tag,
            ct_commitment: h.ct_commitment,
            ct: h.ct.clone(),
        }
    }
}

/// What one transfer's channel needs, for the circuit witness and extData.
#[derive(Clone, Debug)]
pub struct ChannelWitness {
    /// A handshake (S = S_0) or a ratchet transfer (S = the chain key).
    pub is_handshake: bool,
    /// The chain index (0 for the handshake).
    pub t: u64,
    /// The chain key S the payloads are sealed under.
    pub s: Fr,
    /// C_t = H(COMMIT, S).
    pub c_t: Fr,
    pub kem: KemWitness,
}

impl ChannelWitness {
    /// A transfer on no channel (a deposit to oneself, say): a random chain
    /// key nobody holds and a KEM to a throwaway key, so it looks like any
    /// other ratchet transfer.
    pub fn throwaway() -> Result<Self, Error> {
        let s = Rng::field();
        let kem = KemWitness::new(&ReceiverKeys::generate().public)?;
        Ok(Self {
            is_handshake: false,
            t: 0,
            s,
            c_t: Ratchet::commit(s),
            kem,
        })
    }

    /// Seals a note opening under this transfer's key and `KEY_NOTE`: (C_t,
    /// c_note), what the note envelope app outputs.
    pub fn seal_note(&self, ctx: Fr, note: &NoteOpening) -> Result<(Fr, [Fr; 6]), Error> {
        Ratchet::seal_payload(Ratchet::key_note(), self.s, ctx, &note.to_payload())
    }
}

/// A channel from this sender to one receiver.
#[derive(Clone, Debug)]
pub struct Sender {
    pub(crate) pk_b: Fr,
    pub(crate) to: ReceiverPublic,
    pub(crate) not_after: u64,
    pub(crate) chain: Option<SenderChain>,
}

impl Sender {
    /// Accepts a receiver's bundle (PROTOCOL.md §4 step 1): its format, the
    /// chain, the validity window at `now`, V on the curve, ek (fetched by
    /// `fetch` when it's a URL) and its commitment.
    pub fn accept(
        bundle: &[u8],
        chain_id: u64,
        now: u64,
        fetch: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<Self, BundleError> {
        Ok(Self::from_accepted(Bundle::accept(
            bundle, chain_id, now, fetch,
        )?))
    }

    pub fn from_accepted(a: Accepted) -> Self {
        Self {
            pk_b: a.pk_b,
            to: a.receiver,
            not_after: a.not_after,
            chain: None,
        }
    }

    /// The receiver's shielded address: output 0 of a transfer on this channel goes to it.
    pub fn pk_b(&self) -> Fr {
        self.pk_b
    }

    pub fn receiver(&self) -> &ReceiverPublic {
        &self.to
    }

    /// The bundle's `not_after`: re-handshake to a new bundle after it (R3, S5).
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The next chain index, once the handshake happened.
    pub fn index(&self) -> Option<u64> {
        self.chain.as_ref().map(SenderChain::index)
    }

    /// The first transfer on the channel: the KEM to the receiver's keys and
    /// the root. Opens the chain at t = 1. Persist before broadcasting.
    pub fn handshake(&mut self) -> Result<ChannelWitness, Error> {
        if self.chain.is_some() {
            return Err(Error::ChannelAlreadyOpen);
        }
        let kem = KemWitness::new(&self.to)?;
        let s = kem.handshake.root;
        self.chain = Some(SenderChain::after_handshake(s));
        Ok(ChannelWitness {
            is_handshake: true,
            t: 0,
            s,
            c_t: Ratchet::commit(s),
            kem,
        })
    }

    /// A later transfer: the next chain key, and a KEM to a throwaway key so
    /// the transfer has the handshake's shape. Persist before broadcasting.
    pub fn advance(&mut self) -> Result<ChannelWitness, Error> {
        let chain = self.chain.as_mut().ok_or(Error::ChannelNotOpen)?;
        let (t, s) = chain.advance();
        let kem = KemWitness::new(&ReceiverKeys::generate().public)?;
        Ok(ChannelWitness {
            is_handshake: false,
            t,
            s,
            c_t: Ratchet::commit(s),
            kem,
        })
    }

    /// Skips `n` indices (what a crash that lost the counter does; the
    /// receiver's window absorbs up to `W`).
    pub fn skip(&mut self, n: u64) -> Result<(), Error> {
        let chain = self.chain.as_mut().ok_or(Error::ChannelNotOpen)?;
        for _ in 0..n {
            chain.advance();
        }
        Ok(())
    }
}
