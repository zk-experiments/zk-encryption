//! The post-quantum envelope channel of the folded eid + Emit V2 transfer,
//! for wallets and receiver services: the complement to the circuits in
//! `noir/`. `PROTOCOL.md` is the protocol; `README.md` the flows.
//!
//! - Primitives the circuits match: [`poseidon`] (Poseidon2 over BN254 and
//!   the domain tags), [`grumpkin`] (points and keys), [`lattice`] (K-PKE
//!   over a real ML-KEM-768 key with bounded noise, the key and ciphertext
//!   commitments), [`duplex`] (the keyed Poseidon2 duplex).
//! - The channel: [`ratchet`] (the handshake, the chain step, keyed sealing,
//!   the receiver's sessions).
//! - The parties: [`receiver`] (long-term keys, [`bundle`], scanning and
//!   opening) and [`sender`] (accepting a bundle, the handshake and ratchet
//!   witnesses). Both states serialise behind the `serde` feature.
//! - What travels: [`emit`] (the Emit V2 hashes, the `Envelope` event, note
//!   openings, DG1's encoding) and [`witness`] (the values as the session
//!   and envelope apps' Noir inputs).

pub mod bundle;
pub mod duplex;
pub mod emit;
pub mod grumpkin;
pub mod lattice;
pub mod poseidon;
pub mod ratchet;
pub mod receiver;
pub mod sender;
pub mod witness;

#[cfg(feature = "serde")]
mod persist;

/// BN254's scalar field: Noir's `Field`, and Grumpkin's base field.
pub use ark_bn254::Fr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A scalar was zero where a key or ephemeral is needed.
    ZeroScalar,
    /// A point isn't on Grumpkin (or is the identity).
    NotOnCurve,
    /// A payload isn't whole blocks of 3 fields, or bytes have the wrong length.
    BadLength,
    /// The ML-KEM encapsulation key fails the FIPS 203 modulus check.
    BadPqKey,
    /// SampleNTT needs more than the circuit's bound of SHAKE128 blocks (2^-102 per key).
    KeyNeedsMoreBlocks,
    /// A noise coefficient is outside [-2, 2].
    NoiseOutOfRange,
    /// The carried lattice ciphertext doesn't open its commitment.
    CiphertextMismatch,
    /// A handshake's tag doesn't match this receiver's keys.
    NotForUs,
    /// The handshake's root doesn't match its commitment, or a note opening
    /// doesn't match the transfer's C0.
    HandshakeMismatch,
    /// No held chain key matches the transfer's commitment.
    UnknownCommitment,
    /// C_t was already consumed (a reused chain index) or the handshake was
    /// already opened (a replay).
    ReusedIndex,
    /// The sender's channel has no handshake yet, or already has one.
    ChannelNotOpen,
    ChannelAlreadyOpen,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
