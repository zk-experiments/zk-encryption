//! The session app: the channel's key agreement as a pipeline app of its
//! own. It runs the handshake KEM exactly as the transfer app used to (real
//! receiver keys on a handshake, a throwaway key on a ratchet transfer, so
//! every transfer has one shape) and publishes what the receiver scans:
//! `[ctx, C_t, E.x, E.y, tag, ct_commitment]`. `ctx` is a public input it
//! passes through: the envelope apps and the transfer app are bound to it
//! (and to C_t) by the kernel, and a verifier with a transfer recomputes
//! it from the transfer's public values. No link in or out.

use crate::lattice::{LatticeNoise, PqKey};
use crate::ratchet::{COMMIT_DOMAIN, handshake_kem};
use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// The PQ channel to a recipient (uniform handshake shape).
pub struct Channel {
    pub is_handshake: bool,
    pub receiver: EmbeddedCurvePoint,
    pub pq_key: PqKey,
    pub e: Field,
    pub noise: LatticeNoise,
    pub m: [u8; 32],
    /// The chain key for a ratchet transfer (ignored for a handshake).
    pub s: Field,
}

/// The session app's record, all public.
pub global SESSION_FIELDS: u32 = 6;

pub fn session(context: Field, channel: Channel) -> [Field; SESSION_FIELDS] {
    let (ephemeral, tag, ct_commitment, s0) = handshake_kem(
        channel.receiver,
        channel.pq_key,
        channel.e,
        channel.noise,
        channel.m,
    );
    let s = if channel.is_handshake { s0 } else { channel.s };
    [context, Poseidon2::hash([COMMIT_DOMAIN, s], 2), ephemeral.x, ephemeral.y, tag, ct_commitment]
}
