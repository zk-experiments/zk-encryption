//! Pairwise handshake plus symmetric ratchet (reference: reference/src/ratchet.rs, PROTOCOL.md).
//!
//! - Handshake (the sender's first transfer to a receiver): DH with the
//!   receiver's long-term Grumpkin key and a lattice encryption of m under
//!   its long-term ML-KEM-768 key give the transcript-bound root
//!   S_0 = H(ROOT, m, Z, E, ct_commit, pq_commit), Z = e·V. The receiver's
//!   keys are private witnesses; the public tag H(TAG, Z, pq_commit) binds
//!   them.
//! - Every transfer t (the handshake is t = 0): C_t = H(COMMIT, S_t) and, per
//!   payload, the duplex keyed by (H(key_domain, S_t, ctx), C_t) bound to ctx.
//!   S_{t+1} = H(RATCHET, S_t) happens outside the circuit.

use crate::duplex::duplex;
use crate::lattice::{commit_expanded, commit_lattice_ct, lattice_encrypt, LatticeNoise, PqKey};
use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

/// "pq-ratchet/<label>/v1" as big-endian integers.
pub global TAG_DOMAIN: Field = 0x70712d726174636865742f7461672f7631;
pub global ROOT_DOMAIN: Field = 0x70712d726174636865742f726f6f742f7631;
pub global RATCHET_DOMAIN: Field = 0x70712d726174636865742f726174636865742f7631;
pub global COMMIT_DOMAIN: Field = 0x70712d726174636865742f636f6d6d69742f7631;
/// Key domains, one per payload of a transfer.
/// The one key-derivation domain ("pq-ratchet/key/v1"): K = H(KEY, S_t, ctx, domain).
pub global KEY_DOMAIN: Field = 0x70712d726174636865742f6b65792f7631;
/// The payload domains an envelope's family pins (`bind_const`): DG1's
/// ("pq-ratchet/key-payload/v1") and the note opening's ("pq-ratchet/key-note/v1").
pub global KEY_PAYLOAD_DOMAIN: Field = 0x70712d726174636865742f6b65792d7061796c6f61642f7631;
pub global KEY_NOTE_DOMAIN: Field = 0x70712d726174636865742f6b65792d6e6f74652f7631;

/// A payload sealed on the channel.
pub struct Sealed<let N: u32> {
    /// C_t = H(COMMIT, S_t).
    pub commitment: Field,
    pub ciphertext: [Field; N],
}

/// S_{t+1} = H(RATCHET, S_t).
pub fn chain_next(s: Field) -> Field {
    Poseidon2::hash([RATCHET_DOMAIN, s], 2)
}

/// m[0..16] and m[16..32] as little-endian integers.
pub fn halves(m: [u8; 32]) -> [Field; 2] {
    let mut h: [Field; 2] = [0; 2];
    for half in 0..2 {
        let mut p: Field = 1;
        for i in 0..16 {
            h[half] += m[16 * half + i] as Field * p;
            p *= 256;
        }
    }
    h
}

/// C_t = H(COMMIT, S_t) and the duplex under H(KEY, S_t, ctx, domain), keyed
/// with (key, C_t) and bound to ctx. Distinct payload domains let one chain
/// key seal several payloads of one transfer (DG1 and a note opening); the
/// envelope app's family pins the domain, so the sender doesn't choose it.
pub fn seal_keyed<let N: u32>(
    domain: Field,
    s: Field,
    context: Field,
    plaintext: [Field; N],
) -> Sealed<N> {
    let commitment = Poseidon2::hash([COMMIT_DOMAIN, s], 2);
    let key = Poseidon2::hash([KEY_DOMAIN, s, context, domain], 4);
    Sealed { commitment, ciphertext: duplex(key, commitment, 0, context, plaintext) }
}

/// The handshake's KEM half: (E, tag, ciphertext commitment, S_0), with the
/// root bound to the whole transcript (PROTOCOL.md §4):
/// S_0 = H(ROOT, m, Z, E, ct_commit, pq_commit), Z = e·V.
pub fn handshake_kem(
    receiver: EmbeddedCurvePoint,
    pq_key: PqKey,
    e: Field,
    noise: LatticeNoise,
    m: [u8; 32],
) -> (EmbeddedCurvePoint, Field, Field, Field) {
    assert(e != 0, "ephemeral scalar must not be zero");
    // The receiver's point is a private witness and isn't checked to be on
    // the curve: an off-curve or wrong point gives a tag and root that no
    // receiver recognises, so only the prover's own transfer is harmed.
    assert(!receiver.is_infinite(), "receiver key must not be the point at infinity");
    let scalar = EmbeddedCurveScalar::from_field(e);
    let shared = multi_scalar_mul([receiver], [scalar]);
    let key_commitment = commit_expanded(pq_key.a_hat, pq_key.t_hat, pq_key.h_ek);
    let tag = Poseidon2::hash([TAG_DOMAIN, shared.x, shared.y, key_commitment], 4);
    let (u, v) = lattice_encrypt(pq_key.a_hat, pq_key.t_hat, noise.r, noise.e1, noise.e2, m);
    let ephemeral = fixed_base_scalar_mul(scalar);
    let ct_commitment = commit_lattice_ct(u, v);
    let h = halves(m);
    let root = Poseidon2::hash(
        [
            ROOT_DOMAIN,
            h[0],
            h[1],
            shared.x,
            shared.y,
            ephemeral.x,
            ephemeral.y,
            ct_commitment,
            key_commitment,
        ],
        9,
    );
    (ephemeral, tag, ct_commitment, root)
}
