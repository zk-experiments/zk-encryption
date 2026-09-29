//! Parity with the Rust reference (reference/src/bin/gen.rs writes
//! vectors.nr): the lattice encryption, both commitments, the handshake
//! and a sealed payload give the same values here and in Rust.

use crate::lattice::{commit_expanded, commit_lattice_ct, lattice_encrypt};
use crate::{LatticeNoise, PqKey};
use crate::ratchet::{chain_next, handshake_kem, KEY_PAYLOAD_DOMAIN, seal_keyed};
use crate::vectors::{
    CT_COMMITMENT, CT_U, CT_V, CTX, E, HS_EPHEMERAL, HS_ROOT, HS_TAG, M, NEXT, NOISE_E1, NOISE_E2,
    NOISE_R, PAYLOAD9, PAYLOAD9_COMMITMENT, PAYLOAD9_ENVELOPE, PAYLOAD9_SALT, PLAINTEXT, PQ_A_HAT,
    PQ_COMMITMENT, PQ_H_EK, PQ_T_HAT, RECEIVER, S, SEALED_CIPHERTEXT, SEALED_COMMITMENT,
    SESSION_HANDSHAKE, SESSION_RATCHET,
};
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn key() -> PqKey {
    PqKey { a_hat: PQ_A_HAT, t_hat: PQ_T_HAT, h_ek: PQ_H_EK }
}

fn noise() -> LatticeNoise {
    LatticeNoise { r: NOISE_R, e1: NOISE_E1, e2: NOISE_E2 }
}

fn receiver() -> EmbeddedCurvePoint {
    EmbeddedCurvePoint { x: RECEIVER[0], y: RECEIVER[1] }
}

/// The uncompressed K-PKE ciphertext and both commitments equal the reference's.
#[test]
fn lattice_matches_reference() {
    let (u, v) = lattice_encrypt(PQ_A_HAT, PQ_T_HAT, NOISE_R, NOISE_E1, NOISE_E2, M);
    assert_eq(u, CT_U);
    assert_eq(v, CT_V);
    assert_eq(commit_lattice_ct(u, v), CT_COMMITMENT);
    assert_eq(commit_expanded(PQ_A_HAT, PQ_T_HAT, PQ_H_EK), PQ_COMMITMENT);
}

/// E, the tag, the ciphertext commitment and the transcript-bound root.
#[test]
fn handshake_matches_reference() {
    let (ephemeral, tag, ct_commitment, root) = handshake_kem(receiver(), key(), E, noise(), M);
    assert_eq([ephemeral.x, ephemeral.y], HS_EPHEMERAL);
    assert_eq(tag, HS_TAG);
    assert_eq(ct_commitment, CT_COMMITMENT);
    assert_eq(root, HS_ROOT);
}

/// The session app: on a handshake C_0 commits to the transcript-bound root,
/// on a ratchet transfer to the chain key; E, tag and ct_commit are the KEM's.
#[test]
fn session_matches_reference() {
    let chan = |is_handshake| {
        crate::session::Channel {
            is_handshake,
            receiver: receiver(),
            pq_key: key(),
            e: E,
            noise: noise(),
            m: M,
            s: S,
        }
    };
    assert_eq(crate::session::session(CTX, chan(true)), SESSION_HANDSHAKE);
    assert_eq(crate::session::session(CTX, chan(false)), SESSION_RATCHET);
}

/// A payload sealed under a chain key, and the chain step.
#[test]
fn sealing_matches_reference() {
    let sealed = seal_keyed(KEY_PAYLOAD_DOMAIN, S, CTX, PLAINTEXT);
    assert_eq(sealed.commitment, SEALED_COMMITMENT);
    assert_eq(sealed.ciphertext, SEALED_CIPHERTEXT);
    assert_eq(chain_next(S), NEXT);
}

/// Noise at the bound is accepted: every coefficient ±2.
#[test]
fn accepts_noise_at_bound() {
    let mut n = noise();
    for i in 0..3 {
        for k in 0..256 {
            n.r[i][k] = if k % 2 == 0 { 2 } else { -2 };
            n.e1[i][k] = if k % 3 == 0 { -2 } else { 2 };
        }
    }
    let _ = lattice_encrypt(PQ_A_HAT, PQ_T_HAT, n.r, n.e1, n.e2, M);
}

#[test(should_fail)]
fn rejects_noise_3() {
    let mut n = noise();
    n.e2[7] = 3;
    let _ = lattice_encrypt(PQ_A_HAT, PQ_T_HAT, n.r, n.e1, n.e2, M);
}

#[test(should_fail)]
fn rejects_noise_minus_3() {
    let mut n = noise();
    n.r[1][200] = -3;
    let _ = lattice_encrypt(PQ_A_HAT, PQ_T_HAT, n.r, n.e1, n.e2, M);
}

#[test(should_fail_with = "ephemeral scalar must not be zero")]
fn rejects_zero_scalar() {
    let _ = handshake_kem(receiver(), key(), 0, noise(), M);
}

#[test(should_fail_with = "receiver key must not be the point at infinity")]
fn rejects_infinity() {
    let _ = handshake_kem(
        EmbeddedCurvePoint::point_at_infinity(),
        key(),
        E,
        noise(),
        M,
    );
}

/// The payload code is generic in the size: a 9-field payload (three duplex
/// blocks; the frozen circuits use 6) commits and seals as the reference does.
#[test]
fn payload_of_another_size_matches_the_reference() {
    assert_eq(crate::payload::commit(PAYLOAD9_SALT, PAYLOAD9), PAYLOAD9_COMMITMENT);
    assert_eq(
        crate::payload::envelope(
            crate::ratchet::KEY_NOTE_DOMAIN,
            PAYLOAD9,
            PAYLOAD9_SALT,
            CTX,
            S,
        ),
        PAYLOAD9_ENVELOPE,
    );
}
