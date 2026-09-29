//! Payloads: what an envelope app seals. A payload is N fields; a library
//! commits to one with a salt and links the commitment to the envelope app of
//! that size (`PayloadCommitment` in noir-zk's link vocabulary, six fields),
//! which recomputes it, so the app never knows what the fields mean (eid's
//! DG1, a note opening, ...). The code is generic in N; the frozen circuits
//! instantiate N = 6 (`channel_envelope`). Another size is a domain line
//! below, an instantiation and a family. The payload domain (KEY_PAYLOAD for
//! DG1, KEY_NOTE for a note opening) is an input the app writes into its
//! record, and the app's family pins it with a constant binding the kernel
//! enforces: one circuit, two families, and two payloads under one chain key
//! and context never share a keystream (PROTOCOL.md §2).

use crate::ratchet::seal_keyed;
use poseidon::poseidon2::Poseidon2;

pub type Payload<let N: u32> = [Field; N];

/// "pq-channel/payload/v1/<N>" as a big-endian integer: the commitment's
/// domain carries the size (on top of Poseidon2's length-dependent IV).
pub fn payload_domain<let N: u32>() -> Field {
    if N == 6 {
        0x70712d6368616e6e656c2f7061796c6f61642f76312f36
    } else if N == 9 {
        0x70712d6368616e6e656c2f7061796c6f61642f76312f39
    } else {
        std::static_assert(false, "no payload domain for this size");
        0
    }
}

/// A hiding commitment to a payload: `H(payload_domain::<N>(), salt, payload)`.
pub fn commit<let N: u32>(salt: Field, p: Payload<N>) -> Field {
    let mut input: [Field; N + 2] = [0; N + 2];
    input[0] = payload_domain::<N>();
    input[1] = salt;
    for i in 0..N {
        input[2 + i] = p[i];
    }
    Poseidon2::hash(input, N + 2)
}

/// The envelope app's record: `[payload_commitment, ctx, C_t, domain, ciphertext × N]`.
/// A payload (opened from its commitment) sealed under the chain key `s` in
/// context `ctx` (PROTOCOL.md: C_t = H(COMMIT, s), c = Duplex(H(KEY, s, ctx,
/// domain), C_t, ctx, payload)).
pub fn envelope<let N: u32>(
    domain: Field,
    payload: Payload<N>,
    salt: Field,
    context: Field,
    s: Field,
) -> [Field; N + 4] {
    let env = seal_keyed(domain, s, context, payload);
    let mut out: [Field; N + 4] = [0; N + 4];
    out[0] = commit(salt, payload);
    out[1] = context;
    out[2] = env.commitment;
    out[3] = domain;
    for i in 0..N {
        out[4 + i] = env.ciphertext[i];
    }
    out
}
