//! What a transfer carries on the channel, in Emit V2's terms: the hashes
//! (`emit-v2/<label>` domains, as `noir/lib/emit`), the note opening (a
//! channel payload), the `Envelope` event and DG1's encoding (a channel
//! payload).

use crate::lattice::{CT_BYTES, Ciphertext};
use crate::poseidon::{FieldHex, Poseidon};
use crate::ratchet::{Payload, Ratchet};
use crate::{Error, Fr};
use ark_ff::{BigInteger, PrimeField, Zero};

/// Emit V2's hashes.
pub struct Emit;

impl Emit {
    fn d(tag: &str) -> Fr {
        Poseidon::domain(&format!("emit-v2/{tag}"))
    }

    /// The nullifier key of a spending key.
    pub fn nk(sk: Fr) -> Fr {
        Poseidon::hash(&[Self::d("nk"), sk])
    }

    /// The shielded address of a spending key: what a bundle publishes as `pk_B`.
    pub fn pk(sk: Fr) -> Fr {
        Poseidon::hash(&[Self::d("pk"), sk])
    }

    pub fn nullifier(nk: Fr, rho: Fr) -> Fr {
        Poseidon::hash(&[Self::d("nullifier"), nk, rho])
    }

    pub fn commitment(cid: Fr, pk: Fr, value: u128, rho: Fr, r: Fr) -> Fr {
        Poseidon::hash(&[Self::d("commitment"), cid, pk, Fr::from(value), rho, r])
    }

    /// Output `j`'s rho, from the transfer's first nullifier.
    pub fn rho(n0: Fr, j: u64) -> Fr {
        Poseidon::hash(&[Self::d("rho"), n0, Fr::from(j)])
    }

    /// The context every payload of a transfer is bound to (PROTOCOL.md S6).
    pub fn ctx(cid: Fr, nullifiers: [Fr; 2], commitments: [Fr; 2]) -> Fr {
        Poseidon::hash(&[
            Self::d("ctx"),
            cid,
            nullifiers[0],
            nullifiers[1],
            commitments[0],
            commitments[1],
        ])
    }
}

/// A note's opening (value, rho, r): what c_note carries, as the payload
/// `[value, rho, r, 0, 0, 0]` the transfer app commits to and the note
/// envelope app seals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteOpening {
    pub value: u128,
    pub rho: Fr,
    pub r: Fr,
}

impl NoteOpening {
    /// The payload the transfer app commits to and the note envelope seals.
    pub fn to_payload(&self) -> Payload<6> {
        let z = Fr::zero();
        [Fr::from(self.value), self.rho, self.r, z, z, z]
    }

    /// From an opened payload; the value must fit 128 bits and the padding be zero.
    pub fn from_payload(f: &Payload<6>) -> Result<Self, Error> {
        let bytes = f[0].into_bigint().to_bytes_le();
        if bytes[16..].iter().any(|b| *b != 0) || f[3..].iter().any(|x| !x.is_zero()) {
            return Err(Error::HandshakeMismatch);
        }
        Ok(Self {
            value: u128::from_le_bytes(bytes[..16].try_into().expect("16 bytes")),
            rho: f[1],
            r: f[2],
        })
    }

    /// The commitment this opening should equal (the transfer's C0 for the receiver's `pk`).
    pub fn commitment(&self, cid: Fr, pk: Fr) -> Fr {
        Emit::commitment(cid, pk, self.value, self.rho, self.r)
    }

    /// The nullifier the owner spends the note with.
    pub fn nullifier(&self, sk: Fr) -> Fr {
        Emit::nullifier(Emit::nk(sk), self.rho)
    }
}

/// The handshake fields of a transfer (the session app's outputs E, tag and
/// ct_commitment, and the carried ciphertext): real on a handshake, from a
/// throwaway key on a ratchet transfer (every transfer has the same shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kem {
    pub ephemeral: crate::grumpkin::Point,
    pub tag: Fr,
    pub ct_commitment: Fr,
    /// The carried (u, v).
    pub ct: Ciphertext,
}

/// The `Envelope` event: `C_t, E, tag, ct, pqCiphertext, cNote, cId`: the
/// session app's and the envelope apps' public outputs plus the carried
/// lattice ciphertext (the transaction's extData, bound by ct_commitment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub c_t: Fr,
    pub kem: Kem,
    /// The note opening sealed by the note envelope app (a public output).
    pub c_note: [Fr; 6],
    /// DG1 sealed by the DG1 envelope app (a public output; zeros on a
    /// transfer without a document).
    pub c_id: [Fr; 6],
}

impl Envelope {
    /// Bytes of the event: 32 + 64 + 32 + 32 + 1,536 + 192 + 192.
    pub const BYTES: usize = 32 + 64 + 32 + 32 + CT_BYTES + 192 + 192;

    /// The event's ABI layout: big-endian fields, then the 12-bit-packed ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::BYTES);
        b.extend(self.c_t.to_be32());
        b.extend(self.kem.ephemeral.x.to_be32());
        b.extend(self.kem.ephemeral.y.to_be32());
        b.extend(self.kem.tag.to_be32());
        b.extend(self.kem.ct_commitment.to_be32());
        b.extend(self.kem.ct.to_bytes());
        for f in self.c_note.iter().chain(&self.c_id) {
            b.extend(f.to_be32());
        }
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::BYTES {
            return Err(Error::BadLength);
        }
        let f = |i: usize| Fr::from_be_bytes_mod_order(&b[32 * i..32 * i + 32]);
        let ct = Ciphertext::from_bytes(&b[160..160 + CT_BYTES])?;
        let tail = &b[160 + CT_BYTES..];
        let t = |i: usize| Fr::from_be_bytes_mod_order(&tail[32 * i..32 * i + 32]);
        Ok(Self {
            c_t: f(0),
            kem: Kem {
                ephemeral: crate::grumpkin::Point { x: f(1), y: f(2) },
                tag: f(3),
                ct_commitment: f(4),
                ct,
            },
            c_note: [t(0), t(1), t(2), t(3), t(4), t(5)],
            c_id: [t(6), t(7), t(8), t(9), t(10), t(11)],
        })
    }
}

/// One transaction as the receiver reads it: the `Envelope` event and the
/// same transaction's nullifiers and commitments (with the leaf index of
/// C0, the receiver's note), from which it rebuilds ctx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub cid: Fr,
    pub nullifiers: [Fr; 2],
    /// (commitment, leaf index) of the two outputs; output 0 is the receiver's.
    pub commitments: [(Fr, u64); 2],
    pub envelope: Envelope,
}

impl Delivery {
    pub fn ctx(&self) -> Fr {
        Emit::ctx(
            self.cid,
            self.nullifiers,
            [self.commitments[0].0, self.commitments[1].0],
        )
    }
}

/// DG1 (the MRZ with its tags), as the document step commits to it: eid's
/// 6 plaintext fields `[dg1_len, pack_be(95-byte buffer) × 4, 0]`, a channel
/// payload of size 6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dg1(pub Vec<u8>);

impl Dg1 {
    pub const MAX: usize = 95;

    /// The payload the document step commits to and the envelope app seals.
    pub fn to_payload(&self) -> Payload<6> {
        let mut buf = self.0.clone();
        buf.resize(Self::MAX, 0);
        let mut pt = vec![Fr::from(self.0.len() as u64)];
        pt.extend(buf.rchunks(31).map(Fr::from_be_bytes_mod_order));
        pt.push(Fr::zero());
        pt.try_into().expect("6 fields")
    }

    pub fn from_payload(pt: &Payload<6>) -> Self {
        let len = (pt[0].into_bigint().to_bytes_le()[0] as usize).min(Self::MAX);
        let mut out = vec![0u8; Self::MAX];
        for (i, chunk) in out.rchunks_mut(31).enumerate() {
            let be = pt[1 + i].into_bigint().to_bytes_be();
            chunk.copy_from_slice(&be[be.len() - chunk.len()..]);
        }
        out.truncate(len);
        Self(out)
    }

    /// The document step's link: `Ratchet::payload_commitment` of the payload.
    pub fn commitment(&self, salt: Fr) -> Fr {
        Ratchet::payload_commitment(salt, &self.to_payload())
    }

    /// The DG1 envelope app: (C_t, c_id) under chain key `s` and `KEY_PAYLOAD`.
    pub fn seal(&self, s: Fr, ctx: Fr) -> Result<(Fr, [Fr; 6]), Error> {
        Ratchet::seal_payload(Ratchet::key_payload(), s, ctx, &self.to_payload())
    }

    pub fn open(s: Fr, c_t: Fr, ctx: Fr, c_id: &[Fr; 6]) -> Result<Self, Error> {
        let key = Ratchet::key_payload();
        Ok(Self::from_payload(&Ratchet::open_payload(
            key, s, c_t, ctx, c_id,
        )?))
    }
}
