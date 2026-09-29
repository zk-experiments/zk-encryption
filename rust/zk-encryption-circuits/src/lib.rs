//! The post-quantum encrypted channel as one building block for noir-zk
//! pipelines: the circuits (the session app and the payload envelope, frozen
//! as a noir-zk layered registry with bytecode bundled), the wallet library
//! that seals and opens what they seal ([`wallet`]: `zk-encryption`
//! re-exported), and the mapping between the two ([`session`], [`envelope`]:
//! the Rust types onto the circuits' inputs, the pipeline's public outputs
//! back into what a receiver scans).
//!
//! A target project depends on this crate alone and gets: the registry
//! (`circuits::families::{KernelStepSession, KernelStepEnvelope,
//! KernelStepNoteEnvelope}`, `circuits::{LIBRARY, REGISTRY, FAMILIES}` for
//! a combining registry, [`artifacts`]), `wallet::{sender::Sender,
//! receiver::Receiver, bundle::Bundle, ratchet::{Payload, Ratchet}, ...}`,
//! and the input/output mapping. `zk-encryption` stays a standalone crate (no
//! circuits, no noir-zk) for wallets that only need the crypto.
//!
//! The families (`circuits/manifest.toml`):
//! - `channel/session`: `[ctx, C_t, E.x, E.y, tag, ct_commitment]`, all
//!   public, no link. `ctx` is a public input the app passes through; the
//!   envelopes (and a transfer) are bound to it and to `C_t`.
//! - `channel/envelope`: the payload envelope (one circuit) with its payload
//!   domain pinned to DG1's (`Ratchet::key_payload()`) by a constant binding
//!   the kernel enforces: link in `PayloadCommitment`, bound to the
//!   session's `ctx` and `C_t`, publishes `c_id0..5`.
//! - `channel/note_envelope`: the same circuit pinned to the note opening's
//!   domain (`Ratchet::key_note()`), publishes `c_note0..5`. Two envelopes
//!   of one transfer never share a keystream, and a pipeline folding the
//!   circuit twice under one domain is refused at build.

/// Generated from the manifest (see the crate docs).
#[allow(missing_docs, clippy::all)]
pub mod circuits {
    include!(concat!(env!("OUT_DIR"), "/circuits.rs"));
}

/// The noir-zk revision this layer is frozen and folded with (its kernels'
/// family is in every pipeline root): the `feat/pipelines` branch until
/// noir-zk 0.3.0 is on crates.io. `Cargo.toml` and `mise.toml` pin the same.
pub const NOIR_ZK_REV: &str = "dd2d33f";

/// The wallet library (`zk-encryption`): the primitives, the ratchet, `Sender`,
/// `Receiver`, `Bundle`, the `Envelope` event, `Payload`, `NoirToml`.
pub mod wallet {
    pub use zk_encryption::*;
}

/// This layer's circuits as artifacts, bytecode bundled.
pub fn artifacts() -> noir_zk_backend::Frozen<noir_zk_backend::BundledStore> {
    noir_zk_backend::Frozen::layered(
        circuits::REGISTRY,
        circuits::FAMILIES,
        noir_zk_backend::BundledStore(circuits::ASSETS),
    )
}

/// The session app: its inputs from a sender's channel witness, its outputs
/// back into the `Envelope` event.
pub mod session {
    use zk_encryption::Fr;
    use zk_encryption::emit::{Envelope, Kem};
    use zk_encryption::grumpkin::Point;
    use zk_encryption::lattice::Ciphertext;
    use zk_encryption::sender::ChannelWitness;
    use zk_encryption::witness::NoirToml;

    /// The label of the session app in the registry.
    pub const LABEL: &str = "channel_session";

    /// The session app's `Prover.toml`: the channel witness (the handshake or
    /// ratchet KEM, the chain key) and the transfer's `ctx`.
    pub fn inputs(w: &ChannelWitness, ctx: Fr) -> String {
        NoirToml::new().session(w, ctx).finish()
    }

    /// The session app's public outputs as a pipeline publishes them
    /// (`Outputs::{ctx, c_t, e_x, e_y, tag, ct_commitment}` of a pipeline
    /// with a session position).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Outputs {
        pub ctx: Fr,
        pub c_t: Fr,
        pub e_x: Fr,
        pub e_y: Fr,
        pub tag: Fr,
        pub ct_commitment: Fr,
    }

    impl Outputs {
        /// The `Envelope` event of a transaction: these outputs, the carried
        /// lattice ciphertext (the transaction's extData; it must open
        /// `ct_commitment`) and the envelope apps' outputs.
        pub fn envelope(
            &self,
            ct: Ciphertext,
            c_note: [Fr; 6],
            c_id: [Fr; 6],
        ) -> Result<Envelope, zk_encryption::Error> {
            if ct.commitment() != self.ct_commitment {
                return Err(zk_encryption::Error::CiphertextMismatch);
            }
            Ok(Envelope {
                c_t: self.c_t,
                kem: Kem {
                    ephemeral: Point {
                        x: self.e_x,
                        y: self.e_y,
                    },
                    tag: self.tag,
                    ct_commitment: self.ct_commitment,
                    ct,
                },
                c_note,
                c_id,
            })
        }
    }
}

/// The envelope app (both families): its inputs from a payload.
pub mod envelope {
    use zk_encryption::Fr;
    use zk_encryption::witness::NoirToml;

    /// The label of the envelope circuit (a member of both families).
    pub const LABEL: &str = "channel_envelope";

    /// An envelope app's `Prover.toml`: the payload domain the family pins
    /// (`Ratchet::key_payload()` for `channel/envelope`, `Ratchet::key_note()`
    /// for `channel/note_envelope`: any other value is refused by the
    /// kernel), the payload (`Dg1::to_payload`, `NoteOpening::to_payload`,
    /// ...), the salt of its commitment (the link the committing step left),
    /// the session's `ctx` and chain key `s`.
    pub fn inputs(domain: Fr, payload: &[Fr], salt: Fr, ctx: Fr, s: Fr) -> String {
        NoirToml::new()
            .envelope(domain, payload, salt, ctx, s)
            .finish()
    }
}
