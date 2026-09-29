//! The channel's values as the circuits' Noir inputs (`Prover.toml` text),
//! in the layout `noir/lib/emit`'s `Channel` and the envelope app
//! (`noir/circuits/channel`) take, so a wallet doesn't re-derive the field packing.

use crate::Fr;
use crate::lattice::{Noise, PqKey};
use crate::poseidon::FieldHex;
use crate::sender::ChannelWitness;

/// A TOML writer for the circuits' inputs: scalars as hex strings, arrays
/// inline, tables by path.
#[derive(Default)]
pub struct NoirToml {
    out: String,
}

impl NoirToml {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(&mut self, key: &str, v: Fr) -> &mut Self {
        self.out.push_str(&format!("{key} = \"{}\"\n", v.hex()));
        self
    }

    pub fn fields(&mut self, key: &str, v: &[Fr]) -> &mut Self {
        self.out.push_str(&format!(
            "{key} = {}\n",
            Self::list(v.iter().map(|x| format!("\"{}\"", x.hex())))
        ));
        self
    }

    pub fn bool(&mut self, key: &str, v: bool) -> &mut Self {
        self.out.push_str(&format!("{key} = {v}\n"));
        self
    }

    pub fn ints<T: std::fmt::Display>(
        &mut self,
        key: &str,
        v: impl IntoIterator<Item = T>,
    ) -> &mut Self {
        self.out.push_str(&format!(
            "{key} = {}\n",
            Self::list(v.into_iter().map(|x| x.to_string()))
        ));
        self
    }

    /// Starts a table (`[path]`); keys written after it belong to it.
    pub fn table(&mut self, path: &str) -> &mut Self {
        self.out.push_str(&format!("\n[{path}]\n"));
        self
    }

    /// Raw TOML (e.g. another writer's output).
    pub fn raw(&mut self, toml: &str) -> &mut Self {
        self.out.push_str(toml);
        self
    }

    fn list(items: impl Iterator<Item = String>) -> String {
        format!("[{}]", items.collect::<Vec<_>>().join(", "))
    }

    fn polys(p: &[[u16; 256]]) -> String {
        Self::list(
            p.iter()
                .map(|x| Self::list(x.iter().map(|c| c.to_string()))),
        )
    }

    fn signed(p: &[i8; 256]) -> String {
        Self::list(
            p.iter()
                .map(|c| format!("\"{}\"", Fr::from(i64::from(*c)).hex())),
        )
    }

    /// The `PqKey { a_hat, t_hat, h_ek }` struct's keys, into the current table.
    pub fn pq_key(&mut self, k: &PqKey) -> &mut Self {
        self.out.push_str(&format!(
            "a_hat = {}\n",
            Self::list(k.a_hat.iter().map(|r| Self::polys(r)))
        ));
        self.out
            .push_str(&format!("t_hat = {}\n", Self::polys(&k.t_hat)));
        self.out.push_str(&format!(
            "h_ek = {}\n",
            Self::list(k.h_ek_lanes().iter().map(|l| format!("\"{l}\"")))
        ));
        self
    }

    /// The `LatticeNoise { r, e1, e2 }` struct's keys, into the current table.
    pub fn noise(&mut self, n: &Noise) -> &mut Self {
        self.out.push_str(&format!(
            "r = {}\n",
            Self::list(n.r.iter().map(Self::signed))
        ));
        self.out.push_str(&format!(
            "e1 = {}\n",
            Self::list(n.e1.iter().map(Self::signed))
        ));
        self.out
            .push_str(&format!("e2 = {}\n", Self::signed(&n.e2)));
        self
    }

    /// The session app's inputs: `context` and the `channel: Channel` tables
    /// `[channel]`, `[channel.receiver]`, `[channel.pq_key]`, `[channel.noise]`.
    pub fn session(&mut self, w: &ChannelWitness, ctx: Fr) -> &mut Self {
        let k = &w.kem;
        self.field("context", ctx)
            .table("channel")
            .bool("is_handshake", w.is_handshake)
            .field("e", k.e)
            .ints("m", k.m)
            .field("s", if w.is_handshake { Fr::from(0u64) } else { w.s })
            .table("channel.receiver")
            .field("x", k.receiver.grumpkin.x)
            .field("y", k.receiver.grumpkin.y)
            .table("channel.pq_key")
            .pq_key(&k.receiver.pq)
            .table("channel.noise")
            .noise(&k.noise)
    }

    pub fn int(&mut self, key: &str, v: impl std::fmt::Display) -> &mut Self {
        self.out.push_str(&format!("{key} = {v}\n"));
        self
    }

    /// The envelope app's inputs: the payload domain its family pins
    /// (`Ratchet::key_payload()` for DG1, `key_note()` for a note opening),
    /// the payload, its commitment salt, the context and the chain key `s`.
    pub fn envelope(&mut self, domain: Fr, payload: &[Fr], salt: Fr, ctx: Fr, s: Fr) -> &mut Self {
        self.field("domain", domain)
            .fields("payload", payload)
            .field("salt", salt)
            .field("context", ctx)
            .field("s", s)
    }

    pub fn finish(&self) -> String {
        self.out.clone()
    }
}
