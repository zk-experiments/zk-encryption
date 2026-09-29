//! `Serialize`/`Deserialize` (feature `serde`) for the persisted state:
//! field elements as hex, the ML-KEM key pair as its 64-byte seed, a
//! receiver's public key as V and ek (re-expanded on load).

use crate::Fr;
use crate::grumpkin::Point;
use crate::lattice::{EK_BYTES, MlKemKeys};
use crate::poseidon::FieldHex;
use crate::ratchet::{ReceiverKeys, ReceiverPublic, SenderChain, Session};
use crate::receiver::Receiver;
use crate::sender::Sender;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::VecDeque;

fn hx(f: &Fr) -> String {
    f.hex()
}

fn fr(s: &str) -> Fr {
    Fr::from_hex(s)
}

fn bytes<const N: usize, E: serde::de::Error>(s: &str) -> Result<[u8; N], E> {
    hex::decode(s)
        .map_err(E::custom)?
        .try_into()
        .map_err(|_| E::custom(format!("expected {N} bytes")))
}

#[derive(Serialize, Deserialize)]
struct PublicRecord {
    v_x: String,
    v_y: String,
    ek: String,
}

impl Serialize for ReceiverPublic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        PublicRecord {
            v_x: hx(&self.grumpkin.x),
            v_y: hx(&self.grumpkin.y),
            ek: hex::encode(self.ek),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for ReceiverPublic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = PublicRecord::deserialize(d)?;
        let ek: [u8; EK_BYTES] = bytes(&r.ek)?;
        Self::from_published(
            Point {
                x: fr(&r.v_x),
                y: fr(&r.v_y),
            },
            &ek,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct KeysRecord {
    v: String,
    seed: String,
}

impl Serialize for ReceiverKeys {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (v, seed) = self.secrets();
        KeysRecord {
            v: hx(&v),
            seed: hex::encode(seed),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for ReceiverKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = KeysRecord::deserialize(d)?;
        Ok(Self::from_secrets(
            fr(&r.v),
            MlKemKeys::from_seed(bytes(&r.seed)?),
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct ChainRecord {
    t: u64,
    s: String,
}

impl Serialize for SenderChain {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ChainRecord {
            t: self.t,
            s: hx(&self.s),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for SenderChain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = ChainRecord::deserialize(d)?;
        Ok(Self {
            t: r.t,
            s: fr(&r.s),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SessionRecord {
    next_t: u64,
    next_s: String,
    window: u64,
    highest: u64,
    max_skipped: usize,
    /// (C_t, t, S_t), by t.
    keys: Vec<(String, u64, String)>,
}

impl Serialize for Session {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut keys: Vec<(String, u64, String)> = self
            .keys
            .iter()
            .map(|(c, (t, k))| (hx(c), *t, hx(k)))
            .collect();
        keys.sort_by_key(|k| k.1);
        SessionRecord {
            next_t: self.next_t,
            next_s: hx(&self.next_s),
            window: self.window,
            highest: self.highest,
            max_skipped: self.max_skipped,
            keys,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = SessionRecord::deserialize(d)?;
        Ok(Self {
            next_t: r.next_t,
            next_s: fr(&r.next_s),
            window: r.window,
            highest: r.highest,
            max_skipped: r.max_skipped,
            keys: r
                .keys
                .iter()
                .map(|(c, t, k)| (fr(c), (*t, fr(k))))
                .collect(),
        })
    }
}

#[derive(Serialize)]
struct ReceiverOut<'a> {
    keys: &'a ReceiverKeys,
    pk: String,
    window: u64,
    max_skipped: usize,
    sessions: &'a [Session],
    consumed: Vec<String>,
    channels: Vec<String>,
}

#[derive(Deserialize)]
struct ReceiverRecord {
    keys: ReceiverKeys,
    pk: String,
    window: u64,
    max_skipped: usize,
    sessions: Vec<Session>,
    consumed: Vec<String>,
    channels: Vec<String>,
}

impl Serialize for Receiver {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ReceiverOut {
            keys: &self.keys,
            pk: hx(&self.pk),
            window: self.window,
            max_skipped: self.max_skipped,
            sessions: &self.sessions,
            consumed: self.consumed.iter().map(hx).collect(),
            channels: self.channels.iter().map(hx).collect(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Receiver {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = ReceiverRecord::deserialize(d)?;
        Ok(Self {
            keys: r.keys,
            pk: fr(&r.pk),
            window: r.window,
            max_skipped: r.max_skipped,
            sessions: r.sessions,
            consumed: r.consumed.iter().map(|s| fr(s)).collect::<VecDeque<_>>(),
            channels: r.channels.iter().map(|s| fr(s)).collect(),
        })
    }
}

#[derive(Serialize)]
struct SenderOut<'a> {
    pk_b: String,
    to: &'a ReceiverPublic,
    not_after: u64,
    chain: &'a Option<SenderChain>,
}

#[derive(Deserialize)]
struct SenderRecord {
    pk_b: String,
    to: ReceiverPublic,
    not_after: u64,
    chain: Option<SenderChain>,
}

impl Serialize for Sender {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        SenderOut {
            pk_b: hx(&self.pk_b),
            to: &self.to,
            not_after: self.not_after,
            chain: &self.chain,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Sender {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = SenderRecord::deserialize(d)?;
        Ok(Self {
            pk_b: fr(&r.pk_b),
            to: r.to,
            not_after: r.not_after,
            chain: r.chain,
        })
    }
}
