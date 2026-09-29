//! The receiver bundle, as bytes for a QR code or link (PROTOCOL.md §3):
//!
//! | field | bytes |
//! |---|---|
//! | version | 1 (= 1) |
//! | chain_id | 8, big-endian |
//! | pk_B | 32 |
//! | V | 32: Grumpkin x, big-endian, top bit = y's parity |
//! | pq | 32 |
//! | ek | 1 (0 = URL, 1 = inline) + 2 (length, big-endian) + bytes |
//! | not_before, not_after | 8 + 8, big-endian seconds |
//! | sig | 1 (0 = none, 1 = present) + 65 |
//!
//! The signature is carried but not verified here: it's the receiver's
//! account signature, which depends on the chain's account scheme.

use crate::Fr;
use crate::grumpkin::Point;
use crate::lattice::EK_BYTES;
use crate::poseidon::FieldHex;
use crate::ratchet::ReceiverPublic;
use ark_ff::PrimeField;
use base64::Engine;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ek {
    Url(String),
    Inline(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub chain_id: u64,
    pub pk_b: Fr,
    pub v: Point,
    pub pq: Fr,
    pub ek: Ek,
    pub not_before: u64,
    pub not_after: u64,
    pub sig: Option<[u8; 65]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleError {
    Malformed,
    UnsupportedVersion,
    WrongChain,
    NotYetValid,
    Expired,
    BadGrumpkinKey,
    EkUnavailable,
    BadEk,
    PqMismatch,
}

/// What a sender keeps after accepting a bundle.
#[derive(Clone, Debug)]
pub struct Accepted {
    pub pk_b: Fr,
    pub receiver: ReceiverPublic,
    pub not_after: u64,
}

impl Bundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![1u8];
        b.extend(self.chain_id.to_be_bytes());
        b.extend(self.pk_b.to_be32());
        b.extend(self.v.compress());
        b.extend(self.pq.to_be32());
        let (kind, ek): (u8, &[u8]) = match &self.ek {
            Ek::Url(u) => (0, u.as_bytes()),
            Ek::Inline(e) => (1, e),
        };
        b.push(kind);
        b.extend((ek.len() as u16).to_be_bytes());
        b.extend(ek);
        b.extend(self.not_before.to_be_bytes());
        b.extend(self.not_after.to_be_bytes());
        match &self.sig {
            Some(s) => {
                b.push(1);
                b.extend(s);
            }
            None => b.push(0),
        }
        b
    }

    pub fn to_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.encode())
    }

    pub fn decode(b: &[u8]) -> Result<Self, BundleError> {
        let mut i = 0;
        let mut take = |n: usize| -> Result<&[u8], BundleError> {
            let s = b.get(i..i + n).ok_or(BundleError::Malformed)?;
            i += n;
            Ok(s)
        };
        if take(1)?[0] != 1 {
            return Err(BundleError::UnsupportedVersion);
        }
        let u64be = |s: &[u8]| u64::from_be_bytes(s.try_into().expect("8 bytes"));
        let chain_id = u64be(take(8)?);
        let pk_b = Fr::from_be_bytes_mod_order(take(32)?);
        let v = Point::decompress(take(32)?.try_into().expect("32 bytes"))
            .ok_or(BundleError::BadGrumpkinKey)?;
        let pq = Fr::from_be_bytes_mod_order(take(32)?);
        let kind = take(1)?[0];
        let len = u16::from_be_bytes(take(2)?.try_into().expect("2 bytes")) as usize;
        let data = take(len)?.to_vec();
        let ek = match kind {
            0 => Ek::Url(String::from_utf8(data).map_err(|_| BundleError::Malformed)?),
            1 => Ek::Inline(data),
            _ => return Err(BundleError::Malformed),
        };
        let not_before = u64be(take(8)?);
        let not_after = u64be(take(8)?);
        let sig = match take(1)?[0] {
            0 => None,
            1 => Some(take(65)?.try_into().expect("65 bytes")),
            _ => return Err(BundleError::Malformed),
        };
        if i != b.len() {
            return Err(BundleError::Malformed);
        }
        Ok(Bundle {
            chain_id,
            pk_b,
            v,
            pq,
            ek,
            not_before,
            not_after,
            sig,
        })
    }

    /// The sender's checks (PROTOCOL.md §4.1): the format, the chain, the
    /// validity window at `now`, V on the curve, ek fetched and FIPS
    /// 203-valid, and pq equal to the commitment to ek's expansion.
    pub fn accept(
        bytes: &[u8],
        chain_id: u64,
        now: u64,
        fetch: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<Accepted, BundleError> {
        let b = Self::decode(bytes)?;
        if b.chain_id != chain_id {
            return Err(BundleError::WrongChain);
        }
        if now < b.not_before {
            return Err(BundleError::NotYetValid);
        }
        if now > b.not_after {
            return Err(BundleError::Expired);
        }
        let ek = match &b.ek {
            Ek::Url(u) => fetch(u).ok_or(BundleError::EkUnavailable)?,
            Ek::Inline(e) => e.clone(),
        };
        let ek: [u8; EK_BYTES] = ek.try_into().map_err(|_| BundleError::BadEk)?;
        let receiver = ReceiverPublic::from_published(b.v, &ek).map_err(|_| BundleError::BadEk)?;
        if receiver.pq_commitment != b.pq {
            return Err(BundleError::PqMismatch);
        }
        Ok(Accepted {
            pk_b: b.pk_b,
            receiver,
            not_after: b.not_after,
        })
    }
}
