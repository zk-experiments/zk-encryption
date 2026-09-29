//! Poseidon2 over BN254 as Noir's `Poseidon2::hash` and permutation (the
//! `pso-poseidon` crate, the same one eid-circuits uses), domain tags, and
//! hex encoding of field elements.

use crate::Fr;
use ark_ff::{BigInteger, PrimeField};
use pso_poseidon::poseidon2::Poseidon2;

/// The hash the circuits use.
pub struct Poseidon;

impl Poseidon {
    /// Noir's Poseidon2 sponge (`Poseidon2::hash(inputs, inputs.len())`).
    pub fn hash(inputs: &[Fr]) -> Fr {
        Poseidon2::<Fr>::new().hash_noir(inputs)
    }

    /// The width-4 permutation.
    pub fn permute(state: [Fr; 4]) -> [Fr; 4] {
        Poseidon2::<Fr>::new().permutation(&state)
    }

    /// A domain tag: the ASCII string as a big-endian integer.
    pub fn domain(tag: &str) -> Fr {
        Fr::from_be_bytes_mod_order(tag.as_bytes())
    }
}

/// Hex encoding and decoding of field elements, as nargo prints them.
pub trait FieldHex: Sized {
    fn hex(&self) -> String;
    fn from_hex(s: &str) -> Self;
    fn to_be32(&self) -> [u8; 32];
}

impl FieldHex for Fr {
    fn hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_be32()))
    }

    fn from_hex(s: &str) -> Self {
        let s = s.trim_start_matches("0x");
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        Fr::from_be_bytes_mod_order(&hex::decode(s).expect("hex"))
    }

    fn to_be32(&self) -> [u8; 32] {
        let b = self.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    }
}

/// Randomness from the OS CSPRNG.
pub struct Rng;

impl Rng {
    pub fn field() -> Fr {
        let mut b = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        Fr::from_le_bytes_mod_order(&b)
    }

    pub fn bytes<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        b
    }
}
