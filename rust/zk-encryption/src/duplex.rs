//! The envelope cipher: eid_envelope's Poseidon2 duplex (width 4, rate 3),
//! keyed with (key, a, b, CIPHER) and bound to ctx. Each ciphertext field is
//! the plaintext field plus a state element and replaces it; one permutation
//! per block of three.

use crate::poseidon::Poseidon;
use crate::{Error, Fr};

pub struct Duplex;

impl Duplex {
    fn cipher_domain() -> Fr {
        Poseidon::domain("eid-envelope/cipher/v1")
    }

    fn run(key: Fr, a: Fr, b: Fr, ctx: Fr, input: &[Fr], encrypt: bool) -> Result<Vec<Fr>, Error> {
        let mut state = Poseidon::permute([key, a, b, Self::cipher_domain()]);
        state[0] += ctx;
        state = Poseidon::permute(state);
        let mut out = Vec::with_capacity(input.len());
        for block in input.chunks(3) {
            for (j, x) in block.iter().enumerate() {
                let c = if encrypt { *x + state[j] } else { *x };
                out.push(if encrypt { c } else { *x - state[j] });
                state[j] = c;
            }
            state = Poseidon::permute(state);
        }
        Ok(out)
    }

    /// Encrypts `plaintext` (blocks of 3 fields, the last possibly partial).
    pub fn seal(key: Fr, a: Fr, b: Fr, ctx: Fr, plaintext: &[Fr]) -> Result<Vec<Fr>, Error> {
        Self::run(key, a, b, ctx, plaintext, true)
    }

    pub fn open(key: Fr, a: Fr, b: Fr, ctx: Fr, ciphertext: &[Fr]) -> Result<Vec<Fr>, Error> {
        Self::run(key, a, b, ctx, ciphertext, false)
    }
}
