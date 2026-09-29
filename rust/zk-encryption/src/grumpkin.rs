//! Grumpkin points: the classical half of the handshake (`E = e·G`,
//! `Z = e·V`) and the receiver's long-term key `V = v·G`.

use crate::{Error, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField, Zero};

/// An affine Grumpkin point (never the point at infinity once validated).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    /// `s·G` for a non-zero scalar.
    pub fn generator_mul(s: Fr) -> Result<Self, Error> {
        Self::mul_affine(s, ark_grumpkin::Affine::generator())
    }

    /// `s·self`; the point must be on the curve.
    pub fn mul(&self, s: Fr) -> Result<Self, Error> {
        Self::mul_affine(s, self.affine()?)
    }

    fn mul_affine(s: Fr, p: ark_grumpkin::Affine) -> Result<Self, Error> {
        if s.is_zero() {
            return Err(Error::ZeroScalar);
        }
        let scalar = ark_grumpkin::Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le());
        let (x, y) = (p * scalar).into_affine().xy().ok_or(Error::ZeroScalar)?;
        Ok(Self { x, y })
    }

    fn affine(&self) -> Result<ark_grumpkin::Affine, Error> {
        let a = ark_grumpkin::Affine::new_unchecked(self.x, self.y);
        if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() && !a.is_zero() {
            Ok(a)
        } else {
            Err(Error::NotOnCurve)
        }
    }

    /// On the curve and not the identity.
    pub fn is_valid(&self) -> bool {
        self.affine().is_ok()
    }

    fn y_is_odd(y: &Fr) -> bool {
        y.into_bigint().to_bytes_le()[0] & 1 == 1
    }

    /// x with y's parity in the top bit (the bundle's 32-byte form).
    pub fn compress(&self) -> [u8; 32] {
        use crate::poseidon::FieldHex;
        let mut b = self.x.to_be32();
        if Self::y_is_odd(&self.y) {
            b[0] |= 0x80;
        }
        b
    }

    /// Decompression with the curve check (y² = x³ − 17).
    pub fn decompress(b: &[u8; 32]) -> Option<Self> {
        use crate::poseidon::FieldHex;
        let odd = b[0] & 0x80 != 0;
        let mut xb = *b;
        xb[0] &= 0x7f;
        let x = Fr::from_be_bytes_mod_order(&xb);
        if x.to_be32() != xb {
            return None;
        }
        let y = (x * x * x - Fr::from(17u64)).sqrt()?;
        let y = if Self::y_is_odd(&y) == odd { y } else { -y };
        let p = Self { x, y };
        p.is_valid().then_some(p)
    }
}
