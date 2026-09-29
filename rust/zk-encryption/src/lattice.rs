//! The circuit-friendly lattice encryption: ML-KEM-768's K-PKE (FIPS 203
//! Algorithm 14; k = 3, n = 256, q = 3329) with sender-chosen noise |x| ≤ 2
//! and no compression, over a real ML-KEM-768 key. The receiver decrypts
//! with the ŝ inside its ML-KEM-768 decapsulation key (FIPS 203 Algorithm
//! 15 without Decompress). Mirrors `noir/channel/src/lattice.nr`.

use crate::poseidon::Poseidon;
use crate::{Error, Fr};
use ark_ff::{PrimeField, Zero};
use ml_kem::KeyExport;
use ml_kem::ml_kem_768::DecapsulationKey;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake128};

pub const Q: i64 = 3329;
pub const EK_BYTES: usize = 1184;
/// The uncompressed ciphertext's bytes: 1024 coefficients × 12 bits.
pub const CT_BYTES: usize = 1024 * 3 / 2;
/// SHAKE128 blocks SampleNTT squeezes per matrix entry (448 candidates for
/// 256 slots); a key needing more (probability 2^-102) is rejected.
pub const XOF_BLOCKS: usize = 4;

pub type Poly = [i64; 256];

/// R_q = Z_q\[X\]/(X^256 + 1) in ML-KEM's NTT representation.
pub struct Ring;

impl Ring {
    fn zeta(i: usize) -> i64 {
        let br = u8::try_from(i).expect("i < 256").reverse_bits() >> 1;
        (0..br).fold(1, |z, _| z * 17 % Q)
    }

    fn gamma(i: usize) -> i64 {
        Self::zeta(i) * Self::zeta(i) % Q * 17 % Q
    }

    /// FIPS 203 Algorithm 9.
    pub fn ntt(mut f: Poly) -> Poly {
        let mut k = 1;
        let mut len = 128;
        while len >= 2 {
            for start in (0..256).step_by(2 * len) {
                let z = Self::zeta(k);
                k += 1;
                for j in start..start + len {
                    let t = z * f[j + len] % Q;
                    f[j + len] = (f[j] - t).rem_euclid(Q);
                    f[j] = (f[j] + t) % Q;
                }
            }
            len /= 2;
        }
        f
    }

    /// FIPS 203 Algorithm 10.
    pub fn intt(mut f: Poly) -> Poly {
        let mut k = 127;
        let mut len = 2;
        while len <= 128 {
            for start in (0..256).step_by(2 * len) {
                let z = Self::zeta(k);
                k -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = (t + f[j + len]) % Q;
                    f[j + len] = z * (f[j + len] - t).rem_euclid(Q) % Q;
                }
            }
            len *= 2;
        }
        f.map(|x| x * 3303 % Q)
    }

    /// Σⱼ a\[j\] ∘ b\[j\] in the NTT domain (Algorithms 11 and 12).
    pub fn mul_acc(a: &[Poly], b: &[Poly]) -> Poly {
        let mut out = [0i64; 256];
        for (x, y) in a.iter().zip(b) {
            for i in 0..128 {
                let (a0, a1, b0, b1) = (x[2 * i], x[2 * i + 1], y[2 * i], y[2 * i + 1]);
                out[2 * i] = (out[2 * i] + a0 * b0 + a1 * b1 % Q * Self::gamma(i)) % Q;
                out[2 * i + 1] = (out[2 * i + 1] + a0 * b1 + a1 * b0) % Q;
            }
        }
        out
    }

    /// The 12-bit coefficients of a Poly packed 20 per field, for commitments.
    fn packed(coeffs: impl Iterator<Item = u16>) -> Vec<Fr> {
        let coeffs: Vec<u16> = coeffs.collect();
        coeffs
            .chunks(20)
            .map(|chunk| {
                chunk
                    .iter()
                    .rev()
                    .fold(Fr::zero(), |f, c| f * Fr::from(4096u64) + Fr::from(*c))
            })
            .collect()
    }
}

/// The receiver's ML-KEM-768 encapsulation key, pre-expanded as the circuit takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqKey {
    /// Â\[i\]\[j\] = SampleNTT(ρ ‖ j ‖ i).
    pub a_hat: [[[u16; 256]; 3]; 3],
    /// t̂ = ByteDecode_12(ek[0..1152]).
    pub t_hat: [[u16; 256]; 3],
    /// H(ek) = SHA3-256(ek).
    pub h_ek: [u8; 32],
}

impl PqKey {
    /// FIPS 203 Algorithm 7 over at most `XOF_BLOCKS` blocks.
    fn sample_ntt(rho: &[u8], j: u8, i: u8) -> Result<[u16; 256], Error> {
        let mut xof = Shake128::default();
        xof.update(rho);
        xof.update(&[j, i]);
        let mut stream = [0u8; 168 * XOF_BLOCKS];
        xof.finalize_xof().read(&mut stream);
        let mut out = [0u16; 256];
        let mut n = 0;
        for t in stream.chunks(3) {
            let (b0, b1, b2) = (u16::from(t[0]), u16::from(t[1]), u16::from(t[2]));
            for d in [b0 + 256 * (b1 % 16), b1 / 16 + 16 * b2] {
                if i64::from(d) < Q && n < 256 {
                    out[n] = d;
                    n += 1;
                }
            }
        }
        if n < 256 {
            Err(Error::KeyNeedsMoreBlocks)
        } else {
            Ok(out)
        }
    }

    /// Expands ek. Rejects keys failing the FIPS 203 modulus check and keys
    /// whose matrix needs more XOF blocks than the circuit's expansion bound.
    pub fn expand(ek: &[u8; EK_BYTES]) -> Result<Self, Error> {
        let mut t_hat = [[0u16; 256]; 3];
        for (p, poly) in t_hat.iter_mut().enumerate() {
            for k in 0..128 {
                let b = &ek[384 * p + 3 * k..384 * p + 3 * k + 3];
                let (b0, b1, b2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
                poly[2 * k] = b0 + 256 * (b1 % 16);
                poly[2 * k + 1] = b1 / 16 + 16 * b2;
            }
        }
        if t_hat.iter().flatten().any(|c| i64::from(*c) >= Q) {
            return Err(Error::BadPqKey);
        }
        let mut a_hat = [[[0u16; 256]; 3]; 3];
        for (i, row) in a_hat.iter_mut().enumerate() {
            for (j, poly) in row.iter_mut().enumerate() {
                *poly = Self::sample_ntt(
                    &ek[1152..],
                    u8::try_from(j).expect("j < 3"),
                    u8::try_from(i).expect("i < 3"),
                )?;
            }
        }
        Ok(Self {
            a_hat,
            t_hat,
            h_ek: Sha3_256::digest(ek).into(),
        })
    }

    /// Two little-endian 16-byte halves of 32 bytes.
    pub fn halves(b: &[u8; 32]) -> [Fr; 2] {
        [
            Fr::from_le_bytes_mod_order(&b[..16]),
            Fr::from_le_bytes_mod_order(&b[16..]),
        ]
    }

    /// Poseidon2(PQ_COMMIT, H(ek) halves, Â ‖ t̂ as 12-bit coefficients, 20 per field).
    pub fn commitment(&self) -> Fr {
        let mut packed = vec![Poseidon::domain("eid-envelope/pqcommit/v1")];
        packed.extend(Self::halves(&self.h_ek));
        packed.extend(Ring::packed(
            self.a_hat
                .iter()
                .flatten()
                .chain(self.t_hat.iter())
                .flatten()
                .copied(),
        ));
        Poseidon::hash(&packed)
    }

    /// H(ek) as four little-endian u64 lanes (the circuit's `h_ek`).
    pub fn h_ek_lanes(&self) -> [u64; 4] {
        std::array::from_fn(|i| {
            u64::from_le_bytes(self.h_ek[8 * i..8 * i + 8].try_into().expect("8 bytes"))
        })
    }
}

/// Sender-chosen encryption noise; honest senders sample CBD with η = 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noise {
    pub r: [[i8; 256]; 3],
    pub e1: [[i8; 256]; 3],
    pub e2: [i8; 256],
}

impl Noise {
    /// CBD_2 from a byte stream (one nibble per coefficient, 7·128 bytes).
    pub fn cbd(bytes: &[u8; 7 * 128]) -> Self {
        let mut it = bytes.iter().flat_map(|b| [b & 15, b >> 4]).map(|n| {
            let pop = |x: u8| i8::try_from((x & 1) + ((x >> 1) & 1)).expect("at most 2");
            pop(n & 3) - pop(n >> 2)
        });
        let mut poly = || std::array::from_fn(|_| it.next().expect("7*128 bytes"));
        Self {
            r: [poly(), poly(), poly()],
            e1: [poly(), poly(), poly()],
            e2: poly(),
        }
    }

    /// CBD_2 from the OS CSPRNG.
    pub fn random() -> Self {
        Self::cbd(&crate::poseidon::Rng::bytes())
    }

    /// Every coefficient at the range-check bound (±2 by the bits of `bytes`).
    pub fn extreme(bytes: &[u8; 7 * 256]) -> Self {
        let mut it = bytes.iter().map(|x| if x & 1 == 1 { 2i8 } else { -2 });
        let mut poly = || std::array::from_fn(|_| it.next().expect("7*256 bytes"));
        Self {
            r: [poly(), poly(), poly()],
            e1: [poly(), poly(), poly()],
            e2: poly(),
        }
    }

    pub fn in_range(&self) -> bool {
        self.r
            .iter()
            .chain(&self.e1)
            .flatten()
            .chain(&self.e2)
            .all(|x| x.abs() <= 2)
    }
}

/// The uncompressed ciphertext, canonical mod q (carried next to the proof).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub u: [[u16; 256]; 3],
    pub v: [u16; 256],
}

impl Ciphertext {
    /// ByteEncode_12 of u ‖ v (FIPS 203 §4.2.1: two coefficients per three bytes, little-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(CT_BYTES);
        let coeffs: Vec<u16> = self.u.iter().flatten().chain(&self.v).copied().collect();
        for pair in coeffs.chunks(2) {
            let (a, c) = (u32::from(pair[0]), u32::from(pair[1]));
            let byte = |x: u32| u8::try_from(x & 0xff).expect("masked");
            b.extend([byte(a), byte((a >> 8) | (c << 4)), byte(c >> 4)]);
        }
        b
    }

    /// ByteDecode_12, refusing coefficients ≥ q (the bytes are non-canonical).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != CT_BYTES {
            return Err(Error::BadLength);
        }
        let mut coeffs = Vec::with_capacity(1024);
        for t in b.chunks(3) {
            let (b0, b1, b2) = (u16::from(t[0]), u16::from(t[1]), u16::from(t[2]));
            coeffs.push(b0 | ((b1 & 0x0f) << 8));
            coeffs.push((b1 >> 4) | (b2 << 4));
        }
        if coeffs.iter().any(|c| i64::from(*c) >= Q) {
            return Err(Error::CiphertextMismatch);
        }
        let mut u = [[0u16; 256]; 3];
        for (i, ui) in u.iter_mut().enumerate() {
            ui.copy_from_slice(&coeffs[256 * i..256 * (i + 1)]);
        }
        let v: [u16; 256] = coeffs[768..].try_into().expect("256 coefficients");
        Ok(Self { u, v })
    }

    /// Poseidon2(LATTICE_CT, u ‖ v as canonical 12-bit coefficients, 20 per field).
    pub fn commitment(&self) -> Fr {
        let mut packed = vec![Poseidon::domain("eid-envelope/latticect/v1")];
        packed.extend(Ring::packed(
            self.u.iter().flatten().chain(&self.v).copied(),
        ));
        Poseidon::hash(&packed)
    }
}

/// K-PKE with the circuit's conventions.
pub struct Kpke;

impl Kpke {
    fn poly(p: &[u16; 256]) -> Poly {
        p.map(i64::from)
    }

    fn small(p: &[i8; 256]) -> Poly {
        p.map(|x| i64::from(x).rem_euclid(Q))
    }

    fn bit(m: &[u8; 32], n: usize) -> i64 {
        i64::from((m[n / 8] >> (n % 8)) & 1)
    }

    /// K-PKE.Encrypt with the given noise and no compression:
    /// u = NTT⁻¹(Âᵀ∘NTT(r)) + e1, v = NTT⁻¹(t̂ᵀ∘NTT(r)) + e2 + Decompress_1(m).
    pub fn encrypt(key: &PqKey, noise: &Noise, m: &[u8; 32]) -> Result<Ciphertext, Error> {
        if !noise.in_range() {
            return Err(Error::NoiseOutOfRange);
        }
        let r_hat: Vec<Poly> = noise.r.iter().map(|r| Ring::ntt(Self::small(r))).collect();
        let mut u = [[0u16; 256]; 3];
        for (i, ui) in u.iter_mut().enumerate() {
            let col: Vec<Poly> = (0..3).map(|j| Self::poly(&key.a_hat[j][i])).collect();
            let w = Ring::intt(Ring::mul_acc(&col, &r_hat));
            for n in 0..256 {
                ui[n] =
                    u16::try_from((w[n] + i64::from(noise.e1[i][n])).rem_euclid(Q)).expect("< q");
            }
        }
        let t: Vec<Poly> = key.t_hat.iter().map(Self::poly).collect();
        let w = Ring::intt(Ring::mul_acc(&t, &r_hat));
        let mut v = [0u16; 256];
        for n in 0..256 {
            v[n] = u16::try_from(
                (w[n] + i64::from(noise.e2[n]) + 1665 * Self::bit(m, n)).rem_euclid(Q),
            )
            .expect("< q");
        }
        Ok(Ciphertext { u, v })
    }

    /// ŝ (NTT form) from an ML-KEM-768 decapsulation key: ByteDecode_12 of
    /// the first 1152 bytes of its expanded encoding (dk_pke).
    pub fn s_hat(dk: &DecapsulationKey) -> [Poly; 3] {
        #[allow(deprecated)]
        let bytes = ml_kem::ExpandedKeyEncoding::to_expanded_bytes(dk);
        let mut s = [[0i64; 256]; 3];
        for (p, poly) in s.iter_mut().enumerate() {
            for k in 0..128 {
                let b = &bytes[384 * p + 3 * k..384 * p + 3 * k + 3];
                let (b0, b1, b2) = (i64::from(b[0]), i64::from(b[1]), i64::from(b[2]));
                poly[2 * k] = b0 + 256 * (b1 % 16);
                poly[2 * k + 1] = b1 / 16 + 16 * b2;
            }
        }
        s
    }

    /// w = v − NTT⁻¹(ŝᵀ ∘ NTT(u)) mod q, the value K-PKE.Decrypt rounds.
    pub fn decrypt_raw(s_hat: &[Poly; 3], u: &[Poly; 3], v: &Poly) -> Poly {
        let u_hat: Vec<Poly> = u.iter().map(|x| Ring::ntt(*x)).collect();
        let su = Ring::intt(Ring::mul_acc(s_hat, &u_hat));
        std::array::from_fn(|n| (v[n] - su[n]).rem_euclid(Q))
    }

    /// Compress_1 of each coefficient, as bytes.
    pub fn round(w: &Poly) -> [u8; 32] {
        let mut m = [0u8; 32];
        for (n, x) in w.iter().enumerate() {
            m[n / 8] |= u8::try_from(((2 * x + 1664) / Q) % 2).expect("a bit") << (n % 8);
        }
        m
    }

    /// K-PKE.Decrypt of an uncompressed ciphertext.
    pub fn decrypt(dk: &DecapsulationKey, ct: &Ciphertext) -> [u8; 32] {
        let u = ct.u.map(|p| Self::poly(&p));
        Self::round(&Self::decrypt_raw(&Self::s_hat(dk), &u, &Self::poly(&ct.v)))
    }
}

/// A real ML-KEM-768 key pair (RustCrypto `ml-kem`): the receiver's long-term key.
pub struct MlKemKeys {
    pub dk: DecapsulationKey,
    pub ek: [u8; EK_BYTES],
    /// The seed (d ‖ z) the pair was derived from: what to persist.
    pub seed: [u8; 64],
}

impl MlKemKeys {
    /// From a 64-byte seed (d ‖ z), as FIPS 203 KeyGen_internal.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        let dk = DecapsulationKey::from_seed(seed.into());
        let ek: [u8; EK_BYTES] = dk.encapsulation_key().to_bytes().into();
        Self { dk, ek, seed }
    }

    pub fn generate() -> Self {
        Self::from_seed(crate::poseidon::Rng::bytes())
    }
}
