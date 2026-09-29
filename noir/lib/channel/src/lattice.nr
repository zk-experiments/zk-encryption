//! The circuit-friendly lattice encryption: ML-KEM-768's K-PKE (k = 3,
//! n = 256, q = 3329) with prover-supplied noise range-checked to |x| ≤ 2,
//! no compression and no FO transform, over the receiver's pre-expanded
//! ML-KEM key (Â in NTT form, t̂, H(ek)) bound by a Poseidon2 commitment.
//! Arithmetic mod q runs over the BN254 integers and is reduced only where
//! needed; every function states its bounds. Soundness notes: README.md.

use crate::consts::{GAMMAS, ZETAS};
use poseidon::poseidon2::Poseidon2;

pub global Q: Field = 3329;
/// "eid-envelope/pqcommit/v1" as a big-endian integer.
pub global PQ_COMMIT_DOMAIN: Field = 0x6569642d656e76656c6f70652f7071636f6d6d69742f7631;
/// "eid-envelope/latticect/v1" as a big-endian integer.
pub global LATTICE_CT_DOMAIN: Field = 0x6569642d656e76656c6f70652f6c61747469636563742f7631;

pub type Poly = [Field; 256];

/// The lattice variant's encryption noise, chosen by the prover (honestly:
/// CBD with η = 2); every coefficient is range checked to |x| ≤ 2.
pub struct LatticeNoise {
    pub r: [Poly; 3],
    pub e1: [Poly; 3],
    pub e2: Poly,
}

/// The receiver's ML-KEM-768 key, pre-expanded: Â (SampleNTT from ρ), t̂
/// (ByteDecode_12 of ek) and H(ek) as four little-endian lanes.
pub struct PqKey {
    pub a_hat: [[Poly; 3]; 3],
    pub t_hat: [Poly; 3],
    pub h_ek: [u64; 4],
}

// ---------------------------------------------------------------- mod q

unconstrained fn divmod_q(x: Field) -> (Field, Field) {
    let b: [u8; 32] = x.to_be_bytes();
    let mut qq: Field = 0;
    let mut r: u32 = 0;
    for i in 0..32 {
        let cur = r * 256 + b[i] as u32;
        qq = qq * 256 + (cur / 3329) as Field;
        r = cur % 3329;
    }
    (qq, r as Field)
}

/// A representative of `x mod q` below 2^12 (not necessarily below q).
/// Requires x to be an integer in [0, 2^(QB + 11)) so the quotient fits `QB`
/// bits; callers add a multiple of q to signed values first.
fn reduce_lazy<let QB: u32>(x: Field) -> Field {
    // Safety: the quotient and remainder are range checked and recombined.
    let (qq, r) = unsafe { divmod_q(x) };
    r.assert_max_bit_size::<12>();
    qq.assert_max_bit_size::<QB>();
    assert(qq * Q + r == x);
    r
}

/// `x mod q` in [0, q).
fn reduce<let QB: u32>(x: Field) -> Field {
    let r = reduce_lazy::<QB>(x);
    (3328 - r).assert_max_bit_size::<12>();
    r
}

// ---------------------------------------------------------------- NTT

unconstrained fn identity(x: Field) -> Field {
    x
}

/// x as a fresh witness, so later layers reference one wire instead of
/// re-expanding a dense linear combination (std::as_witness doesn't stop that).
fn materialize(x: Field) -> Field {
    // Safety: constrained equal to x.
    let w = unsafe { identity(x) };
    assert(w == x);
    w
}

/// Offsets (multiples of q) that make the signed values below non-negative
/// before a reduction.
global OFF_MUL: Field = 3329 * 0x4000000000000000000000000; // q·2^98 > 2^109
global OFF_OUT: Field = 3329 * 0x40000000000000000000000000; // q·2^102 > 2^113

/// NTT (Algorithm 9) over the integers, no reductions: every layer output is
/// one witness, a linear combination of two. Input |f| ≤ 2 (CBD), output
/// |f| < 2·3329^7 < 2^83, congruent mod q to the FIPS 203 NTT.
fn ntt(f_in: Poly) -> Poly {
    let mut f = f_in;
    for layer in 0..7 {
        let len: u32 = 128 >> layer;
        for grp in 0..(1 << layer) {
            let zeta = ZETAS[(1 << layer) + grp];
            let start = grp * 2 * len;
            for j in start..start + len {
                let t = zeta * f[j + len];
                f[j + len] = f[j] - t;
                f[j] = f[j] + t;
                f[j + len] = materialize(f[j + len]);
                f[j] = materialize(f[j]);
            }
        }
    }
    f
}

/// NTT⁻¹ without the final 3303 factor (Algorithm 10), no reductions.
/// Input 0 ≤ f < 2^12, output |f| < 2^12·6656^7 < 2^101.
fn intt_unscaled(f_in: Poly) -> Poly {
    let mut f = f_in;
    for layer in 0..7 {
        let len: u32 = 2 << layer;
        for grp in 0..(64 >> layer) {
            let zeta = ZETAS[(128 >> layer) - 1 - grp];
            let start = grp * 2 * len;
            for j in start..start + len {
                let t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = zeta * (f[j + len] - t);
                f[j + len] = materialize(f[j + len]);
                f[j] = materialize(f[j]);
            }
        }
    }
    f
}

/// Σⱼ a[j] ∘ b[j] in the NTT domain (Algorithms 11, 12), lazily reduced.
/// 0 ≤ a < 2^12, |b| < 2^83, so |c| < 3·(2^95 + 2^106.7) < 2^109.
fn mul_acc(a: [Poly; 3], b: [Poly; 3]) -> Poly {
    let mut out: Poly = [0; 256];
    for i in 0..128 {
        let mut c0: Field = 0;
        let mut c1: Field = 0;
        for j in 0..3 {
            let (a0, a1, b0, b1) = (a[j][2 * i], a[j][2 * i + 1], b[j][2 * i], b[j][2 * i + 1]);
            c0 += a0 * b0 + GAMMAS[i] * a1 * b1;
            c1 += a0 * b1 + a1 * b0;
        }
        out[2 * i] = reduce_lazy::<100>(c0 + OFF_MUL);
        out[2 * i + 1] = reduce_lazy::<100>(c1 + OFF_MUL);
    }
    out
}

/// Two little-endian 16-byte halves of four lanes.
fn lanes_to_fields(l: [u64; 4]) -> [Field; 2] {
    let s = 18446744073709551616; // 2^64
    [l[0] as Field + s * l[1] as Field, l[2] as Field + s * l[3] as Field]
}

/// Commitment to a pre-expanded key: Poseidon2 over H(ek) and the
/// 12-bit coefficients of Â and t̂, 20 per field. The range checks make the
/// packing injective, so the commitment binds the coefficients.
pub fn commit_expanded(a_hat: [[Poly; 3]; 3], t_hat: [Poly; 3], h_ek: [u64; 4]) -> Field {
    let mut packed: [Field; 157] = [0; 157];
    packed[0] = PQ_COMMIT_DOMAIN;
    let h = lanes_to_fields(h_ek);
    packed[1] = h[0];
    packed[2] = h[1];
    let mut polys: [Poly; 12] = [[0; 256]; 12];
    for i in 0..3 {
        for j in 0..3 {
            polys[3 * i + j] = a_hat[i][j];
        }
        polys[9 + i] = t_hat[i];
    }
    let mut pow12: [Field; 20] = [1; 20];
    for k in 1..20 {
        pow12[k] = pow12[k - 1] * 4096;
    }
    for p in 0..12 {
        for n in 0..256 {
            let x = polys[p][n];
            x.assert_max_bit_size::<12>();
            let k = 256 * p + n;
            packed[3 + k / 20] += x * pow12[k % 20];
        }
    }
    Poseidon2::hash(packed, 157)
}

/// |x| ≤ 2 for a signed field element (the support of CBD with η = 2).
fn assert_small(x: Field) {
    (x + 2).assert_max_bit_size::<3>();
    (2 - x).assert_max_bit_size::<3>();
}

/// K-PKE.Encrypt (Algorithm 14) with the noise r, e1, e2 supplied by the
/// prover (range checked to |x| ≤ 2) instead of PRF/CBD sampling, and no
/// compression: returns u = NTT⁻¹(Âᵀ∘NTT(r)) + e1 and
/// v = NTT⁻¹(t̂ᵀ∘NTT(r)) + e2 + Decompress_1(m), canonical mod q.
pub fn lattice_encrypt(
    a_hat: [[Poly; 3]; 3],
    t_hat: [Poly; 3],
    r: [Poly; 3],
    e1: [Poly; 3],
    e2: Poly,
    m: [u8; 32],
) -> ([Poly; 3], Poly) {
    let mut r_hat: [Poly; 3] = [[0; 256]; 3];
    for i in 0..3 {
        for n in 0..256 {
            assert_small(r[i][n]);
            assert_small(e1[i][n]);
        }
        r_hat[i] = ntt(r[i]);
    }
    let mut u: [Poly; 3] = [[0; 256]; 3];
    for i in 0..3 {
        let col = [a_hat[0][i], a_hat[1][i], a_hat[2][i]]; // (Âᵀ)[i][j] = Â[j][i]
        let w = intt_unscaled(mul_acc(col, r_hat));
        for n in 0..256 {
            u[i][n] = reduce::<104>(3303 * w[n] + e1[i][n] + OFF_OUT);
        }
    }
    let w = intt_unscaled(mul_acc(t_hat, r_hat));
    let mut v: Poly = [0; 256];
    for b in 0..32 {
        let bits: [bool; 8] = (m[b] as Field).to_le_bits();
        for t in 0..8 {
            let n = 8 * b + t;
            assert_small(e2[n]);
            v[n] = reduce::<104>(3303 * w[n] + e2[n] + 1665 * bits[t] as Field + OFF_OUT);
        }
    }
    (u, v)
}

/// Poseidon2 commitment to an uncompressed ciphertext: LATTICE_CT, then the
/// 1024 canonical 12-bit coefficients of u ‖ v packed 20 per field.
pub fn commit_lattice_ct(u: [Poly; 3], v: Poly) -> Field {
    let mut packed: [Field; 53] = [0; 53];
    packed[0] = LATTICE_CT_DOMAIN;
    let mut pow12: [Field; 20] = [1; 20];
    for k in 1..20 {
        pow12[k] = pow12[k - 1] * 4096;
    }
    for k in 0..1024 {
        let x = if k < 768 {
            u[k / 256][k % 256]
        } else {
            v[k - 768]
        };
        packed[1 + k / 20] += x * pow12[k % 20];
    }
    Poseidon2::hash(packed, 53)
}
