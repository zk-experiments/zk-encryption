//! The post-quantum channel the fold seals its payloads on: the Poseidon2
//! duplex, the circuit-friendly lattice encryption over ML-KEM-768 keys, and
//! the pairwise handshake + ratchet. `reference/` (Rust) implements the same
//! constructions natively and generates `vectors.nr`. Specification:
//! README.md and PROTOCOL.md.

mod consts;
pub mod duplex;
pub mod lattice;
pub mod payload;
pub mod ratchet;
pub mod session;
mod tests;
mod vectors;

pub use lattice::{LatticeNoise, Poly, PqKey};
