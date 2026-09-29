# zk-encryption

A post-quantum encrypted channel for zero-knowledge pipelines: a pairwise handshake (Grumpkin DH plus a circuit-friendly lattice encryption over the receiver's real ML-KEM-768 key) followed by a symmetric Poseidon2 ratchet, and *payload envelopes* that seal six fields to the receiver inside a proof. Three parts, one building block:

- **Circuits** (`noir/`): the `channel` library (K-PKE over ML-KEM-768 keys with prover-supplied noise, the Poseidon2 duplex, the handshake and ratchet, `Payload<N>`) and two apps folded by [noir-zk](https://github.com/zk-experiments/noir-zk)'s generic pipeline kernels: the **session** (the key agreement, `[ctx, C_t, E, tag, ct_commitment]`) and the **envelope** (a payload sealed under the session's key, `[payload_commitment, ctx, C_t, domain, c × 6]`).
- **Wallet library** (`rust/zk-encryption`): everything a sender or a receiver does off-chain: keys and the published `Bundle`, `Sender::{accept, handshake, advance}`, `Receiver::scan`, `Payload` sealing and opening, the circuits' inputs as `Prover.toml` text. No circuits, no noir-zk dependency.
- **The layer** (`rust/zk-encryption-circuits`): the two circuits frozen as a noir-zk layered registry (families `channel/session`, `channel/envelope`, `channel/note_envelope`; bytecode bundled, so nothing is downloaded), the wallet library re-exported as `wallet`, and the mapping between them (`session::inputs`, `envelope::inputs`, `session::Outputs::envelope`). A target project depends on this crate alone.

[`PROTOCOL.md`](PROTOCOL.md) is the protocol. The reference pipeline that folds this layer with an identity document and a private transfer is in [postquantum-zk-encryption-experiment](https://github.com/zk-experiments/postquantum-zk-encryption-experiment) (the ePassport's DG1 as one payload, an Emit V2 note opening as the other).

## The families

| family | circuit | record | |
|---|---|---|---|
| `channel/session` | `channel_session` | `[ctx, C_t, E.x, E.y, tag, ct_commitment]`, all public, no link | The handshake KEM against the receiver's keys on a handshake, against a throwaway key on a ratchet transfer (every transfer has one shape); `C_t = H(COMMIT, S_t)`. `ctx` is a public input it passes through; the kernel binds the envelopes (and a transfer) to it and to `C_t`. |
| `channel/envelope` | `channel_envelope` | `[payload_commitment, ctx, C_t, domain, c × 6]`; link in `PayloadCommitment`, bound to the session's `ctx` and `C_t`, `domain` pinned to `"pq-ratchet/key-payload/v1"`, publishes `c_id0..5` | Seals a six-field payload whose hiding commitment `H("pq-channel/payload/v1/6", salt, payload)` a previous step left as the link: `K = H(KEY, S_t, ctx, domain)`, `c = Duplex(K, C_t, ctx, payload)`. |
| `channel/note_envelope` | `channel_envelope` | the same, `domain` pinned to `"pq-ratchet/key-note/v1"`, publishes `c_note0..5` | The same circuit under the other domain. |

**Constant-binding domains.** One envelope circuit serves both families: the payload domain is an input the app writes into its record, and each family pins it with `bind_const` (a noir-zk layout entry the kernel enforces). The sender doesn't choose the domain, two envelopes of one pipeline never share a keystream, and a pipeline folding the circuit twice under one domain is refused at build. Another payload (another domain string) is another family over the same frozen key.

This freeze's roots (`zk-encryption@0.1.0`, noir 1.0.0-rc.3, bb 7.0.0-nightly.20260927, noir-zk 0.3.0): see `measurements.json` for the gates and the release's `catalog.json` for the roots and layouts.

## Receiver flow

```rust
use zk_encryption_circuits::wallet::{bundle::{Bundle, Ek}, emit::{Delivery, Emit}, receiver::{Receiver, Scan}};

let mut receiver = Receiver::generate(pk, /* window W */ 8);
let bundle = Bundle { chain_id, pk_b: receiver.pk(), v: receiver.keys().public.grumpkin, pq: receiver.keys().public.pq_commitment, ek: Ek::Inline(receiver.keys().ek().to_vec()), not_before, not_after, sig: None };
let published = bundle.to_base64url();

// Per transaction: the session's and the envelopes' public outputs, the carried lattice
// ciphertext (checked against ct_commitment), and the transaction's nullifiers and commitments.
let envelope = session::Outputs { ctx, c_t, e_x, e_y, tag, ct_commitment }.envelope(ct, c_note, c_id)?;
match receiver.scan(&Delivery { cid, nullifiers, commitments, envelope }) {
    Scan::Handshake { note, dg1 } => { /* a new channel */ }
    Scan::Ratchet { t, note, dg1 } => { /* index t on an open channel */ }
    Scan::NotMine => {}
    Scan::Invalid(err) => { /* addressed to us but not to be trusted */ }
}
```

## Sender flow

```rust
use zk_encryption_circuits::{envelope, session, wallet::{sender::Sender, ratchet::Ratchet}};

let mut channel = Sender::accept(&bundle_bytes, chain_id, now, &fetch)?;
let w = if channel.index().is_none() { channel.handshake()? } else { channel.advance()? };
persist(&channel);   // BEFORE the transfer is broadcast (PROTOCOL.md S3)

let session_toml = session::inputs(&w, ctx);                                                   // the session app
let envelope_toml = envelope::inputs(Ratchet::key_payload(), &payload, salt, ctx, w.s);          // channel/envelope
let note_toml = envelope::inputs(Ratchet::key_note(), &opening.to_payload(), note_salt, ctx, w.s); // channel/note_envelope
// extData: the lattice ciphertext `w.kem.kem().ct`, bound by the session's ct_commitment output.
```

## In a pipeline

A combining registry wraps this layer (`noir_zk_codegen::wrapped(LIBRARY, REGISTRY, FAMILIES)` as an `Options::sources` entry named `zk-encryption`) and names the positions:

```toml
[[family]]
layer = "channel"
name = "session"
source = "zk-encryption"

[[pipeline]]
name = "transfer_only"
positions = ["zk-encryption/channel/session", "emit-circuits/emit/transfer", "zk-encryption/channel/note_envelope"]
```

```rust
let pool = noir_zk_core::Merged::new(&[&zk_encryption_circuits::artifacts(), /* other layers */, &noir_zk_backend::kernels::Kernels]);
let (proof, _) = transfer_only::fold(&pool)?
    .app(KernelStepSession::select(session::LABEL, session::inputs(&w, ctx))?)?
    .app(KernelStepTransfer::select("transfer", transfer_toml)?)?                 // bound to ctx; leaves the note's PayloadCommitment
    .app(KernelStepNoteEnvelope::select(envelope::LABEL, note_toml)?)?
    .hiding(&DEPLOYMENT)?;
```

The session precedes every position bound to `ctx`/`C_t`; an envelope's link is the payload commitment the previous linking step left, so it follows that step. The kernel has one link register: a step that leaves a new link (a transfer) must come after the envelope of the previous link.

## Layout

- `noir/lib/channel`: the library (`consts`, `duplex`, `lattice`, `ratchet`, `session`, `payload`, `tests`, `vectors` (generated)).
- `noir/circuits/session`, `noir/circuits/envelope6`: the two apps with a `Prover.toml` sample each.
- `rust/zk-encryption`: the wallet library ([README](rust/zk-encryption/README.md)).
- `rust/zk-encryption-circuits`: the layer ([README](rust/zk-encryption-circuits/README.md)): `circuits/manifest.toml`, `resources/` and `assets/` written by `noir-zk freeze`; `src/bin/vectors` (writes the Noir tests' vectors from the wallet library) and `src/bin/catalog` (the release catalog).
- `resources/srs/grumpkin_g1_v2.flat.dat`: the 2^15-point Grumpkin CRS prefix noir-zk pins (bb generates it from a fixed generator when it first proves a Chonk stack; committed so CI can derive keys without proving); `scripts/bn254_srs.py` expands the BN254 prefix from Aztec's CRS host (`mise run srs`).
- `measurements.json`: Chonk gates of the two apps.

## How to run

The toolchain is pinned in `mise.toml` (nargo 1.0.0-rc.3, bb 7.0.0-nightly.20260927, the noir-zk CLI at the pinned revision), installed into per-version directories under `~/.toolchains` (`mise run install:zk-toolchain install:noir-zk`); every task documents the raw command.

```sh
mise run compile          # nargo compile --workspace (noir/)
mise run srs              # the SRS noir-zk pins, into ~/.bb-crs (once)
mise run test             # nargo test + cargo test --release --all-features
mise run freeze           # noir-zk freeze ... --library zk-encryption@<version> (-- --check via freeze:check)
mise run measure          # bb gates of the two apps into measurements.json
cargo run --release -p zk-encryption-circuits --bin vectors -- --check   # the Noir vectors are current
```

## Releases

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the tests of both crates (with and without `serde`), `nargo fmt --check`, `nargo test`, `freeze --check`, typos, commitlint and cargo-deny; on `main`, cocogitto bumps the version from the conventional commits, tags, and the release job attaches the frozen `manifest.toml`, `resources.tar.gz` (ABIs and verification keys) with its SHA-256 and `catalog.json` (library, version, toolchain pins, the families with their roots and layouts, the kernels' dependency) to the GitHub release and uploads them to the circuits bucket:

- `https://circuits.zk-experiments.dev/zk-encryption/<version>/{catalog.json, manifest.toml, resources.tar.gz, resources.tar.gz.sha256}` (immutable, 1-year cache)
- `https://circuits.zk-experiments.dev/zk-encryption/latest/catalog.json` (5-minute cache)

The prefix `zk-encryption/` is the workflow variable `R2_PREFIX_ZK_ENCRYPTION` so other repositories share the bucket under their own prefixes. The crate carries the bytecode and every pin (`BYTECODE_SHA256`, `VK_SHA256`, `vk_hash`), so the host is a mirror, not a trust anchor.

noir-zk comes from crates.io at an exact version (`=0.3.0` in `rust/zk-encryption-circuits/Cargo.toml`, `NOIR_ZK_VERSION` in `mise.toml`): its kernels' family is in every pipeline root, so a bump is deliberate.
