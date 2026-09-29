# zk-encryption-circuits

The post-quantum channel as one building block for noir-zk pipelines: the circuits, the wallet library that seals and opens what they seal, and the mapping between the two. A target project depends on this crate alone.

## What the layer is

**Circuits** (`circuits/manifest.toml`, frozen by `noir-zk freeze --library zk-encryption-circuits@0.1.0`, bytecode bundled: no packs, no download):

| family | circuit | record | what it does |
|---|---|---|---|
| `channel/session` | `channel_session` | `[ctx, C_t, E.x, E.y, tag, ct_commitment]`, all public, no link | The channel's key agreement: the handshake KEM against the receiver's keys (Grumpkin DH plus the lattice encryption over its ML-KEM-768 key) on a handshake, against a throwaway key on a ratchet transfer, so every transfer has one shape; `C_t = H(COMMIT, S_t)`. `ctx` is a public input it passes through: the envelopes and the transfer are bound to it by the kernel. |
| `channel/envelope` | `channel_envelope` | `[payload_commitment, ctx, C_t, domain, c × 6]`; link in `PayloadCommitment`, bound to the session's `ctx` and `C_t`, `domain` pinned to `"pq-ratchet/key-payload/v1"`, publishes `c_id0..5` | Seals a six-field payload (DG1's plaintext) whose hiding commitment a previous step left as the link: `K = H(KEY, S_t, ctx, domain)`, `c = Duplex(K, C_t, ctx, payload)`. |
| `channel/note_envelope` | `channel_envelope` | the same, `domain` pinned to `"pq-ratchet/key-note/v1"`, publishes `c_note0..5` | The same circuit sealing a note opening. |

One envelope circuit, two families: the payload domain is an input the app writes into its record, and each family pins it with a **constant binding** (`bind_const`) the kernel enforces, so the sender doesn't choose it, the two envelopes of one transfer never share a keystream, and a pipeline that would fold the circuit twice under one domain is refused at build (noir-zk codegen).

**Wallet library** (`wallet`: [`zk-encryption`](../zk-encryption) re-exported): `Sender` (accept a bundle, handshake, advance), `Receiver` (keys, windows, `scan`), `Bundle`, `Payload<N>` with `Ratchet::{payload_commitment, seal_payload, open_payload}`, the `Envelope` event, `Dg1` and `NoteOpening` as payloads, `serde` persistence behind the `serde` feature. `zk-encryption` stays a standalone crate (no circuits, no noir-zk dependency) for wallets that only need the crypto.

**Mapping** (`session`, `envelope`): `session::inputs(&ChannelWitness, ctx)` and `envelope::inputs(domain, payload, salt, ctx, s)` render the circuits' `Prover.toml`; `session::Outputs { ctx, c_t, e_x, e_y, tag, ct_commitment }` (read from a pipeline's typed outputs) plus the carried lattice ciphertext and the envelopes' outputs give the `Envelope` event a receiver scans (`Outputs::envelope(ct, c_note, c_id)`, which checks `ct` against `ct_commitment`).

## In a pipeline

```toml
[[family]]          # in the combining registry's manifest
layer = "channel"
name = "session"
source = "zk-encryption-circuits"     # the wrapped registry: `noir_zk_codegen::wrapped(LIBRARY, REGISTRY, FAMILIES)`

[[pipeline]]
name = "transfer_only"
positions = ["zk-encryption-circuits/channel/session", "emit-circuits/emit/transfer", "zk-encryption-circuits/channel/note_envelope"]
```

```rust
use zk_encryption_circuits::{artifacts, envelope, session, wallet::ratchet::Ratchet};
use zk_encryption_circuits::circuits::families::{KernelStepSession, KernelStepEnvelope, KernelStepNoteEnvelope};

let pool = noir_zk_core::Merged::new(&[&artifacts(), /* the other layers */, &noir_zk_backend::kernels::Kernels]);
let (proof, _) = transfer_only::fold(&pool)?
    .app(KernelStepSession::select(session::LABEL, session::inputs(&w, ctx))?)?
    .app(KernelStepTransfer::select("transfer", transfer_toml)?)?              // bound to ctx; leaves the note commitment
    .app(KernelStepNoteEnvelope::select(envelope::LABEL, envelope::inputs(Ratchet::key_note(), &note.to_payload(), salt, ctx, w.s))?)?
    .hiding(&DEPLOYMENT)?;
let o = transfer_only::verify(&proof)?;
let event = session::Outputs { ctx: o.ctx, c_t: o.c_t, e_x: o.e_x, e_y: o.e_y, tag: o.tag, ct_commitment: o.ct_commitment }
    .envelope(w.kem.handshake.ct.clone(), [o.c_note0, /* ... */ o.c_note5], [Fr::from(0u64); 6])?;
```

The session must come before any position bound to `ctx`/`C_t`; the envelope's link is the payload commitment the previous linking step left (a document step for DG1, the transfer for the note), so the DG1 envelope follows the document step and precedes the transfer.

## Layout

- `circuits/manifest.toml`, `resources/`: the frozen registry (written by `noir-zk freeze`; the families are hand-written and kept).
- `assets/`: the bundled bytecode (written by freeze, `include_bytes!` through codegen).
- `src/lib.rs`: `circuits` (generated), `wallet`, `artifacts`, `session`, `envelope`.
