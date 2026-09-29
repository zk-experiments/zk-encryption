# pq-channel

The post-quantum envelope channel of the folded eid + Emit V2 transfer, as a Rust library: everything a wallet or a receiver service does off-chain, matching the circuits in [`noir/`](../../noir). The protocol is [`PROTOCOL.md`](../../PROTOCOL.md); this crate is its reference implementation, and [`rust/reference`](../reference) drives it through real folded proofs against a mock chain.

No proving here: the crate has no dependency on the Noir toolchain or barretenberg. It renders the circuits' inputs (`witness::NoirToml`) for whatever prover the wallet uses.

## What is in it

| Module | Contents |
|---|---|
| `poseidon` | Poseidon2 over BN254 as Noir's (`pso-poseidon`), domain tags, hex encoding (`FieldHex`), OS randomness (`Rng`). |
| `grumpkin` | `Point`: scalar multiplication, curve check, 32-byte compression. |
| `lattice` | K-PKE over a real ML-KEM-768 key with the circuit's conventions: `PqKey` (the expanded key Â, t̂, H(ek) and its commitment), `Noise` (coefficients in [-2, 2]), `Kpke::{encrypt, decrypt}`, `Ciphertext` (12-bit bytes and its commitment), `MlKemKeys` (FIPS 203 key generation from a seed). |
| `duplex` | The keyed Poseidon2 duplex (`Duplex::{seal, open}`). |
| `ratchet` | The channel's hashes and steps: `Ratchet::{tag, root, next, commit, seal, open}` (K = H(KEY, S_t, ctx, domain) with the payload domains `key_payload` and `key_note`, pinned per envelope family by the kernel), `Payload<N>` (the circuits instantiate 6) with `payload_commitment` (the link to the envelope app of that size), `seal_payload` and `open_payload`; `ReceiverKeys` / `ReceiverPublic`; `Handshake` (the KEM half a sender computes); `SenderChain`; `Session` (a receiver's window of chain keys for one channel). |
| `bundle` | The receiver's published bundle: `Bundle::{encode, decode, to_base64url, accept}` with ek inline or by URL, validity window, chain id and the ek commitment check. |
| `receiver` | `Receiver`: long-term keys, every open channel's `Session`, the bounded consumed set; `scan(&Delivery) -> Scan`. |
| `sender` | `Sender`: one channel to one receiver; `accept`, `handshake`, `advance`, `skip`; `ChannelWitness` / `KemWitness` (what a transfer's proof and extData need). |
| `emit` | Emit V2's hashes (`Emit`), `NoteOpening`, `Kem` (the session app's outputs with the carried ciphertext), the `Envelope` event with its 2,080-byte layout, `Delivery`, `Dg1` (its encoding as a 6-field payload, `to_payload`/`from_payload`, and its sealing); `NoteOpening` is a payload too. |
| `witness` | `NoirToml`: the session app's inputs (`context` and the `channel` tables) and the envelope apps' inputs (the payload, its commitment salt, `context`, `s`), in the `Prover.toml` layout the circuits take. |

`Error` is the crate's one error type (bundle parsing has its own, `bundle::BundleError`). Field elements are `ark_bn254::Fr`, re-exported as `pq_channel::Fr`.

## Receiver flow

```rust
use pq_channel::{bundle::{Bundle, Ek}, emit::{Delivery, Emit, Envelope}, receiver::{Receiver, Scan}};

// Once: long-term keys and the bundle to publish. `pk` is the shielded
// address (Emit::pk(sk)) transfers to this receiver commit their note to.
let mut receiver = Receiver::generate(Emit::pk(sk), /* window W */ 8);
let bundle = Bundle {
    chain_id, pk_b: receiver.pk(),
    v: receiver.keys().public.grumpkin, pq: receiver.keys().public.pq_commitment,
    ek: Ek::Inline(receiver.keys().ek().to_vec()),   // or Ek::Url("https://…/ek")
    not_before, not_after, sig: None,
};
let published = bundle.to_base64url();

// Per transaction: read the Envelope event and the same transaction's
// nullifiers and commitments (with C0's leaf index).
let delivery = Delivery { cid, nullifiers, commitments, envelope: Envelope::from_bytes(&event)? };
match receiver.scan(&delivery) {
    Scan::Handshake { note, dg1 } => { /* a new channel; the note is spendable, dg1 is the sender's MRZ */ }
    Scan::Ratchet { t, note, dg1 } => { /* index t on an open channel */ }
    Scan::NotMine => {}
    Scan::Invalid(err) => { /* addressed to us but not to be trusted: log it */ }
}
```

`scan` opens `c_note` and checks it against the transaction's C0 for this receiver's `pk`, then opens `c_id`; only when both succeed does it consume the chain key (or open the channel). A transfer more than `W` indices ahead of the highest one received is `NotMine`; if a sender may have skipped that many, `receiver.resync(n)` extends every window and the event can be scanned again.

## Sender flow

```rust
use pq_channel::{sender::Sender, witness::NoirToml};

// Once per receiver: accept the bundle (format, chain, validity, V, ek and
// its commitment). `fetch` resolves an ek URL, or `&|_| None` for inline only.
let mut channel = Sender::accept(&bundle_bytes, chain_id, now, &fetch)?;

// The first transfer: the handshake. Then `advance()` for every later one.
let w = if channel.index().is_none() { channel.handshake()? } else { channel.advance()? };
persist(&channel);   // BEFORE the transfer is broadcast (PROTOCOL.md S3)

// Build the transfer: output 0 to channel.pk_b(); its opening is a payload the transfer
// app commits to (with a salt) and the note envelope app seals under the chain key `w.s`.
// The session app takes the channel witness and the transfer's ctx; extData is the
// lattice ciphertext `w.kem.kem().ct` (bound by the session's ct_commitment output).
let session_toml = NoirToml::new().session(&w, ctx).finish();
let note_toml = NoirToml::new().envelope(Ratchet::key_note(), &opening.to_payload(), note_salt, ctx, w.s).finish();
let envelope_toml = NoirToml::new().envelope(Ratchet::key_payload(), &dg1.to_payload(), dg1_salt, ctx, w.s).finish();
```

Every transfer has the same shape: on a ratchet transfer `advance()` runs the KEM against a throwaway key, so `w.kem` is always present. `ChannelWitness::throwaway()` gives a transfer on no channel (a deposit to oneself).

## Persistence

`Receiver` and `Sender` are the two states to persist; `ReceiverKeys`, `ReceiverPublic`, `Session` and `SenderChain` also serialise. With the `serde` feature all of them implement `Serialize` and `Deserialize`: field elements as hex strings, the ML-KEM key pair as its 64-byte seed, a receiver's public key as V and ek (re-expanded and re-checked on load).

- Sender: persist after `handshake()`, `advance()` or `skip()` and before broadcasting the transfer. A state restored from before them reuses a chain index, which links two transfers on chain and makes the second unopenable. Never restore a sender from a backup; open a new channel instead.
- Receiver: persist after every `Scan::Handshake` or `Scan::Ratchet`. A state restored from before one would open a replayed transfer again.

Nothing here is constant-time beyond what the underlying crates provide; see PROTOCOL.md for the threat model.

## Tests

`cargo test -p pq-channel --release` (add `--features serde` for the persistence round trip): known answers against nargo, decryption of real ML-KEM-768 ciphertexts, the extreme-noise bound, the ratchet's windows, the bundle, and a receiver's scans over natively built transfers. The folded proofs are exercised by `rust/reference`'s e2e test.
