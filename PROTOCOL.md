# Protocol

*The channel of the folded identity + private-transfer pipeline (the experiments repository's reference pipeline: an ePassport's DG1 and an Emit V2 note opening as the two payloads). The circuits and the wallet library in this repository implement sections 2 to 6; the pipeline that folds them is the target project's.*

This document specifies how a sender (the passport holder, who proves) and a receiver (the transfer's recipient, who reads DG1) set up and use a post-quantum envelope channel. It states what each party must do, what the verifier checks, and what the protocol guarantees. The circuits and reference code in this repository implement the cryptography; this document is the contract around them. Section 7 lists where the prototype still differs from it.

## 1. Roles and goals

- **Sender (S):** holds the passport and its wallet state. It proves each transfer and seals DG1 to the receiver.
- **Receiver (R):** reads DG1 from the transfers it receives. It may be offline when the sender starts a channel.
- **Verifier (V):** the chain (precompile and contract). It checks the proof and the transfer, and stores the envelope.
- **Observer (O):** anyone who sees the chain and the network, now or later, including with a quantum computer.

Goals:

1. **Confidentiality:** only R reads DG1, now and after a quantum computer exists (harvest-now, decrypt-later).
2. **Receiver guarantee:** a transfer R accepts decrypts to the DG1 whose signature chain the proof checked. S can't give R an envelope that doesn't open.
3. **Unlinkability:** O can't link transfers to each other, to a channel, or to R.
4. **Non-interactive:** S never needs a message from R. R publishes one key bundle and can stay offline.
5. **Cheap repeats:** after the first transfer, the envelope costs a few Poseidon2 calls.

Out of scope: hiding the sender's account, amounts or timing on the chain (the chain's own privacy layer); forging proofs with a quantum computer (capped by ICAO's RSA and ECDSA signatures).

## 2. Primitives

- `H`: Poseidon2 over BN254 (t = 4 sponge), with a distinct domain constant per use: `TAG`, `ROOT`, `RATCHET`, `COMMIT`, and one key domain per payload: `KEY` (the one key derivation: `K = H(KEY, S_t, ctx, domain)`) with a payload *domain* per envelope: `KEY_PAYLOAD` (DG1's) and `KEY_NOTE` (the note opening's) (`"pq-ratchet/<label>/v1"`, e.g. `"pq-ratchet/key-payload/v1"`).
- Grumpkin with generator `G`. Scalars are BN254 base-field elements.
- `KPKE`: ML-KEM-768's K-PKE (k = 3, n = 256, q = 3329), with the circuit-friendly changes: prover-supplied noise range-checked to `|x| ≤ 2`, no compression, no FO transform. Ciphertext `(u, v)`: 1,536 bytes.
- `Commit(Â, t̂, H(ek))`: Poseidon2 commitment to the receiver's expanded ML-KEM key (`pq_commit`).
- The envelope cipher: the Poseidon2 duplex keyed by `(K, C)` and bound to `ctx`, as in the eid envelope.
- **Two payloads under one chain key.** A transfer that carries both DG1 and a note opening seals them under the same `S_t` and `C_t` with different payload domains: `c_id = Duplex(H(KEY, S_t, ctx, KEY_PAYLOAD), C_t, ctx, DG1)` and `c_note = Duplex(H(KEY, S_t, ctx, KEY_NOTE), C_t, ctx, (v', ρ', r', 0, 0, 0))`. One chain index per transfer, never one per payload. The domain is not chosen by the sender: the envelope circuit takes it as an input and writes it into its record, and the pipeline's layout pins it per family (noir-zk's constant binding, enforced by the kernel), so the two envelopes of one transfer are the same circuit under two families and can't share a keystream. A payload is six fields (two duplex blocks); the app that owns it commits to it with a salt, `H("pq-channel/payload/v1/<N>", salt, payload)` (N = 6 in the circuits), and a payload-generic envelope app opens that commitment and seals the fields, one instance per key domain.

## 3. Receiver's key bundle

R publishes a bundle:

| field | content |
|---|---|
| `version` | format version (1) |
| `chain_id` | the chain the bundle is for |
| `pk_B` | R's shielded address `H(PK, sk_B)`: the owner of the notes sent to R |
| `V` | Grumpkin public key, `V = v·G`, `v` uniform and non-zero (compressed) |
| `ek` | ML-KEM-768 encapsulation key (1,184 bytes), from honest ML-KEM key generation; inline, or a URL to fetch it from |
| `pq_commit` | `Commit(Â, t̂, H(ek))`, recomputable by anyone from `ek` |
| `not_before`, `not_after` | validity window |
| `sig` (optional) | R's account signature over the fields above (R2) |

The byte encoding (`rust/pq-channel/src/bundle.rs`) is about 150 bytes with a URL, 1.3 kB with `ek` inline.

**Receiver requirements for the bundle:**

- **R1. Honest key generation.** `v` from a CSPRNG; `ek` from standard ML-KEM-768 key generation (secret `s` and error `e` sampled from CBD₂). The worst-case decryption bound (2⁻⁷² per ciphertext) assumes `s` is honestly sampled and unknown to the sender.
- **R2. Authentic publication.** The bundle is bound to R's identity: published from R's account in a registry contract, or delivered over an authenticated channel. This is the one thing the sender can't check cryptographically inside the protocol.
- **R3. Rotation.** R publishes a new bundle before `not_after`. Rotation bounds how many channels a leaked long-term secret exposes.
- **R4. Deletion.** R deletes the long-term secrets `v` and `s` once `not_after` plus a grace period has passed, since they're only needed to accept new handshakes. Anyone who records handshakes and later obtains a long-term secret can recover every channel it opened, from its first transfer, so this deletion is what gives forward secrecy against long-term key compromise.
- **R5. Multiple devices.** Either every device holds the bundle secrets and the receiver syncs channel state, or each device publishes its own bundle and senders open one channel per device. Pick one per deployment.

## 4. Handshake (the sender's first transfer to R)

**Sender:**

1. **Check the bundle.** It's authentic (R2), inside its validity window, `V` is on the curve and not the identity, `ek` passes the FIPS 203 modulus check, and `pq_commit` matches `ek`.
2. **Sample fresh randomness** from a CSPRNG: `e ∈ Fr \ {0}`, `m ∈ {0,1}²⁵⁶`, and a noise seed from which `(r, e1, e2)` are derived by CBD₂ sampling with SHAKE, natively.
3. **Compute:**
   - `E = e·G`, `Z = e·V`
   - `(u, v) = KPKE.Enc(Â, t̂; m; r, e1, e2)`, `ct_commit = H(u, v)`
   - `tag = H(TAG, Z, pq_commit)`
   - `S₀ = H(ROOT, m, Z, E, ct_commit, pq_commit)`
   - `C₀ = H(COMMIT, S₀)`, and per payload `K = H(KEY_x, S₀, ctx)`, `c = Duplex(K, C₀, ctx, payload)`: `KEY_PAYLOAD` for DG1, `KEY_NOTE` for the note opening
4. **Prove** the eid statement with this envelope. `V`, the expanded key, `e`, `m` and the noise are private. `C₀`, `E`, `tag`, `ct_commit` (the session app's outputs), `ctx`, `c_id` and `c_note` are public outputs of the proof; only `(u, v)` travels in the transaction's `extData`, bound by `ct_commit`. The fold's kernel binds the envelopes and the transfer to the session's `ctx` and `C₀`, and anyone recomputes `ctx` from the transfer's public values (S6).
5. **Carry `(u, v)`** with the transfer, where the receiver can retrieve it for as long as it may be offline (calldata or blob, or storage with the same availability).
6. **Store the channel** `{bundle, t = 1, S₁ = H(RATCHET, S₀)}`, and erase `e`, `m`, the noise and `S₀`. Persist this before broadcasting the transfer (S3).

**Receiver**, for every handshake-shaped transfer it hasn't processed:

1. **Recognise:** for each bundle it still holds, compute `Z' = v·E` and check `H(TAG, Z', pq_commit) = tag`. No match: not for R; stop. This costs one scalar multiplication per bundle (≈ 18 µs).
2. **Fetch `(u, v)`** and check `H(u, v) = ct_commit`.
3. **Decrypt** `m = KPKE.Dec(s, u, v)`.
4. **Derive** `S₀ = H(ROOT, m, Z', E, ct_commit, pq_commit)` and check `H(COMMIT, S₀) = C₀`. This catches the ≤ 2⁻⁷² decryption failure; with a correct tag and a verified proof, nothing else can fail.
5. **Open** `DG1 = Duplex⁻¹(H(KEY, S₀, ctx), C₀, ctx, c)`.
6. **Open the channel:** precompute the window `{C_t → S_t}` for `t = 1..W` and delete `S₀`.

The tag binds `Z` and `pq_commit`, and the proof shows `E`, `Z`, the ciphertext and the envelope come from the same `e`, `V` and expanded key. So a transfer whose tag R recognises was built for R's own keys, and a sender can't make R accept a handshake it can't open.

## 5. Ratchet transfers (every later transfer on a channel)

**Sender**, for transfer `t`:

1. `C_t = H(COMMIT, S_t)`, and per payload `K = H(KEY_x, S_t, ctx)`, `c = Duplex(K, C_t, ctx, payload)`.
2. Prove; `C_t`, `E`, `tag`, `ct_commit`, `ctx`, `c_id` and `c_note` are public outputs, `(u, v)` is the extData.
3. Persist `{t + 1, S_{t+1} = H(RATCHET, S_t)}` and erase `S_t` **before** broadcasting (S3).

**Receiver:**

1. Look up `C_t` in the window map (one hash-map lookup, however many channels R has).
2. Open each payload with `H(KEY_x, S_t, ctx)`; a note opening must open the transfer's `C₀` for `pk_B`, else the transfer is invalid and skipped (state unchanged).
3. Delete `S_t`; extend the window to keep `W` keys ahead of the highest index seen.
4. Keep at most `max_skipped` skipped keys (indices below the highest seen but not yet received); delete the oldest beyond that.
5. **Resync** (`Session::resync(n)`): extend the window by `n` more keys when a channel may have skipped more than `W` indices: the sender says so out of band (a crash, a re-install), or a periodic sweep finds handshake-shaped traffic that isn't recognised while a known sender's channel has gone quiet. A resync only adds keys ahead; it never resurrects deleted ones.

## 6. Requirements

**Sender:**

- **S1. Check the bundle** as in step 4.1 before every handshake.
- **S2. Fresh randomness** for every handshake (`e`, `m`, noise seed) from a CSPRNG. Reuse repeats `E` (linkable) and, with the same `m`, the root.
- **S3. Never reuse a chain index.** Persist the advanced state before broadcasting; a crash then skips an index, which the receiver's window absorbs, and never reuses one. A reused index repeats `C_t`, which links the two transfers, and makes the second unopenable.
- **S4. No rollback.** Never restore channel state from a backup; after a restore, start a new handshake.
- **S5. Re-handshake** every `N` transfers or `T` days, and whenever R's bundle rotates. Until then, a leaked `S_t` exposes every later transfer on the channel (no post-compromise security).
- **S6. Context.** `ctx = H(CTX, cid, N₀, N₁, C₀, C₁)`: the chain id, the transfer's nullifiers and output commitments. It's fixed before proving, unique per transfer (`N₀` is spent once), and binds the envelope to exactly this transfer's outputs, so the envelope can't be moved to another transfer or recipient; there's no separate nonce or sender field, and the sender's account never enters it (the transfer is relayed from a one-time key). The generic form `H(chain id, contract, sender, nonce)` fits a design without a JoinSplit.
- **S7. Scope.** Transfers use `scope = 0`. A scoped nullifier is the same for every proof of one passport in a scope, so using one on transfers links them all; use it once, at onboarding.
- **S8. One shape.** Every transfer runs the same transfer app, which always runs the handshake KEM. Ratchet transfers fill the handshake fields from a throwaway key and fresh randomness and carry a dummy `(u, v)`, so a first contact is indistinguishable from a repeat transfer.

**Receiver:**

- **R1–R5** as in section 3.
- **R6. Check in order** as in section 4: tag, `ct_commit`, decryption, `C₀`, then open. Never open an envelope whose proof the verifier didn't accept.
- **R7. Window and deletion.** A window of `W` keys ahead; delete every key once used; keep at most `max_skipped` skipped keys and delete the oldest beyond that; keep the consumed `C_t` of recent transfers (bounded) to recognise a reused index, and every channel's `C₀` so a replayed handshake is never opened twice.
- **R8. Protect state.** Channel keys `S_t` are as sensitive as the plaintexts they open. Don't roll state back.
- **R9. Scanning.** R must scan every transfer (they all have the handshake's shape, S8) for as long as its bundles are valid: a window lookup by `C_t` first, then the tag.

**Verifier:**

- **V1.** Verify the proof and check its public outputs against the calldata (`ctx` recomputed from the transfer's values). It doesn't check `tag`, `C_t` or any receiver key; that's the receiver's job.
- **V2.** Make `(u, v)` available with the transfer and check `H(u, v) = ct_commit` (the session's output) so that an unavailable or wrong ciphertext can't be posted.

## 7. What the prototype does differently

The circuits and reference in this repository implement sections 4 and 5, including the transcript-bound root, the bundle (`rust/pq-channel/src/bundle.rs`: encoding, validity window, `V` on the curve, `ek` checks, `pq_commit`; the signature is carried but not verified) and the receiver's state machine (window extension, deletion, skipped-key expiry, reused-index detection, resync: `rust/pq-channel/src/ratchet.rs` and `rust/pq-channel/src/receiver.rs`), in the fold of README.md, with these differences:

1. **Persist-before-send and no-rollback** (S3, S4) are the sender application's job; the reference demonstrates what a rollback does (a repeated `C_t`) but doesn't prevent it.
2. **Noise sampling** is from the reference generator (CBD₂ over SHAKE or the OS CSPRNG), not a documented SHAKE-seeded derivation from one stored seed.
3. **Bundle rotation and deletion** (R3, R4) aren't modelled: each test uses one bundle for its lifetime.

## 8. Properties

| property | holds | condition |
|---|---|---|
| confidentiality of a handshake transfer | if Grumpkin CDH **or** MLWE holds | R1, S2 |
| confidentiality of ratchet transfers | ≈ 2¹²⁷, including against a quantum computer | Poseidon2 behaves as a PRF; S3 |
| receiver guarantee | yes | the proof verifies and R6 passes |
| forward secrecy along the channel | a leaked `S_t` exposes `t` onwards, never earlier transfers | S3, R7 |
| forward secrecy against long-term keys | only after rotation and deletion | R3, R4 |
| post-compromise security | none until the next handshake | S5 |
| observer can't link ratchet transfers | yes: `C_t` and `c` are fresh each time, and there's no public key | S3, S7 |
| observer can't see who a handshake is for | classically yes; a quantum observer can recover `e` from `E` and test `tag` against every published bundle | a PQ tag costs a trial decryption per scan (≈ 22× the scan cost) |
| observer can't tell a channel started | yes: one shape for every transfer (S8) | the handshake KEM (about 53k gates) runs on every transfer |
| receiver links the transfers on its channel | yes, by design | – |

## 9. Open questions

- Where bundles are published, and the rotation period.
- `N`, `T` (S5) and `W` (R7).
- Whether a post-quantum tag is worth 22× the scan cost.
- How `(u, v)` is carried and for how long (V2).
