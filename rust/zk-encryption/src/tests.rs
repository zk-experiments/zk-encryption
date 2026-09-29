//! Known answers against nargo, FIPS 203 anchoring, the lattice bounds, the
//! ratchet's windows, the bundle, and a receiver's scans over natively built
//! transfers (no proofs: the fold is `rust/reference`'s e2e test).

use crate::bundle::{Bundle, BundleError, Ek};
use crate::emit::{Delivery, Dg1, Emit, Envelope, NoteOpening};
use crate::grumpkin::Point;
use crate::lattice::{Ciphertext, Kpke, MlKemKeys, Noise, Poly, PqKey, Q, Ring};
use crate::poseidon::{FieldHex, Poseidon, Rng};
use crate::ratchet::{Ratchet, ReceiverKeys, SenderChain, Session};
use crate::receiver::{Receiver, Scan};
use crate::sender::{ChannelWitness, Sender};
use crate::witness::NoirToml;
use crate::{Error, Fr};
use ark_ff::MontFp;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Deterministic test material.
struct Fixture;

impl Fixture {
    fn stream(label: &str, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        let mut x = sha3::Shake256::default();
        x.update(label.as_bytes());
        x.finalize_xof().read(&mut out);
        out
    }

    fn bytes<const N: usize>(label: &str) -> [u8; N] {
        Self::stream(label, N).try_into().expect("size")
    }

    fn dg1() -> Dg1 {
        let mut d = vec![0x61, 0x5b, 0x5f, 0x1f, 0x58];
        d.extend(b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10");
        Dg1(d)
    }

    fn centered(x: i64) -> i64 {
        if x > Q / 2 { x - Q } else { x }
    }

    /// A transfer of `value` to `pk` on `channel`, as the receiver reads it
    /// from the chain (dummy inputs, DG1 from `dg1()`).
    fn delivery(cid: Fr, pk: Fr, value: u128, channel: &ChannelWitness) -> Delivery {
        let nullifiers = [Rng::field(), Rng::field()];
        let openings = [
            NoteOpening {
                value,
                rho: Emit::rho(nullifiers[0], 0),
                r: Rng::field(),
            },
            NoteOpening {
                value: 0,
                rho: Emit::rho(nullifiers[0], 1),
                r: Rng::field(),
            },
        ];
        let commitments = [
            openings[0].commitment(cid, pk),
            openings[1].commitment(cid, Rng::field()),
        ];
        let ctx = Emit::ctx(cid, nullifiers, commitments);
        let (c_t, c_note) = channel.seal_note(ctx, &openings[0]).unwrap();
        let (c_t2, c_id) = Self::dg1().seal(channel.s, ctx).unwrap();
        assert_eq!(c_t, c_t2);
        Delivery {
            cid,
            nullifiers,
            commitments: [(commitments[0], 0), (commitments[1], 1)],
            envelope: Envelope {
                c_t,
                kem: channel.kem.kem(),
                c_note,
                c_id,
            },
        }
    }
}

#[test]
fn poseidon2_and_grumpkin_known_answers() {
    // Values nargo prints (the same known answers eid-envelope pins).
    let s0: Fr = MontFp!("0x224785a48a72c75e2cbb698143e71d5d41bd89a2b9a7185871e39a54ce5785b1");
    assert_eq!(Poseidon::permute([1u64, 2, 3, 4].map(Fr::from))[0], s0);
    let x: Fr = MontFp!("0x06ce1b0827aafa85ddeb49cdaa36306d19a74caa311e13d46d8bc688cdbffffe");
    assert_eq!(Point::generator_mul(Fr::from(2u64)).unwrap().x, x);
    let p = Point::generator_mul(Fr::from(0x1234_5678u64)).unwrap();
    assert_eq!(Point::decompress(&p.compress()), Some(p));
    assert!(
        !Point {
            x: Fr::from(1u64),
            y: Fr::from(1u64)
        }
        .is_valid()
    );
    assert_eq!(Fr::from_hex(&p.x.hex()), p.x);
}

/// Our NTT, ŝ extraction and decryption recover m from real ML-KEM-768
/// ciphertexts (after Decompress), so they agree with FIPS 203.
#[test]
fn decrypts_real_ml_kem_ciphertexts() {
    use ml_kem::{B32, EncapsulationKey768};
    for seed in 0..8u8 {
        let keys = MlKemKeys::from_seed([seed; 64]);
        let m: [u8; 32] = Fixture::bytes(&format!("m{seed}"));
        let ek = EncapsulationKey768::new((&keys.ek).into()).unwrap();
        let (c, _) = ek.encapsulate_deterministic(&B32::from(m));
        let bits = |off: usize, d: usize, count: usize| -> Vec<i64> {
            (0..count)
                .map(|i| {
                    let y: i64 = (0..d)
                        .map(|b| {
                            i64::from((c[off + (i * d + b) / 8] >> ((i * d + b) % 8)) & 1) << b
                        })
                        .sum();
                    (Q * y + (1 << (d - 1))) >> d // Decompress_d
                })
                .collect()
        };
        let uf = bits(0, 10, 768);
        let vf = bits(960, 4, 256);
        let u: [Poly; 3] = std::array::from_fn(|i| uf[256 * i..256 * (i + 1)].try_into().unwrap());
        let v: Poly = vf.try_into().unwrap();
        assert_eq!(
            Kpke::round(&Kpke::decrypt_raw(&Kpke::s_hat(&keys.dk), &u, &v)),
            m
        );
    }
}

#[test]
fn lattice_round_trip_and_checks() {
    let keys = MlKemKeys::from_seed([7u8; 64]);
    let key = PqKey::expand(&keys.ek).unwrap();
    let noise = Noise::cbd(&Fixture::bytes("noise"));
    let m: [u8; 32] = Fixture::bytes("m");
    let ct = Kpke::encrypt(&key, &noise, &m).unwrap();
    assert_eq!(Kpke::decrypt(&keys.dk, &ct), m);
    let other = MlKemKeys::from_seed([8u8; 64]);
    assert_ne!(Kpke::decrypt(&other.dk, &ct), m);
    let mut loud = noise.clone();
    loud.e2[5] = 3;
    assert_eq!(Kpke::encrypt(&key, &loud, &m), Err(Error::NoiseOutOfRange));
    let mut bad = keys.ek;
    bad[0] = 0xff;
    bad[1] |= 0x0f; // first coefficient 4095 ≥ q
    assert_eq!(PqKey::expand(&bad), Err(Error::BadPqKey));
    // NTT round trip.
    let f: Poly = std::array::from_fn(|i| (i64::try_from(i).expect("small") * 7) % Q);
    assert_eq!(Ring::intt(Ring::ntt(f)), f);
    // The ciphertext's bytes: 1,536, canonical.
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 1536);
    assert_eq!(Ciphertext::from_bytes(&bytes).unwrap(), ct);
    let mut big = bytes.clone();
    big[0] = 0xff;
    big[1] |= 0x0f;
    assert_eq!(Ciphertext::from_bytes(&big), Err(Error::CiphertextMismatch));
    assert_eq!(Ciphertext::from_bytes(&bytes[1..]), Err(Error::BadLength));
}

/// Worst case the circuit allows: every r, e1, e2 coefficient at ±2, over
/// many receiver keys. Decryption must stay correct; the observed noise is
/// far inside q/4 (the README's bound is ~2^-72 per ciphertext).
#[test]
fn decrypts_with_extreme_noise() {
    let mut worst = 0i64;
    for key in 0..24u8 {
        let keys = MlKemKeys::from_seed([key.wrapping_add(100); 64]);
        let pq = PqKey::expand(&keys.ek).unwrap();
        let s = Kpke::s_hat(&keys.dk);
        for trial in 0..24 {
            let label = format!("{key}/{trial}");
            let noise = Noise::extreme(&Fixture::bytes(&label));
            let m: [u8; 32] = Fixture::bytes(&format!("m/{label}"));
            let ct = Kpke::encrypt(&pq, &noise, &m).unwrap();
            let w = Kpke::decrypt_raw(&s, &ct.u.map(|p| p.map(i64::from)), &ct.v.map(i64::from));
            assert_eq!(Kpke::round(&w), m, "{label}");
            for (n, x) in w.iter().enumerate() {
                let mu = 1665 * i64::from((m[n / 8] >> (n % 8)) & 1);
                worst = worst.max(Fixture::centered((x - mu).rem_euclid(Q)).abs());
            }
        }
    }
    assert!(
        worst < 832,
        "largest |noise| over 576 extreme-noise ciphertexts: {worst} (threshold 832)"
    );
}

/// Why the receiver's secret must stay secret: a sender who knew s could
/// pick in-range e1 that breaks decryption.
#[test]
#[allow(clippy::needless_range_loop)]
fn sender_knowing_s_can_break_decryption() {
    let keys = MlKemKeys::from_seed([9u8; 64]);
    let s: Vec<Poly> = Kpke::s_hat(&keys.dk)
        .iter()
        .map(|p| Ring::intt(*p))
        .collect();
    let sign = |x: i64| {
        if Fixture::centered(x) > 0 {
            1i8
        } else if Fixture::centered(x) < 0 {
            -1
        } else {
            0
        }
    };
    let mut noise = Noise {
        r: [[0; 256]; 3],
        e1: [[0; 256]; 3],
        e2: [0; 256],
    };
    for j in 0..3 {
        // coefficient 0 of s_j·e1_j is s0·e0 − Σ_{k≥1} s_k·e_{256−k}: make it −2·Σ|s|.
        noise.e1[j][0] = -2 * sign(s[j][0]);
        for k in 1..256 {
            noise.e1[j][256 - k] = 2 * sign(s[j][k]);
        }
    }
    let ct = Kpke::encrypt(&PqKey::expand(&keys.ek).unwrap(), &noise, &[0u8; 32]).unwrap();
    assert_ne!(
        Kpke::decrypt(&keys.dk, &ct)[0] & 1,
        0,
        "coefficient 0 decrypts wrong"
    );
}

#[test]
fn dg1_and_ratchet() {
    assert_eq!(
        Dg1::from_payload(&Fixture::dg1().to_payload()),
        Fixture::dg1()
    );
    // Sealing under two key domains with one chain key; the ratchet advances.
    let (s, ctx) = (Rng::field(), Rng::field());
    let (c, ct) = Fixture::dg1().seal(s, ctx).unwrap();
    assert_eq!(c, Ratchet::commit(s));
    assert_eq!(Dg1::open(s, c, ctx, &ct).unwrap(), Fixture::dg1());
    assert_ne!(
        Dg1::open(s, c, ctx + Fr::from(1u64), &ct).unwrap(),
        Fixture::dg1()
    );
    assert_ne!(
        Ratchet::open(Ratchet::key_note(), s, c, ctx, &ct).unwrap(),
        Fixture::dg1().to_payload()
    );
    let mut chain = SenderChain::after_handshake(s);
    assert_eq!(chain.advance(), (1, Ratchet::next(s)));
    assert_eq!(chain.index(), 2);
}

/// R7: skipped keys are bounded. W = 3 ahead, at most 2 skipped kept.
#[test]
fn skipped_keys_expire() {
    let s0 = Rng::field();
    let mut session = Session::start_with(s0, 3, 2);
    let mut sender = SenderChain::after_handshake(s0);
    let keys: Vec<(u64, Fr)> = (0..6).map(|_| sender.advance()).collect();
    let c = |t: usize| Ratchet::commit(keys[t - 1].1);
    // t = 3 arrives first: 1 and 2 are skipped (2 kept).
    assert_eq!(session.take(c(3)).unwrap().0, 3);
    assert_eq!(session.skipped(), 2);
    // t = 6 arrives: skipped are 1, 2, 4, 5; only 4 and 5 are kept.
    assert_eq!(session.take(c(6)).unwrap().0, 6);
    assert_eq!(session.skipped(), 2);
    assert_eq!(session.take(c(1)), Err(Error::UnknownCommitment));
    assert_eq!(session.take(c(2)), Err(Error::UnknownCommitment));
    assert_eq!(session.take(c(4)).unwrap().0, 4);
    assert_eq!(session.take(c(5)).unwrap().0, 5);
    assert_eq!((session.skipped(), session.held()), (0, 3));
    let c7 = Ratchet::commit(sender.advance().1);
    assert_eq!(session.peek(c7).map(|x| x.0), Some(7));
    assert_eq!(
        session.peek(c7).map(|x| x.0),
        Some(7),
        "peek doesn't consume"
    );
}

#[test]
fn bundle_round_trip_and_validation() {
    let bob = ReceiverKeys::generate();
    let ek = bob.ek().to_vec();
    let fetch = |u: &str| (u == "https://bob.example/ek").then(|| ek.clone());
    let pk_b = Emit::pk(Rng::field());
    let b = Bundle {
        chain_id: 7,
        pk_b,
        v: bob.public.grumpkin,
        pq: bob.public.pq_commitment,
        ek: Ek::Url("https://bob.example/ek".into()),
        not_before: 100,
        not_after: 200,
        sig: None,
    };
    let bytes = b.encode();
    assert_eq!(Bundle::decode(&bytes).unwrap(), b);
    assert!(b.to_base64url().len() > 100);
    let ok = Bundle::accept(&bytes, 7, 150, &fetch).unwrap();
    assert_eq!(
        (ok.pk_b, ok.receiver.pq_commitment),
        (pk_b, bob.public.pq_commitment)
    );
    let inline = Bundle {
        ek: Ek::Inline(ek.clone()),
        sig: Some([9; 65]),
        ..b.clone()
    };
    assert!(Bundle::accept(&inline.encode(), 7, 150, &fetch).is_ok());
    assert_eq!(
        Bundle::accept(&bytes, 7, 201, &fetch).err(),
        Some(BundleError::Expired)
    );
    assert_eq!(
        Bundle::accept(&bytes, 7, 99, &fetch).err(),
        Some(BundleError::NotYetValid)
    );
    assert_eq!(
        Bundle::accept(&bytes, 8, 150, &fetch).err(),
        Some(BundleError::WrongChain)
    );
    let other = ReceiverKeys::generate();
    let wrong_pq = Bundle {
        pq: other.public.pq_commitment,
        ..b.clone()
    };
    assert_eq!(
        Bundle::accept(&wrong_pq.encode(), 7, 150, &fetch).err(),
        Some(BundleError::PqMismatch)
    );
    let mut bad_v = bytes.clone();
    bad_v[1 + 8 + 32..1 + 8 + 64].copy_from_slice(&[0x7f; 32]);
    assert_eq!(
        Bundle::accept(&bad_v, 7, 150, &fetch).err(),
        Some(BundleError::BadGrumpkinKey)
    );
    let gone = Bundle {
        ek: Ek::Url("https://nowhere".into()),
        ..b
    };
    assert_eq!(
        Bundle::accept(&gone.encode(), 7, 150, &fetch).err(),
        Some(BundleError::EkUnavailable)
    );
    // A sender accepts it and can only handshake once.
    let mut alice = Sender::accept(&inline.encode(), 7, 150, &|_| None).unwrap();
    assert_eq!(
        (alice.pk_b(), alice.not_after(), alice.index()),
        (pk_b, 200, None)
    );
    assert_eq!(alice.advance().err(), Some(Error::ChannelNotOpen));
    let hs = alice.handshake().unwrap();
    assert!(hs.is_handshake && hs.t == 0 && hs.c_t == Ratchet::commit(hs.s));
    assert_eq!(alice.handshake().err(), Some(Error::ChannelAlreadyOpen));
    assert_eq!(alice.advance().unwrap().t, 1);
    assert_eq!(alice.index(), Some(2));
}

/// The Envelope event's bytes round-trip and the witness renders every field.
#[test]
fn envelope_bytes_and_witness() {
    let bob = ReceiverKeys::generate();
    let mut alice = Sender::from_accepted(crate::bundle::Accepted {
        pk_b: Rng::field(),
        receiver: bob.public.clone(),
        not_after: 0,
    });
    let hs = alice.handshake().unwrap();
    let d = Fixture::delivery(Rng::field(), alice.pk_b(), 5, &hs);
    let bytes = d.envelope.to_bytes();
    assert_eq!(bytes.len(), Envelope::BYTES);
    assert_eq!(Envelope::from_bytes(&bytes).unwrap(), d.envelope);
    assert_eq!(Envelope::from_bytes(&bytes[..100]), Err(Error::BadLength));
    let toml = NoirToml::new().session(&hs, Rng::field()).finish();
    for key in [
        "context = \"0x",
        "[channel]",
        "is_handshake = true",
        "[channel.receiver]",
        "[channel.pq_key]",
        "a_hat = ",
        "t_hat = ",
        "h_ek = ",
        "[channel.noise]",
        "e1 = ",
    ] {
        assert!(toml.contains(key), "{key}");
    }
    assert_eq!(
        toml.matches("\"0x").count(),
        1 + 2 + 2 + 3 * 256 * 2 + 256,
        "ctx, e, s, V and the noise: quoted hex"
    );
    let env = NoirToml::new()
        .envelope(
            Ratchet::key_payload(),
            &Fixture::dg1().to_payload(),
            Rng::field(),
            Rng::field(),
            hs.s,
        )
        .finish();
    assert!(
        env.contains("payload = [") && env.contains("salt = \"0x"),
        "{env}"
    );
    assert_eq!(env.matches("\"0x").count(), 10);
    // The payload code is generic in the size: 6 (the frozen circuits) and 9
    // (three duplex blocks) round-trip; the last block may be partial.
    fn round_trip<const N: usize>(s: Fr) {
        let payload: [Fr; N] = std::array::from_fn(|i| Fr::from(i as u64 + 7));
        let (ctx, salt) = (Rng::field(), Rng::field());
        let (c_t, ct) = Ratchet::seal_payload(Ratchet::key_note(), s, ctx, &payload).unwrap();
        assert_eq!(c_t, Ratchet::commit(s));
        assert_eq!(
            Ratchet::open_payload(Ratchet::key_note(), s, c_t, ctx, &ct).unwrap(),
            payload
        );
        assert_ne!(
            Ratchet::open_payload(Ratchet::key_payload(), s, c_t, ctx, &ct).unwrap(),
            payload,
            "another key domain is another keystream"
        );
        assert_ne!(
            Ratchet::payload_commitment(salt, &payload),
            Ratchet::payload_commitment(salt + Fr::from(1u64), &payload)
        );
    }
    round_trip::<6>(hs.s);
    round_trip::<9>(hs.s);
    round_trip::<4>(hs.s);
    assert_ne!(
        Fixture::dg1().commitment(Fr::from(1u64)),
        Fixture::dg1().commitment(Fr::from(2u64))
    );
}

/// A receiver's scans over natively built deliveries (no proofs): handshake,
/// out of order, a reused index, beyond the window with resync, another
/// receiver's traffic, an invalid note, the bounded consumed set, a replayed
/// handshake.
#[test]
fn receiver_scans() {
    let cid = Rng::field();
    let sk = Rng::field();
    let mut bob = Receiver::generate(Emit::pk(sk), 2);
    let accepted = crate::bundle::Accepted {
        pk_b: bob.pk(),
        receiver: bob.keys().public.clone(),
        not_after: 0,
    };
    let mut alice = Sender::from_accepted(accepted.clone());
    let hs = alice.handshake().unwrap();
    let d0 = Fixture::delivery(cid, bob.pk(), 5, &hs);
    let ds: Vec<Delivery> = (0..6)
        .map(|_| Fixture::delivery(cid, bob.pk(), 5, &alice.advance().unwrap()))
        .collect();
    let got = bob.scan(&d0);
    assert!(
        matches!(&got, Scan::Handshake { note, dg1 } if note.value == 5 && *dg1 == Fixture::dg1()),
        "{got:?}"
    );
    if let Scan::Handshake { note, .. } = got {
        assert_eq!(note.commitment(cid, bob.pk()), d0.commitments[0].0);
        assert_eq!(note.nullifier(sk), Emit::nullifier(Emit::nk(sk), note.rho));
    }
    // t = 2 before t = 1 (the window W = 2 holds 1 and 2).
    assert!(matches!(bob.scan(&ds[1]), Scan::Ratchet { t: 2, .. }));
    assert!(matches!(bob.scan(&ds[0]), Scan::Ratchet { t: 1, .. }));
    assert_eq!(bob.scan(&ds[0]), Scan::Invalid(Error::ReusedIndex));
    // t = 6 is beyond the window (it holds up to 4) until a resync.
    assert_eq!(bob.scan(&ds[5]), Scan::NotMine);
    bob.resync(4);
    assert!(matches!(bob.scan(&ds[5]), Scan::Ratchet { t: 6, .. }));
    // Someone else's handshake.
    let dave = ReceiverKeys::generate();
    let mut to_dave = Sender::from_accepted(crate::bundle::Accepted {
        pk_b: Rng::field(),
        receiver: dave.public,
        not_after: 0,
    });
    assert_eq!(
        bob.scan(&Fixture::delivery(
            cid,
            Rng::field(),
            1,
            &to_dave.handshake().unwrap()
        )),
        Scan::NotMine
    );
    // A handshake to Bob's keys whose note is for someone else: invalid, nothing changes.
    let (channels, consumed) = (bob.channels(), bob.consumed());
    let mut again = Sender::from_accepted(accepted);
    let d = Fixture::delivery(cid, Rng::field(), 5, &again.handshake().unwrap());
    assert_eq!(bob.scan(&d), Scan::Invalid(Error::HandshakeMismatch));
    assert_eq!((bob.channels(), bob.consumed()), (channels, consumed));
    // A tampered ciphertext is invalid, not merely unknown.
    let mut tampered = d0.clone();
    tampered.envelope.kem.ct.v[0] ^= 1;
    tampered.envelope.c_t = Rng::field();
    assert_eq!(
        bob.scan(&tampered),
        Scan::Invalid(Error::CiphertextMismatch)
    );
    // The consumed set is bounded, oldest forgotten; a handshake is never reopened.
    let limit = bob.consumed_limit();
    bob.resync(40);
    for _ in 0..limit + 3 {
        assert!(matches!(
            bob.scan(&Fixture::delivery(
                cid,
                bob.pk(),
                1,
                &alice.advance().unwrap()
            )),
            Scan::Ratchet { .. }
        ));
    }
    assert_eq!(bob.consumed(), limit);
    assert_eq!(
        bob.scan(&ds[1]),
        Scan::NotMine,
        "a forgotten ratchet C_t is just unknown traffic"
    );
    assert_eq!(
        bob.scan(&d0),
        Scan::Invalid(Error::ReusedIndex),
        "a replayed handshake is never opened twice"
    );
}

/// Both states survive a JSON round trip mid-conversation.
#[cfg(feature = "serde")]
#[test]
fn persisted_state_round_trips() {
    let cid = Rng::field();
    let mut bob = Receiver::generate(Emit::pk(Rng::field()), 3);
    let mut alice = Sender::from_accepted(crate::bundle::Accepted {
        pk_b: bob.pk(),
        receiver: bob.keys().public.clone(),
        not_after: 99,
    });
    let d0 = Fixture::delivery(cid, bob.pk(), 5, &alice.handshake().unwrap());
    assert!(matches!(bob.scan(&d0), Scan::Handshake { .. }));
    let d2 = Fixture::delivery(cid, bob.pk(), 5, &alice.advance().unwrap());
    let _skipped = alice.advance().unwrap();
    let d3 = Fixture::delivery(cid, bob.pk(), 5, &alice.advance().unwrap());
    assert!(matches!(bob.scan(&d3), Scan::Ratchet { t: 3, .. }));
    let mut bob: Receiver = serde_json::from_str(&serde_json::to_string(&bob).unwrap()).unwrap();
    let mut alice: Sender = serde_json::from_str(&serde_json::to_string(&alice).unwrap()).unwrap();
    assert_eq!((alice.index(), alice.not_after()), (Some(4), 99));
    assert!(
        matches!(bob.scan(&d2), Scan::Ratchet { t: 1, .. }),
        "a skipped key survives"
    );
    assert_eq!(
        bob.scan(&d0),
        Scan::Invalid(Error::ReusedIndex),
        "the opened channel is remembered"
    );
    assert!(matches!(
        bob.scan(&Fixture::delivery(
            cid,
            bob.pk(),
            1,
            &alice.advance().unwrap()
        )),
        Scan::Ratchet { t: 4, .. }
    ));
    let keys: ReceiverKeys =
        serde_json::from_str(&serde_json::to_string(bob.keys()).unwrap()).unwrap();
    assert_eq!(keys.public.pq_commitment, bob.keys().public.pq_commitment);
}
