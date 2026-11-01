use super::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nido_dkim_registry::attestation;

/// The first 16 bytes of each test modulus, as `openssl rsa -noout -modulus`
/// printed them when the keys were generated: an independent reading of the
/// same keys.
const OPENSSL_MODULUS_PREFIXES: [(&str, &str); 3] = [
    ("rsa2048-a", "b4c8b8ef43bf1ca56f16d1a5042c8a6d"),
    ("rsa2048-b", "c132470a2a7ea65a041da206414ccff8"),
    ("rsa2048-c", "e0f909571a511dec5753359833777c77"),
];

#[test]
fn rsa_2048_records_parse_in_every_published_shape() {
    for (name, prefix) in OPENSSL_MODULUS_PREFIXES {
        let record = fixture(name).parse().unwrap();
        let KeyRecord::Rsa { modulus, exponent } = &record else {
            panic!("{name}: {record:?}");
        };
        assert_eq!(modulus.len(), 256, "{name}");
        assert_eq!(hex::encode(&modulus[..16]), prefix, "{name}");
        assert_eq!(exponent, &[1, 0, 1], "{name}: e = 65537");
        assert!(modulus_2048(&record).is_some(), "{name}");
    }
}

#[test]
fn a_blanked_record_is_revoked() {
    assert_eq!(fixture("rsa2048-a-blanked").parse(), Ok(KeyRecord::Revoked));
}

#[test]
fn other_key_sizes_parse_but_are_not_rsa_2048() {
    for (name, bytes) in [("rsa1024", 128), ("rsa4096", 512)] {
        let record = fixture(name).parse().unwrap();
        let KeyRecord::Rsa { modulus, .. } = &record else {
            panic!("{name}");
        };
        assert_eq!(modulus.len(), bytes, "{name}");
        assert_eq!(modulus_2048(&record), None, "{name}");
    }
}

#[test]
fn malformed_records_are_refused_as_rfc_6376_requires() {
    assert_eq!(
        fixture("ed25519").parse(),
        Err(RecordError::KeyType("ed25519".into()))
    );
    assert_eq!(
        fixture("wrong-version").parse(),
        Err(RecordError::Version("DKIM2".into()))
    );
    assert_eq!(
        fixture("version-not-first").parse(),
        Err(RecordError::VersionNotFirst)
    );
    assert_eq!(
        fixture("duplicate-tag").parse(),
        Err(RecordError::DuplicateTag("p".into()))
    );
    assert_eq!(fixture("no-p").parse(), Err(RecordError::MissingKey));
    assert_eq!(parse_txt(&["v=DKIM1; p=!!!"]), Err(RecordError::Base64));
    assert_eq!(parse_txt(&["v=DKIM1; p=AAAA"]), Err(RecordError::Der));
    assert_eq!(parse_txt(&["v=DKIM1; garbage"]), Err(RecordError::Syntax));
}

#[test]
fn every_fixture_is_covered() {
    let named = [
        "rsa2048-a",
        "rsa2048-b",
        "rsa2048-c",
        "rsa2048-a-blanked",
        "rsa1024",
        "rsa4096",
        "ed25519",
        "wrong-version",
        "version-not-first",
        "duplicate-tag",
        "no-p",
    ];
    let listed: Vec<String> = fixtures().into_iter().map(|r| r.name).collect();
    assert_eq!(listed, named);
}

fn obs(live: bool) -> Observation {
    let n = modulus_2048(&fixture("rsa2048-a").parse().unwrap()).unwrap();
    Observation {
        domain: "gmail.com".into(),
        selector: "test-a".into(),
        key_hash: key_hash(&n),
        observed_live: live,
        observed_at: 1_793_500_000,
        resolvers: vec!["8.8.8.8".into(), "1.1.1.1".into(), "9.9.9.9".into()],
    }
}

#[test]
fn the_encoding_is_the_spec_layout_and_the_registry_parses_it() {
    let registry = [7u8; 32];
    let o = obs(true);
    let bytes = encode(&registry, &o);
    // Three resolvers: a length byte and 7 bytes each.
    assert_eq!(bytes.len(), attestation::FIXED_LEN + 3 * (1 + 7));
    assert_eq!(&bytes[..38], b"nido/email-recovery/v1/dns-attestation");
    assert_eq!(&bytes[38..70], &registry);
    assert_eq!(bytes[70], 9);
    assert_eq!(&bytes[71..80], b"gmail.com");
    assert!(bytes[80..133].iter().all(|&b| b == 0));
    assert_eq!(bytes[133], 6);
    assert_eq!(&bytes[134..140], b"test-a");
    assert_eq!(&bytes[197..229], &o.key_hash);
    assert_eq!(bytes[229], 1);
    assert_eq!(&bytes[230..238], &1_793_500_000u64.to_be_bytes());
    assert_eq!(bytes[238], 3);

    let a = attestation::parse(&bytes).expect("the registry's parser accepts it");
    assert_eq!(a.registry, registry);
    assert_eq!(a.domain, b"gmail.com");
    assert_eq!(a.selector, b"test-a");
    assert_eq!(a.key_hash, o.key_hash);
    assert!(a.observed_live);
    assert_eq!(a.observed_at, 1_793_500_000);
    assert_eq!(
        a.resolvers(),
        &[&b"8.8.8.8"[..], &b"1.1.1.1"[..], &b"9.9.9.9"[..]]
    );
}

#[test]
fn observe_follows_the_record_by_key_hash() {
    let a = fixture("rsa2048-a");
    let n = modulus_2048(&a.parse().unwrap()).unwrap();
    let kh = key_hash(&n);
    let live = observe(
        "gmail.com",
        "test-a",
        Some(&a.strings()),
        kh,
        1,
        &["8.8.8.8"],
    );
    assert!(live.observed_live);
    let blanked = fixture("rsa2048-a-blanked");
    let gone = observe(
        "gmail.com",
        "test-a",
        Some(&blanked.strings()),
        kh,
        1,
        &["8.8.8.8"],
    );
    assert!(!gone.observed_live);
    assert!(!observe("gmail.com", "test-a", None, kh, 1, &["8.8.8.8"]).observed_live);
    // The selector now serving another key does not publish this one.
    let other = fixture("rsa2048-b");
    assert!(
        !observe(
            "gmail.com",
            "test-a",
            Some(&other.strings()),
            kh,
            1,
            &["8.8.8.8"]
        )
        .observed_live
    );
}

#[test]
fn attestations_verify_under_the_attester_key() {
    let attester = TestAttester::new(0);
    let signed = attester.attest(&[7u8; 32], &obs(false));
    let key = VerifyingKey::from_bytes(&signed.attester).unwrap();
    key.verify(&signed.bytes, &Signature::from_bytes(&signed.signature))
        .unwrap();
    assert_ne!(
        TestAttester::new(0).public_key(),
        TestAttester::new(1).public_key()
    );
    assert_eq!(
        TestAttester::new(2).public_key(),
        TestAttester::new(2).public_key()
    );
}

#[test]
fn spki_and_bare_rsa_public_key_give_the_same_modulus() {
    // rsa2048-c is published as a bare RSAPublicKey; re-wrap it in a
    // SubjectPublicKeyInfo the way `openssl rsa -pubout` writes one.
    let KeyRecord::Rsa { modulus, exponent } = fixture("rsa2048-c").parse().unwrap() else {
        panic!()
    };
    let rec = fixture("rsa2048-c");
    let p = rec.strings.concat();
    let p = p.split("p=").nth(1).unwrap();
    let pkcs1 = STANDARD.decode(p).unwrap();
    let mut bits = vec![0u8];
    bits.extend_from_slice(&pkcs1);
    let mut algorithm = vec![0x30, 13, 0x06, 9];
    algorithm.extend_from_slice(&[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ]);
    let mut body = algorithm;
    body.push(0x03);
    body.extend_from_slice(&[0x82, 0x01, 0x0f]);
    body.extend_from_slice(&bits);
    let mut spki = vec![0x30, 0x82];
    spki.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    spki.extend_from_slice(&body);
    let txt = format!("v=DKIM1; p={}", STANDARD.encode(spki));
    assert_eq!(parse_txt(&[&txt]), Ok(KeyRecord::Rsa { modulus, exponent }));
}
