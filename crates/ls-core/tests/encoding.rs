#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::encoding::{b64, hex};

// RFC 4648 section 10 test vectors, with padding removed.
const B64_VECTORS: &[(&str, &str)] = &[
    ("", ""),
    ("f", "Zg"),
    ("fo", "Zm8"),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg"),
    ("fooba", "Zm9vYmE"),
    ("foobar", "Zm9vYmFy"),
];

#[test]
fn base64url_matches_the_rfc_4648_vectors() {
    for (plain, encoded) in B64_VECTORS {
        assert_eq!(b64::encode(plain.as_bytes()), *encoded, "encoding {plain:?}");
    }
}

#[test]
fn base64url_decodes_the_rfc_4648_vectors() {
    for (plain, encoded) in B64_VECTORS {
        assert_eq!(
            b64::decode(encoded).unwrap(),
            plain.as_bytes(),
            "decoding {encoded:?}"
        );
    }
}

#[test]
fn base64url_uses_the_url_safe_alphabet() {
    // 0xFB 0xFF encodes to the two highest alphabet positions, which are
    // '+' and '/' in standard base64 and '-' and '_' in the URL-safe one.
    assert_eq!(b64::encode(&[0xFB, 0xFF]), "-_8");
    assert_eq!(b64::decode("-_8").unwrap(), vec![0xFB, 0xFF]);
}

#[test]
fn base64url_round_trips_every_byte_value() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(b64::decode(&b64::encode(&all)).unwrap(), all);
}

#[test]
fn base64url_round_trips_every_length_up_to_a_block_boundary() {
    for len in 0..=32usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let encoded = b64::encode(&data);
        assert_eq!(b64::decode(&encoded).unwrap(), data, "length {len}");
    }
}

#[test]
fn base64url_rejects_characters_outside_the_alphabet() {
    assert!(b64::decode("Zm9v!").is_none());
    assert!(b64::decode("Zm9 v").is_none());
    assert!(b64::decode("Zm+v").is_none(), "standard alphabet is not accepted");
    assert!(b64::decode("Zm/v").is_none());
}

#[test]
fn base64url_rejects_padding() {
    assert!(b64::decode("Zg==").is_none());
}

#[test]
fn base64url_rejects_a_truncated_group() {
    // A single leftover character cannot encode any whole byte.
    assert!(b64::decode("Z").is_none());
    assert!(b64::decode("Zm9vZ").is_none());
}

#[test]
fn hex_encodes_lowercase() {
    assert_eq!(hex::encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    assert_eq!(hex::encode(&[]), "");
}

#[test]
fn hex_round_trips_every_byte_value() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(hex::decode(&hex::encode(&all)).unwrap(), all);
}

#[test]
fn hex_accepts_uppercase_input() {
    assert_eq!(hex::decode("000FA5FF").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
}

#[test]
fn hex_rejects_odd_length_and_non_hex_characters() {
    assert!(hex::decode("abc").is_none());
    assert!(hex::decode("zz").is_none());
    assert!(hex::decode("00 11").is_none());
}
