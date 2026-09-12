#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::crypto::token;

#[test]
fn generated_token_carries_the_localsecrets_prefix() {
    let issued = token::generate().unwrap();
    assert!(
        issued.secret().starts_with("lsec_"),
        "token should be identifiable by secret scanners, got {:?}",
        issued.secret()
    );
}

#[test]
fn two_generated_tokens_differ() {
    let a = token::generate().unwrap();
    let b = token::generate().unwrap();
    assert_ne!(a.secret(), b.secret());
    assert_ne!(a.hash().as_bytes(), b.hash().as_bytes());
}

#[test]
fn hash_of_a_token_matches_the_hash_issued_with_it() {
    let issued = token::generate().unwrap();
    let recomputed = token::hash(issued.secret());
    assert_eq!(recomputed.as_bytes(), issued.hash().as_bytes());
}

#[test]
fn hash_does_not_reveal_the_token() {
    let issued = token::generate().unwrap();
    let hash_bytes = issued.hash().as_bytes().to_vec();
    let secret_bytes = issued.secret().as_bytes();
    assert_eq!(hash_bytes.len(), 32);
    assert!(
        !secret_bytes
            .windows(hash_bytes.len().min(secret_bytes.len()))
            .any(|w| w == hash_bytes.as_slice()),
        "the stored hash must not contain the token itself"
    );
}

#[test]
fn verify_accepts_the_right_token_and_rejects_others() {
    let issued = token::generate().unwrap();
    let other = token::generate().unwrap();

    assert!(issued.hash().verify(issued.secret()));
    assert!(!issued.hash().verify(other.secret()));
    assert!(!issued.hash().verify(""));
    assert!(!issued.hash().verify("lsec_not-a-real-token"));
}

#[test]
fn token_hash_round_trips_through_storage_bytes() {
    let issued = token::generate().unwrap();
    let stored = issued.hash().as_bytes().to_vec();

    let loaded = token::TokenHash::from_bytes(&stored).expect("32 bytes is a valid hash");

    assert!(loaded.verify(issued.secret()));
}

#[test]
fn token_hash_rejects_wrongly_sized_storage_bytes() {
    assert!(token::TokenHash::from_bytes(&[0u8; 31]).is_none());
    assert!(token::TokenHash::from_bytes(&[0u8; 33]).is_none());
    assert!(token::TokenHash::from_bytes(&[]).is_none());
}

#[test]
fn debug_output_never_prints_the_token() {
    let issued = token::generate().unwrap();
    let rendered = format!("{issued:?}");
    assert!(
        !rendered.contains(issued.secret()),
        "Debug for an issued token leaked it: {rendered}"
    );
}

#[test]
fn a_token_carries_thirty_two_bytes_of_entropy_in_a_fixed_format() {
    let issued = token::generate().unwrap();
    let body = issued
        .secret()
        .strip_prefix(token::TOKEN_PREFIX)
        .expect("prefix");

    assert_eq!(body.len(), 43, "32 bytes is 43 unpadded base64 characters");
    assert_eq!(
        ls_core::encoding::b64::decode(body).map(|b| b.len()),
        Some(32)
    );
}

#[test]
fn the_secret_can_be_taken_out_for_a_single_delivery() {
    let issued = token::generate().unwrap();
    let hash = issued.hash().clone();

    let secret = issued.into_secret();

    assert!(hash.verify(&secret));
}
