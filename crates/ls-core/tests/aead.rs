#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::crypto::aead::{Aad, AeadError, DataKey, Envelope};

fn slot() -> Aad {
    Aad::secret_slot("proj-1", "env-1", "DB_URL")
}

#[test]
fn a_sealed_value_opens_again_with_the_same_key_and_context() {
    let key = DataKey::generate().unwrap();
    let sealed = key.seal(b"postgres://user:pw@host/db", &slot()).unwrap();

    let opened = key.open(&sealed, &slot()).unwrap();

    assert_eq!(opened, b"postgres://user:pw@host/db");
}

#[test]
fn sealing_the_same_value_twice_produces_different_ciphertext() {
    let key = DataKey::generate().unwrap();
    let a = key.seal(b"same value", &slot()).unwrap();
    let b = key.seal(b"same value", &slot()).unwrap();

    assert_ne!(a.nonce, b.nonce, "each seal needs a fresh nonce");
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn ciphertext_does_not_contain_the_plaintext() {
    let key = DataKey::generate().unwrap();
    let sealed = key.seal(b"postgres://user:pw@host/db", &slot()).unwrap();

    assert!(
        !sealed
            .ciphertext
            .windows(b"postgres".len())
            .any(|w| w == b"postgres"),
        "plaintext visible in ciphertext"
    );
}

#[test]
fn a_tampered_ciphertext_is_rejected() {
    let key = DataKey::generate().unwrap();
    let mut sealed = key.seal(b"postgres://user:pw@host/db", &slot()).unwrap();
    sealed.ciphertext[0] ^= 0x01;

    assert!(matches!(
        key.open(&sealed, &slot()),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn a_tampered_nonce_is_rejected() {
    let key = DataKey::generate().unwrap();
    let mut sealed = key.seal(b"postgres://user:pw@host/db", &slot()).unwrap();
    sealed.nonce[0] ^= 0x01;

    assert!(matches!(
        key.open(&sealed, &slot()),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn another_key_cannot_open_it() {
    let key = DataKey::generate().unwrap();
    let other = DataKey::generate().unwrap();
    let sealed = key.seal(b"postgres://user:pw@host/db", &slot()).unwrap();

    assert!(matches!(
        other.open(&sealed, &slot()),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn a_ciphertext_moved_to_another_environment_will_not_open() {
    let key = DataKey::generate().unwrap();
    let sealed = key
        .seal(b"production password", &Aad::secret_slot("p", "prod", "DB_PW"))
        .unwrap();

    let moved = key.open(&sealed, &Aad::secret_slot("p", "dev", "DB_PW"));

    assert!(
        matches!(moved, Err(AeadError::Decrypt)),
        "moving a row between environments must not leak the value"
    );
}

#[test]
fn a_ciphertext_moved_to_another_key_name_will_not_open() {
    let key = DataKey::generate().unwrap();
    let sealed = key
        .seal(b"value", &Aad::secret_slot("p", "prod", "A"))
        .unwrap();

    assert!(matches!(
        key.open(&sealed, &Aad::secret_slot("p", "prod", "B")),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn context_fields_cannot_be_confused_by_shifting_a_boundary() {
    // Naive concatenation would make these two contexts identical.
    let key = DataKey::generate().unwrap();
    let sealed = key
        .seal(b"value", &Aad::secret_slot("ab", "c", "d"))
        .unwrap();

    assert!(
        matches!(
            key.open(&sealed, &Aad::secret_slot("a", "bc", "d")),
            Err(AeadError::Decrypt)
        ),
        "associated data must be unambiguous across field boundaries"
    );
}

#[test]
fn contexts_for_different_purposes_never_collide() {
    let key = DataKey::generate().unwrap();
    let sealed = key.seal(b"value", &Aad::key_wrap("project-dek", "p1")).unwrap();

    assert!(matches!(
        key.open(&sealed, &Aad::secret_slot("project-dek", "p1", "")),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn an_empty_value_round_trips() {
    let key = DataKey::generate().unwrap();
    let sealed = key.seal(b"", &slot()).unwrap();
    assert_eq!(key.open(&sealed, &slot()).unwrap(), Vec::<u8>::new());
}

#[test]
fn oversized_values_are_rejected_rather_than_stored() {
    let key = DataKey::generate().unwrap();
    let huge = vec![b'x'; ls_core::crypto::aead::MAX_PLAINTEXT_LEN + 1];

    assert!(matches!(
        key.seal(&huge, &slot()),
        Err(AeadError::PlaintextTooLarge { .. })
    ));
}

#[test]
fn a_key_round_trips_through_storage_bytes() {
    let key = DataKey::generate().unwrap();
    let sealed = key.seal(b"value", &slot()).unwrap();

    let reloaded = DataKey::from_bytes(key.expose_bytes()).unwrap();

    assert_eq!(reloaded.open(&sealed, &slot()).unwrap(), b"value");
}

#[test]
fn a_key_of_the_wrong_size_is_rejected() {
    assert!(DataKey::from_bytes(&[0u8; 16]).is_none());
    assert!(DataKey::from_bytes(&[]).is_none());
}

#[test]
fn a_nonce_of_the_wrong_size_is_rejected_instead_of_panicking() {
    let key = DataKey::generate().unwrap();
    let broken = Envelope {
        nonce: vec![0u8; 4],
        ciphertext: vec![0u8; 32],
    };

    assert!(matches!(key.open(&broken, &slot()), Err(AeadError::Decrypt)));
}

#[test]
fn debug_output_never_prints_key_material() {
    let key = DataKey::generate().unwrap();
    let rendered = format!("{key:?}");
    let leaked = key
        .expose_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert!(!rendered.contains(&leaked), "key leaked via Debug: {rendered}");
}
