#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::crypto::password;

#[test]
fn a_hashed_password_verifies_against_itself() {
    let hash = password::hash("correct horse battery staple").unwrap();
    assert!(password::verify("correct horse battery staple", &hash));
}

#[test]
fn a_wrong_password_does_not_verify() {
    let hash = password::hash("correct horse battery staple").unwrap();
    assert!(!password::verify("Correct horse battery staple", &hash));
    assert!(!password::verify("", &hash));
    assert!(!password::verify("correct horse battery stapl", &hash));
}

#[test]
fn hashing_the_same_password_twice_gives_different_hashes() {
    let a = password::hash("hunter2hunter2").unwrap();
    let b = password::hash("hunter2hunter2").unwrap();
    assert_ne!(a, b, "each hash must use a fresh salt");
    assert!(password::verify("hunter2hunter2", &a));
    assert!(password::verify("hunter2hunter2", &b));
}

#[test]
fn hash_is_argon2id_in_phc_string_format() {
    let hash = password::hash("hunter2hunter2").unwrap();
    assert!(
        hash.starts_with("$argon2id$"),
        "expected a PHC argon2id string, got {hash}"
    );
}

#[test]
fn hash_never_embeds_the_password() {
    let hash = password::hash("hunter2hunter2").unwrap();
    assert!(!hash.contains("hunter2hunter2"));
}

#[test]
fn verify_rejects_a_malformed_hash_instead_of_panicking() {
    assert!(!password::verify("anything", ""));
    assert!(!password::verify("anything", "not-a-phc-string"));
    assert!(!password::verify("anything", "$argon2id$v=19$garbage"));
}

#[test]
fn short_passwords_are_rejected_at_hash_time() {
    let err = password::hash("short").unwrap_err();
    assert!(
        matches!(err, password::PasswordError::TooShort { .. }),
        "expected TooShort, got {err:?}"
    );
}

#[test]
fn very_long_passwords_are_rejected_rather_than_burning_cpu() {
    let long = "a".repeat(4096);
    let err = password::hash(&long).unwrap_err();
    assert!(
        matches!(err, password::PasswordError::TooLong { .. }),
        "expected TooLong, got {err:?}"
    );
}
