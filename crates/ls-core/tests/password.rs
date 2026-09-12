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

#[test]
fn verify_refuses_a_stored_hash_demanding_absurd_work() {
    // A tampered store must not be able to make the server spend four gigabytes
    // and ten passes on every login attempt.
    let hostile = "$argon2id$v=19$m=4194304,t=10,p=4$c2FsdHNhbHRzYWx0c2FsdA$\
aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";

    let started = std::time::Instant::now();
    assert!(!password::verify("anything", hostile));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "parameters were not capped before hashing"
    );
}

#[test]
fn verify_accepts_a_hash_produced_at_the_configured_parameters() {
    let stored = password::hash("correct horse battery staple").unwrap();
    assert!(
        stored.contains("m=19456,t=2,p=1"),
        "unexpected params: {stored}"
    );
    assert!(password::verify("correct horse battery staple", &stored));
}

#[test]
fn the_minimum_length_counts_characters_and_the_maximum_counts_bytes() {
    // Twelve characters of Japanese is thirty-six bytes: long enough by the
    // strength rule, nowhere near the resource limit.
    let twelve_multibyte = "\u{65e5}".repeat(12);
    assert_eq!(twelve_multibyte.chars().count(), 12);
    assert_eq!(twelve_multibyte.len(), 36);
    assert!(password::hash(&twelve_multibyte).is_ok());

    let eleven = "\u{65e5}".repeat(11);
    assert!(matches!(
        password::hash(&eleven),
        Err(password::PasswordError::TooShort { .. })
    ));
}
