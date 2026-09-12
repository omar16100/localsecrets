#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ls_core::crypto::aead::Envelope;
use ls_core::time::Timestamp;
use ls_store::{Event, Sealed, State, TokenKind};

fn sealed(tag: u8) -> Sealed {
    Sealed::from(Envelope {
        nonce: vec![tag; 12],
        ciphertext: vec![tag; 20],
    })
}

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix(seconds)
}

fn user_created() -> Event {
    Event::UserCreated {
        id: "u1".into(),
        email: "dev@example.com".into(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        created_at: at(1_000),
    }
}

fn project_created() -> Event {
    Event::ProjectCreated {
        id: "p1".into(),
        slug: "demo".into(),
        name: "Demo".into(),
        data_key: sealed(1),
        created_at: at(1_100),
    }
}

fn environment_created() -> Event {
    Event::EnvironmentCreated {
        id: "e1".into(),
        project_id: "p1".into(),
        slug: "dev".into(),
        name: "Development".into(),
        created_at: at(1_200),
    }
}

fn secret_set(key: &str, tag: u8, when: i64) -> Event {
    Event::SecretSet {
        project_id: "p1".into(),
        environment_id: "e1".into(),
        key: key.into(),
        value: sealed(tag),
        at: at(when),
    }
}

fn session_token(id: &str, expires: Option<i64>) -> Event {
    Event::TokenIssued {
        id: id.into(),
        token_hash: vec![7u8; 32],
        kind: TokenKind::Session,
        user_id: Some("u1".into()),
        project_id: None,
        environment_id: None,
        label: None,
        expires_at: expires.map(at),
        created_at: at(1_000),
    }
}

fn state_from(events: Vec<Event>) -> State {
    let mut state = State::default();
    for event in events {
        state.apply(event);
    }
    state
}

// --- serialisation ---------------------------------------------------------

#[test]
fn every_event_survives_a_round_trip_through_its_stored_form() {
    let events = vec![
        user_created(),
        project_created(),
        environment_created(),
        secret_set("DB_URL", 3, 1_300),
        Event::SecretDeleted {
            project_id: "p1".into(),
            environment_id: "e1".into(),
            key: "DB_URL".into(),
            at: at(1_400),
        },
        session_token("t1", Some(9_999)),
        Event::TokenIssued {
            id: "t2".into(),
            token_hash: vec![1u8; 32],
            kind: TokenKind::Machine,
            user_id: None,
            project_id: Some("p1".into()),
            environment_id: Some("e1".into()),
            label: Some("ci".into()),
            expires_at: None,
            created_at: at(1_500),
        },
        Event::TokenRevoked {
            id: "t1".into(),
            at: at(1_600),
        },
        Event::Audited {
            at: at(1_700),
            actor: "u1".into(),
            action: "secret.read".into(),
            target: "demo/dev/DB_URL".into(),
            outcome: "ok".into(),
        },
    ];

    for event in events {
        let encoded = event.to_bytes();
        let decoded = Event::from_bytes(&encoded).expect("should decode");
        assert_eq!(decoded, event, "round trip failed for {event:?}");
    }
}

#[test]
fn the_stored_form_is_json_with_a_type_tag() {
    let encoded = user_created().to_bytes();
    let text = String::from_utf8(encoded).unwrap();

    assert!(text.starts_with('{'), "got {text}");
    assert!(text.contains("\"type\":\"user.created\""), "got {text}");
}

#[test]
fn an_unknown_event_type_is_refused_rather_than_ignored() {
    // Silently skipping an event this build does not understand would mean
    // replaying an old binary against a newer log and losing state.
    let encoded = br#"{"type":"something.new","id":"x"}"#;

    assert!(Event::from_bytes(encoded).is_err());
}

#[test]
fn a_malformed_event_is_refused() {
    assert!(Event::from_bytes(b"not json").is_err());
    assert!(Event::from_bytes(b"{}").is_err(), "no type tag");
    assert!(
        Event::from_bytes(br#"{"type":"user.created"}"#).is_err(),
        "missing fields"
    );
    assert!(
        Event::from_bytes(br#"{"type":"user.created","id":1,"email":"a","password_hash":"h","created_at":"1970-01-01T00:00:00Z"}"#).is_err(),
        "id is not a string"
    );
    assert!(
        Event::from_bytes(br#"{"type":"user.created","id":"u","email":"a","password_hash":"h","created_at":"not a time"}"#).is_err(),
        "unparseable timestamp"
    );
}

#[test]
fn a_sealed_value_round_trips_exactly() {
    let original = sealed(0xAB);
    let event = secret_set("K", 0xAB, 1);

    let decoded = Event::from_bytes(&event.to_bytes()).unwrap();

    match decoded {
        Event::SecretSet { value, .. } => assert_eq!(value, original),
        other => panic!("wrong event: {other:?}"),
    }
}

// --- folding events into state --------------------------------------------

#[test]
fn a_created_user_can_be_found_by_email() {
    let state = state_from(vec![user_created()]);

    let user = state.user_by_email("dev@example.com").expect("user");
    assert_eq!(user.id, "u1");
    assert!(state.user_by_email("nobody@example.com").is_none());
}

#[test]
fn email_lookup_ignores_case_and_surrounding_space() {
    let state = state_from(vec![user_created()]);

    assert!(state.user_by_email("DEV@EXAMPLE.COM").is_some());
    assert!(state.user_by_email("  dev@example.com  ").is_some());
}

#[test]
fn a_project_can_be_found_by_slug_and_carries_its_wrapped_key() {
    let state = state_from(vec![project_created()]);

    let project = state.project_by_slug("demo").expect("project");
    assert_eq!(project.id, "p1");
    assert_eq!(project.data_key, sealed(1));
    assert!(state.project_by_slug("missing").is_none());
}

#[test]
fn an_environment_is_found_within_its_project_only() {
    let state = state_from(vec![project_created(), environment_created()]);

    assert!(state.environment_by_slug("p1", "dev").is_some());
    assert!(
        state.environment_by_slug("p2", "dev").is_none(),
        "environments must not leak across projects"
    );
}

#[test]
fn a_secret_is_found_at_its_slot() {
    let state = state_from(vec![
        project_created(),
        environment_created(),
        secret_set("DB_URL", 3, 1_300),
    ]);

    let secret = state.secret("p1", "e1", "DB_URL").expect("secret");
    assert_eq!(secret.value, sealed(3));
    assert!(state.secret("p1", "e1", "OTHER").is_none());
    assert!(state.secret("p1", "e2", "DB_URL").is_none());
}

#[test]
fn setting_a_secret_again_replaces_the_value_and_keeps_one_entry() {
    let state = state_from(vec![
        secret_set("DB_URL", 3, 1_300),
        secret_set("DB_URL", 4, 1_400),
    ]);

    assert_eq!(state.secret("p1", "e1", "DB_URL").unwrap().value, sealed(4));
    assert_eq!(state.secrets_in("p1", "e1").len(), 1);
}

#[test]
fn a_deleted_secret_is_gone() {
    let state = state_from(vec![
        secret_set("DB_URL", 3, 1_300),
        Event::SecretDeleted {
            project_id: "p1".into(),
            environment_id: "e1".into(),
            key: "DB_URL".into(),
            at: at(1_400),
        },
    ]);

    assert!(state.secret("p1", "e1", "DB_URL").is_none());
    assert!(state.secrets_in("p1", "e1").is_empty());
}

#[test]
fn listing_an_environment_returns_its_secrets_sorted_by_key() {
    let state = state_from(vec![
        secret_set("ZED", 1, 1_300),
        secret_set("ALPHA", 2, 1_310),
        secret_set("MIDDLE", 3, 1_320),
    ]);

    let keys: Vec<&str> = state
        .secrets_in("p1", "e1")
        .iter()
        .map(|s| s.key.as_str())
        .collect();

    assert_eq!(keys, vec!["ALPHA", "MIDDLE", "ZED"]);
}

#[test]
fn a_token_is_found_by_its_hash() {
    let state = state_from(vec![session_token("t1", None)]);

    let token = state.token_by_hash(&[7u8; 32]).expect("token");
    assert_eq!(token.id, "t1");
    assert!(state.token_by_hash(&[0u8; 32]).is_none());
}

#[test]
fn a_token_without_an_expiry_stays_valid() {
    let state = state_from(vec![session_token("t1", None)]);
    let token = state.token_by_hash(&[7u8; 32]).unwrap();

    assert!(token.is_valid_at(at(9_999_999)));
}

#[test]
fn an_expired_token_is_not_valid() {
    let state = state_from(vec![session_token("t1", Some(5_000))]);
    let token = state.token_by_hash(&[7u8; 32]).unwrap();

    assert!(token.is_valid_at(at(4_999)));
    assert!(
        !token.is_valid_at(at(5_000)),
        "a token must stop working at its expiry, not after it"
    );
    assert!(!token.is_valid_at(at(5_001)));
}

#[test]
fn a_revoked_token_is_not_valid_even_before_its_expiry() {
    let state = state_from(vec![
        session_token("t1", Some(9_999)),
        Event::TokenRevoked {
            id: "t1".into(),
            at: at(2_000),
        },
    ]);
    let token = state.token_by_hash(&[7u8; 32]).unwrap();

    assert!(!token.is_valid_at(at(2_001)));
    assert!(
        !token.is_valid_at(at(1_999)),
        "revocation is not retroactive bookkeeping; the token is dead"
    );
}

#[test]
fn revoking_a_token_that_does_not_exist_changes_nothing() {
    let state = state_from(vec![
        session_token("t1", None),
        Event::TokenRevoked {
            id: "nonexistent".into(),
            at: at(2_000),
        },
    ]);

    assert!(
        state
            .token_by_hash(&[7u8; 32])
            .unwrap()
            .is_valid_at(at(3_000))
    );
}

#[test]
fn audit_events_do_not_become_state() {
    // They belong in the log, which is the record. Holding every one in memory
    // would grow without bound.
    let state = state_from(vec![
        user_created(),
        Event::Audited {
            at: at(1_700),
            actor: "u1".into(),
            action: "secret.read".into(),
            target: "demo/dev/DB_URL".into(),
            outcome: "ok".into(),
        },
    ]);

    assert_eq!(state.users.len(), 1);
}

#[test]
fn state_holds_no_plaintext_secret_values() {
    // Everything a secret carries through state is ciphertext. This is the
    // property that makes replaying the log on a sealed server safe.
    let state = state_from(vec![secret_set("DB_URL", 3, 1_300)]);
    let secret = state.secret("p1", "e1", "DB_URL").unwrap();

    assert_eq!(secret.value.nonce.len(), 12);
    assert!(!secret.value.ciphertext.is_empty());
}

#[test]
fn debug_output_of_a_sealed_value_does_not_print_it() {
    let rendered = format!("{:?}", sealed(0xCD));
    assert!(
        !rendered.contains("cdcdcd"),
        "sealed value leaked: {rendered}"
    );
}
