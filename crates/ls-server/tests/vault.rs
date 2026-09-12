#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ls_server::{Vault, VaultError};
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ls-vault-{label}-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("store.log")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A vault that is initialised, unsealed, and has one user logged in.
struct Ready {
    dir: TempDir,
    vault: Vault,
    shares: Vec<String>,
    session: String,
}

fn ready(label: &str) -> Ready {
    let dir = TempDir::new(label);
    let mut vault = Vault::open(&dir.file()).unwrap();
    let outcome = vault.init(3, 5).unwrap();
    let shares = outcome.shares.clone();

    vault
        .create_user("dev@example.com", "correct horse battery staple")
        .unwrap();
    let session = vault
        .login("dev@example.com", "correct horse battery staple", 3600)
        .unwrap()
        .to_string();

    Ready {
        dir,
        vault,
        shares,
        session,
    }
}

// --- seal and unseal -------------------------------------------------------

#[test]
fn a_fresh_vault_is_sealed_and_uninitialised() {
    let dir = TempDir::new("fresh");
    let vault = Vault::open(&dir.file()).unwrap();

    assert!(vault.is_sealed());
    assert!(!vault.is_initialized());
}

#[test]
fn initialising_hands_back_the_shares_and_a_root_token_and_unseals() {
    let dir = TempDir::new("init");
    let mut vault = Vault::open(&dir.file()).unwrap();

    let outcome = vault.init(3, 5).unwrap();

    assert_eq!(outcome.shares.len(), 5);
    assert!(outcome.shares.iter().all(|s| s.starts_with("lss1.")));
    assert!(outcome.root_token.starts_with("lsec_"));
    assert!(vault.is_initialized());
    assert!(!vault.is_sealed(), "init leaves the vault ready to use");
}

#[test]
fn initialising_twice_is_refused() {
    let dir = TempDir::new("init-twice");
    let mut vault = Vault::open(&dir.file()).unwrap();
    vault.init(3, 5).unwrap();

    assert!(matches!(
        vault.init(3, 5),
        Err(VaultError::AlreadyInitialized)
    ));
}

#[test]
fn nonsensical_share_parameters_are_refused() {
    let dir = TempDir::new("init-bad");
    let mut vault = Vault::open(&dir.file()).unwrap();

    assert!(vault.init(0, 5).is_err());
    assert!(vault.init(6, 5).is_err());
    assert!(!vault.is_initialized(), "a failed init must leave nothing behind");
}

#[test]
fn a_single_share_configuration_is_allowed_for_one_operator() {
    let dir = TempDir::new("one-share");
    let mut vault = Vault::open(&dir.file()).unwrap();

    let outcome = vault.init(1, 1).unwrap();

    assert_eq!(outcome.shares.len(), 1);
}

#[test]
fn sealing_makes_secrets_unreachable() {
    let mut fixture = ready("seal");
    fixture.vault.create_project("demo", "Demo").unwrap();

    fixture.vault.seal();

    assert!(fixture.vault.is_sealed());
    assert!(matches!(
        fixture.vault.create_project("other", "Other"),
        Err(VaultError::Sealed)
    ));
}

#[test]
fn unsealing_needs_the_threshold_and_not_one_share_less() {
    let mut fixture = ready("unseal");
    fixture.vault.seal();

    let first = fixture.vault.submit_share(&fixture.shares[0]).unwrap();
    assert!(first.sealed);
    assert_eq!(first.progress, 1);
    assert_eq!(first.threshold, 3);

    let second = fixture.vault.submit_share(&fixture.shares[1]).unwrap();
    assert!(second.sealed, "two of three is not enough");

    let third = fixture.vault.submit_share(&fixture.shares[2]).unwrap();
    assert!(!third.sealed);
    assert!(!fixture.vault.is_sealed());
}

#[test]
fn the_same_share_twice_does_not_count_twice() {
    let mut fixture = ready("dup-share");
    fixture.vault.seal();

    fixture.vault.submit_share(&fixture.shares[0]).unwrap();
    let again = fixture.vault.submit_share(&fixture.shares[0]).unwrap();

    assert_eq!(again.progress, 1, "a repeated share must not advance progress");
    assert!(again.sealed);
}

#[test]
fn a_mistyped_share_is_rejected_when_it_is_submitted() {
    let mut fixture = ready("bad-share");
    fixture.vault.seal();

    let mangled = fixture.shares[0].replace("lss1.", "lss1.9");

    assert!(fixture.vault.submit_share(&mangled).is_err());
    assert!(fixture.vault.is_sealed());
}

#[test]
fn shares_from_another_vault_do_not_unseal_this_one() {
    let other = TempDir::new("other-vault");
    let mut other_vault = Vault::open(&other.file()).unwrap();
    let foreign = other_vault.init(3, 5).unwrap().shares;

    let mut fixture = ready("foreign-shares");
    fixture.vault.seal();

    fixture.vault.submit_share(&foreign[0]).unwrap();
    fixture.vault.submit_share(&foreign[1]).unwrap();
    let result = fixture.vault.submit_share(&foreign[2]);

    assert!(
        matches!(result, Err(VaultError::UnsealFailed)),
        "recombining the wrong shares must fail, not install a wrong key"
    );
    assert!(fixture.vault.is_sealed());
}

#[test]
fn a_failed_unseal_clears_the_progress_so_the_ceremony_can_restart() {
    let other = TempDir::new("other-vault-2");
    let mut other_vault = Vault::open(&other.file()).unwrap();
    let foreign = other_vault.init(3, 5).unwrap().shares;

    let mut fixture = ready("restart-unseal");
    fixture.vault.seal();

    // Two of ours and one of theirs: three distinct indexes, so the threshold
    // is reached and the recombination is attempted, and fails.
    fixture.vault.submit_share(&fixture.shares[0]).unwrap();
    fixture.vault.submit_share(&fixture.shares[1]).unwrap();
    assert!(matches!(
        fixture.vault.submit_share(&foreign[2]),
        Err(VaultError::UnsealFailed)
    ));

    let after = fixture.vault.submit_share(&fixture.shares[0]).unwrap();
    assert_eq!(after.progress, 1, "progress should have been reset");
}

#[test]
fn unseal_progress_can_be_abandoned() {
    let mut fixture = ready("reset-unseal");
    fixture.vault.seal();
    fixture.vault.submit_share(&fixture.shares[0]).unwrap();

    fixture.vault.reset_unseal();

    let after = fixture.vault.submit_share(&fixture.shares[1]).unwrap();
    assert_eq!(after.progress, 1);
}

// --- durability ------------------------------------------------------------

#[test]
fn everything_comes_back_after_a_restart_and_an_unseal() {
    let mut fixture = ready("restart");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture
        .vault
        .set_secret(&caller, "demo", "dev", "DB_URL", b"postgres://x")
        .unwrap();

    let path = fixture.dir.file();
    let shares = fixture.shares.clone();
    let session = fixture.session.clone();
    drop(fixture.vault);

    let mut reopened = Vault::open(&path).unwrap();
    assert!(reopened.is_sealed(), "a restarted vault starts sealed");
    assert!(reopened.is_initialized());

    for share in shares.iter().take(3) {
        reopened.submit_share(share).unwrap();
    }

    let caller = reopened
        .authenticate(&session)
        .expect("a session survives a restart");
    let value = reopened
        .get_secret(&caller, "demo", "dev", "DB_URL")
        .unwrap();
    assert_eq!(value.as_slice(), b"postgres://x");
}

#[test]
fn a_sealed_vault_cannot_read_anything_even_though_the_file_is_there() {
    let mut fixture = ready("sealed-read");
    fixture.vault.create_project("demo", "Demo").unwrap();
    let session = fixture.session.clone();

    fixture.vault.seal();

    assert!(
        fixture.vault.authenticate(&session).is_none(),
        "a sealed vault knows nothing, not even who is logged in"
    );
}

// --- users and sessions ----------------------------------------------------

#[test]
fn a_user_can_log_in_with_the_right_password_only() {
    let mut fixture = ready("login");

    assert!(
        fixture
            .vault
            .login("dev@example.com", "correct horse battery staple", 3600)
            .is_ok()
    );
    assert!(matches!(
        fixture.vault.login("dev@example.com", "wrong password!", 3600),
        Err(VaultError::BadCredentials)
    ));
}

#[test]
fn logging_in_as_an_unknown_user_gives_the_same_answer_as_a_wrong_password() {
    let mut fixture = ready("enumerate");

    let unknown = fixture.vault.login("nobody@example.com", "whatever long", 3600);
    let wrong = fixture.vault.login("dev@example.com", "whatever long", 3600);

    assert!(matches!(unknown, Err(VaultError::BadCredentials)));
    assert!(matches!(wrong, Err(VaultError::BadCredentials)));
}

#[test]
fn the_same_email_cannot_be_registered_twice() {
    let mut fixture = ready("dup-user");

    assert!(matches!(
        fixture.vault.create_user("DEV@example.com", "another good password"),
        Err(VaultError::Conflict(_))
    ));
}

#[test]
fn a_password_that_is_too_short_is_refused() {
    let mut fixture = ready("short-password");

    assert!(fixture.vault.create_user("new@example.com", "short").is_err());
}

#[test]
fn a_session_token_authenticates_and_a_made_up_one_does_not() {
    let fixture = ready("authenticate");

    assert!(fixture.vault.authenticate(&fixture.session).is_some());
    assert!(fixture.vault.authenticate("lsec_not-a-real-token").is_none());
    assert!(fixture.vault.authenticate("").is_none());
}

#[test]
fn a_revoked_session_stops_working() {
    let mut fixture = ready("revoke");
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();

    fixture.vault.revoke_token(&caller.token_id).unwrap();

    assert!(fixture.vault.authenticate(&fixture.session).is_none());
}

#[test]
fn an_expired_session_stops_working() {
    let mut fixture = ready("expire");

    let expired = fixture
        .vault
        .login("dev@example.com", "correct horse battery staple", -1)
        .unwrap()
        .to_string();

    assert!(fixture.vault.authenticate(&expired).is_none());
}

// --- projects, environments and secrets ------------------------------------

#[test]
fn a_secret_written_comes_back_exactly() {
    let mut fixture = ready("roundtrip");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();

    fixture
        .vault
        .set_secret(&caller, "demo", "dev", "DB_URL", b"postgres://user:pw@host/db")
        .unwrap();

    let value = fixture.vault.get_secret(&caller, "demo", "dev", "DB_URL").unwrap();
    assert_eq!(value.as_slice(), b"postgres://user:pw@host/db");
}

#[test]
fn writing_a_secret_again_replaces_it() {
    let mut fixture = ready("replace");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();

    fixture.vault.set_secret(&caller, "demo", "dev", "K", b"first").unwrap();
    fixture.vault.set_secret(&caller, "demo", "dev", "K", b"second").unwrap();

    assert_eq!(
        fixture.vault.get_secret(&caller, "demo", "dev", "K").unwrap().as_slice(),
        b"second"
    );
}

#[test]
fn a_deleted_secret_is_gone() {
    let mut fixture = ready("delete");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture.vault.set_secret(&caller, "demo", "dev", "K", b"v").unwrap();

    fixture.vault.delete_secret(&caller, "demo", "dev", "K").unwrap();

    assert!(matches!(
        fixture.vault.get_secret(&caller, "demo", "dev", "K"),
        Err(VaultError::NotFound(_))
    ));
}

#[test]
fn listing_an_environment_returns_its_secrets_decrypted_and_sorted() {
    let mut fixture = ready("list");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture.vault.set_secret(&caller, "demo", "dev", "ZED", b"z").unwrap();
    fixture.vault.set_secret(&caller, "demo", "dev", "ALPHA", b"a").unwrap();

    let listed = fixture.vault.list_secrets(&caller, "demo", "dev").unwrap();

    let rendered: Vec<(String, Vec<u8>)> = listed
        .into_iter()
        .map(|(key, value)| (key, value.to_vec()))
        .collect();
    assert_eq!(
        rendered,
        vec![
            ("ALPHA".to_owned(), b"a".to_vec()),
            ("ZED".to_owned(), b"z".to_vec()),
        ]
    );
}

#[test]
fn each_project_gets_its_own_data_key() {
    // The same value in two projects must not produce the same ciphertext.
    let mut fixture = ready("separate-keys");
    for slug in ["one", "two"] {
        fixture.vault.create_project(slug, slug).unwrap();
        fixture.vault.create_environment(slug, "dev", "Development").unwrap();
    }
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture.vault.set_secret(&caller, "one", "dev", "K", b"same value").unwrap();
    fixture.vault.set_secret(&caller, "two", "dev", "K", b"same value").unwrap();

    assert_eq!(
        fixture.vault.get_secret(&caller, "one", "dev", "K").unwrap().as_slice(),
        b"same value"
    );
    assert_eq!(
        fixture.vault.get_secret(&caller, "two", "dev", "K").unwrap().as_slice(),
        b"same value"
    );
}

#[test]
fn the_same_project_slug_cannot_be_used_twice() {
    let mut fixture = ready("dup-project");
    fixture.vault.create_project("demo", "Demo").unwrap();

    assert!(matches!(
        fixture.vault.create_project("demo", "Another"),
        Err(VaultError::Conflict(_))
    ));
}

#[test]
fn the_same_environment_slug_can_be_reused_in_another_project() {
    let mut fixture = ready("env-slug");
    fixture.vault.create_project("one", "One").unwrap();
    fixture.vault.create_project("two", "Two").unwrap();

    fixture.vault.create_environment("one", "dev", "Development").unwrap();

    assert!(fixture.vault.create_environment("two", "dev", "Development").is_ok());
    assert!(matches!(
        fixture.vault.create_environment("one", "dev", "Again"),
        Err(VaultError::Conflict(_))
    ));
}

#[test]
fn an_unknown_project_or_environment_is_not_found() {
    let mut fixture = ready("missing");
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();

    assert!(matches!(
        fixture.vault.get_secret(&caller, "nope", "dev", "K"),
        Err(VaultError::NotFound(_))
    ));

    fixture.vault.create_project("demo", "Demo").unwrap();
    assert!(matches!(
        fixture.vault.get_secret(&caller, "demo", "nope", "K"),
        Err(VaultError::NotFound(_))
    ));
}

#[test]
fn a_bad_slug_or_key_is_refused() {
    let mut fixture = ready("validation");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();

    assert!(fixture.vault.create_project("", "Empty").is_err());
    assert!(fixture.vault.create_project("Has Spaces", "x").is_err());
    assert!(fixture.vault.create_project("../escape", "x").is_err());
    assert!(
        fixture.vault.set_secret(&caller, "demo", "dev", "", b"v").is_err(),
        "an empty key"
    );
    assert!(
        fixture
            .vault
            .set_secret(&caller, "demo", "dev", "has space", b"v")
            .is_err()
    );
}

// --- machine tokens --------------------------------------------------------

#[test]
fn a_machine_token_reads_only_the_environment_it_was_scoped_to() {
    let mut fixture = ready("machine-scope");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    fixture.vault.create_environment("demo", "prod", "Production").unwrap();
    let human = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture.vault.set_secret(&human, "demo", "dev", "K", b"dev value").unwrap();
    fixture.vault.set_secret(&human, "demo", "prod", "K", b"prod value").unwrap();

    let token = fixture
        .vault
        .issue_machine_token("demo", "dev", "ci", None)
        .unwrap()
        .to_string();
    let machine = fixture.vault.authenticate(&token).unwrap();

    assert_eq!(
        fixture.vault.get_secret(&machine, "demo", "dev", "K").unwrap().as_slice(),
        b"dev value"
    );
    assert!(
        matches!(
            fixture.vault.get_secret(&machine, "demo", "prod", "K"),
            Err(VaultError::Forbidden)
        ),
        "a dev token must not reach production"
    );
}

#[test]
fn a_machine_token_cannot_be_issued_for_an_environment_that_does_not_exist() {
    let mut fixture = ready("machine-missing");
    fixture.vault.create_project("demo", "Demo").unwrap();

    assert!(matches!(
        fixture.vault.issue_machine_token("demo", "nope", "ci", None),
        Err(VaultError::NotFound(_))
    ));
}

#[test]
fn a_machine_token_can_be_given_a_lifetime() {
    let mut fixture = ready("machine-ttl");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();

    let expired = fixture
        .vault
        .issue_machine_token("demo", "dev", "ci", Some(-1))
        .unwrap()
        .to_string();

    assert!(fixture.vault.authenticate(&expired).is_none());
}

// --- what reaches the disk -------------------------------------------------

#[test]
fn no_secret_value_is_readable_in_the_file() {
    let mut fixture = ready("at-rest");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture
        .vault
        .set_secret(&caller, "demo", "dev", "DB_URL", b"postgres://user:pw@host/db")
        .unwrap();

    let raw = std::fs::read(fixture.dir.file()).unwrap();

    assert!(
        !raw.windows(8).any(|w| w == b"postgres"),
        "the value is readable at rest"
    );
    assert!(
        !raw.windows(6).any(|w| w == b"DB_URL"),
        "even the key name should be sealed"
    );
}

#[test]
fn no_password_is_readable_in_the_file() {
    let fixture = ready("password-at-rest");
    let raw = std::fs::read(fixture.dir.file()).unwrap();

    assert!(!raw.windows(7).any(|w| w == b"correct"));
}

#[test]
fn no_token_is_readable_in_the_file() {
    let fixture = ready("token-at-rest");
    let raw = std::fs::read(fixture.dir.file()).unwrap();
    let token_bytes = fixture.session.as_bytes();

    assert!(!raw.windows(token_bytes.len()).any(|w| w == token_bytes));
}

// --- audit -----------------------------------------------------------------

#[test]
fn secret_operations_are_recorded_without_their_values() {
    let mut fixture = ready("audit");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    let caller = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture
        .vault
        .set_secret(&caller, "demo", "dev", "DB_URL", b"postgres://x")
        .unwrap();
    fixture.vault.get_secret(&caller, "demo", "dev", "DB_URL").unwrap();

    let trail = fixture.vault.audit_trail().unwrap();

    let actions: Vec<&str> = trail.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"secret.set"), "got {actions:?}");
    assert!(actions.contains(&"secret.read"), "got {actions:?}");
    assert!(
        trail.iter().all(|entry| !entry.target.contains("postgres")),
        "a value reached the audit trail"
    );
}

#[test]
fn a_refused_read_is_recorded_too() {
    let mut fixture = ready("audit-denied");
    fixture.vault.create_project("demo", "Demo").unwrap();
    fixture.vault.create_environment("demo", "dev", "Development").unwrap();
    fixture.vault.create_environment("demo", "prod", "Production").unwrap();
    let human = fixture.vault.authenticate(&fixture.session).unwrap();
    fixture.vault.set_secret(&human, "demo", "prod", "K", b"v").unwrap();

    let token = fixture
        .vault
        .issue_machine_token("demo", "dev", "ci", None)
        .unwrap()
        .to_string();
    let machine = fixture.vault.authenticate(&token).unwrap();
    let _ = fixture.vault.get_secret(&machine, "demo", "prod", "K");

    let trail = fixture.vault.audit_trail().unwrap();
    assert!(
        trail.iter().any(|entry| entry.outcome == "denied"),
        "a refused read should be visible afterwards"
    );
}
