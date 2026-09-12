#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ls_http::{Client, Limits, Server, ServerHandle};
use ls_json::{Value, parse};
use ls_server::{Vault, handler};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct Harness {
    dir: PathBuf,
    handle: Option<ServerHandle>,
    client: Client,
}

impl Harness {
    fn start(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ls-api-{label}-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();

        let vault = Vault::open(&dir.join("store.log")).unwrap();
        let server = Server::bind("127.0.0.1:0", Limits::default()).unwrap();
        let address = server.local_addr().unwrap();
        let handle = server.spawn(4, handler(Arc::new(Mutex::new(vault))));

        Self {
            dir,
            handle: Some(handle),
            client: Client::new(address),
        }
    }

    fn get(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        self.call("GET", path, token, "")
    }

    fn post(&self, path: &str, token: Option<&str>, body: &str) -> (u16, Value) {
        self.call("POST", path, token, body)
    }

    fn put(&self, path: &str, token: Option<&str>, body: &str) -> (u16, Value) {
        self.call("PUT", path, token, body)
    }

    fn delete(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        self.call("DELETE", path, token, "")
    }

    fn call(&self, method: &str, path: &str, token: Option<&str>, body: &str) -> (u16, Value) {
        let bearer = token.map(|t| format!("Bearer {t}"));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(bearer) = &bearer {
            headers.push(("authorization", bearer));
        }

        let response = match self.client.send(method, path, &headers, body.as_bytes()) {
            Ok(response) => response,
            Err(e) => panic!("{method} {path} failed: {e:?}"),
        };
        // A 204 has no body at all, which is not an error here.
        let text = response.body_text().unwrap_or("").trim();
        let value = if text.is_empty() {
            Value::Null
        } else {
            parse(text).unwrap_or_else(|e| panic!("body was not JSON ({e}): {text}"))
        };
        (response.status, value)
    }

    /// Initialise, create a user and log in. Returns (shares, session token).
    fn ready(&self) -> (Vec<String>, String) {
        let (status, body) = self.post("/v1/sys/init", None, r#"{"threshold":2,"shares":3}"#);
        assert_eq!(status, 200, "init failed: {body}");

        let shares: Vec<String> = body
            .get("shares")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let root = body
            .get("root_token")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();

        let (status, body) = self.post(
            "/v1/users",
            Some(&root),
            r#"{"email":"dev@example.com","password":"correct horse battery staple"}"#,
        );
        assert_eq!(status, 201, "creating the first user failed: {body}");

        let (status, body) = self.post(
            "/v1/auth/login",
            None,
            r#"{"email":"dev@example.com","password":"correct horse battery staple"}"#,
        );
        assert_eq!(status, 200, "login failed: {body}");
        let session = body
            .get("token")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();

        (shares, session)
    }

    /// A project with a dev environment, and a session token.
    fn with_project(&self) -> String {
        let (_, session) = self.ready();
        let (status, body) = self.post(
            "/v1/projects",
            Some(&session),
            r#"{"slug":"demo","name":"Demo"}"#,
        );
        assert_eq!(status, 201, "{body}");
        let (status, body) = self.post(
            "/v1/projects/demo/envs",
            Some(&session),
            r#"{"slug":"dev","name":"Development"}"#,
        );
        assert_eq!(status, 201, "{body}");
        session
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// --- system ---------------------------------------------------------------

#[test]
fn health_reports_a_fresh_server_as_sealed_and_uninitialised() {
    let api = Harness::start("health");

    let (status, body) = api.get("/v1/sys/health", None);

    assert_eq!(status, 200);
    assert_eq!(body.get("sealed").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.get("initialized").and_then(Value::as_bool),
        Some(false)
    );
    assert!(body.get("version").is_some());
}

#[test]
fn health_needs_no_token_but_everything_else_does() {
    let api = Harness::start("health-open");
    api.ready();

    assert_eq!(api.get("/v1/sys/health", None).0, 200);
    assert_eq!(api.get("/v1/projects", None).0, 401);
}

#[test]
fn initialising_returns_the_shares_once_and_refuses_a_second_time() {
    let api = Harness::start("init");

    let (status, body) = api.post("/v1/sys/init", None, r#"{"threshold":2,"shares":3}"#);
    assert_eq!(status, 200);
    assert_eq!(
        body.get("shares").and_then(Value::as_array).unwrap().len(),
        3
    );

    let (status, _) = api.post("/v1/sys/init", None, r#"{"threshold":2,"shares":3}"#);
    assert_eq!(status, 409);
}

#[test]
fn sealing_then_unsealing_puts_the_server_back_in_service() {
    let api = Harness::start("seal-cycle");
    let (shares, session) = api.ready();

    assert_eq!(api.post("/v1/sys/seal", Some(&session), "").0, 200);
    assert_eq!(
        api.get("/v1/projects", Some(&session)).0,
        503,
        "a sealed server must refuse, not answer emptily"
    );

    let (status, body) = api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, shares[0]),
    );
    assert_eq!(status, 200);
    assert_eq!(body.get("sealed").and_then(Value::as_bool), Some(true));
    assert_eq!(body.get("progress").and_then(Value::as_i64), Some(1));

    let (status, body) = api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, shares[1]),
    );
    assert_eq!(status, 200);
    assert_eq!(body.get("sealed").and_then(Value::as_bool), Some(false));

    assert_eq!(api.get("/v1/projects", Some(&session)).0, 200);
}

#[test]
fn an_unseal_attempt_can_be_abandoned() {
    let api = Harness::start("unseal-reset");
    let (shares, session) = api.ready();
    api.post("/v1/sys/seal", Some(&session), "");
    api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, shares[0]),
    );

    let (status, _) = api.post("/v1/sys/unseal", None, r#"{"reset":true}"#);
    assert_eq!(status, 200);

    let (_, body) = api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, shares[1]),
    );
    assert_eq!(body.get("progress").and_then(Value::as_i64), Some(1));
}

#[test]
fn a_bad_share_is_a_bad_request() {
    let api = Harness::start("bad-share");
    let (_, session) = api.ready();
    api.post("/v1/sys/seal", Some(&session), "");

    let (status, _) = api.post("/v1/sys/unseal", None, r#"{"share":"not a share"}"#);
    assert_eq!(status, 400);
}

// --- users and sessions ---------------------------------------------------

#[test]
fn the_first_user_needs_the_root_token() {
    let api = Harness::start("first-user");
    let (_, body) = api.post("/v1/sys/init", None, r#"{"threshold":1,"shares":1}"#);
    let root = body
        .get("root_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let unauthenticated = api.post(
        "/v1/users",
        None,
        r#"{"email":"a@example.com","password":"a long enough password"}"#,
    );
    assert_eq!(unauthenticated.0, 401);

    let with_root = api.post(
        "/v1/users",
        Some(&root),
        r#"{"email":"a@example.com","password":"a long enough password"}"#,
    );
    assert_eq!(with_root.0, 201);
}

#[test]
fn login_returns_a_token_and_a_wrong_password_does_not() {
    let api = Harness::start("login");
    api.ready();

    let (status, body) = api.post(
        "/v1/auth/login",
        None,
        r#"{"email":"dev@example.com","password":"wrong password here"}"#,
    );

    assert_eq!(status, 401);
    assert!(body.get("token").is_none());
}

#[test]
fn logging_out_stops_the_token_working() {
    let api = Harness::start("logout");
    let (_, session) = api.ready();

    assert_eq!(api.post("/v1/auth/logout", Some(&session), "").0, 200);
    assert_eq!(api.get("/v1/projects", Some(&session)).0, 401);
}

#[test]
fn repeated_failed_logins_are_slowed_down() {
    let api = Harness::start("rate-limit");
    api.ready();

    let attempt = || {
        api.post(
            "/v1/auth/login",
            None,
            r#"{"email":"dev@example.com","password":"wrong password here"}"#,
        )
        .0
    };

    let mut saw_limit = false;
    for _ in 0..12 {
        if attempt() == 429 {
            saw_limit = true;
            break;
        }
    }

    assert!(saw_limit, "a password can be guessed at without limit");
}

// --- projects, environments, secrets --------------------------------------

#[test]
fn a_project_and_environment_can_be_created_and_listed() {
    let api = Harness::start("projects");
    let session = api.with_project();

    let (status, body) = api.get("/v1/projects", Some(&session));
    assert_eq!(status, 200);
    assert_eq!(
        body.get("projects").and_then(Value::as_array).unwrap()[0]
            .as_str()
            .unwrap(),
        "demo"
    );

    let (status, body) = api.get("/v1/projects/demo/envs", Some(&session));
    assert_eq!(status, 200);
    assert_eq!(
        body.get("environments").and_then(Value::as_array).unwrap()[0]
            .as_str()
            .unwrap(),
        "dev"
    );
}

#[test]
fn a_duplicate_project_is_a_conflict() {
    let api = Harness::start("dup-project");
    let session = api.with_project();

    let (status, _) = api.post(
        "/v1/projects",
        Some(&session),
        r#"{"slug":"demo","name":"Again"}"#,
    );

    assert_eq!(status, 409);
}

#[test]
fn a_secret_can_be_written_read_listed_and_deleted() {
    let api = Harness::start("secrets");
    let session = api.with_project();

    let (status, _) = api.put(
        "/v1/projects/demo/envs/dev/secrets/DB_URL",
        Some(&session),
        r#"{"value":"postgres://user:pw@host/db"}"#,
    );
    assert_eq!(status, 204);

    let (status, body) = api.get("/v1/projects/demo/envs/dev/secrets/DB_URL", Some(&session));
    assert_eq!(status, 200);
    assert_eq!(
        body.get("value").and_then(Value::as_str),
        Some("postgres://user:pw@host/db")
    );

    let (status, body) = api.get("/v1/projects/demo/envs/dev/secrets", Some(&session));
    assert_eq!(status, 200);
    assert_eq!(
        body.get("secrets")
            .and_then(|s| s.get("DB_URL"))
            .and_then(Value::as_str),
        Some("postgres://user:pw@host/db")
    );

    assert_eq!(
        api.delete("/v1/projects/demo/envs/dev/secrets/DB_URL", Some(&session))
            .0,
        204
    );
    assert_eq!(
        api.get("/v1/projects/demo/envs/dev/secrets/DB_URL", Some(&session))
            .0,
        404
    );
}

#[test]
fn several_secrets_can_be_written_at_once() {
    let api = Harness::start("bulk");
    let session = api.with_project();

    let (status, _) = api.post(
        "/v1/projects/demo/envs/dev/secrets",
        Some(&session),
        r#"{"secrets":{"A":"one","B":"two"}}"#,
    );
    assert_eq!(status, 204);

    let (_, body) = api.get("/v1/projects/demo/envs/dev/secrets", Some(&session));
    let secrets = body.get("secrets").unwrap();
    assert_eq!(secrets.get("A").and_then(Value::as_str), Some("one"));
    assert_eq!(secrets.get("B").and_then(Value::as_str), Some("two"));
}

#[test]
fn a_value_with_awkward_characters_survives_the_round_trip() {
    let api = Harness::start("awkward");
    let session = api.with_project();

    let awkward = "line1\nline2\t\"quoted\" \\ backslash 日本語 😀";
    let body = Value::object([("value", Value::from(awkward))]).to_string();

    api.put(
        "/v1/projects/demo/envs/dev/secrets/ODD",
        Some(&session),
        &body,
    );

    let (_, got) = api.get("/v1/projects/demo/envs/dev/secrets/ODD", Some(&session));
    assert_eq!(got.get("value").and_then(Value::as_str), Some(awkward));
}

#[test]
fn an_unknown_project_environment_or_secret_is_not_found() {
    let api = Harness::start("missing");
    let session = api.with_project();

    assert_eq!(
        api.get("/v1/projects/nope/envs/dev/secrets", Some(&session))
            .0,
        404
    );
    assert_eq!(
        api.get("/v1/projects/demo/envs/nope/secrets", Some(&session))
            .0,
        404
    );
    assert_eq!(
        api.get("/v1/projects/demo/envs/dev/secrets/NOPE", Some(&session))
            .0,
        404
    );
}

// --- machine tokens --------------------------------------------------------

#[test]
fn a_machine_token_reads_its_own_environment_and_no_other() {
    let api = Harness::start("machine");
    let session = api.with_project();
    api.post(
        "/v1/projects/demo/envs",
        Some(&session),
        r#"{"slug":"prod","name":"Production"}"#,
    );
    api.put(
        "/v1/projects/demo/envs/dev/secrets/K",
        Some(&session),
        r#"{"value":"dev value"}"#,
    );
    api.put(
        "/v1/projects/demo/envs/prod/secrets/K",
        Some(&session),
        r#"{"value":"prod value"}"#,
    );

    let (status, body) = api.post(
        "/v1/tokens",
        Some(&session),
        r#"{"project":"demo","environment":"dev","label":"ci"}"#,
    );
    assert_eq!(status, 201, "{body}");
    let machine = body
        .get("token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let (status, body) = api.get("/v1/projects/demo/envs/dev/secrets/K", Some(&machine));
    assert_eq!(status, 200);
    assert_eq!(body.get("value").and_then(Value::as_str), Some("dev value"));

    assert_eq!(
        api.get("/v1/projects/demo/envs/prod/secrets/K", Some(&machine))
            .0,
        403,
        "a dev token reached production"
    );
}

#[test]
fn a_machine_token_can_be_revoked() {
    let api = Harness::start("revoke");
    let session = api.with_project();
    let (_, body) = api.post(
        "/v1/tokens",
        Some(&session),
        r#"{"project":"demo","environment":"dev","label":"ci"}"#,
    );
    let machine = body
        .get("token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let id = body.get("id").and_then(Value::as_str).unwrap().to_owned();

    assert_eq!(
        api.get("/v1/projects/demo/envs/dev/secrets", Some(&machine))
            .0,
        200
    );
    assert_eq!(
        api.delete(&format!("/v1/tokens/{id}"), Some(&session)).0,
        204
    );
    assert_eq!(
        api.get("/v1/projects/demo/envs/dev/secrets", Some(&machine))
            .0,
        401
    );
}

// --- audit and errors ------------------------------------------------------

#[test]
fn the_audit_trail_records_reads_and_writes_without_values() {
    let api = Harness::start("audit");
    let session = api.with_project();
    api.put(
        "/v1/projects/demo/envs/dev/secrets/DB_URL",
        Some(&session),
        r#"{"value":"postgres://secret"}"#,
    );
    api.get("/v1/projects/demo/envs/dev/secrets/DB_URL", Some(&session));

    let (status, body) = api.get("/v1/audit", Some(&session));

    assert_eq!(status, 200);
    let rendered = body.to_string();
    assert!(rendered.contains("secret.set"), "{rendered}");
    assert!(rendered.contains("secret.read"), "{rendered}");
    assert!(
        !rendered.contains("postgres://secret"),
        "a value reached the audit trail"
    );
}

#[test]
fn an_unknown_route_is_not_found() {
    let api = Harness::start("route");
    let (_, session) = api.ready();

    assert_eq!(api.get("/v1/nothing-here", Some(&session)).0, 404);
    assert_eq!(api.get("/", None).0, 404);
}

#[test]
fn the_wrong_method_on_a_known_route_is_refused() {
    let api = Harness::start("method");
    let (_, session) = api.ready();

    assert_eq!(api.delete("/v1/projects", Some(&session)).0, 405);
}

#[test]
fn a_body_that_is_not_json_is_a_bad_request() {
    let api = Harness::start("bad-json");
    let (_, session) = api.ready();

    assert_eq!(
        api.post("/v1/projects", Some(&session), "not json at all")
            .0,
        400
    );
    assert_eq!(
        api.post("/v1/projects", Some(&session), r#"{"name":"no slug"}"#)
            .0,
        400
    );
}

#[test]
fn an_error_body_never_carries_a_secret_value() {
    let api = Harness::start("error-body");
    let session = api.with_project();
    api.put(
        "/v1/projects/demo/envs/dev/secrets/K",
        Some(&session),
        r#"{"value":"do-not-echo-me"}"#,
    );

    let (status, body) = api.put(
        "/v1/projects/demo/envs/dev/secrets/bad key",
        Some(&session),
        r#"{"value":"do-not-echo-me"}"#,
    );

    assert!(status >= 400);
    assert!(!body.to_string().contains("do-not-echo-me"), "{body}");
}

// --- a machine token must not be able to grow into an account ---------------

/// A project with a dev environment and a machine token scoped to it.
fn machine_token(api: &Harness) -> String {
    let session = api.with_project();
    let (status, body) = api.post(
        "/v1/tokens",
        Some(&session),
        r#"{"project":"demo","environment":"dev","label":"ci"}"#,
    );
    assert_eq!(status, 201, "{body}");
    body.get("token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

#[test]
fn a_machine_token_cannot_create_an_account() {
    // This is the escalation that matters: an account is unconfined, so a
    // machine token that can make one owns every project.
    let api = Harness::start("machine-no-user");
    let machine = machine_token(&api);

    let (status, _) = api.post(
        "/v1/users",
        Some(&machine),
        r#"{"email":"attacker@example.com","password":"a long enough password"}"#,
    );

    assert_eq!(status, 403);
}

#[test]
fn a_machine_token_cannot_create_projects_or_environments() {
    let api = Harness::start("machine-no-projects");
    let machine = machine_token(&api);

    assert_eq!(
        api.post(
            "/v1/projects",
            Some(&machine),
            r#"{"slug":"mine","name":"Mine"}"#
        )
        .0,
        403
    );
    assert_eq!(
        api.post(
            "/v1/projects/demo/envs",
            Some(&machine),
            r#"{"slug":"prod","name":"Production"}"#
        )
        .0,
        403
    );
}

#[test]
fn a_machine_token_cannot_list_projects_or_read_the_audit_trail() {
    let api = Harness::start("machine-no-listing");
    let machine = machine_token(&api);

    assert_eq!(api.get("/v1/projects", Some(&machine)).0, 403);
    assert_eq!(api.get("/v1/audit", Some(&machine)).0, 403);
}

#[test]
fn a_machine_token_cannot_mint_another_token() {
    let api = Harness::start("machine-no-minting");
    let machine = machine_token(&api);

    let (status, _) = api.post(
        "/v1/tokens",
        Some(&machine),
        r#"{"project":"demo","environment":"dev","label":"copy"}"#,
    );

    assert_eq!(status, 403);
}

#[test]
fn a_machine_token_cannot_seal_the_server() {
    let api = Harness::start("machine-no-seal");
    let machine = machine_token(&api);

    assert_eq!(api.post("/v1/sys/seal", Some(&machine), "").0, 403);
    assert_eq!(api.get("/v1/sys/health", None).0, 200);
}

#[test]
fn a_machine_token_reads_but_cannot_write_or_delete() {
    let api = Harness::start("machine-read-only");
    let machine = machine_token(&api);

    assert_eq!(
        api.get("/v1/projects/demo/envs/dev/secrets", Some(&machine))
            .0,
        200
    );
    assert_eq!(
        api.put(
            "/v1/projects/demo/envs/dev/secrets/K",
            Some(&machine),
            r#"{"value":"changed"}"#
        )
        .0,
        403
    );
    assert_eq!(
        api.delete("/v1/projects/demo/envs/dev/secrets/K", Some(&machine))
            .0,
        403
    );
}

#[test]
fn the_root_token_is_spent_by_creating_the_first_account() {
    let api = Harness::start("root-spent");
    let (_, body) = api.post("/v1/sys/init", None, r#"{"threshold":1,"shares":1}"#);
    let root = body
        .get("root_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    assert_eq!(
        api.post(
            "/v1/users",
            Some(&root),
            r#"{"email":"first@example.com","password":"a long enough password"}"#
        )
        .0,
        201
    );

    assert_eq!(
        api.post(
            "/v1/users",
            Some(&root),
            r#"{"email":"second@example.com","password":"a long enough password"}"#
        )
        .0,
        401,
        "the root token should not work a second time"
    );
}

#[test]
fn the_root_token_cannot_do_anything_but_create_the_first_account() {
    let api = Harness::start("root-narrow");
    let (_, body) = api.post("/v1/sys/init", None, r#"{"threshold":1,"shares":1}"#);
    let root = body
        .get("root_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    assert_eq!(
        api.post(
            "/v1/projects",
            Some(&root),
            r#"{"slug":"demo","name":"Demo"}"#
        )
        .0,
        403
    );
    assert_eq!(api.get("/v1/audit", Some(&root)).0, 403);
}

// --- re-splitting the shares over the API ----------------------------------

#[test]
fn the_shares_can_be_re_split_and_the_old_ones_stop_working() {
    let api = Harness::start("rekey");
    let (old, session) = api.ready();

    let (status, body) = api.post(
        "/v1/sys/rekey",
        Some(&session),
        r#"{"threshold":2,"shares":4}"#,
    );
    assert_eq!(status, 200, "{body}");
    let fresh: Vec<String> = body
        .get("shares")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(fresh.len(), 4);

    api.post("/v1/sys/seal", Some(&session), "");

    api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, old[0]),
    );
    let (status, _) = api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, old[1]),
    );
    assert_eq!(status, 400, "an old share should no longer be a quorum");

    api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, fresh[0]),
    );
    let (_, body) = api.post(
        "/v1/sys/unseal",
        None,
        &format!(r#"{{"share":"{}"}}"#, fresh[1]),
    );
    assert_eq!(body.get("sealed").and_then(Value::as_bool), Some(false));
}

#[test]
fn re_splitting_needs_a_session_and_an_unsealed_vault() {
    let api = Harness::start("rekey-auth");
    let session = api.with_project();
    let (_, body) = api.post(
        "/v1/tokens",
        Some(&session),
        r#"{"project":"demo","environment":"dev","label":"ci"}"#,
    );
    let machine = body
        .get("token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    assert_eq!(
        api.post(
            "/v1/sys/rekey",
            Some(&machine),
            r#"{"threshold":1,"shares":1}"#
        )
        .0,
        403
    );
    assert_eq!(
        api.post("/v1/sys/rekey", None, r#"{"threshold":1,"shares":1}"#)
            .0,
        401
    );

    api.post("/v1/sys/seal", Some(&session), "");
    assert_eq!(
        api.post(
            "/v1/sys/rekey",
            Some(&session),
            r#"{"threshold":1,"shares":1}"#
        )
        .0,
        503
    );
}

#[test]
fn a_re_split_never_returns_a_root_token() {
    // Only init mints one, and it is spent on the first account. Handing one
    // back here would quietly restore an unconfined credential.
    let api = Harness::start("rekey-no-root");
    let (_, session) = api.ready();

    let (_, body) = api.post(
        "/v1/sys/rekey",
        Some(&session),
        r#"{"threshold":1,"shares":1}"#,
    );

    assert!(body.get("root_token").is_none(), "{body}");
}
