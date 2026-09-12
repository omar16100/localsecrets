//! The HTTP layer: routing, request bodies, status codes.
//!
//! It holds no rules of its own. Every decision about what is allowed belongs
//! to [`Vault`]; this translates a request into a call and a result into a
//! response.

use crate::rate_limit::RateLimiter;
use crate::{Caller, Vault, VaultError};
use ls_http::{Request, Response};
use ls_json::{Value, parse};
use std::sync::{Arc, Mutex};

/// How long a session lasts.
const SESSION_SECONDS: i64 = 12 * 3600;

/// Unseal and init attempts allowed per minute, across all callers.
///
/// These endpoints cannot require a token, because the whole point of them is
/// to reach a vault that cannot yet authenticate anyone. Anything that can
/// reach the port can therefore feed the ceremony well-formed rubbish: share
/// checksums are unkeyed, so forging one is easy, and enough of them push the
/// attempt past its threshold, fail the recombination, and clear the progress
/// the operator had built up. A generous ceiling leaves a real ceremony
/// untouched and stops that being free.
const CEREMONY_BUDGET: u32 = 60;

/// Shared server state.
struct Api {
    vault: Arc<Mutex<Vault>>,
    logins: Mutex<RateLimiter>,
    ceremonies: Mutex<RateLimiter>,
}

/// Build the request handler.
pub fn handler(vault: Arc<Mutex<Vault>>) -> impl Fn(Request) -> Response + Send + Sync + 'static {
    let api = Arc::new(Api {
        vault,
        logins: Mutex::new(RateLimiter::default()),
        ceremonies: Mutex::new(RateLimiter::with_budget(CEREMONY_BUDGET)),
    });

    move |request| {
        let path = request.path.clone();
        let method = request.method.clone();
        let response = api.route(&request);

        ls_log::info!(
            "request",
            method = method,
            path = path,
            status = response.status
        );
        response
    }
}

impl Api {
    fn route(&self, request: &Request) -> Response {
        let segments: Vec<&str> = request
            .path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        let method = request.method.as_str();

        if let Some(refusal) = refuse_cross_origin(request) {
            return refusal;
        }

        match segments.as_slice() {
            ["v1", "sys", "health"] => self.only(method, "GET", || self.health()),
            ["v1", "sys", "init"] => self.only(method, "POST", || self.init(request)),
            ["v1", "sys", "unseal"] => self.only(method, "POST", || self.unseal(request)),
            ["v1", "sys", "rekey"] => self.only(method, "POST", || self.rekey(request)),
            ["v1", "sys", "seal"] => self.only(method, "POST", || {
                self.authed(request, |caller, vault| {
                    vault.seal_as(&caller)?;
                    Ok(Response::json(200, r#"{"sealed":true}"#))
                })
            }),

            ["v1", "users"] => self.only(method, "POST", || self.create_user(request)),
            ["v1", "auth", "login"] => self.only(method, "POST", || self.login(request)),
            ["v1", "auth", "logout"] => self.only(method, "POST", || {
                self.authed(request, |caller, vault| {
                    vault.revoke_token(&caller, &caller.token_id)?;
                    Ok(Response::json(200, r#"{"ok":true}"#))
                })
            }),

            ["v1", "audit"] => self.only(method, "GET", || self.audit(request)),

            ["v1", "tokens"] => self.only(method, "POST", || self.issue_token(request)),
            ["v1", "tokens", id] => self.only(method, "DELETE", || {
                self.authed(request, |caller, vault| {
                    vault.revoke_token(&caller, id)?;
                    Ok(Response::new(204, Vec::new()))
                })
            }),

            ["v1", "projects"] => match method {
                "GET" => self.authed(request, |caller, vault| {
                    let slugs: Vec<Value> = vault
                        .project_slugs(&caller)?
                        .into_iter()
                        .map(Value::from)
                        .collect();
                    Ok(Response::json(
                        200,
                        &Value::object([("projects", Value::Array(slugs))]).to_string(),
                    ))
                }),
                "POST" => self.create_project(request),
                _ => method_not_allowed(),
            },

            ["v1", "projects", project, "envs"] => match method {
                "GET" => self.authed(request, |caller, vault| {
                    let slugs: Vec<Value> = vault
                        .environment_slugs(&caller, project)?
                        .into_iter()
                        .map(Value::from)
                        .collect();
                    Ok(Response::json(
                        200,
                        &Value::object([("environments", Value::Array(slugs))]).to_string(),
                    ))
                }),
                "POST" => self.create_environment(request, project),
                _ => method_not_allowed(),
            },

            ["v1", "projects", project, "envs", environment, "secrets"] => match method {
                "GET" => self.list_secrets(request, project, environment),
                "POST" => self.set_many(request, project, environment),
                _ => method_not_allowed(),
            },

            [
                "v1",
                "projects",
                project,
                "envs",
                environment,
                "secrets",
                key,
            ] => match method {
                "GET" => self.get_secret(request, project, environment, key),
                "PUT" => self.put_secret(request, project, environment, key),
                "DELETE" => self.authed(request, |caller, vault| {
                    vault.delete_secret(&caller, project, environment, key)?;
                    Ok(Response::new(204, Vec::new()))
                }),
                _ => method_not_allowed(),
            },

            _ => error_response(404, "not found"),
        }
    }

    // --- system ------------------------------------------------------------

    fn health(&self) -> Response {
        let vault = self.lock();
        Response::json(
            200,
            &Value::object([
                ("sealed", Value::Bool(vault.is_sealed())),
                ("initialized", Value::Bool(vault.is_initialized())),
                ("version", Value::from(ls_core::VERSION)),
            ])
            .to_string(),
        )
    }

    /// Both unauthenticated system endpoints share one budget.
    fn ceremony_allowed(&self) -> bool {
        Self::guard(&self.ceremonies).allow("sys")
    }

    fn init(&self, request: &Request) -> Response {
        if !self.ceremony_allowed() {
            ls_log::warn!("init rate limited");
            return error_response(429, "too many attempts, try again shortly");
        }

        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };

        let (threshold, shares) = match share_parameters(&body) {
            Ok(pair) => pair,
            Err(response) => return response,
        };

        let mut vault = self.lock();
        match vault.init(threshold, shares) {
            Ok(outcome) => {
                ls_log::info!("vault initialised", threshold = threshold, shares = shares);
                let shares: Vec<Value> = outcome
                    .shares
                    .iter()
                    .map(|share| Value::from(share.as_str()))
                    .collect();
                Response::json(
                    200,
                    &Value::object([
                        ("shares", Value::Array(shares)),
                        ("threshold", Value::Int(i64::from(outcome.threshold))),
                        ("root_token", Value::from(outcome.root_token.as_str())),
                    ])
                    .to_string(),
                )
            }
            Err(error) => vault_error(&error),
        }
    }

    fn rekey(&self, request: &Request) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (threshold, shares) = match share_parameters(&body) {
            Ok(pair) => pair,
            Err(response) => return response,
        };

        self.authed(request, |caller, vault| {
            let outcome = vault.rekey(&caller, threshold, shares)?;
            ls_log::info!(
                "unseal shares re-split",
                threshold = threshold,
                shares = shares
            );

            let listed: Vec<Value> = outcome
                .shares
                .iter()
                .map(|share| Value::from(share.as_str()))
                .collect();
            Ok(Response::json(
                200,
                &Value::object([
                    ("shares", Value::Array(listed)),
                    ("threshold", Value::Int(i64::from(outcome.threshold))),
                ])
                .to_string(),
            ))
        })
    }

    fn unseal(&self, request: &Request) -> Response {
        if !self.ceremony_allowed() {
            ls_log::warn!("unseal rate limited");
            return error_response(429, "too many attempts, try again shortly");
        }

        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };

        let mut vault = self.lock();

        if body.get("reset").and_then(Value::as_bool) == Some(true) {
            vault.reset_unseal();
            let threshold = vault.threshold().unwrap_or(0);
            return Response::json(
                200,
                &unseal_body(vault.is_sealed(), 0, threshold).to_string(),
            );
        }

        let Some(share) = body.get("share").and_then(Value::as_str) else {
            return error_response(400, "a share is required");
        };

        match vault.submit_share(share) {
            Ok(status) => {
                ls_log::info!(
                    "unseal share accepted",
                    progress = status.progress,
                    sealed = status.sealed
                );
                Response::json(
                    200,
                    &unseal_body(status.sealed, status.progress, status.threshold).to_string(),
                )
            }
            Err(error) => {
                ls_log::warn!("unseal attempt failed", reason = error.to_string());
                vault_error(&error)
            }
        }
    }

    // --- users and sessions ------------------------------------------------

    fn create_user(&self, request: &Request) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(email), Some(password)) = (text(&body, "email"), text(&body, "password")) else {
            return error_response(400, "email and password are required");
        };

        self.authed(request, |caller, vault| {
            let id = vault.create_user(&caller, &email, &password)?;
            ls_log::info!("user created", id = id);
            Ok(Response::json(
                201,
                &Value::object([("id", Value::from(id))]).to_string(),
            ))
        })
    }

    fn login(&self, request: &Request) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(email), Some(password)) = (text(&body, "email"), text(&body, "password")) else {
            return error_response(400, "email and password are required");
        };

        // Rate limit before touching the vault, so guessing costs the attacker
        // rather than the server.
        // Taking the value out of a poisoned lock rather than giving up on it:
        // the limiter has no invariant spanning two operations, and the
        // alternative is that one panic disables the only control standing
        // between a password and an unlimited number of guesses.
        if !Self::guard(&self.logins).allow(&email) {
            ls_log::warn!("login rate limited", email = email);
            return error_response(429, "too many attempts, try again shortly");
        }

        let mut vault = self.lock();
        match vault.login(&email, &password, SESSION_SECONDS) {
            Ok(token) => {
                Self::guard(&self.logins).succeeded(&email);
                ls_log::info!("login", email = email, outcome = "ok");
                Response::json(
                    200,
                    &Value::object([("token", Value::from(token.as_str()))]).to_string(),
                )
            }
            Err(error) => {
                ls_log::warn!("login", email = email, outcome = "refused");
                vault_error(&error)
            }
        }
    }

    fn issue_token(&self, request: &Request) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(project), Some(environment)) =
            (text(&body, "project"), text(&body, "environment"))
        else {
            return error_response(400, "project and environment are required");
        };
        let label = text(&body, "label").unwrap_or_else(|| "machine".to_owned());
        let ttl = body.get("ttl_seconds").and_then(Value::as_i64);

        self.authed(request, |caller, vault| {
            let token = vault.issue_machine_token(&caller, &project, &environment, &label, ttl)?;
            let id = vault
                .authenticate(&token)
                .map(|caller| caller.token_id)
                .unwrap_or_default();

            ls_log::info!(
                "machine token issued",
                project = project,
                environment = environment,
                label = label
            );
            Ok(Response::json(
                201,
                &Value::object([
                    ("token", Value::from(token.as_str())),
                    ("id", Value::from(id)),
                ])
                .to_string(),
            ))
        })
    }

    // --- projects and environments -----------------------------------------

    fn create_project(&self, request: &Request) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(slug) = text(&body, "slug") else {
            return error_response(400, "a slug is required");
        };
        let name = text(&body, "name").unwrap_or_else(|| slug.clone());

        self.authed(request, |caller, vault| {
            let id = vault.create_project(&caller, &slug, &name)?;
            ls_log::info!("project created", slug = slug);
            Ok(Response::json(
                201,
                &Value::object([
                    ("id", Value::from(id)),
                    ("slug", Value::from(slug.as_str())),
                ])
                .to_string(),
            ))
        })
    }

    fn create_environment(&self, request: &Request, project: &str) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(slug) = text(&body, "slug") else {
            return error_response(400, "a slug is required");
        };
        let name = text(&body, "name").unwrap_or_else(|| slug.clone());

        self.authed(request, |caller, vault| {
            let id = vault.create_environment(&caller, project, &slug, &name)?;
            ls_log::info!("environment created", project = project, slug = slug);
            Ok(Response::json(
                201,
                &Value::object([
                    ("id", Value::from(id)),
                    ("slug", Value::from(slug.as_str())),
                ])
                .to_string(),
            ))
        })
    }

    // --- secrets -----------------------------------------------------------

    fn get_secret(
        &self,
        request: &Request,
        project: &str,
        environment: &str,
        key: &str,
    ) -> Response {
        self.authed(request, |caller, vault| {
            let value = vault.get_secret(&caller, project, environment, key)?;
            let text = String::from_utf8(value.to_vec())
                .map_err(|_| VaultError::Invalid("stored value is not text"))?;

            Ok(Response::json(
                200,
                &Value::object([("key", Value::from(key)), ("value", Value::from(text))])
                    .to_string(),
            ))
        })
    }

    fn put_secret(
        &self,
        request: &Request,
        project: &str,
        environment: &str,
        key: &str,
    ) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(value) = text(&body, "value") else {
            return error_response(400, "a value is required");
        };

        self.authed(request, |caller, vault| {
            vault.set_secret(&caller, project, environment, key, value.as_bytes())?;
            Ok(Response::new(204, Vec::new()))
        })
    }

    fn set_many(&self, request: &Request, project: &str, environment: &str) -> Response {
        let body = match body_of(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(Value::Object(pairs)) = body.get("secrets") else {
            return error_response(400, "secrets must be an object of key to value");
        };

        let mut entries = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            let Some(text) = value.as_str() else {
                return error_response(400, "every value must be text");
            };
            entries.push((key.clone(), text.to_owned()));
        }

        self.authed(request, |caller, vault| {
            // Everything is checked before anything is written, so a refusal
            // does not leave half the batch in place with no way to tell which
            // half.
            for (key, value) in &entries {
                vault.check_secret(&caller, project, environment, key, value.as_bytes())?;
            }
            for (key, value) in &entries {
                vault.set_secret(&caller, project, environment, key, value.as_bytes())?;
            }
            Ok(Response::new(204, Vec::new()))
        })
    }

    fn list_secrets(&self, request: &Request, project: &str, environment: &str) -> Response {
        self.authed(request, |caller, vault| {
            let secrets = vault.list_secrets(&caller, project, environment)?;

            let mut fields = Vec::with_capacity(secrets.len());
            for (key, value) in secrets {
                let text = String::from_utf8(value.to_vec())
                    .map_err(|_| VaultError::Invalid("stored value is not text"))?;
                fields.push((key, Value::from(text)));
            }

            Ok(Response::json(
                200,
                &Value::object([("secrets", Value::Object(fields))]).to_string(),
            ))
        })
    }

    fn audit(&self, request: &Request) -> Response {
        self.authed(request, |caller, vault| {
            let entries: Vec<Value> = vault
                .audit_trail(&caller)?
                .into_iter()
                .map(|entry| {
                    Value::object([
                        ("at", Value::from(entry.at.to_rfc3339())),
                        ("actor", Value::from(entry.actor)),
                        ("action", Value::from(entry.action)),
                        ("target", Value::from(entry.target)),
                        ("outcome", Value::from(entry.outcome)),
                    ])
                })
                .collect();

            Ok(Response::json(
                200,
                &Value::object([("entries", Value::Array(entries))]).to_string(),
            ))
        })
    }

    // --- plumbing ----------------------------------------------------------

    /// Take a lock, recovering it if a panic poisoned it.
    fn guard<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                lock.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vault> {
        let poisoned = self.vault.is_poisoned();
        let mut guard = Self::guard(&self.vault);

        if poisoned {
            // A handler panicked partway through an operation. Memory may now
            // disagree with the log: an event can be durable while the state
            // built from it is not, which would leave a revoked token working.
            // Sealing forces the next unseal to rebuild state from the file,
            // which is the only version that is certainly right.
            ls_log::error!("a request panicked mid-operation; sealing to force a rebuild");
            guard.seal();
        }

        guard
    }

    /// Resolve the bearer token, then run `work` with the caller and the vault.
    fn authed<F>(&self, request: &Request, work: F) -> Response
    where
        F: FnOnce(Caller, &mut Vault) -> Result<Response, VaultError>,
    {
        let mut vault = self.lock();

        if vault.is_sealed() {
            return error_response(503, "the vault is sealed");
        }

        let Some(token) = bearer(request) else {
            return error_response(401, "a bearer token is required");
        };
        let Some(caller) = vault.authenticate(token) else {
            return error_response(401, "that token is not usable");
        };

        match work(caller, &mut vault) {
            Ok(response) => response,
            Err(error) => vault_error(&error),
        }
    }

    fn only<F: FnOnce() -> Response>(&self, method: &str, expected: &str, work: F) -> Response {
        if method == expected {
            work()
        } else {
            method_not_allowed()
        }
    }
}

/// Refuse anything a page on another site could send us without asking first.
///
/// A browser will post to 127.0.0.1 from any website without a preflight, so
/// long as the request looks like something a form could produce. Requiring
/// `application/json` on every request that changes state forces the preflight,
/// which such a page cannot satisfy. This matters most for the endpoints that
/// need no token: without it, a visited page can call `init` on a fresh vault,
/// after which the operator can never initialise it and never saw the shares.
fn refuse_cross_origin(request: &Request) -> Option<Response> {
    if matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return None;
    }

    let json = request
        .header("content-type")
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);

    if json {
        None
    } else {
        Some(error_response(
            415,
            "this endpoint needs a content-type of application/json",
        ))
    }
}

fn unseal_body(sealed: bool, progress: usize, threshold: u8) -> Value {
    Value::object([
        ("sealed", Value::Bool(sealed)),
        ("progress", Value::from(progress)),
        ("threshold", Value::Int(i64::from(threshold))),
    ])
}

fn bearer(request: &Request) -> Option<&str> {
    request
        .header("authorization")?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Parse the body, treating an empty one as an empty object so handlers that
/// take no fields do not need a body at all.
fn body_of(request: &Request) -> Result<Value, Response> {
    if request.body.is_empty() {
        return Ok(Value::Object(Vec::new()));
    }
    let Some(text) = request.body_text() else {
        return Err(error_response(400, "body is not UTF-8"));
    };
    parse(text).map_err(|_| error_response(400, "body is not valid JSON"))
}

fn text(body: &Value, name: &str) -> Option<String> {
    body.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Read the threshold and share count.
///
/// Absent means the default. Present but unusable is an error: quietly falling
/// back to one share would, on a re-split, destroy an existing quorum because
/// of a typo.
fn share_parameters(body: &Value) -> Result<(u8, u8), Response> {
    let read = |name: &str| -> Result<u8, Response> {
        match body.get(name) {
            None | Some(Value::Null) => Ok(1),
            Some(Value::Int(n)) => u8::try_from(*n)
                .map_err(|_| error_response(400, "threshold and shares must be between 1 and 255")),
            Some(_) => Err(error_response(400, "threshold and shares must be numbers")),
        }
    };

    Ok((read("threshold")?, read("shares")?))
}

fn method_not_allowed() -> Response {
    error_response(405, "method not allowed")
}

/// Error bodies carry the reason and nothing else. In particular they never
/// echo a request body, which is where a secret value would be.
fn error_response(status: u16, message: &str) -> Response {
    Response::json(
        status,
        &Value::object([("error", Value::from(message))]).to_string(),
    )
}

fn vault_error(error: &VaultError) -> Response {
    let status = match error {
        VaultError::Sealed => 503,
        VaultError::AlreadyInitialized | VaultError::Conflict(_) => 409,
        VaultError::NotInitialized => 412,
        VaultError::BadCredentials => 401,
        VaultError::Forbidden => 403,
        VaultError::NotFound(_) => 404,
        VaultError::UnsealFailed | VaultError::BadShare | VaultError::Invalid(_) => 400,
        VaultError::ValueTooLarge { .. } => 413,
        VaultError::UnreadableBarrier(_)
        | VaultError::InitIncomplete
        | VaultError::Crypto
        | VaultError::Store(_) => 500,
    };

    if status >= 500 {
        ls_log::error!("request failed", reason = error.to_string());
    }
    error_response(status, &error.to_string())
}
