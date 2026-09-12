//! The events written to the log, and how they are stored.
//!
//! One event per record, as JSON with a `type` tag. JSON because a log outlives
//! the binary that wrote it, and a format a person can read with `strings` is
//! worth more during an incident than a few saved bytes. Nothing sensitive is
//! readable in it: values arrive already sealed, passwords as argon2 hashes and
//! tokens as SHA-256 hashes.

use crate::StoreError;
use ls_core::crypto::aead::Envelope;
use ls_core::encoding::hex;
use ls_core::time::Timestamp;
use ls_json::{Value, parse};

/// A nonce and ciphertext pair on its way to or from the log.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The nonce it was sealed with.
    pub nonce: Vec<u8>,
    /// The ciphertext, with its authentication tag.
    pub ciphertext: Vec<u8>,
}

impl From<Envelope> for Sealed {
    fn from(envelope: Envelope) -> Self {
        Self {
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
        }
    }
}

impl From<&Sealed> for Envelope {
    fn from(sealed: &Sealed) -> Self {
        Self {
            nonce: sealed.nonce.clone(),
            ciphertext: sealed.ciphertext.clone(),
        }
    }
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealed({} bytes)", self.ciphertext.len())
    }
}

impl Sealed {
    fn to_value(&self) -> Value {
        Value::object([
            ("nonce", Value::from(hex::encode(&self.nonce))),
            ("ciphertext", Value::from(hex::encode(&self.ciphertext))),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, StoreError> {
        Ok(Self {
            nonce: bytes_field(value, "nonce")?,
            ciphertext: bytes_field(value, "ciphertext")?,
        })
    }
}

/// What kind of caller a token stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// The token minted by `init`, able to create the first user.
    Root,
    /// A person, after logging in.
    Session,
    /// A machine, scoped to one project and environment.
    Machine,
}

impl TokenKind {
    /// The name used in the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Session => "session",
            Self::Machine => "machine",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "root" => Some(Self::Root),
            "session" => Some(Self::Session),
            "machine" => Some(Self::Machine),
            _ => None,
        }
    }
}

/// Everything that can happen, as recorded.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A user account was created.
    UserCreated {
        /// Identifier.
        id: String,
        /// Lowercased email address.
        email: String,
        /// argon2id PHC string.
        password_hash: String,
        /// When.
        created_at: Timestamp,
    },
    /// A token was issued.
    TokenIssued {
        /// Identifier.
        id: String,
        /// SHA-256 of the token.
        token_hash: Vec<u8>,
        /// What the token stands for.
        kind: TokenKind,
        /// The user, for a session token.
        user_id: Option<String>,
        /// The project, for a machine token.
        project_id: Option<String>,
        /// The environment, for a machine token.
        environment_id: Option<String>,
        /// A name to recognise it by.
        label: Option<String>,
        /// When it stops working, if ever.
        expires_at: Option<Timestamp>,
        /// When.
        created_at: Timestamp,
    },
    /// A token was revoked.
    TokenRevoked {
        /// Which token.
        id: String,
        /// When.
        at: Timestamp,
    },
    /// A project was created.
    ProjectCreated {
        /// Identifier.
        id: String,
        /// Short name used in paths.
        slug: String,
        /// Display name.
        name: String,
        /// The project data key, wrapped by the root key.
        data_key: Sealed,
        /// When.
        created_at: Timestamp,
    },
    /// An environment was created inside a project.
    EnvironmentCreated {
        /// Identifier.
        id: String,
        /// Owning project.
        project_id: String,
        /// Short name used in paths.
        slug: String,
        /// Display name.
        name: String,
        /// When.
        created_at: Timestamp,
    },
    /// A secret was written, new or replacing an older value.
    SecretSet {
        /// Owning project.
        project_id: String,
        /// Owning environment.
        environment_id: String,
        /// The key.
        key: String,
        /// The value, sealed under the project data key.
        value: Sealed,
        /// When.
        at: Timestamp,
    },
    /// A secret was removed.
    SecretDeleted {
        /// Owning project.
        project_id: String,
        /// Owning environment.
        environment_id: String,
        /// The key.
        key: String,
        /// When.
        at: Timestamp,
    },
    /// Something happened that the operator may want to look back on. Never
    /// carries a secret value.
    Audited {
        /// When.
        at: Timestamp,
        /// Who, as an identifier.
        actor: String,
        /// What was attempted.
        action: String,
        /// What it was attempted on.
        target: String,
        /// How it went.
        outcome: String,
    },
}

impl Event {
    /// The `type` tag used in the log.
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::UserCreated { .. } => "user.created",
            Self::TokenIssued { .. } => "token.issued",
            Self::TokenRevoked { .. } => "token.revoked",
            Self::ProjectCreated { .. } => "project.created",
            Self::EnvironmentCreated { .. } => "environment.created",
            Self::SecretSet { .. } => "secret.set",
            Self::SecretDeleted { .. } => "secret.deleted",
            Self::Audited { .. } => "audit",
        }
    }

    /// Render for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_value().to_string().into_bytes()
    }

    /// Read back from storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let text = std::str::from_utf8(bytes).map_err(|_| StoreError::MalformedEvent("not UTF-8"))?;
        let value = parse(text).map_err(|_| StoreError::MalformedEvent("not JSON"))?;
        Self::from_value(&value)
    }

    fn to_value(&self) -> Value {
        let tag = ("type", Value::from(self.type_name()));
        match self {
            Self::UserCreated {
                id,
                email,
                password_hash,
                created_at,
            } => Value::object([
                tag,
                ("id", Value::from(id.as_str())),
                ("email", Value::from(email.as_str())),
                ("password_hash", Value::from(password_hash.as_str())),
                ("created_at", time_value(*created_at)),
            ]),
            Self::TokenIssued {
                id,
                token_hash,
                kind,
                user_id,
                project_id,
                environment_id,
                label,
                expires_at,
                created_at,
            } => Value::object([
                tag,
                ("id", Value::from(id.as_str())),
                ("token_hash", Value::from(hex::encode(token_hash))),
                ("kind", Value::from(kind.as_str())),
                ("user_id", optional_text(user_id)),
                ("project_id", optional_text(project_id)),
                ("environment_id", optional_text(environment_id)),
                ("label", optional_text(label)),
                ("expires_at", optional_time(*expires_at)),
                ("created_at", time_value(*created_at)),
            ]),
            Self::TokenRevoked { id, at } => Value::object([
                tag,
                ("id", Value::from(id.as_str())),
                ("at", time_value(*at)),
            ]),
            Self::ProjectCreated {
                id,
                slug,
                name,
                data_key,
                created_at,
            } => Value::object([
                tag,
                ("id", Value::from(id.as_str())),
                ("slug", Value::from(slug.as_str())),
                ("name", Value::from(name.as_str())),
                ("data_key", data_key.to_value()),
                ("created_at", time_value(*created_at)),
            ]),
            Self::EnvironmentCreated {
                id,
                project_id,
                slug,
                name,
                created_at,
            } => Value::object([
                tag,
                ("id", Value::from(id.as_str())),
                ("project_id", Value::from(project_id.as_str())),
                ("slug", Value::from(slug.as_str())),
                ("name", Value::from(name.as_str())),
                ("created_at", time_value(*created_at)),
            ]),
            Self::SecretSet {
                project_id,
                environment_id,
                key,
                value,
                at,
            } => Value::object([
                tag,
                ("project_id", Value::from(project_id.as_str())),
                ("environment_id", Value::from(environment_id.as_str())),
                ("key", Value::from(key.as_str())),
                ("value", value.to_value()),
                ("at", time_value(*at)),
            ]),
            Self::SecretDeleted {
                project_id,
                environment_id,
                key,
                at,
            } => Value::object([
                tag,
                ("project_id", Value::from(project_id.as_str())),
                ("environment_id", Value::from(environment_id.as_str())),
                ("key", Value::from(key.as_str())),
                ("at", time_value(*at)),
            ]),
            Self::Audited {
                at,
                actor,
                action,
                target,
                outcome,
            } => Value::object([
                tag,
                ("at", time_value(*at)),
                ("actor", Value::from(actor.as_str())),
                ("action", Value::from(action.as_str())),
                ("target", Value::from(target.as_str())),
                ("outcome", Value::from(outcome.as_str())),
            ]),
        }
    }

    fn from_value(value: &Value) -> Result<Self, StoreError> {
        let kind = text_field(value, "type")?;
        match kind.as_str() {
            "user.created" => Ok(Self::UserCreated {
                id: text_field(value, "id")?,
                email: text_field(value, "email")?,
                password_hash: text_field(value, "password_hash")?,
                created_at: time_field(value, "created_at")?,
            }),
            "token.issued" => Ok(Self::TokenIssued {
                id: text_field(value, "id")?,
                token_hash: bytes_field(value, "token_hash")?,
                kind: TokenKind::parse(&text_field(value, "kind")?)
                    .ok_or(StoreError::MalformedEvent("unknown token kind"))?,
                user_id: optional_text_field(value, "user_id")?,
                project_id: optional_text_field(value, "project_id")?,
                environment_id: optional_text_field(value, "environment_id")?,
                label: optional_text_field(value, "label")?,
                expires_at: optional_time_field(value, "expires_at")?,
                created_at: time_field(value, "created_at")?,
            }),
            "token.revoked" => Ok(Self::TokenRevoked {
                id: text_field(value, "id")?,
                at: time_field(value, "at")?,
            }),
            "project.created" => Ok(Self::ProjectCreated {
                id: text_field(value, "id")?,
                slug: text_field(value, "slug")?,
                name: text_field(value, "name")?,
                data_key: Sealed::from_value(
                    value
                        .get("data_key")
                        .ok_or(StoreError::MalformedEvent("missing data_key"))?,
                )?,
                created_at: time_field(value, "created_at")?,
            }),
            "environment.created" => Ok(Self::EnvironmentCreated {
                id: text_field(value, "id")?,
                project_id: text_field(value, "project_id")?,
                slug: text_field(value, "slug")?,
                name: text_field(value, "name")?,
                created_at: time_field(value, "created_at")?,
            }),
            "secret.set" => Ok(Self::SecretSet {
                project_id: text_field(value, "project_id")?,
                environment_id: text_field(value, "environment_id")?,
                key: text_field(value, "key")?,
                value: Sealed::from_value(
                    value
                        .get("value")
                        .ok_or(StoreError::MalformedEvent("missing value"))?,
                )?,
                at: time_field(value, "at")?,
            }),
            "secret.deleted" => Ok(Self::SecretDeleted {
                project_id: text_field(value, "project_id")?,
                environment_id: text_field(value, "environment_id")?,
                key: text_field(value, "key")?,
                at: time_field(value, "at")?,
            }),
            "audit" => Ok(Self::Audited {
                at: time_field(value, "at")?,
                actor: text_field(value, "actor")?,
                action: text_field(value, "action")?,
                target: text_field(value, "target")?,
                outcome: text_field(value, "outcome")?,
            }),
            // Refusing is the point: a build that quietly skipped an event it
            // did not understand would replay an old log into the wrong state.
            _ => Err(StoreError::MalformedEvent("unknown event type")),
        }
    }
}

fn time_value(at: Timestamp) -> Value {
    Value::from(at.to_rfc3339())
}

fn optional_text(text: &Option<String>) -> Value {
    match text {
        Some(text) => Value::from(text.as_str()),
        None => Value::Null,
    }
}

fn optional_time(at: Option<Timestamp>) -> Value {
    match at {
        Some(at) => time_value(at),
        None => Value::Null,
    }
}

fn text_field(value: &Value, name: &'static str) -> Result<String, StoreError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(StoreError::MalformedEvent(name))
}

fn optional_text_field(value: &Value, name: &'static str) -> Result<Option<String>, StoreError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(StoreError::MalformedEvent(name)),
    }
}

fn time_field(value: &Value, name: &'static str) -> Result<Timestamp, StoreError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(Timestamp::parse_rfc3339)
        .ok_or(StoreError::MalformedEvent(name))
}

fn optional_time_field(value: &Value, name: &'static str) -> Result<Option<Timestamp>, StoreError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Timestamp::parse_rfc3339(text)
            .map(Some)
            .ok_or(StoreError::MalformedEvent(name)),
        Some(_) => Err(StoreError::MalformedEvent(name)),
    }
}

fn bytes_field(value: &Value, name: &'static str) -> Result<Vec<u8>, StoreError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(hex::decode)
        .ok_or(StoreError::MalformedEvent(name))
}
