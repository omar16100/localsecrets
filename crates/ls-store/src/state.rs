//! The current state, which is whatever you get by folding the log.
//!
//! Nothing here holds a plaintext secret. Values are ciphertext, passwords are
//! argon2 hashes and tokens are SHA-256 hashes, so building this state does not
//! require the root key. Reading a value does.

use crate::{Event, Sealed, TokenKind};
use ls_core::time::Timestamp;

/// A user account.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    /// Identifier.
    pub id: String,
    /// Lowercased email address.
    pub email: String,
    /// argon2id PHC string.
    pub password_hash: String,
    /// When the account was created.
    pub created_at: Timestamp,
}

/// An issued token.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// Identifier.
    pub id: String,
    /// SHA-256 of the token itself.
    pub token_hash: Vec<u8>,
    /// What the token stands for.
    pub kind: TokenKind,
    /// The user, for a session token.
    pub user_id: Option<String>,
    /// The project, for a machine token.
    pub project_id: Option<String>,
    /// The environment, for a machine token.
    pub environment_id: Option<String>,
    /// A name to recognise it by.
    pub label: Option<String>,
    /// When it stops working, if ever.
    pub expires_at: Option<Timestamp>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<Timestamp>,
    /// When it was issued.
    pub created_at: Timestamp,
}

impl Token {
    /// Whether this token works at the given moment.
    ///
    /// Revocation is absolute: a revoked token has never been valid since, and
    /// asking about an earlier moment does not bring it back.
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        match self.expires_at {
            Some(expiry) => now < expiry,
            None => true,
        }
    }
}

/// A project.
#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    /// Identifier.
    pub id: String,
    /// Short name used in paths.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// The project data key, wrapped by the root key.
    pub data_key: Sealed,
    /// When it was created.
    pub created_at: Timestamp,
}

/// An environment inside a project.
#[derive(Debug, Clone, PartialEq)]
pub struct Environment {
    /// Identifier.
    pub id: String,
    /// Owning project.
    pub project_id: String,
    /// Short name used in paths.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// When it was created.
    pub created_at: Timestamp,
}

/// A stored secret. The value is ciphertext.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    /// Owning project.
    pub project_id: String,
    /// Owning environment.
    pub environment_id: String,
    /// The key.
    pub key: String,
    /// The value, sealed under the project data key.
    pub value: Sealed,
    /// When it was last written.
    pub updated_at: Timestamp,
}

/// Everything the server knows, rebuilt from the log at startup.
#[derive(Debug, Default)]
pub struct State {
    /// Accounts, in creation order.
    pub users: Vec<User>,
    /// Tokens, in issue order.
    pub tokens: Vec<Token>,
    /// Projects, in creation order.
    pub projects: Vec<Project>,
    /// Environments, in creation order.
    pub environments: Vec<Environment>,
    /// Secrets, one entry per slot.
    pub secrets: Vec<Secret>,
}

impl State {
    /// Fold one event in.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::UserCreated {
                id,
                email,
                password_hash,
                created_at,
            } => self.users.push(User {
                id,
                email,
                password_hash,
                created_at,
            }),

            Event::TokenIssued {
                id,
                token_hash,
                kind,
                user_id,
                project_id,
                environment_id,
                label,
                expires_at,
                created_at,
            } => self.tokens.push(Token {
                id,
                token_hash,
                kind,
                user_id,
                project_id,
                environment_id,
                label,
                expires_at,
                revoked_at: None,
                created_at,
            }),

            Event::TokenRevoked { id, at } => {
                if let Some(token) = self.tokens.iter_mut().find(|t| t.id == id) {
                    token.revoked_at = Some(at);
                }
            }

            Event::ProjectCreated {
                id,
                slug,
                name,
                data_key,
                created_at,
            } => self.projects.push(Project {
                id,
                slug,
                name,
                data_key,
                created_at,
            }),

            Event::EnvironmentCreated {
                id,
                project_id,
                slug,
                name,
                created_at,
            } => self.environments.push(Environment {
                id,
                project_id,
                slug,
                name,
                created_at,
            }),

            Event::SecretSet {
                project_id,
                environment_id,
                key,
                value,
                at,
            } => {
                match self.secrets.iter_mut().find(|s| {
                    s.project_id == project_id && s.environment_id == environment_id && s.key == key
                }) {
                    Some(existing) => {
                        existing.value = value;
                        existing.updated_at = at;
                    }
                    None => self.secrets.push(Secret {
                        project_id,
                        environment_id,
                        key,
                        value,
                        updated_at: at,
                    }),
                }
            }

            Event::SecretDeleted {
                project_id,
                environment_id,
                key,
                ..
            } => self.secrets.retain(|s| {
                !(s.project_id == project_id && s.environment_id == environment_id && s.key == key)
            }),

            // The log is the audit record. Keeping every entry in memory as
            // well would grow without bound and buy nothing.
            Event::Audited { .. } => {}
        }
    }

    /// Find a user by email, ignoring case and surrounding space.
    pub fn user_by_email(&self, email: &str) -> Option<&User> {
        let wanted = email.trim().to_ascii_lowercase();
        self.users.iter().find(|user| user.email == wanted)
    }

    /// Find a user by identifier.
    pub fn user(&self, id: &str) -> Option<&User> {
        self.users.iter().find(|user| user.id == id)
    }

    /// Find a token by the hash of the presented secret.
    pub fn token_by_hash(&self, hash: &[u8]) -> Option<&Token> {
        self.tokens.iter().find(|token| token.token_hash == hash)
    }

    /// Find a token by identifier.
    pub fn token(&self, id: &str) -> Option<&Token> {
        self.tokens.iter().find(|token| token.id == id)
    }

    /// Find a project by its slug.
    pub fn project_by_slug(&self, slug: &str) -> Option<&Project> {
        self.projects.iter().find(|project| project.slug == slug)
    }

    /// Find a project by identifier.
    pub fn project(&self, id: &str) -> Option<&Project> {
        self.projects.iter().find(|project| project.id == id)
    }

    /// Find an environment by slug within one project.
    pub fn environment_by_slug(&self, project_id: &str, slug: &str) -> Option<&Environment> {
        self.environments
            .iter()
            .find(|env| env.project_id == project_id && env.slug == slug)
    }

    /// Every environment of a project, in creation order.
    pub fn environments_in(&self, project_id: &str) -> Vec<&Environment> {
        self.environments
            .iter()
            .filter(|env| env.project_id == project_id)
            .collect()
    }

    /// The secret at one slot.
    pub fn secret(&self, project_id: &str, environment_id: &str, key: &str) -> Option<&Secret> {
        self.secrets.iter().find(|secret| {
            secret.project_id == project_id
                && secret.environment_id == environment_id
                && secret.key == key
        })
    }

    /// Every secret in one environment, sorted by key so listings are stable.
    pub fn secrets_in(&self, project_id: &str, environment_id: &str) -> Vec<&Secret> {
        let mut found: Vec<&Secret> = self
            .secrets
            .iter()
            .filter(|secret| {
                secret.project_id == project_id && secret.environment_id == environment_id
            })
            .collect();
        found.sort_by(|a, b| a.key.cmp(&b.key));
        found
    }
}
