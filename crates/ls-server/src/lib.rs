//! The localsecrets server.
//!
//! [`Vault`] holds the rules: seal state, the key hierarchy, and every
//! operation on secrets. The HTTP layer above it only translates requests into
//! calls and results into responses.

#![warn(missing_docs)]

mod api;
mod barrier;
mod rate_limit;
mod validate;
mod vault;

pub use api::handler;

pub use vault::{
    AuditEntry, Caller, InitOutcome, RevealedSecret, UnsealStatus, Vault, VaultError,
};
