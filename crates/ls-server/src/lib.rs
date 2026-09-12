//! The localsecrets server.
//!
//! [`Vault`] holds the rules: seal state, the key hierarchy, and every
//! operation on secrets. The HTTP layer above it only translates requests into
//! calls and results into responses.

#![warn(missing_docs)]

mod barrier;
mod validate;
mod vault;

pub use vault::{
    AuditEntry, Caller, InitOutcome, RevealedSecret, UnsealStatus, Vault, VaultError,
};
