//! localsecrets core: crypto primitives, encodings and domain types. No I/O.

#![warn(missing_docs)]

pub mod crypto;
pub mod encoding;
pub mod random;

/// Crate version, surfaced by the server health endpoint.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
