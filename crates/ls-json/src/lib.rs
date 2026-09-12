//! Minimal JSON for localsecrets: a value type, a strict parser and a renderer.
//!
//! Written on the standard library alone, like everything here that is not a
//! cryptographic primitive. Strictness is the point: bodies arriving over the
//! network are attacker controlled, so ambiguity is rejected rather than
//! guessed at, and recursion is bounded.

#![warn(missing_docs)]

mod parser;
mod value;

pub use parser::parse;
pub use value::Value;

/// Deepest nesting the parser accepts, so a hostile body cannot exhaust the stack.
pub const MAX_DEPTH: usize = 64;

/// Why a document could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// Input ended in the middle of a value.
    UnexpectedEnd,
    /// An unexpected byte, at this offset.
    Unexpected(usize),
    /// A complete value was followed by more text.
    TrailingContent,
    /// The same object key appeared twice, which different readers may resolve
    /// differently.
    DuplicateKey(String),
    /// Nesting exceeded [`MAX_DEPTH`].
    TooDeep,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("input ended unexpectedly"),
            Self::Unexpected(at) => write!(f, "unexpected character at byte {at}"),
            Self::TrailingContent => f.write_str("unexpected text after the value"),
            Self::DuplicateKey(key) => write!(f, "duplicate object key {key:?}"),
            Self::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
        }
    }
}

impl std::error::Error for JsonError {}
