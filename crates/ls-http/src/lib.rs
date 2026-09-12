//! A small blocking HTTP/1.1 server and client on the standard library.
//!
//! Only what this project needs, and strict about the rest. Requests arrive
//! from the network, so the parser refuses anything ambiguous rather than
//! guessing: two `Content-Length` headers, a `Transfer-Encoding` it will not
//! honour, folded header lines, bare newlines, or a head or body over its limit.

#![warn(missing_docs)]

mod client;
mod request;
mod response;
mod server;

pub use client::{Client, ClientResponse};
pub use request::Request;
pub use response::Response;
pub use server::{Server, ServerHandle};

/// Bounds applied to an incoming request, so one caller cannot exhaust memory
/// or hold a worker indefinitely.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest request line plus headers, in bytes.
    pub max_head: usize,
    /// Most headers accepted on one request.
    pub max_headers: usize,
    /// Largest body accepted, in bytes.
    pub max_body: usize,
    /// How long a whole request may take to arrive.
    ///
    /// A per-read timeout is not enough: a client sending one byte just inside
    /// it holds a worker for as long as it likes. This bounds the request as a
    /// whole, so a handful of slow clients cannot occupy the pool.
    pub head_deadline: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head: 8 * 1024,
            max_headers: 64,
            max_body: 1024 * 1024,
            head_deadline: std::time::Duration::from_secs(10),
        }
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum HttpError {
    /// The connection ended before a complete request arrived.
    Incomplete,
    /// The request did not arrive within [`Limits::head_deadline`].
    TimedOut,
    /// The request line or a header was not well formed.
    Malformed(&'static str),
    /// The HTTP version is not one this server speaks.
    UnsupportedVersion(String),
    /// More than one `Content-Length`, which is how request smuggling starts.
    AmbiguousLength,
    /// A `Transfer-Encoding` header. Chunked bodies are not supported, and
    /// accepting the header while ignoring it would be worse than refusing.
    UnsupportedTransferEncoding,
    /// The body was shorter than its declared length.
    IncompleteBody,
    /// The declared body exceeds [`Limits::max_body`].
    BodyTooLarge {
        /// Length declared by the caller.
        declared: usize,
        /// Largest length accepted.
        limit: usize,
    },
    /// The request line and headers exceed [`Limits::max_head`].
    HeadTooLarge,
    /// More headers than [`Limits::max_headers`].
    TooManyHeaders,
    /// The underlying connection failed.
    Io(std::io::Error),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("request ended early"),
            Self::TimedOut => f.write_str("request took too long to arrive"),
            Self::Malformed(what) => write!(f, "malformed request: {what}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported HTTP version {v}"),
            Self::AmbiguousLength => f.write_str("more than one Content-Length"),
            Self::UnsupportedTransferEncoding => f.write_str("Transfer-Encoding is not supported"),
            Self::IncompleteBody => f.write_str("body shorter than its declared length"),
            Self::BodyTooLarge { declared, limit } => {
                write!(f, "body of {declared} bytes exceeds the limit of {limit}")
            }
            Self::HeadTooLarge => f.write_str("request head too large"),
            Self::TooManyHeaders => f.write_str("too many headers"),
            Self::Io(e) => write!(f, "connection failed: {e}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl HttpError {
    /// The status code a server should answer with.
    pub fn status(&self) -> u16 {
        match self {
            Self::BodyTooLarge { .. } => 413,
            Self::HeadTooLarge | Self::TooManyHeaders => 431,
            Self::UnsupportedVersion(_) => 505,
            Self::UnsupportedTransferEncoding => 501,
            Self::TimedOut => 408,
            Self::Io(_) | Self::Incomplete => 400,
            _ => 400,
        }
    }
}
