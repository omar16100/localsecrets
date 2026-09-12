//! The localsecrets store: one append-only file.
//!
//! Every change is a record appended to the end and flushed to disk. State is
//! whatever you get by replaying the file from the start. There is no database
//! engine, no in-place update, and nothing to corrupt halfway: a crash during
//! an append leaves a partial record at the tail, which is discarded on the
//! next open.
//!
//! Records are sealed with the root key and bound to their position in the
//! file, so a record cannot be edited, replayed or reordered without the
//! replay failing. The one exception is the barrier record, which holds the
//! root key wrapped by the master key and therefore has to be readable before
//! there is any key to read with.

#![warn(missing_docs)]

mod event;
mod log;
mod state;

pub use StoreError as Error;
pub use event::{Event, Sealed, TokenKind};
pub use log::{Log, Record};
pub use state::{Environment, Project, Secret, State, Token, User};

/// Bytes of file header: magic plus a format version.
pub const HEADER_LEN: usize = 8;

/// Largest single record. A record holds one event, not a file.
pub const MAX_RECORD_LEN: usize = 1024 * 1024;

/// Why the store could not be read or written.
#[derive(Debug)]
pub enum StoreError {
    /// The file does not start with the localsecrets magic.
    NotALog,
    /// The file was written by a format version this build does not know.
    UnsupportedVersion(u8),
    /// A record failed authentication: the wrong key, an edit, or a record
    /// moved to another position.
    Unreadable {
        /// Which record, counting from zero.
        sequence: usize,
    },
    /// The record is larger than [`MAX_RECORD_LEN`].
    RecordTooLarge {
        /// Length offered.
        len: usize,
        /// Largest length accepted.
        limit: usize,
    },
    /// Encryption failed, which in practice means the system ran out of entropy.
    Crypto,
    /// A record did not hold an event this build understands.
    MalformedEvent(&'static str),
    /// An earlier append failed partway, so the log cannot be written to again
    /// until it is reopened and rescanned.
    Broken,
    /// A record frame is structurally impossible, which means the file was
    /// edited. An interrupted write cannot produce this.
    Corrupt {
        /// Byte offset of the frame.
        at: u64,
        /// What was wrong with it.
        why: &'static str,
    },
    /// The underlying file failed.
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotALog => f.write_str("not a localsecrets log"),
            Self::UnsupportedVersion(v) => {
                write!(f, "log format version {v} is newer than this build")
            }
            Self::Unreadable { sequence } => {
                write!(f, "record {sequence} could not be authenticated")
            }
            Self::RecordTooLarge { len, limit } => {
                write!(f, "record of {len} bytes exceeds the limit of {limit}")
            }
            Self::Crypto => f.write_str("could not encrypt a record"),
            Self::MalformedEvent(what) => write!(f, "record is not a usable event: {what}"),
            Self::Broken => f.write_str("an earlier write failed; the store must be reopened"),
            Self::Corrupt { at, why } => write!(f, "the store is damaged at byte {at}: {why}"),
            Self::Io(e) => write!(f, "store file failed: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
