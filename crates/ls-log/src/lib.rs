//! Structured logging to standard error.
//!
//! One line per event: a timestamp, a level, a message, then `key=value`
//! fields. Values are escaped, so nothing that reaches a field can forge a
//! second record, which is the usual way a log stops being evidence.
//!
//! What never goes in a log here is a secret value. The logger cannot enforce
//! that; the call sites do, and the tests check it.

#![warn(missing_docs)]

use ls_core::time::Timestamp;
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

/// How much to log. Ordered from least to most verbose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Something failed that the operator needs to know about.
    Error,
    /// Something suspicious that did not stop the operation.
    Warn,
    /// Normal operation worth recording.
    Info,
    /// Detail for working out what happened.
    Debug,
}

impl Level {
    /// Fixed-width name, so lines stay in columns.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN ",
            Self::Info => "INFO ",
            Self::Debug => "DEBUG",
        }
    }

    /// Read a level from text, ignoring case.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(2);

/// Set the level directly.
pub fn set_level(level: Level) {
    LEVEL.store(level.as_u8(), Ordering::Relaxed);
}

/// Read the level from `LS_LOG`, defaulting to `info`.
pub fn init_from_env() {
    if let Ok(text) = std::env::var("LS_LOG")
        && let Some(level) = Level::parse(&text)
    {
        set_level(level);
    }
}

/// Whether a message at this level would be written.
pub fn enabled(level: Level) -> bool {
    level.as_u8() <= LEVEL.load(Ordering::Relaxed)
}

/// Build one log line. Public so its escaping can be tested directly.
pub fn format_line(
    at: Timestamp,
    level: Level,
    message: &str,
    fields: &[(&str, String)],
) -> String {
    let mut line = String::with_capacity(96);
    line.push_str(&at.to_rfc3339());
    line.push(' ');
    line.push_str(level.name());
    line.push(' ');
    push_escaped(&mut line, message, false);

    for (key, value) in fields {
        line.push(' ');
        push_escaped(&mut line, key, false);
        line.push('=');
        push_escaped(&mut line, value, true);
    }

    line
}

/// Write a line, if the level is enabled. Used by the macros.
pub fn emit(level: Level, message: &str, fields: &[(&str, String)]) {
    if !enabled(level) {
        return;
    }
    let line = format_line(Timestamp::now(), level, message, fields);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

/// Escape a fragment so it cannot break the line, quoting a value when it
/// would otherwise be ambiguous.
fn push_escaped(out: &mut String, text: &str, quote_when_ambiguous: bool) {
    let needs_quotes = quote_when_ambiguous
        && (text.is_empty()
            || text
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '='));

    if needs_quotes {
        out.push('"');
    }
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    if needs_quotes {
        out.push('"');
    }
}

/// Log at a given level: `log!(Level::Info, "message", key = value, ...)`.
#[macro_export]
macro_rules! log {
    ($level:expr, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        if $crate::enabled($level) {
            $crate::emit(
                $level,
                $message,
                &[$((stringify!($key), ::std::string::ToString::to_string(&$value))),*],
            );
        }
    };
}

/// Log an error.
#[macro_export]
macro_rules! error {
    ($($rest:tt)*) => { $crate::log!($crate::Level::Error, $($rest)*) };
}

/// Log a warning.
#[macro_export]
macro_rules! warn {
    ($($rest:tt)*) => { $crate::log!($crate::Level::Warn, $($rest)*) };
}

/// Log normal operation.
#[macro_export]
macro_rules! info {
    ($($rest:tt)*) => { $crate::log!($crate::Level::Info, $($rest)*) };
}

/// Log detail.
#[macro_export]
macro_rules! debug {
    ($($rest:tt)*) => { $crate::log!($crate::Level::Debug, $($rest)*) };
}
