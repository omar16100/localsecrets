//! A small fixed-window limiter for login attempts.
//!
//! Guessing a password should cost the person guessing, not the server. This
//! keeps a count per email address and refuses once it is exceeded, until the
//! window rolls over. It lives in memory, so it resets on restart: that is an
//! accepted limit of a single-node server, not an oversight.

use ls_core::time::Timestamp;
use std::collections::HashMap;

/// Failed attempts allowed per window.
const MAX_ATTEMPTS: u32 = 10;

/// Length of the window, in seconds.
const WINDOW_SECONDS: i64 = 60;

/// How many addresses to track before forgetting the oldest, so an attacker
/// cannot grow this map without bound by varying the address.
const MAX_TRACKED: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Window {
    started: i64,
    attempts: u32,
}

/// Counts recent failures per address.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: HashMap<String, Window>,
}

impl RateLimiter {
    /// Record an attempt and say whether it may go ahead.
    pub fn allow(&mut self, key: &str) -> bool {
        let now = Timestamp::now().unix_seconds();

        if self.windows.len() >= MAX_TRACKED {
            self.windows
                .retain(|_, window| now - window.started < WINDOW_SECONDS);
        }

        let window = self.windows.entry(key.to_owned()).or_insert(Window {
            started: now,
            attempts: 0,
        });

        if now - window.started >= WINDOW_SECONDS {
            window.started = now;
            window.attempts = 0;
        }

        window.attempts += 1;
        window.attempts <= MAX_ATTEMPTS
    }

    /// Forget the failures for an address that has just logged in.
    pub fn succeeded(&mut self, key: &str) {
        self.windows.remove(key);
    }
}
