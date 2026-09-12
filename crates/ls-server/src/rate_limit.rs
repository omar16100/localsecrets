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
    ///
    /// The key is normalised first: without that, `Dev@Example.com ` and
    /// `dev@example.com` are different buckets and the limit counts for
    /// nothing.
    pub fn allow(&mut self, key: &str) -> bool {
        let key = normalise(key);
        let now = Timestamp::now().unix_seconds();

        if self.windows.len() >= MAX_TRACKED {
            self.windows
                .retain(|_, window| now - window.started < WINDOW_SECONDS);
        }

        // Still full after dropping what has expired: refuse rather than grow.
        // Someone flooding fresh addresses is the reason the map is full, and
        // growing it is how that becomes a memory problem.
        if self.windows.len() >= MAX_TRACKED && !self.windows.contains_key(&key) {
            return false;
        }

        let window = self.windows.entry(key).or_insert(Window {
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
        self.windows.remove(&normalise(key));
    }

    /// How many addresses are being tracked. For tests.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.windows.len()
    }
}

/// The same normalisation the vault applies to an email address.
fn normalise(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{MAX_ATTEMPTS, MAX_TRACKED, RateLimiter};

    #[test]
    fn attempts_are_allowed_up_to_the_limit_and_then_refused() {
        let mut limiter = RateLimiter::default();

        for attempt in 1..=MAX_ATTEMPTS {
            assert!(limiter.allow("a@example.com"), "attempt {attempt}");
        }
        assert!(!limiter.allow("a@example.com"));
    }

    #[test]
    fn case_and_spacing_do_not_create_a_second_bucket() {
        let mut limiter = RateLimiter::default();

        for _ in 0..MAX_ATTEMPTS {
            limiter.allow("dev@example.com");
        }

        assert!(!limiter.allow("  DEV@Example.COM  "));
    }

    #[test]
    fn a_successful_login_clears_the_count() {
        let mut limiter = RateLimiter::default();
        for _ in 0..MAX_ATTEMPTS {
            limiter.allow("dev@example.com");
        }

        limiter.succeeded("DEV@EXAMPLE.COM");

        assert!(limiter.allow("dev@example.com"));
    }

    #[test]
    fn addresses_are_counted_separately() {
        let mut limiter = RateLimiter::default();
        for _ in 0..=MAX_ATTEMPTS {
            limiter.allow("one@example.com");
        }

        assert!(limiter.allow("two@example.com"));
    }

    #[test]
    fn flooding_fresh_addresses_does_not_grow_the_map_without_bound() {
        let mut limiter = RateLimiter::default();

        for i in 0..MAX_TRACKED * 2 {
            limiter.allow(&format!("flood-{i}@example.com"));
        }

        assert!(
            limiter.tracked() <= MAX_TRACKED,
            "tracked {} addresses",
            limiter.tracked()
        );
    }
}
