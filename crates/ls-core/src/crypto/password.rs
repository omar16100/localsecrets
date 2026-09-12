//! Password hashing with argon2id.
//!
//! Hashes are PHC strings, so the parameters travel with the hash and can be
//! raised later without invalidating existing users.

use crate::random::{self, EntropyError};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};

/// Shortest password we accept. Long enough that argon2 is not the only thing
/// standing between an attacker and an account.
pub const MIN_LEN: usize = 12;

/// Longest password we accept, so a huge body cannot be used to burn server CPU.
pub const MAX_LEN: usize = 1024;

/// Salt length in bytes. 16 is the argon2 recommendation.
const SALT_LEN: usize = 16;

/// Why a password could not be hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// Below [`MIN_LEN`].
    TooShort {
        /// Length supplied.
        len: usize,
        /// Minimum required.
        min: usize,
    },
    /// Above [`MAX_LEN`].
    TooLong {
        /// Length supplied.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// The hashing library refused the input.
    Hashing(String),
    /// No entropy was available for the salt.
    Entropy,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len, min } => {
                write!(f, "password must be at least {min} characters, got {len}")
            }
            Self::TooLong { len, max } => {
                write!(f, "password must be at most {max} bytes, got {len}")
            }
            Self::Hashing(detail) => write!(f, "could not hash password: {detail}"),
            Self::Entropy => f.write_str("could not read entropy"),
        }
    }
}

impl std::error::Error for PasswordError {}

impl From<EntropyError> for PasswordError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

/// OWASP's argon2id baseline: 19 MiB, two passes, one lane.
fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|e| PasswordError::Hashing(format!("invalid argon2 parameters: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a password, returning a PHC string safe to store.
pub fn hash(password: &str) -> Result<String, PasswordError> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(PasswordError::TooShort { len, min: MIN_LEN });
    }
    if password.len() > MAX_LEN {
        return Err(PasswordError::TooLong {
            len: password.len(),
            max: MAX_LEN,
        });
    }

    let salt = random::bytes::<SALT_LEN>()?;
    let hashed: PasswordHash = argon2()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::Hashing(e.to_string()))?;
    Ok(hashed.to_string())
}

/// Highest argon2 cost this server will ever spend verifying one password.
///
/// The parameters used for verification come out of the stored hash, so a
/// tampered store could otherwise ask for gigabytes of memory and many passes
/// on every login attempt. These caps leave room to raise the working
/// parameters later without invalidating hashes already written.
const MAX_VERIFY_MEMORY_KIB: u32 = 256 * 1024;
const MAX_VERIFY_PASSES: u32 = 10;
const MAX_VERIFY_LANES: u32 = 4;

/// Check a password against a stored PHC string. A malformed, unreadable or
/// unreasonably expensive hash fails closed rather than panicking.
pub fn verify(password: &str, stored: &str) -> bool {
    if password.len() > MAX_LEN {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    if !cost_is_acceptable(&parsed) {
        return false;
    }
    match argon2() {
        Ok(hasher) => hasher.verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Read the work parameters out of a stored hash and decide whether we are
/// willing to spend that much on one verification.
fn cost_is_acceptable(parsed: &PasswordHash) -> bool {
    let numeric = |name: &str| -> Option<u32> {
        parsed
            .params
            .get(name)
            .and_then(|value| value.decimal().ok())
    };

    let memory = numeric("m").unwrap_or(0);
    let passes = numeric("t").unwrap_or(0);
    let lanes = numeric("p").unwrap_or(0);

    memory <= MAX_VERIFY_MEMORY_KIB && passes <= MAX_VERIFY_PASSES && lanes <= MAX_VERIFY_LANES
}
