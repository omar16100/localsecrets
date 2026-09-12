//! Opaque bearer tokens.
//!
//! A token is 32 random bytes rendered as URL-safe base64 behind an `lsec_`
//! prefix. The server stores only the SHA-256 of the whole string, so a leaked
//! database does not yield usable credentials. Comparison is constant time.

use crate::encoding::b64;
use crate::random::{self, EntropyError};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

/// Prefix on every issued token, so secret scanners can recognise one on sight.
pub const TOKEN_PREFIX: &str = "lsec_";

/// Number of random bytes behind the prefix.
const TOKEN_BYTES: usize = 32;

/// Length of a stored token hash.
pub const HASH_LEN: usize = 32;

/// A freshly minted token: the secret to hand to the caller once, and the hash
/// to persist. The secret is deliberately awkward to print.
pub struct IssuedToken {
    secret: String,
    hash: TokenHash,
}

impl IssuedToken {
    /// The token string. Show this to the caller exactly once.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The value to store.
    pub fn hash(&self) -> &TokenHash {
        &self.hash
    }

    /// Consume the token, yielding the secret string.
    pub fn into_secret(mut self) -> String {
        std::mem::take(&mut self.secret)
    }
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken")
            .field("secret", &"[redacted]")
            .field("hash", &self.hash)
            .finish()
    }
}

impl Drop for IssuedToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The SHA-256 of a token, as stored in the database.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenHash([u8; HASH_LEN]);

impl TokenHash {
    /// Reconstruct a hash read back from storage. Returns `None` unless the
    /// input is exactly [`HASH_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array: [u8; HASH_LEN] = bytes.try_into().ok()?;
        Some(Self(array))
    }

    /// The bytes to persist.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Constant-time check that `presented` is the token this hash was made from.
    pub fn verify(&self, presented: &str) -> bool {
        hash(presented).0.ct_eq(&self.0).into()
    }
}

impl std::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenHash(..)")
    }
}

/// Mint a new token.
pub fn generate() -> Result<IssuedToken, EntropyError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    random::fill(&mut bytes)?;
    let secret = format!("{TOKEN_PREFIX}{}", b64::encode(&bytes));
    bytes.zeroize();

    let hash = hash(&secret);
    Ok(IssuedToken { secret, hash })
}

/// Hash a presented token so it can be looked up or compared.
pub fn hash(secret: &str) -> TokenHash {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    TokenHash(out)
}
