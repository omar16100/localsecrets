//! The single source of randomness: the operating system.
//!
//! Entropy failure is treated as an error rather than a panic, because a
//! secrets manager that silently produces predictable keys is worse than one
//! that refuses to start.

/// The operating system refused to supply entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError;

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not read entropy from the operating system")
    }
}

impl std::error::Error for EntropyError {}

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> Result<(), EntropyError> {
    getrandom::fill(buf).map_err(|_| EntropyError)
}

/// Return `N` random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N], EntropyError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
