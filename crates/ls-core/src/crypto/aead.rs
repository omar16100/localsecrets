//! Authenticated encryption for stored values and wrapped keys.
//!
//! AES-256-GCM with a fresh random 96-bit nonce per operation. Every ciphertext
//! is bound to the slot it belongs in through canonical associated data, so a
//! row copied between environments, projects or key names fails to decrypt
//! instead of leaking the value.
//!
//! On random nonces: the chance of a repeat after `q` encryptions under one key
//! is about `q(q-1)/2^97`, roughly `2^-33` at `2^32` writes. One data key per
//! project at human write rates stays far below that. If a key ever approaches
//! it, the answer is rotation, not a larger nonce.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use crate::random::{self, EntropyError};
use zeroize::Zeroize as _;

/// Key length in bytes.
pub const KEY_LEN: usize = 32;

/// Nonce length in bytes (96 bits, the value GCM is specified for).
pub const NONCE_LEN: usize = 12;

/// Largest value we will encrypt. Secrets are configuration, not files.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024;

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    /// Decryption or authentication failed. Deliberately carries no detail:
    /// a wrong key, a tampered ciphertext and a wrong context are the same
    /// answer to a caller.
    Decrypt,
    /// The value exceeds [`MAX_PLAINTEXT_LEN`].
    PlaintextTooLarge {
        /// Length supplied.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// The cipher refused to encrypt.
    Encrypt,
    /// No entropy was available for the nonce.
    Entropy,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decrypt => f.write_str("could not decrypt"),
            Self::PlaintextTooLarge { len, max } => {
                write!(f, "value is {len} bytes, limit is {max}")
            }
            Self::Encrypt => f.write_str("could not encrypt"),
            Self::Entropy => f.write_str("could not read entropy"),
        }
    }
}

impl std::error::Error for AeadError {}

impl From<EntropyError> for AeadError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

/// Canonical associated data: an unambiguous encoding of the context a
/// ciphertext belongs to.
///
/// Fields are length-prefixed rather than concatenated, so `("ab", "c")` and
/// `("a", "bc")` never produce the same bytes. Lengths are written as 64-bit
/// counts, which a `usize` always fits, so no field can be long enough to wrap
/// a counter and collide with a different context.
#[derive(Clone, PartialEq, Eq)]
pub struct Aad(Vec<u8>);

impl Aad {
    /// Build from a domain tag and an ordered list of fields.
    pub fn new(domain: &str, fields: &[&str]) -> Self {
        let mut buf = Vec::with_capacity(64);
        push_field(&mut buf, domain.as_bytes());
        buf.extend_from_slice(&(fields.len() as u64).to_be_bytes());
        for field in fields {
            push_field(&mut buf, field.as_bytes());
        }
        Self(buf)
    }

    /// Context for a secret value living at project / environment / key.
    pub fn secret_slot(project_id: &str, environment_id: &str, key: &str) -> Self {
        Self::new("localsecrets.secret.v1", &[project_id, environment_id, key])
    }

    /// Context for one key wrapping another, e.g. the root key wrapping a
    /// project data key.
    pub fn key_wrap(purpose: &str, owner_id: &str) -> Self {
        Self::new("localsecrets.keywrap.v1", &[purpose, owner_id])
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Aad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aad({} bytes)", self.0.len())
    }
}

fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// A nonce and ciphertext pair, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Random per-operation nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext with the GCM tag appended.
    pub ciphertext: Vec<u8>,
}

/// A 256-bit symmetric key. Zeroed on drop, never printed, never copied.
///
/// There is deliberately no way to read the raw bytes back out. A key is used
/// by sealing with it, or wrapped by another key through [`DataKey::wrap`];
/// anything else would make it easy to log or persist key material by accident.
pub struct DataKey([u8; KEY_LEN]);

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DataKey {
    /// Generate a fresh random key.
    pub fn generate() -> Result<Self, EntropyError> {
        Ok(Self(random::bytes::<KEY_LEN>()?))
    }

    /// Reconstruct a key from stored bytes. `None` unless exactly [`KEY_LEN`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().ok()?;
        Some(Self(array))
    }

    /// Encrypt another key under this one, binding it to `aad`.
    pub fn wrap(&self, key: &DataKey, aad: &Aad) -> Result<Envelope, AeadError> {
        self.seal(&key.0, aad)
    }

    /// Recover a key wrapped by [`DataKey::wrap`] under the same `aad`.
    ///
    /// Anything that does not decrypt to exactly [`KEY_LEN`] bytes is refused,
    /// so a ciphertext that is not a key cannot become one.
    pub fn unwrap_key(&self, envelope: &Envelope, aad: &Aad) -> Result<DataKey, AeadError> {
        let mut material = self.open(envelope, aad)?;
        let key = DataKey::from_bytes(&material).ok_or(AeadError::Decrypt);
        material.zeroize();
        key
    }

    /// Encrypt `plaintext`, binding it to `aad`.
    pub fn seal(&self, plaintext: &[u8], aad: &Aad) -> Result<Envelope, AeadError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(AeadError::PlaintextTooLarge {
                len: plaintext.len(),
                max: MAX_PLAINTEXT_LEN,
            });
        }

        let nonce_bytes = random::bytes::<NONCE_LEN>()?;

        let nonce = Nonce::from(nonce_bytes);
        let cipher = Aes256Gcm::new(&self.0.into());
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AeadError::Encrypt)?;

        Ok(Envelope {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Decrypt an envelope that was sealed under the same key and `aad`.
    pub fn open(&self, envelope: &Envelope, aad: &Aad) -> Result<Vec<u8>, AeadError> {
        if envelope.nonce.len() != NONCE_LEN {
            return Err(AeadError::Decrypt);
        }

        let Ok(nonce) = Nonce::try_from(envelope.nonce.as_slice()) else {
            return Err(AeadError::Decrypt);
        };
        let cipher = Aes256Gcm::new(&self.0.into());
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AeadError::Decrypt)
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataKey([redacted; {KEY_LEN}])")
    }
}
