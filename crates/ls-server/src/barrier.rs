//! The barrier record: the root key, wrapped by the master key.
//!
//! This is the one record stored in the clear, because it has to be readable
//! before there is any key to read with. What it holds is not: the root key
//! inside it only opens with a master key reconstructed from a quorum of
//! unseal shares.

use ls_core::crypto::aead::Aad;
use ls_core::encoding::hex;
use ls_core::time::Timestamp;
use ls_json::{Value, parse};
use ls_store::Sealed;

/// The format this build writes and reads.
pub const BARRIER_FORMAT: i64 = 1;

/// The barrier, as stored.
#[derive(Debug, Clone)]
pub struct Barrier {
    /// How many shares an unseal needs.
    pub threshold: u8,
    /// How many shares were issued.
    pub shares: u8,
    /// The root key, wrapped by the master key.
    pub root_key: Sealed,
    /// When the vault was initialised.
    pub created_at: Timestamp,
}

impl Barrier {
    /// Associated data binding the wrapped root key to this purpose.
    pub fn context() -> Aad {
        Aad::key_wrap("root-key", "barrier")
    }

    /// Render for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        Value::object([
            ("type", Value::from("barrier")),
            ("v", Value::Int(BARRIER_FORMAT)),
            ("threshold", Value::Int(i64::from(self.threshold))),
            ("shares", Value::Int(i64::from(self.shares))),
            (
                "root_key_nonce",
                Value::from(hex::encode(&self.root_key.nonce)),
            ),
            (
                "root_key_ciphertext",
                Value::from(hex::encode(&self.root_key.ciphertext)),
            ),
            ("created_at", Value::from(self.created_at.to_rfc3339())),
        ])
        .to_string()
        .into_bytes()
    }

    /// Read back from storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8")?;
        let value = parse(text).map_err(|_| "not JSON")?;

        if value.get("type").and_then(Value::as_str) != Some("barrier") {
            return Err("not a barrier record");
        }
        if value.get("v").and_then(Value::as_i64) != Some(BARRIER_FORMAT) {
            return Err("barrier written in a format this build does not know");
        }

        let small = |name: &str| -> Result<u8, &'static str> {
            value
                .get(name)
                .and_then(Value::as_i64)
                .and_then(|n| u8::try_from(n).ok())
                .ok_or("bad share count")
        };
        let blob = |name: &str| -> Result<Vec<u8>, &'static str> {
            value
                .get(name)
                .and_then(Value::as_str)
                .and_then(hex::decode)
                .ok_or("bad key material")
        };

        Ok(Self {
            threshold: small("threshold")?,
            shares: small("shares")?,
            root_key: Sealed {
                nonce: blob("root_key_nonce")?,
                ciphertext: blob("root_key_ciphertext")?,
            },
            created_at: value
                .get("created_at")
                .and_then(Value::as_str)
                .and_then(Timestamp::parse_rfc3339)
                .ok_or("bad timestamp")?,
        })
    }
}
