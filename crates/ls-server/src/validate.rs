//! Input rules.
//!
//! Slugs and key names end up in paths, associated data and audit entries, so
//! they are kept to a small, obvious character set rather than escaped
//! everywhere afterwards.

use crate::VaultError;

/// Longest slug.
const MAX_SLUG: usize = 64;

/// Longest secret key name.
const MAX_KEY: usize = 256;

/// Longest email address, per the SMTP limit.
const MAX_EMAIL: usize = 254;

/// Lowercase letters, digits and dashes, not starting or ending with a dash.
pub fn slug(input: &str, what: &'static str) -> Result<String, VaultError> {
    let invalid = VaultError::Invalid(what);

    if input.is_empty() || input.len() > MAX_SLUG {
        return Err(invalid);
    }
    if input.starts_with('-') || input.ends_with('-') {
        return Err(invalid);
    }
    if !input
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid);
    }

    Ok(input.to_owned())
}

/// The shape of an environment variable name, give or take: letters, digits,
/// underscore, dot and dash.
pub fn secret_key(input: &str) -> Result<String, VaultError> {
    let invalid = VaultError::Invalid("secret key");

    if input.is_empty() || input.len() > MAX_KEY {
        return Err(invalid);
    }
    if !input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        return Err(invalid);
    }

    Ok(input.to_owned())
}

/// Lowercased and trimmed. The check is deliberately loose: the only way to
/// know an address is real is to send to it.
pub fn email(input: &str) -> Result<String, VaultError> {
    let trimmed = input.trim().to_ascii_lowercase();
    let invalid = VaultError::Invalid("email");

    if trimmed.len() < 3 || trimmed.len() > MAX_EMAIL {
        return Err(invalid);
    }
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(invalid);
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(invalid);
    }
    if trimmed.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(invalid);
    }

    Ok(trimmed)
}
