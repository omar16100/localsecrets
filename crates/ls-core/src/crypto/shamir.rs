//! Shamir secret sharing over GF(2^8).
//!
//! Used to split the master key into unseal shares. Byte-wise sharing over
//! GF(2^8) handles arbitrary byte strings exactly, which a prime-field scheme
//! does not: a uniform 32-byte key does not fit any curve scalar field without
//! bias.
//!
//! The scheme is information-theoretic and carries no integrity of its own.
//! Two protections sit on top: each printed share carries a checksum that
//! catches transcription mistakes, and a wrong recombination fails the AEAD
//! authentication on the root key, so a bad unseal is detected rather than
//! silently producing a wrong key.

#[cfg(test)]
mod gf_tests {
    use super::gf;

    // FIPS-197 section 4.2: 0x57 * 0x83 = 0xc1 in the AES field.
    #[test]
    fn multiplication_matches_the_fips_197_example() {
        assert_eq!(gf::mul(0x57, 0x83), 0xc1);
    }

    // FIPS-197 section 4.4: 0x53 and 0xca are multiplicative inverses.
    #[test]
    fn the_fips_197_inverse_pair_multiplies_to_one() {
        assert_eq!(gf::mul(0x53, 0xca), 0x01);
        assert_eq!(gf::inverse(0x53), 0xca);
        assert_eq!(gf::inverse(0xca), 0x53);
    }

    #[test]
    fn multiplication_by_zero_and_one_behaves() {
        for a in 0..=255u8 {
            assert_eq!(gf::mul(a, 0), 0);
            assert_eq!(gf::mul(0, a), 0);
            assert_eq!(gf::mul(a, 1), a);
        }
    }

    #[test]
    fn multiplication_is_commutative_and_associative() {
        for a in [0x00u8, 0x01, 0x53, 0x7f, 0xca, 0xff] {
            for b in [0x00u8, 0x01, 0x53, 0x7f, 0xca, 0xff] {
                assert_eq!(gf::mul(a, b), gf::mul(b, a));
                for c in [0x02u8, 0x11, 0xfe] {
                    assert_eq!(
                        gf::mul(gf::mul(a, b), c),
                        gf::mul(a, gf::mul(b, c)),
                        "associativity failed for {a:#x} {b:#x} {c:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf::mul(a, gf::inverse(a)), 1, "no inverse for {a:#x}");
        }
    }

    #[test]
    fn division_undoes_multiplication() {
        for a in 1..=255u8 {
            for b in [0x01u8, 0x53, 0xca, 0xff] {
                assert_eq!(gf::div(gf::mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn addition_is_xor_and_is_its_own_inverse() {
        for a in 0..=255u8 {
            assert_eq!(gf::add(a, a), 0);
            assert_eq!(gf::add(gf::add(a, 0x5a), 0x5a), a);
        }
    }
}

use crate::encoding::{b64, hex};
use crate::random::{self, EntropyError};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

/// Prefix identifying a printed share and its format version.
pub const SHARE_PREFIX: &str = "lss1";

/// Bytes of checksum carried by a printed share.
const CHECKSUM_LEN: usize = 4;

/// Arithmetic in GF(2^8) with the AES reduction polynomial 0x11B.
///
/// Every operation is table free and branches only on loop counters, not on
/// secret values, so timing does not depend on the data being shared.
mod gf {
    /// Addition in a binary field is XOR.
    pub const fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Russian-peasant multiplication, constant time with respect to operands.
    pub const fn mul(a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut product: u8 = 0;
        let mut step = 0;
        while step < 8 {
            // Add `a` when the low bit of `b` is set, without branching.
            product ^= a.wrapping_mul(b & 1);
            // Double `a`, reducing by 0x11B when it overflows the field.
            let high_bit = a >> 7;
            a <<= 1;
            a ^= 0x1B_u8.wrapping_mul(high_bit);
            b >>= 1;
            step += 1;
        }
        product
    }

    /// Multiplicative inverse. `inverse(0)` is defined as 0.
    pub const fn inverse(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        // a^254 = a^-1 in GF(2^8), by Fermat's little theorem.
        let mut result: u8 = 1;
        let mut power = 0;
        while power < 254 {
            result = mul(result, a);
            power += 1;
        }
        result
    }

    /// Division. Dividing by zero yields zero, which callers must never rely on.
    pub const fn div(a: u8, b: u8) -> u8 {
        mul(a, inverse(b))
    }
}

/// Why a split or combine failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// A threshold below one cannot protect anything.
    ThresholdTooLow,
    /// More shares would be needed to reach the threshold than exist.
    ThresholdAboveShareCount {
        /// Threshold requested.
        threshold: u8,
        /// Shares requested.
        shares: u8,
    },
    /// There is nothing to split.
    EmptySecret,
    /// No shares were supplied.
    NotEnoughShares,
    /// The same share was supplied twice, which adds no information.
    DuplicateIndex(u8),
    /// Shares came from different secrets.
    LengthMismatch,
    /// The printed form is not a share.
    MalformedShare,
    /// The share was transcribed incorrectly.
    ChecksumMismatch,
    /// No entropy was available for the polynomial coefficients.
    Entropy,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThresholdTooLow => f.write_str("threshold must be at least 1"),
            Self::ThresholdAboveShareCount { threshold, shares } => write!(
                f,
                "threshold {threshold} cannot exceed the share count {shares}"
            ),
            Self::EmptySecret => f.write_str("secret is empty"),
            Self::NotEnoughShares => f.write_str("no shares supplied"),
            Self::DuplicateIndex(i) => write!(f, "share {i} was supplied more than once"),
            Self::LengthMismatch => f.write_str("shares are of different lengths"),
            Self::MalformedShare => f.write_str("not a valid share"),
            Self::ChecksumMismatch => {
                f.write_str("share checksum does not match; check for a typo")
            }
            Self::Entropy => f.write_str("could not read entropy"),
        }
    }
}

impl std::error::Error for ShamirError {}

impl From<EntropyError> for ShamirError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

/// One unseal share: an x coordinate and the polynomial values at it.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    index: u8,
    data: Vec<u8>,
}

impl Share {
    /// The x coordinate. Never zero.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The share bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Parse the printed form, verifying the checksum.
    pub fn parse(printed: &str) -> Result<Self, ShamirError> {
        let parts: Vec<&str> = printed.trim().split('.').collect();
        if parts.len() != 4 || parts[0] != SHARE_PREFIX {
            return Err(ShamirError::MalformedShare);
        }

        let index: u8 = parts[1].parse().map_err(|_| ShamirError::MalformedShare)?;
        if index == 0 {
            return Err(ShamirError::MalformedShare);
        }

        let data = b64::decode(parts[2]).ok_or(ShamirError::MalformedShare)?;
        if data.is_empty() {
            return Err(ShamirError::MalformedShare);
        }

        let supplied = hex::decode(parts[3]).ok_or(ShamirError::MalformedShare)?;
        if supplied.len() != CHECKSUM_LEN {
            return Err(ShamirError::MalformedShare);
        }
        if supplied != checksum(index, &data) {
            return Err(ShamirError::ChecksumMismatch);
        }

        Ok(Self { index, data })
    }
}

impl std::fmt::Display for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{SHARE_PREFIX}.{}.{}.{}",
            self.index,
            b64::encode(&self.data),
            hex::encode(&checksum(self.index, &self.data))
        )
    }
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("data", &"[redacted]")
            .finish()
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// A transcription check, not a security property: it catches typos before the
/// error surfaces as an unexplained decryption failure.
fn checksum(index: u8, data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_PREFIX.as_bytes());
    hasher.update([index]);
    hasher.update(data);
    hasher.finalize()[..CHECKSUM_LEN].to_vec()
}

/// Split `secret` into `shares` pieces, any `threshold` of which recover it.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, ShamirError> {
    if threshold < 1 {
        return Err(ShamirError::ThresholdTooLow);
    }
    if threshold > shares {
        return Err(ShamirError::ThresholdAboveShareCount { threshold, shares });
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    // One polynomial per byte: constant term is the secret byte, the remaining
    // `threshold - 1` coefficients are random.
    let degree = usize::from(threshold - 1);
    let mut coefficients = vec![0u8; secret.len() * degree];
    if !coefficients.is_empty() {
        random::fill(&mut coefficients)?;
    }

    let mut out = Vec::with_capacity(usize::from(shares));
    for index in 1..=shares {
        let mut data = Vec::with_capacity(secret.len());
        for (byte_position, &secret_byte) in secret.iter().enumerate() {
            let coeffs = &coefficients[byte_position * degree..(byte_position + 1) * degree];
            data.push(evaluate(secret_byte, coeffs, index));
        }
        out.push(Share { index, data });
    }

    coefficients.zeroize();
    Ok(out)
}

/// Evaluate the polynomial `constant + c1*x + c2*x^2 + ...` at `x` by Horner's rule.
fn evaluate(constant: u8, coefficients: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coefficients.iter().rev() {
        acc = gf::add(gf::mul(acc, x), c);
    }
    gf::add(gf::mul(acc, x), constant)
}

/// Recover the secret from shares.
///
/// Supplying fewer than the threshold returns a wrong value rather than an
/// error: that is inherent to the scheme, which is why the recovered key is
/// always checked by an authenticated decryption afterwards.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NotEnoughShares);
    }

    let length = shares[0].data.len();
    for (position, share) in shares.iter().enumerate() {
        if share.data.len() != length {
            return Err(ShamirError::LengthMismatch);
        }
        if shares[..position].iter().any(|s| s.index == share.index) {
            return Err(ShamirError::DuplicateIndex(share.index));
        }
    }

    // Lagrange interpolation at x = 0.
    let mut secret = Vec::with_capacity(length);
    for byte_position in 0..length {
        let mut accumulated = 0u8;
        for (i, share) in shares.iter().enumerate() {
            let mut basis = 1u8;
            for (j, other) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                basis = gf::mul(
                    basis,
                    gf::div(other.index, gf::add(share.index, other.index)),
                );
            }
            accumulated = gf::add(accumulated, gf::mul(share.data[byte_position], basis));
        }
        secret.push(accumulated);
    }

    Ok(Zeroizing::new(secret))
}
