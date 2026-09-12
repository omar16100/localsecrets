//! Byte encodings. Deliberately small and dependency free.

/// URL-safe base64 without padding, as used for tokens and unseal shares.
pub mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encode bytes. Output never contains `+`, `/` or `=`.
    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let bits = (b0 << 16) | (b1 << 8) | b2;

            // Every chunk yields one more character than it has bytes.
            let chars = chunk.len() + 1;
            for i in 0..chars {
                let index = ((bits >> (18 - 6 * i)) & 0x3F) as usize;
                out.push(ALPHABET[index] as char);
            }
        }
        out
    }

    /// Decode a URL-safe, unpadded base64 string. `None` on any malformed input,
    /// including padding characters and the standard alphabet's `+` and `/`.
    pub fn decode(input: &str) -> Option<Vec<u8>> {
        let bytes = input.as_bytes();
        // A group of one leftover character carries no whole byte.
        if bytes.len() % 4 == 1 {
            return None;
        }

        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for chunk in bytes.chunks(4) {
            let mut bits: u32 = 0;
            for (i, &c) in chunk.iter().enumerate() {
                bits |= (value_of(c)? as u32) << (18 - 6 * i);
            }

            // A short final group carries bits that encode nothing. They must be
            // zero, otherwise a value would have more than one spelling and a
            // checksum over the decoded bytes could not detect an edited one.
            let unused_bits = match chunk.len() {
                2 => 4,
                3 => 2,
                _ => 0,
            };
            if unused_bits > 0 && (bits >> (24 - 6 * chunk.len())) & ((1 << unused_bits) - 1) != 0 {
                return None;
            }

            // A group of n characters carries n - 1 bytes.
            for i in 0..chunk.len() - 1 {
                out.push(((bits >> (16 - 8 * i)) & 0xFF) as u8);
            }
        }
        Some(out)
    }

    fn value_of(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
}

/// Lowercase hexadecimal, used for identifiers and debugging output.
pub mod hex {
    /// Encode bytes as lowercase hex.
    pub fn encode(input: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(input.len() * 2);
        for &byte in input {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0F) as usize] as char);
        }
        out
    }

    /// Decode hex, accepting either case. `None` on odd length or stray characters.
    pub fn decode(input: &str) -> Option<Vec<u8>> {
        let bytes = input.as_bytes();
        if bytes.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks(2) {
            out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
        }
        Some(out)
    }

    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}
