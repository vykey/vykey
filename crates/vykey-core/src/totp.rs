//! RFC 6238 TOTP, matching `internal/totp` of the Go implementation
//! (HMAC-SHA1, base32 secret, spaces ignored, case-insensitive).

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::InvalidTotpSecret);
    }
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::InvalidTotpSecret)
}

/// Returns `true` if `secret` is a decodable base32 TOTP secret.
pub fn is_valid_secret(secret: &str) -> bool {
    decode_secret(secret).is_ok()
}

/// Code for unix time `unix_secs`.
pub fn code(secret: &str, unix_secs: u64, digits: u32, period: u32) -> Result<String> {
    let key = decode_secret(secret)?;
    let period = u64::from(period.max(1));
    let digits = digits.clamp(1, 9);
    let counter = unix_secs / period;

    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(&key).map_err(|_| Error::InvalidTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();

    let offset = usize::from(h[h.len() - 1] & 0x0f);
    let bin =
        u32::from_be_bytes([h[offset], h[offset + 1], h[offset + 2], h[offset + 3]]) & 0x7fff_ffff;
    let code = bin % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

/// Seconds until the current code expires.
pub fn remaining(unix_secs: u64, period: u32) -> u32 {
    let period = u64::from(period.max(1));
    (period - unix_secs % period) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B, SHA1 seed "12345678901234567890".
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        assert_eq!(code(SECRET, 59, 8, 30).unwrap(), "94287082");
        assert_eq!(code(SECRET, 1_111_111_109, 8, 30).unwrap(), "07081804");
        assert_eq!(code(SECRET, 2_000_000_000, 8, 30).unwrap(), "69279037");
    }

    #[test]
    fn lenient_secret_parsing() {
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(code(spaced, 59, 8, 30).unwrap(), "94287082");
        assert!(!is_valid_secret("not base32!"));
        assert!(!is_valid_secret("   "));
    }

    #[test]
    fn remaining_seconds() {
        assert_eq!(remaining(59, 30), 1);
        assert_eq!(remaining(60, 30), 30);
    }
}
