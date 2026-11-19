//! Payment card helpers: number validation (Luhn), payment system, display
//! formatting and expiry.

/// Digits of a card number, ignoring spaces and dashes.
pub fn digits(number: &str) -> String {
    number.chars().filter(char::is_ascii_digit).collect()
}

/// Luhn checksum of a card number (spaces allowed). 12–19 digits.
pub fn luhn_valid(number: &str) -> bool {
    let d = digits(number);
    if !(12..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let n = u32::from(b - b'0');
            if i % 2 == 1 {
                let x = n * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                n
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Payment system by the leading digits (IIN ranges).
pub fn brand(number: &str) -> Option<&'static str> {
    let d = digits(number);
    let prefix = |n: usize| d.get(..n).and_then(|p| p.parse::<u32>().ok());
    match (prefix(1), prefix(2), prefix(4)) {
        (_, _, Some(2200..=2204)) => Some("Mir"),
        (_, _, Some(2221..=2720)) | (_, Some(51..=55), _) => Some("Mastercard"),
        (Some(4), _, _) => Some("Visa"),
        (_, Some(34 | 37), _) => Some("American Express"),
        (_, Some(62), _) => Some("UnionPay"),
        (_, _, Some(3528..=3589)) => Some("JCB"),
        (_, Some(50 | 56..=69), _) => Some("Maestro"),
        _ => None,
    }
}

/// "2200123412341234" → "2200 1234 1234 1234" (Amex: 4-6-5).
pub fn format_number(number: &str) -> String {
    let d = digits(number);
    let groups: &[usize] = if d.len() == 15 && matches!(d.get(..2), Some("34" | "37")) {
        &[4, 6, 5]
    } else {
        &[4, 4, 4, 4, 4]
    };
    let mut out = String::new();
    let mut rest = d.as_str();
    for &g in groups {
        if rest.is_empty() {
            break;
        }
        let (head, tail) = rest.split_at(g.min(rest.len()));
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(head);
        rest = tail;
    }
    if !rest.is_empty() {
        out.push(' ');
        out.push_str(rest);
    }
    out
}

/// Last four digits, "" if the number is shorter.
pub fn last4(number: &str) -> String {
    let d = digits(number);
    if d.len() >= 4 {
        d[d.len() - 4..].to_owned()
    } else {
        String::new()
    }
}

/// "08/28", "08/2028", "0828", "8/28" → (8, 2028).
pub fn parse_expiry(expiry: &str) -> Option<(u32, i32)> {
    let parts: Vec<&str> = expiry
        .split(['/', '.', '-', ' '])
        .filter(|p| !p.is_empty())
        .collect();
    let (m, y) = match parts.as_slice() {
        [m, y] => ((*m).to_owned(), (*y).to_owned()),
        [my] if my.len() == 4 || my.len() == 6 => (my[..2].to_owned(), my[2..].to_owned()),
        _ => return None,
    };
    let month: u32 = m.parse().ok().filter(|m| (1..=12).contains(m))?;
    let year: i32 = match y.len() {
        2 => 2000 + y.parse::<i32>().ok()?,
        4 => y.parse().ok()?,
        _ => return None,
    };
    Some((month, year))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    Valid,
    /// Expires at the end of this or the next month.
    ExpiringSoon,
    Expired,
}

/// (year, month) of a unix timestamp, UTC.
fn year_month(unix: i64) -> (i32, u32) {
    // Civil-from-days (H. Hinnant).
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
    (year, month)
}

/// A card is valid through the last day of its expiry month.
pub fn expiry_status(month: u32, year: i32, now_unix: i64) -> ExpiryStatus {
    let (ny, nm) = year_month(now_unix);
    let months_left = (year - ny) * 12 + (month as i32 - nm as i32);
    match months_left {
        ..0 => ExpiryStatus::Expired,
        0..=1 => ExpiryStatus::ExpiringSoon,
        _ => ExpiryStatus::Valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn() {
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(luhn_valid("2200-0000-0000-0004"));
        assert!(!luhn_valid("4111 1111 1111 1112"));
        assert!(!luhn_valid("1234"));
    }

    #[test]
    fn brands() {
        assert_eq!(brand("2200 1234"), Some("Mir"));
        assert_eq!(brand("4111111111111111"), Some("Visa"));
        assert_eq!(brand("5500000000000004"), Some("Mastercard"));
        assert_eq!(brand("2221000000000009"), Some("Mastercard"));
        assert_eq!(brand("378282246310005"), Some("American Express"));
        assert_eq!(brand("9999"), None);
    }

    #[test]
    fn formatting() {
        assert_eq!(format_number("2200123412341234"), "2200 1234 1234 1234");
        assert_eq!(format_number("378282246310005"), "3782 822463 10005");
        assert_eq!(format_number("22001"), "2200 1");
        assert_eq!(last4("2200 1234 1234 5678"), "5678");
        assert_eq!(last4("12"), "");
    }

    #[test]
    fn expiry() {
        assert_eq!(parse_expiry("08/28"), Some((8, 2028)));
        assert_eq!(parse_expiry("8/2028"), Some((8, 2028)));
        assert_eq!(parse_expiry("0828"), Some((8, 2028)));
        assert_eq!(parse_expiry("13/28"), None);
        assert_eq!(parse_expiry(""), None);

        // 2026-11-18
        let now = 1_795_000_000;
        assert_eq!(year_month(now), (2026, 11));
        assert_eq!(expiry_status(10, 2026, now), ExpiryStatus::Expired);
        assert_eq!(expiry_status(11, 2026, now), ExpiryStatus::ExpiringSoon);
        assert_eq!(expiry_status(12, 2026, now), ExpiryStatus::ExpiringSoon);
        assert_eq!(expiry_status(1, 2027, now), ExpiryStatus::Valid);
    }
}
