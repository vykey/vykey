//! Display helpers: avatars, domains, date parts, score ring, input masks.
//! Language-dependent wording is composed in `text.rs` from `Tr` strings.

use std::time::Duration;

use chrono::{DateTime, Datelike, Local, TimeZone};
use slint::Color;

/// Up to two initials from a vault name: "Alex Kim" → "AK", "work" → "W".
pub fn initials(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| c.is_whitespace() || c == '-' || c == '_' || c == '.')
        .filter(|w| !w.is_empty())
        .collect();
    let s: String = words
        .iter()
        .take(2)
        .filter_map(|w| w.chars().next())
        .flat_map(char::to_uppercase)
        .collect();
    if s.is_empty() { "?".into() } else { s }
}

/// First letter or digit of a title, upper-cased.
pub fn letter(title: &str) -> String {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "#".into())
}

/// Stable per-title accent from a set of brand-like colours.
pub fn avatar_color(title: &str) -> Color {
    const PALETTE: [u32; 10] = [
        0x8F81FF, 0xA259FF, 0x4285F4, 0x21A038, 0x1DB954, 0x5C8DFF, 0xFC6D26, 0xF2555A, 0xE0A01B,
        0x2E9E8F,
    ];
    // FNV-1a
    let hash = title
        .to_lowercase()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        });
    Color::from_argb_encoded(0xFF00_0000 | PALETTE[(hash % PALETTE.len() as u64) as usize])
}

/// Folder dot colours offered by the folder dialog. Stored as `#RRGGBB`.
pub const FOLDER_COLORS: [&str; 8] = [
    "#8F81FF", "#3DD68C", "#FFB224", "#F2555A", "#4CB8FF", "#FF7AB8", "#2EC4B6", "#9C9CA8",
];

/// Index of a stored folder colour in [`FOLDER_COLORS`] (0 if unknown).
pub fn folder_color_index(hex: &str) -> usize {
    FOLDER_COLORS
        .iter()
        .position(|c| c.eq_ignore_ascii_case(hex.trim()))
        .unwrap_or(0)
}

/// `#RRGGBB` → colour; anything else falls back to the first palette colour.
pub fn folder_color(hex: &str) -> Color {
    let rgb = hex
        .trim()
        .strip_prefix('#')
        .filter(|h| h.len() == 6)
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0x8F81FF);
    Color::from_argb_encoded(0xFF00_0000 | rgb)
}

/// "https://www.github.com/login" → "github.com".
pub fn domain(url: &str) -> String {
    let rest = url.trim();
    let rest = rest.split_once("://").map_or(rest, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    host.strip_prefix("www.").unwrap_or(host).to_owned()
}

/// "482901" → "482 901".
pub fn group_code(code: &str) -> String {
    let mid = code.len() / 2;
    if code.len() >= 6 && code.is_char_boundary(mid) {
        format!("{} {}", &code[..mid], &code[mid..])
    } else {
        code.to_owned()
    }
}

fn local(ts: i64) -> Option<DateTime<Local>> {
    Local.timestamp_opt(ts, 0).single()
}

/// Local (day, month0, year) of a unix timestamp.
pub fn date_parts(ts: i64) -> Option<(u32, u32, i32)> {
    local(ts).map(|d| (d.day(), d.month0(), d.year()))
}

/// Current local time, "09:41".
pub fn time_now() -> String {
    Local::now().format("%H:%M").to_string()
}

/// How long ago `ts` was, as shown in "modified 3 days ago".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ago {
    JustNow,
    Minutes(i64),
    Hours(i64),
    Yesterday,
    Days(i64),
    /// A month or more: show the date instead.
    Older,
}

pub fn ago(ts: i64, now: i64) -> Ago {
    let secs = (now - ts).max(0);
    let (mins, hours, days) = (secs / 60, secs / 3600, secs / 86_400);
    if secs < 60 {
        Ago::JustNow
    } else if hours < 1 {
        Ago::Minutes(mins)
    } else if days < 1 {
        Ago::Hours(hours)
    } else if days == 1 {
        Ago::Yesterday
    } else if days < 30 {
        Ago::Days(days)
    } else {
        Ago::Older
    }
}

/// SVG path for the security score arc: clockwise from 12 o'clock, r = 52 in
/// a 120×120 viewbox.
pub fn score_ring(score: u32) -> String {
    let score = score.min(100);
    if score == 0 {
        return String::new();
    }
    let theta =
        (f64::from(score) / 100.0 * std::f64::consts::TAU).min(std::f64::consts::TAU - 1e-3);
    let x = 60.0 + 52.0 * theta.sin();
    let y = 60.0 - 52.0 * theta.cos();
    let large = u8::from(theta > std::f64::consts::PI);
    format!("M 60 8 A 52 52 0 {large} 1 {x:.2} {y:.2}")
}

/// Security score level: 0 = excellent, 1 = good, 2 = fair, 3 = weak.
pub fn score_level(score: u32) -> i32 {
    match score {
        90.. => 0,
        70..=89 => 1,
        50..=69 => 2,
        _ => 3,
    }
}

/// Parses Go-style durations used by `VYKEY_LOCK_TIMEOUT`: "30s", "5m", "1h30m", "0".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s == "0" {
        return Some(Duration::ZERO);
    }
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let value: f64 = num.parse().ok()?;
        num.clear();
        let unit = match c {
            'h' => 3600.0,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                0.001
            }
            'm' => 60.0,
            's' => 1.0,
            _ => return None,
        };
        total += Duration::from_secs_f64(value * unit);
        any = true;
    }
    (any && num.is_empty()).then_some(total)
}

/// Input masks for card fields, applied while typing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mask {
    /// "4111 1111 1111 1111" (Amex "3782 822463 10005"), up to 19 digits.
    CardNumber,
    /// "MM/YY".
    Expiry,
    /// Digits only, up to 4 (CVV, PIN).
    ShortDigits,
}

impl Mask {
    pub fn from_index(i: i32) -> Option<Self> {
        match i {
            1 => Some(Self::CardNumber),
            2 => Some(Self::Expiry),
            3 => Some(Self::ShortDigits),
            _ => None,
        }
    }

    fn max_digits(self) -> usize {
        match self {
            Self::CardNumber => 19,
            Self::Expiry | Self::ShortDigits => 4,
        }
    }

    fn render(self, digits: &str) -> String {
        match self {
            Self::CardNumber => vykey_core::card::format_number(digits),
            Self::ShortDigits => digits.to_owned(),
            Self::Expiry => {
                if digits.len() > 2 {
                    format!("{}/{}", &digits[..2], &digits[2..])
                } else {
                    digits.to_owned()
                }
            }
        }
    }
}

/// Byte offset right after the `n`-th digit of `s` (0 → 0).
fn offset_after_digits(s: &str, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut seen = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() {
            seen += 1;
            if seen == n {
                return i + c.len_utf8();
            }
        }
    }
    s.len()
}

/// Re-formats `text` after an edit and maps the cursor (byte offset) so it
/// stays after the same digit. `prev` is the value before the edit: if the
/// edit only removed a separator (backspace on a space or "/"), the digit
/// before it is removed instead.
pub fn mask_input(mask: Mask, text: &str, cursor: usize, prev: &str) -> (String, usize) {
    let cursor = cursor.min(text.len());
    let mut digits: String = text.chars().filter(char::is_ascii_digit).collect();
    let mut before = text[..cursor].chars().filter(char::is_ascii_digit).count();

    let prev_digits: String = prev.chars().filter(char::is_ascii_digit).collect();
    if text.len() < prev.len() && digits == prev_digits && before > 0 {
        digits.remove(before - 1);
        before -= 1;
    }

    if mask == Mask::Expiry && digits.len() == 1 && digits != "0" && digits != "1" {
        // "8" → "08": a month cannot start with 2..9.
        digits.insert(0, '0');
        before += 1;
    }
    digits.truncate(mask.max_digits());
    let before = before.min(digits.len());

    let out = mask.render(&digits);
    let pos = offset_after_digits(&out, before);
    (out, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_helpers() {
        assert_eq!(initials("Алексей Ким"), "АК");
        assert_eq!(initials("work"), "W");
        assert_eq!(initials(""), "?");
        assert_eq!(letter("  github"), "G");
        assert_eq!(letter("СберБанк"), "С");
        assert_eq!(domain("https://www.github.com/login?x=1"), "github.com");
        assert_eq!(domain("user@mail.ru"), "mail.ru");
        assert_eq!(group_code("482901"), "482 901");
    }

    #[test]
    fn folder_colors() {
        assert_eq!(folder_color_index("#3dd68c"), 1);
        assert_eq!(folder_color_index("bogus"), 0);
        assert_eq!(
            folder_color("#FFB224"),
            Color::from_rgb_u8(0xFF, 0xB2, 0x24)
        );
        assert_eq!(folder_color(""), folder_color(FOLDER_COLORS[0]));
    }

    #[test]
    fn ages() {
        assert_eq!(ago(0, 30), Ago::JustNow);
        assert_eq!(ago(0, 5 * 60), Ago::Minutes(5));
        assert_eq!(ago(0, 3 * 3600), Ago::Hours(3));
        assert_eq!(ago(0, 86_400), Ago::Yesterday);
        assert_eq!(ago(0, 3 * 86_400), Ago::Days(3));
        assert_eq!(ago(0, 40 * 86_400), Ago::Older);
        assert_eq!(ago(100, 0), Ago::JustNow);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("5"), None);
    }

    #[test]
    fn card_number_mask() {
        let m = Mask::CardNumber;
        // typing at the end
        assert_eq!(mask_input(m, "41111", 5, "4111"), ("4111 1".into(), 6));
        assert_eq!(
            mask_input(m, "4111 11111", 10, "4111 1111"),
            ("4111 1111 1".into(), 11)
        );
        // paste with junk
        assert_eq!(
            mask_input(m, "4111-1111 1111.1111", 19, ""),
            ("4111 1111 1111 1111".into(), 19)
        );
        // Amex grouping
        assert_eq!(
            mask_input(m, "378282246310005", 15, "").0,
            "3782 822463 10005"
        );
        // editing in the middle keeps the cursor after the typed digit
        assert_eq!(
            mask_input(m, "41191 1111", 4, "4111 1111"),
            ("4119 1111 1".into(), 4)
        );
        // backspace on a space removes the digit before it
        assert_eq!(
            mask_input(m, "41111111", 4, "4111 1111"),
            ("4111 111".into(), 3)
        );
        // max 19 digits
        assert_eq!(
            mask_input(m, "12345678901234567890", 20, "").0,
            "1234 5678 9012 3456 789"
        );
        assert_eq!(mask_input(m, "", 0, "4").0, "");
    }

    #[test]
    fn expiry_and_short_masks() {
        let e = Mask::Expiry;
        assert_eq!(mask_input(e, "8", 1, ""), ("08".into(), 2));
        assert_eq!(mask_input(e, "1", 1, ""), ("1".into(), 1));
        assert_eq!(mask_input(e, "082", 3, "08"), ("08/2".into(), 4));
        assert_eq!(mask_input(e, "08/289", 6, "08/28"), ("08/28".into(), 5));
        // backspace on "/" removes the month digit before it
        assert_eq!(mask_input(e, "082", 2, "08/2"), ("02".into(), 1));
        let s = Mask::ShortDigits;
        assert_eq!(mask_input(s, "12a3", 4, "12"), ("123".into(), 3));
        assert_eq!(mask_input(s, "12345", 5, "1234"), ("1234".into(), 4));
    }

    #[test]
    fn ring() {
        assert_eq!(score_ring(0), "");
        assert_eq!(score_ring(50), "M 60 8 A 52 52 0 0 1 60.00 112.00");
        assert!(score_ring(100).contains(" 0 1 1 "));
    }
}
