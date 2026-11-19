//! Password generation (same alphabet as the Go implementation) and a simple
//! entropy-based strength estimate used by the UI and the security audit.

use rand::seq::IndexedRandom;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 64;
pub const DEFAULT_LENGTH: usize = 16;

/// Random password of `length` characters from lower, upper, digits and
/// symbols, guaranteed to contain at least one character of each class.
pub fn generate(length: usize) -> String {
    let length = length.clamp(MIN_LENGTH, MAX_LENGTH);
    let classes = [LOWER, UPPER, DIGITS, SYMBOLS];
    let all: Vec<u8> = classes.concat().into_bytes();
    let mut rng = rand::rng();
    loop {
        let pw: String = (0..length)
            .map(|_| char::from(*all.choose(&mut rng).expect("non-empty alphabet")))
            .collect();
        if classes
            .iter()
            .all(|class| pw.chars().any(|c| class.contains(c)))
        {
            return pw;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

impl Strength {
    pub fn bars(self) -> i32 {
        self as i32
    }
}

/// Rough entropy in bits: `length * log2(pool)` where the pool is the union
/// of character classes present in the password.
pub fn entropy_bits(password: &str) -> f64 {
    let len = password.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password
        .chars()
        .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric())
    {
        pool += 33;
    }
    if !password.is_ascii() {
        pool += 64;
    }
    // Repeated characters add little; count distinct chars more than repeats.
    let distinct = {
        let mut v: Vec<char> = password.chars().collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    let effective = distinct as f64 + (len - distinct) as f64 * 0.25;
    effective * f64::from(pool.max(1)).log2()
}

pub fn strength(password: &str) -> Strength {
    match entropy_bits(password) {
        b if b < 50.0 => Strength::Weak,
        b if b < 70.0 => Strength::Fair,
        b if b < 90.0 => Strength::Strong,
        _ => Strength::VeryStrong,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_all_classes() {
        for len in [MIN_LENGTH, DEFAULT_LENGTH, MAX_LENGTH] {
            let pw = generate(len);
            assert_eq!(pw.len(), len);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn strength_levels() {
        assert_eq!(strength("123456"), Strength::Weak);
        assert_eq!(strength("password"), Strength::Weak);
        assert_eq!(strength("aaaaaaaaaaaaaaaaaaaa"), Strength::Weak);
        assert_eq!(strength("X7$k9!mQ2#vL"), Strength::Strong);
        assert!(strength(&generate(DEFAULT_LENGTH)) >= Strength::Strong);
    }
}
