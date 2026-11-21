//! Proof of work for account creation (`docs/sync-protocol.md`).
//!
//! Challenges are stateless: the server signs what it hands out and
//! remembers only the challenges already used, until they expire. The
//! difficulty rises with the registration rate, so a flood gets
//! exponentially more expensive while an ordinary sign-up pays about a
//! second of CPU once.
//!
//! Challenge layout (42 bytes):
//!
//! ```text
//! version (1) ‖ issued_at (8, LE) ‖ difficulty (1) ‖ random (16) ‖ HMAC-SHA256 (16, truncated)
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use vykey_sync_proto::{Challenge, pow};

const VERSION: u8 = 1;
const SIGNED: usize = 1 + 8 + 1 + 16;
const LEN: usize = SIGNED + 16;
/// Seconds a challenge stays valid.
pub const TTL: u64 = 600;
/// Clock skew tolerated between issue and use (several server threads).
const SKEW: u64 = 60;
/// Most bits added on top of the base difficulty under load.
const MAX_EXTRA: u8 = 8;
/// Used challenges remembered before expired ones are pruned.
const PRUNE_AT: usize = 10_000;

#[derive(Debug, Clone, Copy)]
pub struct PowConfig {
    /// Difficulty at a normal registration rate (leading zero bits).
    pub base_bits: u8,
    /// Registrations per hour considered normal; each doubling above it
    /// adds one bit.
    pub target_per_hour: u32,
}

pub struct Pow {
    key: [u8; 32],
    cfg: PowConfig,
    /// Random part of used challenges → expiry.
    used: Mutex<HashMap<[u8; 16], u64>>,
    rate: Mutex<Rate>,
}

/// Registrations in the current and the previous hour.
#[derive(Default)]
struct Rate {
    hour: u64,
    current: u64,
    previous: u64,
}

impl Pow {
    /// A fresh signing key from the system; challenges from before a
    /// restart become invalid, which costs a client one retry.
    pub fn new(cfg: PowConfig) -> Result<Self, getrandom::Error> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self::with_key(cfg, key))
    }

    pub fn with_key(cfg: PowConfig, key: [u8; 32]) -> Self {
        let cfg = PowConfig {
            base_bits: cfg.base_bits.min(pow::MAX_DIFFICULTY),
            target_per_hour: cfg.target_per_hour.max(1),
        };
        Pow {
            key,
            cfg,
            used: Mutex::new(HashMap::new()),
            rate: Mutex::new(Rate::default()),
        }
    }

    pub fn issue(&self, now: u64) -> Result<Challenge, getrandom::Error> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let difficulty = self.difficulty(now);
        let mut c = Vec::with_capacity(LEN);
        c.push(VERSION);
        c.extend_from_slice(&now.to_le_bytes());
        c.push(difficulty);
        c.extend_from_slice(&random);
        let tag = self.mac(&c).finalize().into_bytes();
        c.extend_from_slice(&tag[..16]);
        Ok(Challenge {
            challenge: c,
            difficulty,
            expires_in: TTL as u32,
        })
    }

    /// Checks a solved challenge and marks it used.
    pub fn verify(&self, c: &[u8], nonce: u64, now: u64) -> Result<(), &'static str> {
        if c.len() != LEN || c[0] != VERSION {
            return Err("malformed challenge");
        }
        self.mac(&c[..SIGNED])
            .verify_truncated_left(&c[SIGNED..])
            .map_err(|_| "challenge not issued by this server")?;
        let issued = u64::from_le_bytes(c[1..9].try_into().expect("8 bytes"));
        if issued > now + SKEW || now >= issued.saturating_add(TTL) {
            return Err("challenge expired");
        }
        if !pow::check(c, nonce, c[9]) {
            return Err("wrong solution");
        }
        let random: [u8; 16] = c[10..26].try_into().expect("16 bytes");
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        if used.len() >= PRUNE_AT {
            used.retain(|_, &mut expiry| expiry > now);
        }
        if used.insert(random, issued + TTL).is_some() {
            return Err("challenge already used");
        }
        Ok(())
    }

    /// Counts a successful registration towards the rate.
    pub fn record_registration(&self, now: u64) {
        let mut r = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        r.roll(now);
        r.current += 1;
    }

    /// Base difficulty, plus one bit per doubling of the hourly rate over
    /// the target, at most [`MAX_EXTRA`] more.
    pub fn difficulty(&self, now: u64) -> u8 {
        let rate = {
            let mut r = self.rate.lock().unwrap_or_else(|e| e.into_inner());
            r.roll(now);
            // Sliding estimate: the part of the previous hour still inside
            // the last 60 minutes, plus the current hour.
            let into_hour = now % 3600;
            r.current + r.previous * (3600 - into_hour) / 3600
        };
        let mut extra = 0u8;
        let mut threshold = u64::from(self.cfg.target_per_hour);
        while rate > threshold && extra < MAX_EXTRA {
            extra += 1;
            threshold *= 2;
        }
        (self.cfg.base_bits + extra).min(pow::MAX_DIFFICULTY)
    }

    fn mac(&self, data: &[u8]) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .expect("HMAC takes keys of any length");
        m.update(data);
        m
    }
}

impl Rate {
    fn roll(&mut self, now: u64) {
        let hour = now / 3600;
        if hour == self.hour {
            return;
        }
        self.previous = if hour == self.hour + 1 {
            self.current
        } else {
            0
        };
        self.current = 0;
        self.hour = hour;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn pow(base_bits: u8) -> Pow {
        Pow::with_key(
            PowConfig {
                base_bits,
                target_per_hour: 100,
            },
            [7; 32],
        )
    }

    fn solved(p: &Pow, now: u64) -> (Vec<u8>, u64) {
        let c = p.issue(now).unwrap();
        let nonce = pow::solve(&c.challenge, c.difficulty).unwrap();
        (c.challenge, nonce)
    }

    #[test]
    fn issued_challenge_verifies_once() {
        let p = pow(8);
        let c = p.issue(NOW).unwrap();
        assert_eq!(
            (c.challenge.len(), c.difficulty, c.expires_in),
            (LEN, 8, 600)
        );
        let nonce = pow::solve(&c.challenge, c.difficulty).unwrap();
        assert_eq!(p.verify(&c.challenge, nonce, NOW + 5), Ok(()));
        assert_eq!(
            p.verify(&c.challenge, nonce, NOW + 6),
            Err("challenge already used")
        );
    }

    #[test]
    fn wrong_solution() {
        let p = pow(8);
        let c = p.issue(NOW).unwrap();
        let bad = (0..).find(|&n| !pow::check(&c.challenge, n, 8)).unwrap();
        assert_eq!(p.verify(&c.challenge, bad, NOW), Err("wrong solution"));
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let p = pow(8);
        let (c, nonce) = solved(&p, NOW);
        // Lower the difficulty, move the issue time, or sign with another key.
        for i in [1, 9, 20] {
            let mut t = c.clone();
            t[i] ^= 1;
            assert_eq!(
                p.verify(&t, nonce, NOW),
                Err("challenge not issued by this server"),
                "byte {i}"
            );
        }
        let other = Pow::with_key(
            PowConfig {
                base_bits: 8,
                target_per_hour: 100,
            },
            [8; 32],
        );
        assert!(other.verify(&c, nonce, NOW).is_err());
        assert_eq!(p.verify(&c[..40], nonce, NOW), Err("malformed challenge"));
    }

    #[test]
    fn expiry() {
        let p = pow(4);
        let (c, n) = solved(&p, NOW);
        assert_eq!(p.verify(&c, n, NOW + TTL), Err("challenge expired"));
        let (c, n) = solved(&p, NOW + SKEW + 1);
        assert_eq!(
            p.verify(&c, n, NOW),
            Err("challenge expired"),
            "from the future"
        );
        let (c, n) = solved(&p, NOW);
        assert_eq!(p.verify(&c, n, NOW + TTL - 1), Ok(()));
    }

    #[test]
    fn used_set_is_pruned() {
        let p = pow(0);
        for i in 0..PRUNE_AT as u64 {
            let (c, n) = solved(&p, NOW + i % 10);
            p.verify(&c, n, NOW + i % 10).unwrap();
        }
        let (c, n) = solved(&p, NOW + TTL + 20);
        p.verify(&c, n, NOW + TTL + 20).unwrap();
        assert_eq!(p.used.lock().unwrap().len(), 1);
    }

    #[test]
    fn difficulty_follows_the_registration_rate() {
        let p = pow(20);
        let hour_start = NOW - NOW % 3600;
        assert_eq!(p.difficulty(hour_start), 20);
        for _ in 0..100 {
            p.record_registration(hour_start);
        }
        assert_eq!(p.difficulty(hour_start), 20, "at the target");
        p.record_registration(hour_start);
        assert_eq!(p.difficulty(hour_start), 21);
        for _ in 0..300 {
            p.record_registration(hour_start);
        }
        assert_eq!(p.difficulty(hour_start), 23, "401 > 4 x 100");

        // Half way into the next hour, half of the previous one counts.
        assert_eq!(
            p.difficulty(hour_start + 3600 + 1800),
            21,
            "~200: one doubling"
        );
        // Two hours later the flood is forgotten.
        assert_eq!(p.difficulty(hour_start + 2 * 3600), 20);
    }

    #[test]
    fn difficulty_is_capped() {
        let p = pow(30);
        for _ in 0..100_000 {
            p.record_registration(NOW);
        }
        assert_eq!(p.difficulty(NOW), pow::MAX_DIFFICULTY);
        let q = pow(10);
        for _ in 0..1_000_000 {
            q.record_registration(NOW);
        }
        assert_eq!(q.difficulty(NOW), 10 + MAX_EXTRA);
    }
}
