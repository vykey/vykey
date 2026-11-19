//! Offline security audit of decrypted entries: weak, reused and stale
//! passwords, and 2FA coverage. No network access (no breach checks).

use std::collections::HashMap;

use crate::card::{self, ExpiryStatus};
use crate::password::{self, Strength};
use crate::store::{Entry, EntryKind};

/// Passwords not changed for longer than this are reported as stale.
pub const STALE_AFTER_SECS: i64 = 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueKind {
    /// Weak password, also used by the listed titles.
    WeakReused(Vec<String>),
    Weak,
    /// Password also used by the listed titles.
    Reused(Vec<String>),
    Stale,
    CardExpired,
    CardExpiring,
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub entry_id: String,
    pub title: String,
    pub kind: IssueKind,
}

impl Issue {
    pub fn severity(&self) -> Severity {
        match self.kind {
            IssueKind::WeakReused(_) | IssueKind::Weak => Severity::High,
            IssueKind::Reused(_) | IssueKind::CardExpired => Severity::Medium,
            IssueKind::Stale | IssueKind::CardExpiring => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub total: usize,
    /// Entries of kind login (password checks and 2FA apply to them).
    pub logins: usize,
    pub with_password: usize,
    pub weak: usize,
    pub reused: usize,
    pub stale: usize,
    pub with_totp: usize,
    /// 0..=100
    pub score: u32,
    /// Sorted by severity, then title.
    pub issues: Vec<Issue>,
}

pub fn audit(entries: &[Entry], now_unix: i64) -> Report {
    let mut by_password: HashMap<&str, Vec<&Entry>> = HashMap::new();
    let logins = || entries.iter().filter(|e| e.kind == EntryKind::Login);
    for e in logins() {
        if let Some(pw) = e.password.as_deref().filter(|p| !p.is_empty()) {
            by_password.entry(pw).or_default().push(e);
        }
    }

    let mut r = Report {
        total: entries.len(),
        logins: logins().count(),
        ..Default::default()
    };
    for e in entries.iter().filter(|e| e.kind == EntryKind::Card) {
        let status = e
            .card
            .as_ref()
            .and_then(|c| card::parse_expiry(&c.expiry))
            .map(|(m, y)| card::expiry_status(m, y, now_unix));
        let kind = match status {
            Some(ExpiryStatus::Expired) => IssueKind::CardExpired,
            Some(ExpiryStatus::ExpiringSoon) => IssueKind::CardExpiring,
            _ => continue,
        };
        r.issues.push(Issue {
            entry_id: e.id.clone(),
            title: e.title.clone(),
            kind,
        });
    }
    for e in logins() {
        if e.totp_secret
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            r.with_totp += 1;
        }
        let Some(pw) = e.password.as_deref().filter(|p| !p.is_empty()) else {
            continue;
        };
        r.with_password += 1;

        let weak = password::strength(pw) == Strength::Weak;
        let others: Vec<String> = by_password[pw]
            .iter()
            .filter(|o| o.id != e.id)
            .map(|o| o.title.clone())
            .collect();
        let stale = now_unix - e.updated_at > STALE_AFTER_SECS;

        if weak {
            r.weak += 1;
        }
        if !others.is_empty() {
            r.reused += 1;
        }
        if stale {
            r.stale += 1;
        }

        let kind = match (weak, others.is_empty(), stale) {
            (true, false, _) => Some(IssueKind::WeakReused(others)),
            (true, true, _) => Some(IssueKind::Weak),
            (false, false, _) => Some(IssueKind::Reused(others)),
            (false, true, true) => Some(IssueKind::Stale),
            (false, true, false) => None,
        };
        if let Some(kind) = kind {
            r.issues.push(Issue {
                entry_id: e.id.clone(),
                title: e.title.clone(),
                kind,
            });
        }
    }
    r.issues.sort_by(|a, b| {
        a.severity()
            .cmp(&b.severity())
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });

    r.score = if r.with_password == 0 {
        100
    } else {
        let n = r.with_password as f64;
        let penalty = (r.weak as f64 * 1.0 + r.reused as f64 * 0.6 + r.stale as f64 * 0.2) / n;
        let totp_bonus = r.with_totp as f64 / r.logins.max(1) as f64 * 0.1;
        ((1.0 - penalty * 0.9 + totp_bonus).clamp(0.0, 1.0) * 100.0).round() as u32
    };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, pw: Option<&str>, updated_at: i64) -> Entry {
        let mut e = Entry::default();
        e.id = id.into();
        e.title = id.into();
        e.password = pw.map(Into::into);
        e.updated_at = updated_at;
        e
    }

    #[test]
    fn finds_issues() {
        let now = 2 * STALE_AFTER_SECS;
        let entries = vec![
            entry("a", Some("123456"), now),
            entry("b", Some("Tr0ub4dor&3-horse-staple"), now),
            entry("c", Some("Tr0ub4dor&3-horse-staple"), now),
            entry("d", Some("Xq9!vL2#mK7$pR4@"), 0),
            entry("e", None, 0),
        ];
        let r = audit(&entries, now);
        assert_eq!((r.total, r.with_password), (5, 4));
        assert_eq!((r.weak, r.reused, r.stale), (1, 2, 1));
        assert_eq!(r.issues.len(), 4);
        assert_eq!(r.issues[0].kind, IssueKind::Weak);
        assert_eq!(r.issues[1].kind, IssueKind::Reused(vec!["c".into()]));
        assert_eq!(r.issues[3].kind, IssueKind::Stale);
        assert!(r.score < 100);
    }

    #[test]
    fn cards_and_notes() {
        use crate::store::Card;
        // 2026-11-18
        let now = 1_795_000_000;
        let card = |id: &str, expiry: &str| {
            let mut e = entry(id, None, now);
            e.kind = EntryKind::Card;
            e.card = Some(Card {
                expiry: expiry.into(),
                ..Card::default()
            });
            e
        };
        let mut note = entry("note", Some("123"), 0);
        note.kind = EntryKind::Note;
        let entries = vec![
            card("old", "10/26"),
            card("soon", "12/26"),
            card("ok", "05/29"),
            note,
            entry("login", Some("Xq9!vL2#mK7$pR4@"), now),
        ];
        let r = audit(&entries, now);
        assert_eq!((r.total, r.logins, r.with_password), (5, 1, 1));
        // The note's weak "password" is not audited.
        assert_eq!(r.weak, 0);
        let kinds: Vec<_> = r
            .issues
            .iter()
            .map(|i| (i.title.as_str(), i.kind.clone()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("old", IssueKind::CardExpired),
                ("soon", IssueKind::CardExpiring)
            ]
        );
    }

    #[test]
    fn empty_vault_scores_full() {
        assert_eq!(audit(&[], 0).score, 100);
    }
}
