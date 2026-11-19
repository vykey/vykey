//! Language-dependent texts composed in Rust. The wording comes from the `Tr`
//! global (ui/i18n.slint), so it follows the selected UI language; this
//! module only picks the right string and fills in the values.

use vykey_core::Error;

use crate::Tr;
use crate::format::{self, Ago};

/// "12 Mar 2025".
pub fn date(tr: &Tr, ts: i64) -> String {
    format::date_parts(ts).map_or_else(String::new, |(day, month0, year)| {
        format!("{day} {} {year}", tr.invoke_month(month0 as i32))
    })
}

/// "just now", "5 minutes ago", "yesterday", "3 days ago", "12 Mar 2025".
pub fn relative(tr: &Tr, ts: i64, now: i64) -> String {
    match format::ago(ts, now) {
        Ago::JustNow => tr.invoke_just_now(),
        Ago::Minutes(n) => tr.invoke_minutes_ago(clamp(n)),
        Ago::Hours(n) => tr.invoke_hours_ago(clamp(n)),
        Ago::Yesterday => tr.invoke_yesterday(),
        Ago::Days(n) => tr.invoke_days_ago(clamp(n)),
        Ago::Older => return date(tr, ts),
    }
    .into()
}

/// Entry details footer: "Created 12 Mar 2025, modified 3 days ago".
pub fn entry_meta(tr: &Tr, created: i64, updated: i64, now: i64) -> String {
    let created_on = date(tr, created).into();
    if updated - created < 60 {
        tr.invoke_created(created_on).into()
    } else {
        tr.invoke_created_modified(created_on, relative(tr, updated, now).into())
            .into()
    }
}

/// "GitHub", "GitHub and Amazon", "GitHub, Amazon and 2 more".
pub fn list(tr: &Tr, titles: &[String]) -> String {
    match titles {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => tr.invoke_list_two(a.into(), b.into()).into(),
        [a, b, rest @ ..] => tr
            .invoke_list_more(a.into(), b.into(), clamp(rest.len() as i64))
            .into(),
    }
}

/// Security score text: "Good protection. Fix 3 risks below to improve it."
pub fn score_summary(tr: &Tr, score: u32, issues: usize) -> String {
    format!(
        "{} {}",
        tr.invoke_score_level(format::score_level(score)),
        tr.invoke_score_issues(clamp(issues as i64))
    )
}

/// User-facing text for a store error.
pub fn error(tr: &Tr, e: &Error) -> String {
    match e {
        Error::WrongPassword => tr.invoke_wrong_password(),
        Error::VaultExists(_) => tr.invoke_vault_exists(),
        Error::FolderExists(_) => tr.invoke_folder_exists(),
        Error::FolderNotFound => tr.invoke_folder_not_found(),
        Error::SchemaTooNew(..) => tr.invoke_schema_too_new(),
        other => tr.invoke_error(other.to_string().into()),
    }
    .into()
}

fn clamp(n: i64) -> i32 {
    n.clamp(0, i64::from(i32::MAX)) as i32
}
