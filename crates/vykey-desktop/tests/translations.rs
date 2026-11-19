//! Every `@tr(...)` string in ui/*.slint must be translated in each
//! translations/<lang>/LC_MESSAGES/vykey-desktop.po, and a catalogue must not
//! keep entries the UI no longer uses. A missing translation would silently
//! fall back to English, so this is checked here instead of at runtime.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// (context, msgid, msgid_plural)
type Key = (String, String, String);

/// Reads a Slint/PO string literal starting at `s[0] == '"'`; returns the
/// unescaped text and the rest after the closing quote.
fn literal(s: &str) -> (String, &str) {
    assert!(s.starts_with('"'), "expected a string literal at: {s:.40}");
    let mut out = String::new();
    let mut chars = s[1..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return (out, &s[i + 2..]),
            '\\' => match chars.next().map(|(_, c)| c) {
                Some('n') => out.push('\n'),
                Some(c) => out.push(c),
                None => break,
            },
            c => out.push(c),
        }
    }
    panic!("unterminated string literal");
}

fn ui_strings(dir: &Path) -> BTreeSet<Key> {
    let mut keys = BTreeSet::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "slint") {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap();
        for (pos, _) in src.match_indices("@tr(") {
            let rest = src[pos + 4..].trim_start();
            let (first, rest) = literal(rest);
            let rest = rest.trim_start();
            let (context, msgid, rest) = match rest.strip_prefix("=>") {
                Some(r) => {
                    let (id, r) = literal(r.trim_start());
                    (first, id, r)
                }
                None => (String::new(), first, rest),
            };
            let plural = match rest.trim_start().strip_prefix('|') {
                Some(r) => literal(r.trim_start()).0,
                None => String::new(),
            };
            keys.insert((context, msgid, plural));
        }
    }
    keys
}

/// Entries of a PO file with their translations (header skipped).
fn po_entries(path: &Path) -> Vec<(Key, Vec<String>)> {
    let src = fs::read_to_string(path).unwrap();
    let mut entries = Vec::new();
    for block in src.split("\n\n") {
        let (mut ctx, mut id, mut plural, mut strs) =
            (String::new(), None, String::new(), Vec::new());
        // Continuation lines ("...") only occur in the header, which is skipped.
        for line in block
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with('"'))
        {
            let (word, value) = line.split_once(' ').unwrap();
            let value = literal(value.trim()).0;
            match word {
                "msgctxt" => ctx = value,
                "msgid" => id = Some(value),
                "msgid_plural" => plural = value,
                w if w.starts_with("msgstr") => strs.push(value),
                w => panic!("unexpected PO keyword {w}"),
            }
        }
        match id {
            Some(id) if !id.is_empty() => entries.push(((ctx, id, plural), strs)),
            _ => {}
        }
    }
    entries
}

#[test]
fn translations_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let used = ui_strings(&root.join("ui"));
    assert!(used.len() > 100, "found only {} @tr strings", used.len());

    let mut languages = 0;
    for lang in fs::read_dir(root.join("translations")).unwrap() {
        let lang = lang.unwrap().path();
        let po = lang.join("LC_MESSAGES/vykey-desktop.po");
        let entries = po_entries(&po);
        languages += 1;

        let mut known = BTreeSet::new();
        for (key, strs) in &entries {
            assert!(
                !strs.is_empty() && strs.iter().all(|s| !s.is_empty()),
                "{}: untranslated {key:?}",
                po.display()
            );
            assert!(
                known.insert(key.clone()),
                "{}: duplicate {key:?}",
                po.display()
            );
        }
        let missing: Vec<_> = used.difference(&known).collect();
        let unused: Vec<_> = known.difference(&used).collect();
        assert!(missing.is_empty(), "{}: missing {missing:#?}", po.display());
        assert!(unused.is_empty(), "{}: unused {unused:#?}", po.display());
    }
    assert!(languages > 0, "no translations found");
}
