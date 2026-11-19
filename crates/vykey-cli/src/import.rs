//! `vy import`: logins and secure notes from a Bitwarden CSV export.
//! Bitwarden folders become vykey folders (created when missing).

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use vykey_core::{EntryInput, EntryKind, Store, Vault, VaultMeta};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One row of a Bitwarden CSV export (columns: folder, favorite, type,
/// name, notes, fields, reprompt, login_uri, login_username,
/// login_password, login_totp).
#[derive(Debug, Default, PartialEq)]
pub struct Row {
    pub folder: String,
    pub favorite: bool,
    pub kind: String,
    pub name: String,
    pub notes: String,
    pub uri: String,
    pub username: String,
    pub password: String,
    pub totp: String,
}

pub fn parse(reader: impl Read) -> Result<Vec<Row>> {
    let mut csv = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(reader);
    let index: HashMap<String, usize> = csv
        .headers()?
        .iter()
        .enumerate()
        .map(|(i, h)| (h.to_lowercase(), i))
        .collect();
    if !index.contains_key("name") {
        return Err("not a Bitwarden CSV export (no \"name\" column)".into());
    }
    let mut rows = Vec::new();
    for record in csv.records() {
        let record = record?;
        let get = |key: &str| {
            index
                .get(key)
                .and_then(|&i| record.get(i))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        rows.push(Row {
            folder: get("folder"),
            favorite: get("favorite") == "1",
            kind: get("type").to_lowercase(),
            name: get("name"),
            notes: get("notes"),
            // Several URIs are comma-separated; keep the first.
            uri: get("login_uri")
                .split(',')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned(),
            username: get("login_username"),
            password: get("login_password"),
            totp: get("login_totp"),
        });
    }
    Ok(rows)
}

/// Secret and issuer from an `otpauth://` URI; other values are a bare secret.
pub fn parse_totp(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    let Some(rest) = raw.strip_prefix("otpauth://") else {
        return (raw.replace(' ', ""), None);
    };
    let query = rest.split_once('?').map_or("", |(_, q)| q);
    let param = |key: &str| {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| percent_decode(v))
    };
    (
        param("secret").unwrap_or_default(),
        param("issuer").filter(|s| !s.is_empty()),
    )
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn pick_vault(store: &Store, name: Option<&str>) -> Result<VaultMeta> {
    if let Some(name) = name {
        return Ok(store.vault_meta(name)?);
    }
    let mut vaults = store.list_vaults()?;
    match vaults.len() {
        0 => Err("no vault yet: run `vy` to create one".into()),
        1 => Ok(vaults.remove(0)),
        _ => {
            let names: Vec<_> = vaults.iter().map(|v| v.name.as_str()).collect();
            Err(format!(
                "several vaults ({}): choose one with --vault NAME",
                names.join(", ")
            )
            .into())
        }
    }
}

/// Adds `rows` to `vault`; returns (imported, skipped). `folder` keeps only
/// rows from that Bitwarden folder.
fn import_rows(
    store: &Store,
    vault: &Vault,
    rows: Vec<Row>,
    folder: Option<&str>,
) -> Result<(usize, usize)> {
    let mut folders: HashMap<String, String> = store
        .list_folders(vault)?
        .into_iter()
        .map(|f| (f.name.to_lowercase(), f.id))
        .collect();
    let (mut imported, mut skipped) = (0, 0);
    for row in rows {
        if folder.is_some_and(|f| !row.folder.eq_ignore_ascii_case(f)) {
            skipped += 1;
            continue;
        }
        let kind = match row.kind.as_str() {
            "" | "login" => EntryKind::Login,
            "note" => EntryKind::Note,
            other => {
                eprintln!("  skip {:?}: unsupported type {other}", row.name);
                skipped += 1;
                continue;
            }
        };
        let folder_id = if row.folder.is_empty() {
            None
        } else if let Some(id) = folders.get(&row.folder.to_lowercase()) {
            Some(id.clone())
        } else {
            let id = store.create_folder(vault, &row.folder, "")?;
            folders.insert(row.folder.to_lowercase(), id.clone());
            Some(id)
        };
        let opt = |s: &str| Some(s.to_owned()).filter(|s| !s.is_empty());
        let (secret, issuer) = parse_totp(&row.totp);
        let mut input = EntryInput::default();
        input.kind = kind;
        input.favorite = row.favorite;
        input.title = if row.name.is_empty() {
            "(untitled)".into()
        } else {
            row.name.clone()
        };
        input.username = opt(&row.username);
        input.password = opt(&row.password);
        input.url = opt(&row.uri);
        input.notes = opt(&row.notes);
        input.folder = folder_id;
        input.totp_secret = opt(&secret);
        input.totp_issuer = issuer;
        match store.create_entry(vault, &input) {
            Ok(_) => {
                println!("  + {}", input.title);
                imported += 1;
            }
            Err(e) => {
                eprintln!("  skip {:?}: {e}", row.name);
                skipped += 1;
            }
        }
    }
    Ok((imported, skipped))
}

pub fn run(store: &Store, file: &Path, vault: Option<&str>, folder: Option<&str>) -> Result<()> {
    let rows = parse(std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?)?;
    let meta = pick_vault(store, vault)?;
    let password = zeroize::Zeroizing::new(rpassword::prompt_password(format!(
        "Master password for vault \"{}\": ",
        meta.name
    ))?);
    let vault = Vault::unlock(meta, &password)?;
    store.prepare_vault(&vault)?;
    let (imported, skipped) = import_rows(store, &vault, rows, folder)?;
    println!("\nDone: {imported} imported, {skipped} skipped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "\
folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,GitHub,,,0,\"https://github.com,https://gist.github.com\",alex,hunter2,otpauth://totp/GitHub:alex?secret=JBSWY3DPEHPK3PXP&issuer=Git%20Hub
,,note,Wi-Fi,\"SSID home
pass 123\",,0,,,,
,,card,Visa,,,0,,,,
";

    #[test]
    fn parses_bitwarden_csv() {
        let rows = parse(CSV.as_bytes()).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].folder, "Work");
        assert!(rows[0].favorite);
        assert_eq!(rows[0].uri, "https://github.com");
        assert_eq!(rows[1].kind, "note");
        assert_eq!(rows[1].notes, "SSID home\npass 123");
        assert!(parse("a,b\n1,2\n".as_bytes()).is_err());
    }

    #[test]
    fn totp_values() {
        assert_eq!(
            parse_totp("otpauth://totp/x?secret=JBSWY3DP&issuer=Git%20Hub"),
            ("JBSWY3DP".into(), Some("Git Hub".into()))
        );
        assert_eq!(parse_totp("jbsw y3dp"), ("jbswy3dp".into(), None));
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn imports_into_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("vykey.db")).unwrap();
        let vault = Vault::create("default", "correct horse").unwrap();
        store.insert_vault(&vault).unwrap();
        assert_eq!(pick_vault(&store, None).unwrap().name, "default");
        assert!(pick_vault(&store, Some("nope")).is_err());

        let rows = parse(CSV.as_bytes()).unwrap();
        assert_eq!(import_rows(&store, &vault, rows, None).unwrap(), (2, 1));
        let entries = store.list_entries(&vault).unwrap();
        let gh = entries.iter().find(|e| e.title == "GitHub").unwrap();
        assert!(gh.favorite);
        assert_eq!(gh.password.as_deref(), Some("hunter2"));
        assert_eq!(gh.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(gh.totp_issuer.as_deref(), Some("Git Hub"));
        let folders = store.list_folders(&vault).unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(gh.folder.as_deref(), Some(folders[0].id.as_str()));
        let note = entries.iter().find(|e| e.title == "Wi-Fi").unwrap();
        assert_eq!(note.kind, EntryKind::Note);
        assert_eq!(note.folder, None);

        // Folder filter; the existing "work" folder is reused.
        let rows = parse(CSV.as_bytes()).unwrap();
        assert_eq!(
            import_rows(&store, &vault, rows, Some("work")).unwrap(),
            (1, 2)
        );
        assert_eq!(store.list_folders(&vault).unwrap().len(), 1);
    }
}
