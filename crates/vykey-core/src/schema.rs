//! Database schema and migrations.
//!
//! vykey owns the format. Versions 1 and 2 are compatible with databases
//! created by the Go app; versions are recorded in goose's
//! `goose_db_version` table, so databases created by the Go app (v1) are
//! upgraded in place.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Error, Result};

/// Migrations in order; index + 1 is the schema version.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_entries_vault_id.sql"),
    include_str!("../migrations/0003_entry_data.sql"),
    include_str!("../migrations/0004_folders.sql"),
    include_str!("../migrations/0005_wrapped_key.sql"),
    include_str!("../migrations/0006_sync.sql"),
];

/// Latest schema version this crate understands.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

const GOOSE_TABLE: &str = "CREATE TABLE goose_db_version (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    is_applied INTEGER NOT NULL,
    tstamp TIMESTAMP DEFAULT (datetime('now'))
)";

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Schema version of the database; 0 for a new (empty) one.
pub fn version(conn: &Connection) -> Result<i64> {
    if !table_exists(conn, "goose_db_version")? {
        return Ok(0);
    }
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1",
        [],
        |r| r.get(0),
    )?)
}

/// Brings the database to [`SCHEMA_VERSION`] and refuses databases written
/// by a newer version.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    if !table_exists(&tx, "goose_db_version")? {
        tx.execute_batch(GOOSE_TABLE)?;
        // goose records version 0 when it creates its table.
        tx.execute(
            "INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, 1)",
            [],
        )?;
    }
    let current: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1",
        [],
        |r| r.get(0),
    )?;
    if current > SCHEMA_VERSION {
        return Err(Error::SchemaTooNew(current, SCHEMA_VERSION));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let version = i as i64 + 1;
        if version > current {
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO goose_db_version (version_id, is_applied) VALUES (?1, 1)",
                [version],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}
