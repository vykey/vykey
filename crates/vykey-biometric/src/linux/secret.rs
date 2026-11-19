//! Secret Service client (`org.freedesktop.secrets` on the session bus):
//! GNOME Keyring, KWallet, KeePassXC. Items carry the attributes
//! `application = vykey`, `vault-id = <vault_meta.id>`.
//!
//! The session uses the "plain" algorithm: the secret travels unencrypted
//! over the session bus, which only processes of the same user can watch —
//! and they can read the keyring anyway.

use std::collections::HashMap;

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::{dbus_error, service_unknown};
use crate::{Error, Result};

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const SESSION_IFACE: &str = "org.freedesktop.Secret.Session";

/// (session, parameters, value, content type)
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

fn attributes(vault_id: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", "vykey"), ("vault-id", vault_id)])
}

/// "/" stands for "no object" (e.g. no prompt needed).
fn is_none(path: &OwnedObjectPath) -> bool {
    path.as_str() == "/"
}

struct Keyring {
    conn: Connection,
    service: Proxy<'static>,
    session: OwnedObjectPath,
}

impl Keyring {
    fn open() -> Result<Self> {
        let keyring_error = |e: zbus::Error| {
            if service_unknown(&e) {
                Error::NoKeyring("no keyring daemon is running".into())
            } else {
                dbus_error(e)
            }
        };
        let conn = Connection::session().map_err(dbus_error)?;
        let service =
            Proxy::new(&conn, SERVICE, SERVICE_PATH, SERVICE_IFACE).map_err(dbus_error)?;
        let (_, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(keyring_error)?;
        Ok(Self {
            conn,
            service,
            session,
        })
    }

    fn proxy(&self, path: &OwnedObjectPath, iface: &'static str) -> Result<Proxy<'static>> {
        Proxy::new(&self.conn, SERVICE, path.clone(), iface).map_err(dbus_error)
    }

    /// (unlocked, locked) items of this vault.
    fn search(&self, vault_id: &str) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        self.service
            .call("SearchItems", &(attributes(vault_id),))
            .map_err(dbus_error)
    }

    fn unlock(&self, objects: &[OwnedObjectPath]) -> Result<()> {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = self
            .service
            .call("Unlock", &(objects,))
            .map_err(dbus_error)?;
        self.prompt(&prompt)
    }

    /// Shows the keyring's own dialog (e.g. its password) and waits for it.
    fn prompt(&self, path: &OwnedObjectPath) -> Result<()> {
        if is_none(path) {
            return Ok(());
        }
        let prompt = self.proxy(path, PROMPT_IFACE)?;
        let mut completed = prompt.receive_signal("Completed").map_err(dbus_error)?;
        prompt
            .call::<_, _, ()>("Prompt", &("",))
            .map_err(dbus_error)?;
        let msg = completed.next().ok_or(Error::Dismissed)?;
        let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize().map_err(dbus_error)?;
        if dismissed {
            Err(Error::Dismissed)
        } else {
            Ok(())
        }
    }

    fn store(&self, vault_id: &str, label: &str, secret: &[u8]) -> Result<()> {
        let collection: OwnedObjectPath = self
            .service
            .call("ReadAlias", &("default",))
            .map_err(dbus_error)?;
        if is_none(&collection) {
            return Err(Error::NoKeyring(
                "the keyring has no default collection".into(),
            ));
        }
        self.unlock(std::slice::from_ref(&collection))?;
        let properties = HashMap::from([
            ("org.freedesktop.Secret.Item.Label", Value::from(label)),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(attributes(vault_id)),
            ),
        ]);
        let secret = Zeroizing::new(secret.to_vec());
        let value = (
            self.session.clone(),
            Vec::<u8>::new(),
            &*secret,
            "application/octet-stream",
        );
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .proxy(&collection, COLLECTION_IFACE)?
            .call("CreateItem", &(properties, value, true))
            .map_err(dbus_error)?;
        self.prompt(&prompt)
    }

    fn load(&self, vault_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let (unlocked, locked) = self.search(vault_id)?;
        let item = match (unlocked.first(), locked.first()) {
            (Some(item), _) => item.clone(),
            (None, Some(item)) => {
                self.unlock(std::slice::from_ref(item))?;
                item.clone()
            }
            (None, None) => return Ok(None),
        };
        let (_, _, value, _): Secret = self
            .proxy(&item, ITEM_IFACE)?
            .call("GetSecret", &(&self.session,))
            .map_err(dbus_error)?;
        Ok(Some(Zeroizing::new(value)))
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        let (unlocked, locked) = self.search(vault_id)?;
        for item in unlocked.iter().chain(&locked) {
            let prompt: OwnedObjectPath = self
                .proxy(item, ITEM_IFACE)?
                .call("Delete", &())
                .map_err(dbus_error)?;
            self.prompt(&prompt)?;
        }
        Ok(())
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        if let Ok(session) = self.proxy(&self.session, SESSION_IFACE) {
            let _ = session.call::<_, _, ()>("Close", &());
        }
    }
}

pub fn has_secret(vault_id: &str) -> Result<bool> {
    let (unlocked, locked) = Keyring::open()?.search(vault_id)?;
    Ok(!unlocked.is_empty() || !locked.is_empty())
}

pub fn store_secret(vault_id: &str, label: &str, secret: &[u8]) -> Result<()> {
    Keyring::open()?.store(vault_id, label, secret)
}

pub fn load_secret(vault_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Keyring::open()?.load(vault_id)
}

pub fn delete_secret(vault_id: &str) -> Result<()> {
    Keyring::open()?.delete(vault_id)
}
