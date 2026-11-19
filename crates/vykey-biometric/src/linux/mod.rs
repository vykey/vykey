//! Linux: fprintd on the system bus checks the finger, the kernel keyring
//! keeps the key.

mod fprint;
mod keyring;

pub use fprint::{Cancel, availability, verify};
pub use keyring::{delete_secret, has_secret, load_secret, store_secret};

use crate::Error;

/// Maps fprintd's D-Bus error names; everything else is [`Error::Dbus`].
fn dbus_error(e: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, msg, _) = &e {
        let msg = msg.clone().unwrap_or_default();
        match name.as_str() {
            "net.reactivated.Fprint.Error.NoSuchDevice" => return Error::NoReader,
            "net.reactivated.Fprint.Error.NoEnrolledPrints" => return Error::NoFingers,
            "net.reactivated.Fprint.Error.AlreadyInUse" => return Error::Busy,
            "net.reactivated.Fprint.Error.PermissionDenied" => return Error::Denied(msg),
            _ => {}
        }
    }
    Error::Dbus(e.to_string())
}

/// No such service on the bus (fprintd not installed).
fn service_unknown(e: &zbus::Error) -> bool {
    matches!(e, zbus::Error::MethodError(name, ..)
        if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown")
}
