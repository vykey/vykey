//! Linux: fprintd on the system bus, Secret Service on the session bus.

mod fprint;
mod secret;

pub use fprint::{Cancel, availability, verify};
pub use secret::{delete_secret, has_secret, load_secret, store_secret};

use crate::Error;

/// Maps well-known D-Bus error names; everything else is [`Error::Dbus`].
fn dbus_error(e: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, msg, _) = &e {
        let msg = msg.clone().unwrap_or_default();
        match name.as_str() {
            "net.reactivated.Fprint.Error.NoSuchDevice" => return Error::NoReader,
            "net.reactivated.Fprint.Error.NoEnrolledPrints" => return Error::NoFingers,
            "net.reactivated.Fprint.Error.AlreadyInUse" => return Error::Busy,
            "net.reactivated.Fprint.Error.PermissionDenied" => return Error::Denied(msg),
            "org.freedesktop.Secret.Error.IsLocked" => return Error::Dismissed,
            _ => {}
        }
    }
    Error::Dbus(e.to_string())
}

/// No such service on the bus (fprintd / keyring daemon not installed).
fn service_unknown(e: &zbus::Error) -> bool {
    matches!(e, zbus::Error::MethodError(name, ..)
        if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown")
}
