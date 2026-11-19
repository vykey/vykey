//! fprintd client (`net.reactivated.Fprint` on the system bus): the daemon
//! behind `pam_fprintd`. Claiming the reader for the current user is allowed
//! by fprintd's default polkit rules in an active local session.

use std::time::{Duration, Instant};

use futures_lite::StreamExt;
use futures_lite::future::or;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Message, Proxy};

use super::{dbus_error, service_unknown};
use crate::{Availability, Error, Event, Finger, MAX_ATTEMPTS, Result, Retry, Verdict};

const SERVICE: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";
/// Empty user name: the caller's own user.
const ME: &str = "";

#[derive(Clone)]
pub struct Cancel {
    tx: async_channel::Sender<()>,
    rx: async_channel::Receiver<()>,
}

impl Cancel {
    pub fn new() -> Self {
        let (tx, rx) = async_channel::bounded(1);
        Self { tx, rx }
    }

    pub fn cancel(&self) {
        self.tx.close();
    }

    pub fn is_cancelled(&self) -> bool {
        self.tx.is_closed()
    }

    /// Resolves once [`Self::cancel`] was called.
    async fn cancelled(&self) {
        let _ = self.rx.recv().await;
    }
}

async fn device(conn: &Connection) -> zbus::Result<Proxy<'static>> {
    let manager = Proxy::new(conn, SERVICE, MANAGER_PATH, MANAGER_IFACE).await?;
    let path: OwnedObjectPath = manager.call("GetDefaultDevice", &()).await?;
    Proxy::new(conn, SERVICE, path, DEVICE_IFACE).await
}

async fn probe() -> zbus::Result<Vec<String>> {
    let conn = Connection::system().await?;
    let dev = device(&conn).await?;
    dev.call("ListEnrolledFingers", &(ME,)).await
}

pub fn availability() -> Availability {
    match async_io::block_on(probe()) {
        Ok(fingers) if !fingers.is_empty() => Availability::Ready,
        Ok(_) => Availability::NoFingers,
        Err(e) if service_unknown(&e) => Availability::Unsupported,
        Err(e) => match dbus_error(e) {
            Error::NoReader => Availability::NoReader,
            Error::NoFingers => Availability::NoFingers,
            _ => Availability::Unsupported,
        },
    }
}

pub fn verify(
    cancel: &Cancel,
    timeout: Duration,
    mut on_event: impl FnMut(Event),
) -> Result<Verdict> {
    async_io::block_on(async {
        let conn = Connection::system().await.map_err(dbus_error)?;
        let dev = device(&conn).await.map_err(|e| {
            if service_unknown(&e) {
                Error::Unsupported
            } else {
                dbus_error(e)
            }
        })?;
        let swipe = dev
            .get_property::<String>("scan-type")
            .await
            .is_ok_and(|t| t == "swipe");
        if !claim(&dev, cancel).await? {
            return Ok(Verdict::Cancelled);
        }
        let result = run(&dev, cancel, Instant::now() + timeout, swipe, &mut on_event).await;
        // Fails harmlessly when no verification is running.
        let _ = dev.call::<_, _, ()>("VerifyStop", &()).await;
        let _ = dev.call::<_, _, ()>("Release", &()).await;
        result
    })
}

enum Wake {
    Status(Option<Message>),
    Finger(Option<Message>),
    Cancel,
    Timeout,
}

async fn run(
    dev: &Proxy<'_>,
    cancel: &Cancel,
    deadline: Instant,
    swipe: bool,
    on_event: &mut impl FnMut(Event),
) -> Result<Verdict> {
    // Subscribe before starting, so no signal is missed.
    let mut status = dev
        .receive_signal("VerifyStatus")
        .await
        .map_err(dbus_error)?;
    let mut selected = dev
        .receive_signal("VerifyFingerSelected")
        .await
        .map_err(dbus_error)?;
    start(dev).await?;
    let mut failures = 0;
    loop {
        let wake = or(
            async { Wake::Status(status.next().await) },
            or(
                async { Wake::Finger(selected.next().await) },
                or(
                    async {
                        cancel.cancelled().await;
                        Wake::Cancel
                    },
                    async {
                        async_io::Timer::at(deadline).await;
                        Wake::Timeout
                    },
                ),
            ),
        )
        .await;
        let msg = match wake {
            Wake::Cancel => return Ok(Verdict::Cancelled),
            Wake::Timeout => return Ok(Verdict::TimedOut),
            Wake::Status(None) | Wake::Finger(None) => return Err(Error::Disconnected),
            Wake::Finger(Some(msg)) => {
                let name: String = msg.body().deserialize().map_err(dbus_error)?;
                on_event(Event::Prompt {
                    finger: Finger::from_fprintd(&name),
                    swipe,
                });
                continue;
            }
            Wake::Status(Some(msg)) => msg,
        };
        let (result, done): (String, bool) = msg.body().deserialize().map_err(dbus_error)?;
        match result.as_str() {
            "verify-match" => return Ok(Verdict::Match),
            "verify-no-match" => {
                failures += 1;
                if failures >= MAX_ATTEMPTS {
                    return Ok(Verdict::NoMatch);
                }
                on_event(Event::NoMatch {
                    attempts_left: MAX_ATTEMPTS - failures,
                });
            }
            "verify-retry-scan" => on_event(Event::Retry(Retry::Scan)),
            "verify-swipe-too-short" => on_event(Event::Retry(Retry::SwipeTooShort)),
            "verify-finger-not-centered" => on_event(Event::Retry(Retry::NotCentered)),
            "verify-remove-and-retry" => on_event(Event::Retry(Retry::RemoveAndRetry)),
            "verify-disconnected" => return Err(Error::Disconnected),
            other => return Err(Error::Reader(other.to_owned())),
        }
        // A finished verification has to be stopped before the next one.
        if done {
            dev.call::<_, _, ()>("VerifyStop", &())
                .await
                .map_err(dbus_error)?;
            start(dev).await?;
        }
    }
}

/// How long a busy reader is retried: a check that was just cancelled (in
/// this or another process) needs a moment to release it.
const CLAIM_RETRY: Duration = Duration::from_secs(2);

/// Claims the reader for the current user. `Ok(false)`: cancelled meanwhile.
async fn claim(dev: &Proxy<'_>, cancel: &Cancel) -> Result<bool> {
    let deadline = Instant::now() + CLAIM_RETRY;
    loop {
        if cancel.is_cancelled() {
            return Ok(false);
        }
        match dev
            .call::<_, _, ()>("Claim", &(ME,))
            .await
            .map_err(dbus_error)
        {
            Ok(()) => return Ok(true),
            Err(Error::Busy) if Instant::now() < deadline => {
                async_io::Timer::after(Duration::from_millis(150)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn start(dev: &Proxy<'_>) -> Result<()> {
    dev.call::<_, _, ()>("VerifyStart", &("any",))
        .await
        .map_err(dbus_error)
}
