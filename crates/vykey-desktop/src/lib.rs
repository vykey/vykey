//! vykey desktop GUI: application state and wiring between `vykey-core` and the
//! Slint UI in `ui/`. The binary in `main.rs` only calls [`run`].

mod format;
mod text;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use slint::{
    ComponentHandle, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer, TimerMode,
    VecModel,
};
use vykey_biometric::{
    self as biometric, Availability, Cancel as FpCancel, Event as FpEvent, Retry, Verdict,
};
use vykey_core::audit::{self, IssueKind, Severity};
use vykey_core::card::{self as card_fmt, ExpiryStatus};
use vykey_core::settings::{Settings, ThemeMode};
use vykey_core::sync::http::HttpClient;
use vykey_core::sync::proto::{ErrorCode, Token};
use vykey_core::sync::{self as vsync, AddressError, Report, SyncAccount, SyncError};
use vykey_core::{
    Card, Entry, EntryInput, EntryKind, Error, Folder, Store, Vault, VaultMeta, password, totp,
};

slint::include_modules!();

/// Copied secrets are removed from the clipboard after this delay.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
/// Length of the delete animation (see `Dust` in vault.slint).
const SNAP_DURATION: Duration = Duration::from_millis(1500);
const TOAST_DURATION: Duration = Duration::from_millis(2200);

/// Sync server offered first in the setup dialog, next to "own server".
/// `None`: only own servers.
const PUBLIC_SERVER: Option<&str> = Some(vsync::CLOUD_SERVER);
/// Delay between a local change and the sync that uploads it (changes in
/// quick succession go together).
const SYNC_SOON: Duration = Duration::from_secs(2);
/// Poll interval until the server names its own (`poll_after`).
const SYNC_POLL: Duration = Duration::from_secs(300);

/// Background sync of this database.
#[derive(Default)]
struct SyncState {
    /// A sync round runs on a worker thread.
    running: bool,
    /// When the next round starts.
    due: Option<Instant>,
    /// The server's poll interval.
    poll: Option<Duration>,
    /// Failed rounds in a row (for the retry delay).
    failures: u32,
    /// Why the last round failed; shown instead of the last sync time.
    error: Option<String>,
    /// The setup dialog waits for the server.
    setting_up: bool,
    /// Disconnect once the running round is over.
    disconnect_after: bool,
}

struct App {
    ui: slint::Weak<AppWindow>,
    store: Option<Store>,
    vaults: Vec<VaultMeta>,
    vault: Option<Vault>,
    entries: Vec<Entry>,
    folders: Vec<Folder>,
    folder_items: Rc<VecModel<FolderItem>>,
    visible: Vec<usize>,
    items: Rc<VecModel<EntryItem>>,
    issues: Rc<VecModel<Issue>>,
    /// Kept across ticks so the digit rollers animate instead of being recreated.
    totp_digits: Rc<VecModel<i32>>,
    query: String,
    /// 0 = all, 1 = favourites, 2 = cards, 3 = notes, 4 = folder
    filter: i32,
    /// Folder shown when `filter == 4`.
    folder: Option<String>,
    /// Folder in the edit / delete dialog (`None` = new folder).
    folder_edit: Option<String>,
    sort_by_date: bool,
    selected: Option<String>,
    deleting: Option<String>,
    last_activity: Instant,
    lock_timeout: Option<Duration>,
    clipboard: Option<arboard::Clipboard>,
    copied: Option<(Instant, String)>,
    toast_until: Option<Instant>,
    _timer: Timer,
    /// Fires when the delete ("snap") animation is over.
    fx_timer: Timer,
    settings: Settings,
    /// Where `settings` is saved; `None` if no config directory is known.
    settings_path: Option<PathBuf>,
    /// Fingerprint reader, probed once at start.
    fp_support: Availability,
    /// Stops the fingerprint check running on the unlock screen, and the
    /// id of the vault it is for.
    fp_cancel: Option<(FpCancel, String)>,
    /// Bumped whenever that check is stopped: results of older ones are dropped.
    fp_round: u64,
    /// Path of the database, opened again by the sync worker thread.
    db_path: Option<PathBuf>,
    sync: SyncState,
}

/// End of a fingerprint check on the unlock screen.
enum FpOutcome {
    Opened(Vault),
    /// The stored key no longer opens the vault and was removed.
    Reset,
    NoMatch,
    TimedOut,
    Failed(biometric::Error),
}

/// Runs `f` on the UI thread, unless fingerprint check `round` was stopped.
fn post_fp(round: u64, f: impl FnOnce(&mut App) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        with_app(|app| {
            if app.fp_round == round {
                f(app);
            }
        })
    });
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    /// Window snapshot for the delete animation. Kept outside `APP` because
    /// it is read from a pure callback while the UI renders.
    static SNAPSHOT: RefCell<Option<SharedPixelBuffer<Rgba8Pixel>>> = const { RefCell::new(None) };
}

/// Cuts a `w`×`h` piece at (`x`, `y`) out of the delete-animation snapshot.
fn snapshot_tile(x: i32, y: i32, w: i32, h: i32) -> slint::Image {
    SNAPSHOT.with_borrow(|snap| {
        let Some(snap) = snap else {
            return slint::Image::default();
        };
        let (sw, sh) = (snap.width() as i32, snap.height() as i32);
        let (w, h) = (w.clamp(1, 64), h.clamp(1, 64));
        let mut tile = SharedPixelBuffer::<Rgba8Pixel>::new(w as u32, h as u32);
        let src = snap.as_slice();
        let dst = tile.make_mut_slice();
        for ty in 0..h {
            for tx in 0..w {
                let (sx, sy) = (x + tx, y + ty);
                if (0..sw).contains(&sx) && (0..sh).contains(&sy) {
                    dst[(ty * w + tx) as usize] = src[(sy * sw + sx) as usize];
                }
            }
        }
        slint::Image::from_rgba8(tile)
    })
}

/// Runs `f` with the application state. Only call from the UI thread and
/// never from inside another `with_app`.
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> R {
    APP.with_borrow_mut(|app| f(app.as_mut().expect("app state initialised")))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn kind_index(kind: EntryKind) -> i32 {
    match kind {
        EntryKind::Login => 0,
        EntryKind::Card => 1,
        EntryKind::Note => 2,
    }
}

fn kind_from(index: i32) -> EntryKind {
    match index {
        1 => EntryKind::Card,
        2 => EntryKind::Note,
        _ => EntryKind::Login,
    }
}

/// List subtitle: login → username or domain, card → "Mir •••• 1234",
/// note → first line of the text.
fn subtitle(tr: &Tr, e: &Entry) -> String {
    match e.kind {
        EntryKind::Login => e
            .username
            .clone()
            .or_else(|| e.url.as_deref().map(format::domain))
            .unwrap_or_default(),
        EntryKind::Card => {
            let c = e.card.clone().unwrap_or_default();
            let last4 = card_fmt::last4(&c.number);
            if last4.is_empty() {
                c.holder.clone()
            } else {
                let brand = card_fmt::brand(&c.number)
                    .map_or_else(|| tr.invoke_card().to_string(), str::to_owned);
                format!("{brand} •••• {last4}")
            }
        }
        EntryKind::Note => {
            let line = e
                .notes
                .as_deref()
                .and_then(|n| n.lines().map(str::trim).find(|l| !l.is_empty()))
                .unwrap_or_default();
            line.chars().take(80).collect()
        }
    }
}

fn card_status(c: &Card, now: i64) -> i32 {
    match card_fmt::parse_expiry(&c.expiry).map(|(m, y)| card_fmt::expiry_status(m, y, now)) {
        Some(ExpiryStatus::ExpiringSoon) => 1,
        Some(ExpiryStatus::Expired) => 2,
        _ => 0,
    }
}

impl App {
    fn ui(&self) -> AppWindow {
        self.ui.upgrade().expect("window alive")
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// A text in the current UI language: `self.say(|tr| tr.invoke_item_saved())`.
    fn say(&self, f: impl FnOnce(&Tr) -> SharedString) -> String {
        f(&self.ui().global::<Tr>()).into()
    }

    fn error_text(&self, e: &Error) -> String {
        text::error(&self.ui().global::<Tr>(), e)
    }

    /// Fills the auto-lock dropdown (names depend on the UI language).
    fn update_lock_choices(&self) {
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        let current = self.settings.lock_timeout;
        let options = lock_options(current);
        let names: Vec<SharedString> = options.iter().map(|&s| lock_name(&tr, s)).collect();
        ui.set_lock_names(ModelRc::new(VecModel::from(names)));
        ui.set_lock_index(options.iter().position(|&s| s == current).unwrap_or(0) as i32);
        ui.set_lock_env(vykey_core::settings::lock_timeout_from_env().is_some());
    }

    fn set_lock_timeout(&mut self, index: i32) {
        let options = lock_options(self.settings.lock_timeout);
        let Some(&secs) = usize::try_from(index).ok().and_then(|i| options.get(i)) else {
            return;
        };
        self.settings.lock_timeout = secs;
        self.lock_timeout = self.settings.lock_timeout();
        self.update_lock_choices();
        self.save_settings();
    }

    fn save_settings(&mut self) {
        let saved = self.settings_path.as_deref().map(|p| self.settings.save(p));
        if !matches!(saved, Some(Ok(()))) {
            self.toast(&self.say(|tr| tr.invoke_settings_save_failed()));
        }
    }

    /// Re-renders the texts composed in Rust after a language switch; the
    /// `@tr` strings in the UI update by themselves.
    fn refresh_texts(&mut self) {
        self.update_sync_ui();
        if self.vault.is_some() {
            self.update_list();
            self.update_detail();
            self.update_security();
        }
    }

    fn toast(&mut self, text: &str) {
        self.ui().set_toast(text.into());
        self.toast_until = Some(Instant::now() + TOAST_DURATION);
    }

    // ---------- unlock / lock ----------

    fn load_vaults(&mut self) {
        let ui = self.ui();
        match self.store.as_ref().map(Store::list_vaults) {
            Some(Ok(vaults)) => self.vaults = vaults,
            Some(Err(e)) => ui.set_unlock_error(self.error_text(&e).into()),
            None => {}
        }
        let items: Vec<VaultItem> = self
            .vaults
            .iter()
            .map(|v| VaultItem {
                name: v.name.as_str().into(),
                initials: format::initials(&v.name).into(),
            })
            .collect();
        let index = ui
            .get_vault_index()
            .clamp(0, (items.len() as i32 - 1).max(0));
        ui.set_vaults(ModelRc::new(VecModel::from(items)));
        ui.set_vault_index(index);
        // The first-run hint depends on whether there are vaults.
        self.update_sync_ui();
    }

    fn start_unlock(&mut self, name: &str, password: SharedString) {
        let ui = self.ui();
        let Some(store) = &self.store else {
            ui.set_unlock_error(self.say(|tr| tr.invoke_db_unavailable()).into());
            return;
        };
        let meta = match store.vault_meta(name) {
            Ok(m) => m,
            Err(e) => {
                ui.set_unlock_error(self.error_text(&e).into());
                return;
            }
        };
        ui.set_busy(true);
        ui.set_unlock_error("".into());
        std::thread::spawn(move || {
            let result = Vault::unlock(meta, password.as_str());
            drop(password);
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_unlock(result, true))
            });
        });
    }

    fn start_create(&mut self, name: &str, password: SharedString) {
        let ui = self.ui();
        if self.store.is_none() {
            ui.set_unlock_error(self.say(|tr| tr.invoke_db_unavailable()).into());
            return;
        }
        let name = name.trim().to_owned();
        ui.set_busy(true);
        ui.set_unlock_error("".into());
        std::thread::spawn(move || {
            let result = Vault::create(&name, password.as_str());
            drop(password);
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| {
                    let result = result.and_then(|vault| {
                        app.store
                            .as_ref()
                            .expect("checked above")
                            .insert_vault(&vault)?;
                        Ok(vault)
                    });
                    app.finish_unlock(result, true);
                    app.load_vaults();
                })
            });
        });
    }

    /// `by_password`: opened with the master password (not a finger), which
    /// renews the stored fingerprint key.
    fn finish_unlock(&mut self, result: vykey_core::Result<Vault>, by_password: bool) {
        let ui = self.ui();
        ui.set_busy(false);
        // Password and fingerprint may both succeed: the first one wins.
        if self.vault.is_some() {
            return;
        }
        match result {
            Ok(vault) => {
                self.stop_fingerprint();
                // Bind entries written without a vault and encrypt legacy
                // plaintext titles (databases from older vykey versions).
                if let Some(store) = &self.store
                    && let Err(e) = store.prepare_vault(&vault)
                {
                    ui.set_unlock_error(self.error_text(&e).into());
                    return;
                }
                // The password restarts the fingerprint key's lifetime; a
                // finger never does, so the password is asked at least daily.
                if by_password
                    && self.settings.fingerprint(&vault.meta().id)
                    && let Err(e) = biometric::store_key(&vault.meta().id, vault.key())
                {
                    let text = self.fp_error_text(&e);
                    self.toast(&text);
                }
                ui.set_create_mode(false);
                ui.set_vault_name(vault.meta().name.as_str().into());
                ui.set_vault_initials(format::initials(&vault.meta().name).into());
                self.vault = Some(vault);
                self.query.clear();
                self.set_filter_state(0, None);
                self.selected = None;
                ui.set_query("".into());
                ui.set_page(Page::Vault);
                ui.set_password_revealed(false);
                self.touch();
                self.reload();
                if let Some(&first) = self.visible.first() {
                    self.selected = Some(self.entries[first].id.clone());
                    self.update_detail();
                }
                ui.set_screen(Screen::Main);
                self.refresh_fp_enabled();
                // Fetch what other devices changed in this vault.
                self.schedule_sync(Duration::ZERO);
            }
            Err(e) => ui.set_unlock_error(self.error_text(&e).into()),
        }
    }

    fn lock(&mut self) {
        if self.vault.is_none() {
            return;
        }
        let ui = self.ui();
        self.end_snap();
        let name = self.vault.as_ref().map(|v| v.meta().name.clone());
        self.vault = None; // master key is zeroized on drop
        self.entries.clear(); // entries are zeroized on drop
        self.folders.clear();
        self.folder_items.set_vec(Vec::new());
        self.folder_edit = None;
        self.visible.clear();
        self.items.set_vec(Vec::new());
        self.issues.set_vec(Vec::new());
        self.selected = None;
        self.deleting = None;
        self.query.clear();
        ui.set_form_open(false);
        ui.set_delete_open(false);
        ui.set_vault_dialog(0);
        ui.set_vault_dialog_busy(false);
        ui.set_folder_dialog(0);
        self.set_filter_state(0, None);
        ui.set_form_initial(EntryForm::default());
        ui.set_detail(EntryDetail::default());
        ui.set_has_detail(false);
        ui.set_totp_code("".into());
        ui.set_totp_raw("".into());
        self.totp_digits.set_vec(Vec::new());
        ui.set_password_revealed(false);
        ui.set_query("".into());
        ui.set_unlock_error("".into());
        ui.set_toast("".into());
        self.load_vaults();
        if let Some(i) = name.and_then(|n| self.vaults.iter().position(|v| v.name == n)) {
            ui.set_vault_index(i as i32);
        }
        ui.set_screen(Screen::Unlock);
        self.start_fingerprint();
    }

    // ---------- fingerprint ----------

    fn fp_text(&self, event: FpEvent) -> String {
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        // `Finger` is declared in the order of `Tr.finger`.
        let finger = |f: biometric::Finger| tr.invoke_finger(f as i32);
        match event {
            FpEvent::Prompt {
                finger: Some(f),
                swipe: false,
            } => tr.invoke_fp_place(finger(f)),
            FpEvent::Prompt {
                finger: Some(f),
                swipe: true,
            } => tr.invoke_fp_swipe(finger(f)),
            FpEvent::Prompt {
                finger: None,
                swipe: false,
            } => tr.invoke_fp_place_any(),
            FpEvent::Prompt {
                finger: None,
                swipe: true,
            } => tr.invoke_fp_swipe_any(),
            FpEvent::Retry(Retry::Scan) => tr.invoke_fp_retry_scan(),
            FpEvent::Retry(Retry::SwipeTooShort) => tr.invoke_fp_swipe_short(),
            FpEvent::Retry(Retry::NotCentered) => tr.invoke_fp_not_centered(),
            FpEvent::Retry(Retry::RemoveAndRetry) => tr.invoke_fp_remove_retry(),
            FpEvent::NoMatch { attempts_left } => tr.invoke_fp_no_match(attempts_left as i32),
        }
        .into()
    }

    fn fp_error_text(&self, e: &biometric::Error) -> String {
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        match e {
            biometric::Error::Busy => tr.invoke_fp_busy(),
            e => tr.invoke_fp_error(e.to_string().into()),
        }
        .into()
    }

    /// `state`: 0 = hidden, 1 = waiting for a finger, 2 = stopped (retry
    /// link), 3 = note only (no key: the password is needed first).
    fn fp_show(&self, state: i32, text: &str) {
        let ui = self.ui();
        ui.set_fp_state(state);
        ui.set_fp_message(text.into());
    }

    /// Stops the fingerprint check, if any, and hides its prompt.
    fn stop_fingerprint(&mut self) {
        self.fp_round += 1;
        if let Some((cancel, _)) = self.fp_cancel.take() {
            cancel.cancel();
        }
        self.fp_show(0, "");
    }

    /// On the unlock screen: if the selected vault has fingerprint unlock and
    /// its key is still stored, waits for a finger in the background, like
    /// sudo with pam_fprintd. The password field keeps working meanwhile.
    fn start_fingerprint(&mut self) {
        let ui = self.ui();
        let meta = if self.fp_support != Availability::Ready
            || self.vault.is_some()
            || ui.get_screen() != Screen::Unlock
            || ui.get_create_mode()
        {
            None
        } else {
            usize::try_from(ui.get_vault_index())
                .ok()
                .and_then(|i| self.vaults.get(i))
                .cloned()
        };
        // Already waiting for this vault (several triggers fire at start).
        if let (Some(meta), Some((_, id))) = (&meta, &self.fp_cancel)
            && meta.id == *id
        {
            return;
        }
        self.stop_fingerprint();
        let Some(meta) = meta.filter(|m| self.settings.fingerprint(&m.id)) else {
            return;
        };
        // Expired or never stored since the last restart.
        if !biometric::has_key(&meta.id) {
            self.fp_show(3, &self.say(|tr| tr.invoke_fp_expired()));
            return;
        }
        let cancel = FpCancel::new();
        self.fp_cancel = Some((cancel.clone(), meta.id.clone()));
        let round = self.fp_round;
        std::thread::spawn(move || {
            post_fp(round, |app| {
                let text = app.fp_text(FpEvent::Prompt {
                    finger: None,
                    swipe: false,
                });
                app.fp_show(1, &text);
            });
            let verdict = biometric::verify(&cancel, biometric::VERIFY_TIMEOUT, |event| {
                post_fp(round, move |app| {
                    let text = app.fp_text(event);
                    app.fp_show(1, &text);
                });
            });
            let outcome = match verdict {
                Ok(Verdict::Match) => match biometric::open(meta) {
                    Ok(Some(vault)) => FpOutcome::Opened(vault),
                    Ok(None) => FpOutcome::Reset,
                    Err(e) => FpOutcome::Failed(e),
                },
                Ok(Verdict::NoMatch) => FpOutcome::NoMatch,
                Ok(Verdict::TimedOut) => FpOutcome::TimedOut,
                Ok(Verdict::Cancelled) => return,
                Err(e) => FpOutcome::Failed(e),
            };
            post_fp(round, move |app| app.finish_fingerprint(outcome));
        });
    }

    fn finish_fingerprint(&mut self, outcome: FpOutcome) {
        self.fp_cancel = None;
        let text = match outcome {
            FpOutcome::Opened(vault) => {
                self.finish_unlock(Ok(vault), false);
                return;
            }
            FpOutcome::Reset => {
                self.stop_fingerprint();
                let text = self.say(|tr| tr.invoke_fp_reset());
                self.ui().set_unlock_error(text.into());
                return;
            }
            FpOutcome::NoMatch => self.say(|tr| tr.invoke_fp_failed()),
            FpOutcome::TimedOut => self.say(|tr| tr.invoke_fp_timed_out()),
            FpOutcome::Failed(e) => self.fp_error_text(&e),
        };
        self.fp_show(2, &text);
    }

    /// Updates the settings switch for the open vault.
    fn refresh_fp_enabled(&self) {
        let on = self
            .vault
            .as_ref()
            .is_some_and(|v| self.settings.fingerprint(&v.meta().id));
        self.ui().set_fp_enabled(on);
    }

    /// Settings switch. On: stores the open vault's key right away (the
    /// vault is open, so this counts as a password unlock). Off: removes it.
    fn set_fingerprint(&mut self, on: bool) {
        let Some(vault) = &self.vault else {
            return;
        };
        let id = vault.meta().id.clone();
        let result = if on {
            biometric::store_key(&id, vault.key())
        } else {
            biometric::remove_key(&id)
        };
        match result {
            Ok(()) => {
                self.settings.set_fingerprint(&id, on);
                self.save_settings();
                self.ui().set_fp_enabled(on);
                let text = self.say(|tr| {
                    if on {
                        tr.invoke_fp_on()
                    } else {
                        tr.invoke_fp_off()
                    }
                });
                self.toast(&text);
            }
            Err(e) => {
                self.refresh_fp_enabled();
                let text = self.fp_error_text(&e);
                self.toast(&text);
            }
        }
    }

    // ---------- entries ----------

    fn reload(&mut self) {
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let entries = store.list_entries(vault);
        let folders = store.list_folders(vault);
        match entries {
            Ok(entries) => self.entries = entries,
            Err(e) => self.toast(&self.error_text(&e)),
        }
        match folders {
            Ok(folders) => self.folders = folders,
            Err(e) => self.toast(&self.error_text(&e)),
        }
        // The shown folder may have been deleted.
        if self.filter == 4
            && self
                .folder
                .as_deref()
                .and_then(|id| self.find_folder(id))
                .is_none()
        {
            self.set_filter_state(0, None);
        }
        self.update_list();
        self.update_detail();
        self.update_security();
    }

    fn matches_filter(&self, e: &Entry) -> bool {
        match self.filter {
            1 => e.favorite,
            2 => e.kind == EntryKind::Card,
            3 => e.kind == EntryKind::Note,
            4 => e.folder.is_some() && e.folder == self.folder,
            _ => true,
        }
    }

    fn find_folder(&self, id: &str) -> Option<&Folder> {
        self.folders.iter().find(|f| f.id == id)
    }

    /// The entry's folder, if it still exists.
    fn folder_of(&self, e: &Entry) -> Option<&Folder> {
        e.folder.as_deref().and_then(|id| self.find_folder(id))
    }

    fn set_filter_state(&mut self, filter: i32, folder: Option<String>) {
        let ui = self.ui();
        ui.set_filter(filter);
        ui.set_active_folder(folder.as_deref().unwrap_or_default().into());
        self.filter = filter;
        self.folder = folder;
    }

    fn update_list(&mut self) {
        let q = self.query.trim().to_lowercase();
        let has = |s: Option<&str>| s.is_some_and(|s| s.to_lowercase().contains(&q));
        let mut visible: Vec<usize> = (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                self.matches_filter(e)
                    && (q.is_empty()
                        || e.title.to_lowercase().contains(&q)
                        || has(e.username.as_deref())
                        || has(e.url.as_deref())
                        || (e.kind == EntryKind::Note && has(e.notes.as_deref()))
                        || e.card.as_ref().is_some_and(|c| {
                            has(Some(&c.holder))
                                || (q.len() >= 4 && card_fmt::digits(&c.number).ends_with(&q))
                        }))
            })
            .collect();
        if self.sort_by_date {
            visible.sort_by_key(|&i| std::cmp::Reverse(self.entries[i].updated_at));
        } else {
            visible.sort_by_cached_key(|&i| self.entries[i].title.to_lowercase());
        }
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        let items: Vec<EntryItem> = visible
            .iter()
            .map(|&i| {
                let e = &self.entries[i];
                EntryItem {
                    id: e.id.as_str().into(),
                    title: e.title.as_str().into(),
                    subtitle: subtitle(&tr, e).into(),
                    letter: format::letter(&e.title).into(),
                    color: format::avatar_color(&e.title),
                    has_totp: e.kind == EntryKind::Login && e.totp_secret.is_some(),
                    kind: kind_index(e.kind),
                    favorite: e.favorite,
                }
            })
            .collect();
        self.items.set_vec(items);
        self.visible = visible;

        let ui = self.ui();
        let count =
            |f: &dyn Fn(&Entry) -> bool| self.entries.iter().filter(|e| f(e)).count() as i32;
        ui.set_total(self.entries.len() as i32);
        ui.set_favorite_count(count(&|e| e.favorite));
        ui.set_card_count(count(&|e| e.kind == EntryKind::Card));
        ui.set_note_count(count(&|e| e.kind == EntryKind::Note));
        ui.set_sort_by_date(self.sort_by_date);

        let folder_items: Vec<FolderItem> = self
            .folders
            .iter()
            .map(|f| FolderItem {
                id: f.id.as_str().into(),
                name: f.name.as_str().into(),
                color: format::folder_color(&f.color),
                count: count(&|e| e.folder.as_deref() == Some(f.id.as_str())),
            })
            .collect();
        self.folder_items.set_vec(folder_items);
        let active_name = self
            .folder
            .as_deref()
            .and_then(|id| self.find_folder(id))
            .map(|f| f.name.clone())
            .unwrap_or_default();
        ui.set_active_folder_name(active_name.into());
    }

    /// Keeps the selection if still visible, otherwise selects the first row.
    fn ensure_selection(&mut self) {
        let visible = self
            .selected
            .as_deref()
            .is_some_and(|id| self.visible.iter().any(|&i| self.entries[i].id == id));
        if !visible {
            self.selected = self.visible.first().map(|&i| self.entries[i].id.clone());
            self.ui().set_password_revealed(false);
        }
        self.update_detail();
    }

    fn select_filter(&mut self, filter: i32) {
        self.set_filter_state(filter, None);
        let ui = self.ui();
        ui.set_page(Page::Vault);
        self.update_list();
        self.ensure_selection();
    }

    fn select_folder(&mut self, id: &str) {
        if self.find_folder(id).is_none() {
            return;
        }
        self.set_filter_state(4, Some(id.to_owned()));
        self.ui().set_page(Page::Vault);
        self.update_list();
        self.ensure_selection();
    }

    /// Moves an entry to a folder ("" = out of any folder) from the detail chip.
    fn move_to_folder(&mut self, id: &str, folder: &str) {
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let folder = (!folder.is_empty()).then(|| folder.to_owned());
        if let Err(e) = store.set_folder(vault, id, folder.as_deref()) {
            self.toast(&self.error_text(&e));
            self.reload();
            return;
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.folder = folder.clone();
        }
        self.changed();
        let text = match folder.as_deref().and_then(|f| self.find_folder(f)) {
            Some(f) => self.say(|tr| tr.invoke_moved_to_folder(f.name.as_str().into())),
            None => self.say(|tr| tr.invoke_removed_from_folder()),
        };
        self.update_list();
        self.ensure_selection();
        self.toast(&text);
    }

    fn toggle_favorite(&mut self, id: &str) {
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let Some(fav) = self.entries.iter().find(|e| e.id == id).map(|e| e.favorite) else {
            return;
        };
        if let Err(e) = store.set_favorite(vault, id, !fav) {
            self.toast(&self.error_text(&e));
            return;
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.favorite = !fav;
        }
        self.changed();
        self.update_list();
        self.update_detail();
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let id = self.selected.as_deref()?;
        self.entries.iter().find(|e| e.id == id)
    }

    fn update_detail(&mut self) {
        let ui = self.ui();
        let Some(e) = self.selected_entry() else {
            ui.set_has_detail(false);
            ui.set_selected_id("".into());
            return;
        };
        let now = now_unix();
        let card = e.card.clone().unwrap_or_default();
        let folder = self.folder_of(e);
        ui.set_detail(EntryDetail {
            folder_id: folder.map(|f| f.id.as_str()).unwrap_or_default().into(),
            folder_name: folder.map(|f| f.name.as_str()).unwrap_or_default().into(),
            folder_color: folder
                .map(|f| format::folder_color(&f.color))
                .unwrap_or_default(),
            id: e.id.as_str().into(),
            title: e.title.as_str().into(),
            letter: format::letter(&e.title).into(),
            color: format::avatar_color(&e.title),
            domain: e
                .url
                .as_deref()
                .map(format::domain)
                .unwrap_or_default()
                .into(),
            url: e.url.clone().unwrap_or_default().into(),
            username: e.username.clone().unwrap_or_default().into(),
            password: e.password.clone().unwrap_or_default().into(),
            notes: e.notes.clone().unwrap_or_default().into(),
            has_totp: e.kind == EntryKind::Login && e.totp_secret.is_some(),
            meta: text::entry_meta(&ui.global::<Tr>(), e.created_at, e.updated_at, now).into(),
            kind: kind_index(e.kind),
            favorite: e.favorite,
            card_holder: card.holder.as_str().into(),
            card_number: card_fmt::format_number(&card.number).into(),
            card_digits: card_fmt::digits(&card.number).into(),
            card_last4: card_fmt::last4(&card.number).into(),
            card_brand: card_fmt::brand(&card.number).unwrap_or_default().into(),
            card_expiry: card.expiry.as_str().into(),
            card_cvv: card.cvv.as_str().into(),
            card_pin: card.pin.as_str().into(),
            card_status: card_status(&card, now),
        });
        ui.set_selected_id(e.id.as_str().into());
        ui.set_has_detail(true);
        self.update_totp();
    }

    fn update_totp(&self) {
        let ui = self.ui();
        let Some(secret) = self
            .selected_entry()
            .filter(|e| e.kind == EntryKind::Login)
            .and_then(|e| {
                e.totp_secret
                    .as_deref()
                    .map(|s| (s.to_owned(), e.totp_digits, e.totp_period))
            })
        else {
            return;
        };
        let (secret, digits, period) = secret;
        let now = now_unix().max(0) as u64;
        match totp::code(&secret, now, digits, period) {
            Ok(code) => {
                self.set_totp_digits(&code);
                ui.set_totp_code(format::group_code(&code).into());
                ui.set_totp_raw(code.into());
                ui.set_totp_remaining(totp::remaining(now, period) as i32);
            }
            Err(_) => {
                ui.set_totp_code("".into());
                ui.set_totp_raw("".into());
            }
        }
    }

    /// Updates only the digits that changed, so each roller animates.
    fn set_totp_digits(&self, code: &str) {
        let digits: Vec<i32> = code
            .chars()
            .filter_map(|c| c.to_digit(10))
            .map(|d| d as i32)
            .collect();
        if self.totp_digits.row_count() != digits.len() {
            self.totp_digits.set_vec(digits);
            return;
        }
        for (i, d) in digits.into_iter().enumerate() {
            if self.totp_digits.row_data(i) != Some(d) {
                self.totp_digits.set_row_data(i, d);
            }
        }
    }

    fn select(&mut self, id: &str) {
        if self.selected.as_deref() != Some(id) {
            self.ui().set_password_revealed(false);
        }
        self.selected = Some(id.to_owned());
        self.update_detail();
    }

    fn update_security(&mut self) {
        let now = now_unix();
        let report = audit::audit(&self.entries, now);
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        let issues: Vec<Issue> = report
            .issues
            .iter()
            .map(|i| Issue {
                id: i.entry_id.as_str().into(),
                title: i.title.as_str().into(),
                text: match &i.kind {
                    IssueKind::WeakReused(others) => {
                        tr.invoke_issue_weak_reused(text::list(&tr, others).into())
                    }
                    IssueKind::Weak => tr.invoke_issue_weak(),
                    IssueKind::Reused(others) => {
                        tr.invoke_issue_reused(text::list(&tr, others).into())
                    }
                    IssueKind::Stale => tr.invoke_issue_stale(),
                    IssueKind::CardExpired => tr.invoke_issue_card_expired(),
                    IssueKind::CardExpiring => tr.invoke_issue_card_expiring(),
                },
                severity: match i.severity() {
                    Severity::High => 0,
                    Severity::Medium => 1,
                    Severity::Low => 2,
                },
            })
            .collect();
        let month_ago = now - 30 * 24 * 60 * 60;
        let stats = SecurityStats {
            score: report.score as i32,
            ring: format::score_ring(report.score).into(),
            summary: text::score_summary(&tr, report.score, report.issues.len()).into(),
            audited_at: tr.invoke_audited_at(format::time_now().into()),
            weak: report.weak as i32,
            reused: report.reused as i32,
            stale: report.stale as i32,
            with_totp: report.with_totp as i32,
            total: report.total as i32,
            logins: report.logins as i32,
            added_month: self
                .entries
                .iter()
                .filter(|e| e.created_at >= month_ago)
                .count() as i32,
        };
        self.issues.set_vec(issues);
        self.ui().set_stats(stats);
    }

    fn show_form(&self, initial: EntryForm) {
        let ui = self.ui();
        ui.set_form_open(false);
        ui.set_form_error("".into());
        ui.set_form_initial(initial);
        ui.set_form_open(true);
    }

    fn new_entry(&mut self, kind: i32) {
        // A new entry created from the favourites list or a folder starts
        // there.
        let folder = if self.filter == 4 {
            self.folder.as_deref().and_then(|id| self.find_folder(id))
        } else {
            None
        };
        let (folder, folder_name, folder_color) = folder_fields(folder);
        self.show_form(EntryForm {
            kind,
            favorite: self.filter == 1,
            folder,
            folder_name,
            folder_color,
            ..EntryForm::default()
        });
    }

    fn open_form(&mut self, id: &str) {
        let Some(e) = self.entries.iter().find(|e| e.id == id) else {
            return;
        };
        let card = e.card.clone().unwrap_or_default();
        let (folder, folder_name, folder_color) = folder_fields(self.folder_of(e));
        let initial = EntryForm {
            folder,
            folder_name,
            folder_color,
            id: e.id.as_str().into(),
            kind: kind_index(e.kind),
            favorite: e.favorite,
            title: e.title.as_str().into(),
            username: e.username.clone().unwrap_or_default().into(),
            password: e.password.clone().unwrap_or_default().into(),
            url: e.url.clone().unwrap_or_default().into(),
            totp_secret: e.totp_secret.clone().unwrap_or_default().into(),
            notes: e.notes.clone().unwrap_or_default().into(),
            card_holder: card.holder.as_str().into(),
            card_number: card_fmt::format_number(&card.number).into(),
            card_expiry: card.expiry.as_str().into(),
            card_cvv: card.cvv.as_str().into(),
            card_pin: card.pin.as_str().into(),
        };
        self.show_form(initial);
    }

    fn save(&mut self, form: EntryForm) {
        let ui = self.ui();
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let secret = form.totp_secret.trim();
        if !secret.is_empty() && !totp::is_valid_secret(secret) {
            ui.set_form_error(ui.global::<Tr>().invoke_totp_invalid());
            return;
        }
        let kind = kind_from(form.kind);
        let expiry = form.card_expiry.trim();
        if kind == EntryKind::Card && !expiry.is_empty() && card_fmt::parse_expiry(expiry).is_none()
        {
            ui.set_form_error(ui.global::<Tr>().invoke_expiry_invalid());
            return;
        }
        let opt = |s: &SharedString| Some(s.to_string());
        let mut input = EntryInput::default();
        input.kind = kind;
        input.favorite = form.favorite;
        input.title = form.title.trim().to_owned();
        if kind == EntryKind::Card {
            input.card = Some(Card {
                holder: form.card_holder.trim().to_owned(),
                number: card_fmt::digits(&form.card_number),
                expiry: card_fmt::parse_expiry(expiry)
                    .map(|(m, y)| format!("{m:02}/{:02}", y % 100))
                    .unwrap_or_default(),
                cvv: form.card_cvv.trim().to_owned(),
                pin: form.card_pin.trim().to_owned(),
            });
        }
        input.username = opt(&form.username);
        input.password = opt(&form.password);
        input.url = opt(&form.url);
        input.notes = opt(&form.notes);
        input.totp_secret = opt(&form.totp_secret);
        // A folder deleted while the form was open is dropped silently.
        input.folder = Some(form.folder.to_string()).filter(|f| self.find_folder(f).is_some());
        let result = if form.id.is_empty() {
            store.create_entry(vault, &input)
        } else {
            store
                .update_entry(vault, &form.id, &input)
                .map(|()| form.id.to_string())
        };
        match result {
            Ok(id) => {
                ui.set_form_open(false);
                ui.set_form_initial(EntryForm::default());
                if ui.get_page() == Page::Vault {
                    self.selected = Some(id);
                }
                self.reload();
                self.changed();
                self.toast(&self.say(|tr| tr.invoke_item_saved()));
            }
            Err(e) => ui.set_form_error(self.error_text(&e).into()),
        }
    }

    fn request_delete(&mut self, id: &str) {
        let Some(e) = self.entries.iter().find(|e| e.id == id) else {
            return;
        };
        let ui = self.ui();
        ui.set_delete_title(e.title.as_str().into());
        self.deleting = Some(id.to_owned());
        ui.set_delete_open(true);
    }

    fn confirm_delete(&mut self) {
        let ui = self.ui();
        ui.set_delete_open(false);
        let (Some(store), Some(vault), Some(id)) = (&self.store, &self.vault, self.deleting.take())
        else {
            return;
        };
        // The entry is gone from the database right away; the animation is
        // purely visual.
        if let Err(e) = store.delete_entry(vault, &id) {
            self.toast(&self.error_text(&e));
            return;
        }
        self.changed();
        // Select the neighbour of the deleted entry.
        if self.selected.as_deref() == Some(&id) {
            let pos = self.visible.iter().position(|&i| self.entries[i].id == id);
            let next = pos.and_then(|p| {
                self.visible
                    .get(p + 1)
                    .or_else(|| p.checked_sub(1).and_then(|q| self.visible.get(q)))
            });
            self.selected = next.map(|&i| self.entries[i].id.clone());
        }
        self.toast(&self.say(|tr| tr.invoke_item_deleted()));

        // "Thanos snap": dissolve the row using a snapshot of the window
        // (the confirmation dialog is already closed). Without a snapshot,
        // just remove it.
        match ui.window().take_snapshot() {
            Ok(buffer) if ui.get_page() == Page::Vault => {
                let fx = ui.global::<DeleteFx>();
                fx.set_scale(ui.window().scale_factor());
                SNAPSHOT.with_borrow_mut(|s| *s = Some(buffer));
                fx.set_entry_id(id.as_str().into());
                self.fx_timer
                    .start(TimerMode::SingleShot, SNAP_DURATION, || {
                        with_app(|app| {
                            app.end_snap();
                            app.reload();
                        })
                    });
            }
            _ => self.reload(),
        }
    }

    fn end_snap(&mut self) {
        self.fx_timer.stop();
        let ui = self.ui();
        let fx = ui.global::<DeleteFx>();
        fx.set_entry_id("".into());
        SNAPSHOT.with_borrow_mut(|s| *s = None);
    }

    // ---------- vault management ----------

    fn vault_action(&mut self, action: i32) {
        let ui = self.ui();
        match action {
            // Switch: lock and show the vault picker.
            0 => self.lock(),
            // New vault: lock and open the create form.
            1 => {
                self.lock();
                ui.set_create_mode(true);
            }
            2 => {
                ui.set_vault_dialog_error("".into());
                ui.set_vault_dialog(1);
            }
            3 => {
                ui.set_vault_dialog_error("".into());
                ui.set_vault_dialog_busy(false);
                ui.set_vault_dialog(3);
            }
            4 => {
                let count = match (&self.store, &self.vault) {
                    (Some(store), Some(vault)) => store.entry_count(&vault.meta().id).unwrap_or(0),
                    _ => 0,
                };
                ui.set_vault_entry_count(count as i32);
                ui.set_vault_dialog_error("".into());
                ui.set_vault_dialog_busy(false);
                ui.set_vault_dialog(2);
            }
            _ => {}
        }
    }

    fn rename_vault(&mut self, name: &str) {
        let ui = self.ui();
        let (Some(store), Some(vault)) = (&self.store, self.vault.as_mut()) else {
            return;
        };
        match store.rename_vault(vault, name) {
            Ok(()) => {
                ui.set_vault_name(vault.meta().name.as_str().into());
                ui.set_vault_initials(format::initials(&vault.meta().name).into());
                ui.set_vault_dialog(0);
                self.load_vaults();
                self.changed();
                self.toast(&self.say(|tr| tr.invoke_vault_renamed()));
            }
            Err(e) => ui.set_vault_dialog_error(self.error_text(&e).into()),
        }
    }

    /// Checks the current password and wraps the vault key under the new
    /// one (two Argon2 runs on a worker thread), then saves it.
    fn start_change_password(&mut self, current: SharedString, new: SharedString) {
        let Some(change) = self.vault.as_ref().map(Vault::password_change) else {
            return;
        };
        let ui = self.ui();
        ui.set_vault_dialog_busy(true);
        ui.set_vault_dialog_error("".into());
        std::thread::spawn(move || {
            let result = change.prepare(current.as_str(), new.as_str());
            drop((current, new));
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_change_password(result))
            });
        });
    }

    fn finish_change_password(&mut self, result: vykey_core::Result<vykey_core::KeyWrap>) {
        let ui = self.ui();
        ui.set_vault_dialog_busy(false);
        // Locked meanwhile: nothing to save to.
        let (Some(store), Some(vault)) = (&self.store, self.vault.as_mut()) else {
            return;
        };
        match result.and_then(|wrap| store.change_password(vault, wrap)) {
            Ok(()) => {
                ui.set_vault_dialog(0);
                self.changed();
                self.toast(&self.say(|tr| tr.invoke_password_changed()));
            }
            Err(e) => ui.set_vault_dialog_error(self.error_text(&e).into()),
        }
    }

    /// Re-checks the master password (Argon2 on a worker thread), then
    /// deletes the open vault with all its entries.
    fn start_delete_vault(&mut self, password: SharedString) {
        let ui = self.ui();
        let Some(meta) = self.vault.as_ref().map(|v| v.meta().clone()) else {
            return;
        };
        ui.set_vault_dialog_busy(true);
        std::thread::spawn(move || {
            let result = Vault::unlock(meta, password.as_str());
            drop(password);
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_delete_vault(result))
            });
        });
    }

    fn finish_delete_vault(&mut self, result: vykey_core::Result<Vault>) {
        let ui = self.ui();
        ui.set_vault_dialog_busy(false);
        let verified = match result {
            Ok(v) => v,
            Err(e) => {
                ui.set_vault_dialog_error(self.error_text(&e).into());
                return;
            }
        };
        let same = self
            .vault
            .as_ref()
            .is_some_and(|v| v.meta().id == verified.meta().id);
        let Some(store) = &self.store else {
            return;
        };
        if !same {
            return;
        }
        let name = verified.meta().name.clone();
        let id = verified.meta().id.clone();
        if let Err(e) = store.delete_vault(verified) {
            ui.set_vault_dialog_error(self.error_text(&e).into());
            return;
        }
        self.changed();
        // Its key in the keyring opens nothing any more.
        let _ = biometric::remove_key(&id);
        if self.settings.fingerprint(&id) {
            self.settings.set_fingerprint(&id, false);
            self.save_settings();
        }
        self.lock();
        ui.set_vault_index(0);
        self.load_vaults();
        self.toast(&self.say(|tr| tr.invoke_vault_deleted(name.as_str().into())));
    }

    // ---------- folders ----------

    fn new_folder(&mut self) {
        let ui = self.ui();
        self.folder_edit = None;
        ui.set_folder_edit_id("".into());
        ui.set_folder_edit_name("".into());
        // Each new folder gets the next colour of the palette.
        ui.set_folder_edit_color((self.folders.len() % format::FOLDER_COLORS.len()) as i32);
        ui.set_folder_dialog_error("".into());
        ui.set_folder_dialog(1);
    }

    /// From the sidebar folder menu: 0 = edit, 1 = delete.
    fn folder_action(&mut self, id: &str, action: i32) {
        let Some(folder) = self.find_folder(id) else {
            return;
        };
        let ui = self.ui();
        ui.set_folder_edit_id(folder.id.as_str().into());
        ui.set_folder_edit_name(folder.name.as_str().into());
        ui.set_folder_edit_color(format::folder_color_index(&folder.color) as i32);
        ui.set_folder_dialog_error("".into());
        self.folder_edit = Some(folder.id.clone());
        match action {
            0 => ui.set_folder_dialog(1),
            1 => {
                let count = self
                    .entries
                    .iter()
                    .filter(|e| e.folder.as_deref() == Some(id))
                    .count();
                ui.set_folder_delete_count(count as i32);
                ui.set_folder_dialog(2);
            }
            _ => {}
        }
    }

    fn save_folder(&mut self, name: &str, color: i32) {
        let ui = self.ui();
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            ui.set_folder_dialog_error(ui.global::<Tr>().invoke_enter_name());
            return;
        }
        let color = usize::try_from(color)
            .ok()
            .and_then(|i| format::FOLDER_COLORS.get(i))
            .copied()
            .unwrap_or(format::FOLDER_COLORS[0]);
        let result = match &self.folder_edit {
            Some(id) => store.update_folder(vault, id, name, color).map(|()| None),
            None => store.create_folder(vault, name, color).map(Some),
        };
        match result {
            Ok(created) => {
                ui.set_folder_dialog(0);
                self.folder_edit = None;
                self.reload();
                self.changed();
                match created {
                    // Open the new folder, so it can be filled right away.
                    Some(id) => {
                        self.select_folder(&id);
                        self.toast(&self.say(|tr| tr.invoke_folder_created()));
                    }
                    None => self.toast(&self.say(|tr| tr.invoke_folder_saved())),
                }
            }
            Err(e) => ui.set_folder_dialog_error(self.error_text(&e).into()),
        }
    }

    fn confirm_delete_folder(&mut self) {
        let ui = self.ui();
        ui.set_folder_dialog(0);
        let (Some(store), Some(vault), Some(id)) =
            (&self.store, &self.vault, self.folder_edit.take())
        else {
            return;
        };
        let name = self
            .find_folder(&id)
            .map(|f| f.name.clone())
            .unwrap_or_default();
        if let Err(e) = store.delete_folder(vault, &id) {
            self.toast(&self.error_text(&e));
            return;
        }
        self.changed();
        // `reload` falls back to "all entries" if this folder was shown.
        self.reload();
        self.ensure_selection();
        self.toast(&self.say(|tr| tr.invoke_folder_deleted(name.as_str().into())));
    }

    // ---------- clipboard ----------

    fn copy(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.clipboard.is_none() {
            self.clipboard = arboard::Clipboard::new().ok();
        }
        let Some(cb) = self.clipboard.as_mut() else {
            self.toast(&self.say(|tr| tr.invoke_clipboard_unavailable()));
            return;
        };
        match cb.set_text(text.to_owned()) {
            Ok(()) => {
                self.copied = Some((Instant::now(), text.to_owned()));
                self.toast(&self.say(|tr| tr.invoke_copied()));
            }
            Err(_) => self.toast(&self.say(|tr| tr.invoke_copy_failed())),
        }
    }

    // ---------- periodic work ----------

    fn tick(&mut self) {
        // The window may move to a screen with another scale factor.
        let ui = self.ui();
        let hidpi = ui.window().scale_factor() >= 1.5;
        if ui.global::<Theme>().get_hidpi() != hidpi {
            ui.global::<Theme>().set_hidpi(hidpi);
        }
        if self.vault.is_some() {
            if let Some(timeout) = self.lock_timeout
                && self.last_activity.elapsed() >= timeout
            {
                self.lock();
            } else {
                self.update_totp();
            }
        }
        if let Some((at, value)) = &self.copied
            && at.elapsed() >= CLIPBOARD_CLEAR_AFTER
        {
            if let Some(cb) = self.clipboard.as_mut()
                && cb.get_text().ok().as_deref() == Some(value.as_str())
            {
                let _ = cb.clear();
            }
            self.copied = None;
        }
        if self.toast_until.is_some_and(|t| Instant::now() >= t) {
            self.toast_until = None;
            self.ui().set_toast("".into());
        }
        if !self.sync.running && self.sync.due.is_some_and(|t| Instant::now() >= t) {
            self.start_sync();
        }
        // "synced 3 minutes ago" moves on.
        if ui.get_screen() == Screen::Main && ui.get_page() == Page::Settings {
            self.update_sync_ui();
        }
    }

    // ---------- sync ----------

    fn sync_account(&self) -> Option<SyncAccount> {
        self.store.as_ref()?.sync_account().ok().flatten()
    }

    /// Something was saved: upload it shortly.
    fn changed(&mut self) {
        self.schedule_sync(SYNC_SOON);
    }

    /// Runs a sync round after `delay` (or earlier, if one is due earlier).
    fn schedule_sync(&mut self, delay: Duration) {
        if self.sync_account().is_none() {
            self.sync.due = None;
            return;
        }
        let at = Instant::now() + delay;
        self.sync.due = Some(self.sync.due.map_or(at, |t| t.min(at)));
    }

    fn update_sync_ui(&self) {
        let ui = self.ui();
        let account = self.sync_account();
        ui.set_sync_connected(account.is_some());
        ui.set_sync_busy(self.sync.running);
        ui.set_sync_failed(self.sync.error.is_some());
        let tr = ui.global::<Tr>();
        // First run: fetching vaults instead of creating one.
        ui.set_sync_offer(account.is_none() && self.store.is_some());
        let note = match &account {
            Some(a) if self.vaults.is_empty() => match &self.sync.error {
                Some(err) => err.clone(),
                None if self.sync.running || a.last_synced_at.is_none() => {
                    tr.invoke_sync_fetching(server_name(&tr, a)).into()
                }
                None => tr.invoke_sync_account_empty().into(),
            },
            _ => String::new(),
        };
        ui.set_sync_note(note.into());
        let status = account.map_or_else(String::new, |a| {
            let host = server_name(&tr, &a);
            match (&self.sync.error, a.last_synced_at) {
                (Some(err), _) => tr.invoke_sync_failed(host, err.into()),
                (None, Some(at)) => {
                    tr.invoke_sync_synced(host, text::relative(&tr, at, now_unix()).into())
                }
                (None, None) => tr.invoke_sync_never(host),
            }
            .into()
        });
        ui.set_sync_status(status.into());
    }

    fn sync_error_text(&self, e: &SyncError) -> String {
        let ui = self.ui();
        let tr = ui.global::<Tr>();
        match e {
            SyncError::Network(_) => tr.invoke_sync_offline().into(),
            SyncError::Address(AddressError::Insecure) => tr.invoke_sync_insecure().into(),
            SyncError::Address(AddressError::Invalid) => tr.invoke_sync_bad_address().into(),
            SyncError::Store(err) => self.error_text(err),
            SyncError::Server { code, status, .. } => match code {
                Some(ErrorCode::Unauthorized) => tr.invoke_sync_unknown_account().into(),
                Some(ErrorCode::RegistrationClosed) => tr.invoke_sync_registration_closed().into(),
                Some(ErrorCode::QuotaExceeded) => tr.invoke_sync_quota().into(),
                Some(ErrorCode::RateLimited) => tr.invoke_sync_busy_server().into(),
                _ if *status == 502 || *status == 503 || *status == 504 => {
                    tr.invoke_sync_busy_server().into()
                }
                _ => tr.invoke_sync_error(e.to_string().into()).into(),
            },
            _ => tr.invoke_sync_error(e.to_string().into()).into(),
        }
    }

    /// One sync round on a worker thread, with its own database connection
    /// and a copy of the unlocked vault (if any).
    fn start_sync(&mut self) {
        self.sync.due = None;
        let (Some(path), Some(account)) = (self.db_path.clone(), self.sync_account()) else {
            return;
        };
        self.sync.running = true;
        self.update_sync_ui();
        let vault = self.vault.clone();
        let vault_id = vault.as_ref().map(|v| v.meta().id.clone());
        std::thread::spawn(move || {
            let result = (|| -> Result<Report, SyncError> {
                let store = Store::open(&path)?;
                let client = HttpClient::new(&account.server_url)?.with_token(&account.token);
                vsync::sync(&store, vault.as_ref(), &client)
            })();
            drop(vault); // the key copy is wiped
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_sync(result, vault_id))
            });
        });
    }

    fn finish_sync(&mut self, result: Result<Report, SyncError>, vault_id: Option<String>) {
        self.sync.running = false;
        if self.sync.disconnect_after {
            self.disconnect_sync();
            return;
        }
        let open_id = self.vault.as_ref().map(|v| v.meta().id.clone());
        let same_vault = vault_id.is_some() && vault_id == open_id;
        match result {
            Ok(r) => {
                self.sync.failures = 0;
                self.sync.error = None;
                if let Some(secs) = r.poll_after {
                    self.sync.poll = Some(Duration::from_secs(u64::from(secs).clamp(30, 3600)));
                }
                if r.open_vault_deleted && same_vault {
                    let name = self.vault.as_ref().map(|v| v.meta().name.clone());
                    self.lock();
                    if let Some(name) = name {
                        self.toast(&self.say(|tr| tr.invoke_sync_vault_gone(name.as_str().into())));
                    }
                } else {
                    if r.vaults_changed {
                        self.refresh_open_vault();
                        self.load_vaults();
                    }
                    if same_vault && r.open_vault_changed {
                        self.reload();
                    }
                }
                for name in &r.password_changed {
                    let text = self.say(|tr| tr.invoke_sync_password_changed(name.as_str().into()));
                    self.toast(&text);
                }
                // Unlocked (or switched) during the round: its contents next.
                if open_id != vault_id && open_id.is_some() {
                    self.schedule_sync(Duration::ZERO);
                }
                self.schedule_sync(self.sync.poll.unwrap_or(SYNC_POLL));
            }
            Err(e) => {
                self.sync.failures += 1;
                self.sync.error = Some(self.sync_error_text(&e));
                let wait = match &e {
                    SyncError::Server {
                        retry_after: Some(s),
                        ..
                    } => Duration::from_secs(*s),
                    _ => retry_delay(self.sync.failures),
                };
                self.schedule_sync(wait);
            }
        }
        self.update_sync_ui();
    }

    /// After a sync changed vault records: the open vault may have been
    /// renamed (or re-keyed with the same data key) on another device.
    fn refresh_open_vault(&mut self) {
        let (Some(store), Some(vault)) = (&self.store, &self.vault) else {
            return;
        };
        let Ok(vaults) = store.list_vaults() else {
            return;
        };
        let Some(meta) = vaults.into_iter().find(|m| m.id == vault.meta().id) else {
            return;
        };
        match Vault::unlock_with_key(meta, vault.key().clone()) {
            Ok(v) => {
                let ui = self.ui();
                ui.set_vault_name(v.meta().name.as_str().into());
                ui.set_vault_initials(format::initials(&v.meta().name).into());
                self.vault = Some(v);
            }
            // The key no longer opens it: lock, the password will tell.
            Err(_) => self.lock(),
        }
    }

    fn start_sync_create(&mut self, server: &str, invite: &str) {
        if self.sync.setting_up {
            return;
        }
        let (server, invite) = (server.to_owned(), invite.to_owned());
        self.begin_setup();
        std::thread::spawn(move || {
            let result = HttpClient::new(&server).and_then(|c| {
                let token = c.create_account(Some(invite.as_str()))?;
                Ok((c.server_url().to_owned(), token))
            });
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_sync_setup(result, true))
            });
        });
    }

    fn start_sync_join(&mut self, server: &str, token: &str) {
        if self.sync.setting_up {
            return;
        }
        let Ok(token) = token.parse::<Token>() else {
            let text = self.say(|tr| tr.invoke_sync_bad_token());
            self.ui().set_sync_dialog_error(text.into());
            return;
        };
        let server = server.to_owned();
        self.begin_setup();
        std::thread::spawn(move || {
            let result = HttpClient::new(&server).and_then(|c| {
                let c = c.with_token(&token);
                // Checks the token before anything is stored.
                c.account_info()?;
                Ok((c.server_url().to_owned(), token))
            });
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.finish_sync_setup(result, false))
            });
        });
    }

    fn begin_setup(&mut self) {
        self.sync.setting_up = true;
        let ui = self.ui();
        ui.set_sync_dialog_busy(true);
        ui.set_sync_dialog_error("".into());
    }

    fn finish_sync_setup(&mut self, result: Result<(String, Token), SyncError>, created: bool) {
        self.sync.setting_up = false;
        let ui = self.ui();
        ui.set_sync_dialog_busy(false);
        let (url, token) = match result {
            Ok(r) => r,
            Err(e) => {
                ui.set_sync_dialog_error(self.sync_error_text(&e).into());
                return;
            }
        };
        let Some(store) = &self.store else {
            return;
        };
        if let Err(e) = store.set_sync_account(&url, &token) {
            ui.set_sync_dialog_error(self.error_text(&e).into());
            return;
        }
        self.sync = SyncState::default();
        if created {
            // Shown once, to be saved; the dialog closes with "I saved it".
            ui.set_sync_new_token(token.to_string().into());
        } else {
            ui.set_sync_dialog_open(false);
            self.toast(&self.say(|tr| tr.invoke_sync_on()));
        }
        self.schedule_sync(Duration::ZERO);
        self.update_sync_ui();
    }

    fn sync_dialog_done(&mut self) {
        let ui = self.ui();
        ui.set_sync_new_token("".into());
        ui.set_sync_dialog_open(false);
        self.toast(&self.say(|tr| tr.invoke_sync_on()));
    }

    fn copy_sync_token(&mut self) {
        if let Some(a) = self.sync_account() {
            self.copy(&a.token.to_string());
        }
    }

    fn disconnect_sync(&mut self) {
        if self.sync.running {
            // The worker still writes sync state; wait for it.
            self.sync.disconnect_after = true;
            return;
        }
        let Some(store) = &self.store else {
            return;
        };
        if let Err(e) = store.clear_sync_account() {
            self.toast(&self.error_text(&e));
            return;
        }
        self.sync = SyncState::default();
        self.update_sync_ui();
        self.toast(&self.say(|tr| tr.invoke_sync_off()));
    }
}

/// How the account's server is named in the UI: "vykey Cloud" or its host.
fn server_name(tr: &Tr, a: &SyncAccount) -> SharedString {
    if PUBLIC_SERVER == Some(a.server_url.as_str()) {
        tr.invoke_sync_cloud()
    } else {
        server_host(&a.server_url).into()
    }
}

/// "sync.example.com" out of "https://sync.example.com/vykey".
fn server_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

/// Wait after `failures` failed rounds in a row: 15 s, 30 s, 1 min, … up
/// to 5 min, plus a few seconds so devices do not retry in step.
fn retry_delay(failures: u32) -> Duration {
    let base = 15u64
        .saturating_mul(1 << failures.saturating_sub(1).min(5))
        .min(300);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_millis()) % 5000);
    Duration::from_secs(base) + Duration::from_millis(jitter)
}

/// Folder id, name and colour for the entry form ("" when none).
fn folder_fields(folder: Option<&Folder>) -> (SharedString, SharedString, slint::Color) {
    match folder {
        Some(f) => (
            f.id.as_str().into(),
            f.name.as_str().into(),
            format::folder_color(&f.color),
        ),
        None => Default::default(),
    }
}

/// `Theme.mode` index in theme.slint.
fn theme_index(mode: ThemeMode) -> i32 {
    match mode {
        ThemeMode::System => 0,
        ThemeMode::Light => 1,
        ThemeMode::Dark => 2,
    }
}

fn theme_mode(index: i32) -> ThemeMode {
    match index {
        1 => ThemeMode::Light,
        2 => ThemeMode::Dark,
        _ => ThemeMode::System,
    }
}

/// Auto-lock choices in the settings dropdown, in seconds; 0 = never.
const LOCK_PRESETS: &[u64] = &[60, 5 * 60, 15 * 60, 30 * 60, 60 * 60, 0];

/// Dropdown values: the presets, plus a value set by hand in settings.json,
/// ascending with "never" last.
fn lock_options(current: u64) -> Vec<u64> {
    let mut options: Vec<u64> = LOCK_PRESETS.iter().copied().filter(|&s| s != 0).collect();
    if current != 0 && !options.contains(&current) {
        options.push(current);
        options.sort_unstable();
    }
    options.push(0);
    options
}

fn lock_name(tr: &Tr, secs: u64) -> SharedString {
    let n = |v: u64| i32::try_from(v).unwrap_or(i32::MAX);
    match secs {
        0 => tr.invoke_lock_never(),
        s if s % 3600 == 0 => tr.invoke_lock_hours(n(s / 3600)),
        s if s % 60 == 0 => tr.invoke_lock_minutes(n(s / 60)),
        s => tr.invoke_lock_seconds(n(s)),
    }
}

/// UI languages: (code, name in that language). English is the source
/// language of the UI; every other code needs
/// translations/<code>/LC_MESSAGES/vykey-desktop.po. Add new languages here.
const LANGUAGES: &[(&str, &str)] = &[("en", "English"), ("ru", "Русский")];

fn known_language(code: &str) -> Option<&'static str> {
    LANGUAGES.iter().map(|(c, _)| *c).find(|c| *c == code)
}

/// Index in the settings dropdown: 0 = system, i + 1 = `LANGUAGES[i]`.
fn language_index(code: Option<&str>) -> i32 {
    code.and_then(|c| LANGUAGES.iter().position(|(l, _)| *l == c))
        .map_or(0, |i| i as i32 + 1)
}

fn language_code(index: i32) -> Option<&'static str> {
    usize::try_from(index - 1)
        .ok()
        .and_then(|i| LANGUAGES.get(i))
        .map(|(c, _)| *c)
}

/// Language to show: the chosen one, else the system locale's if the app
/// has it ("ru-RU" → "ru"), else English.
fn effective_language(code: Option<&str>) -> &'static str {
    match code {
        Some(c) => known_language(c),
        None => sys_locale::get_locale().and_then(|l| {
            known_language(&l).or_else(|| known_language(l.split(['-', '_']).next()?))
        }),
    }
    .unwrap_or("en")
}

fn apply_language(code: Option<&str>) {
    let lang = effective_language(code);
    // English is the untranslated source (""). Fails only if no
    // translations are bundled, which build.rs ensures.
    let _ = slint::select_bundled_translation(if lang == "en" { "" } else { lang });
}

/// Dropdown entries: "System" (translated), then each language's own name.
fn language_names(ui: &AppWindow) -> ModelRc<SharedString> {
    let system = ui.global::<Tr>().invoke_system_language();
    let names = std::iter::once(system).chain(LANGUAGES.iter().map(|(_, n)| (*n).into()));
    ModelRc::new(VecModel::from(names.collect::<Vec<_>>()))
}

/// Creates the main window with all callbacks wired. The database is
/// `$VYKEY_DB_PATH` or the default vykey location (see `vykey_core::paths`).
pub fn create() -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Before any text is produced: errors below are already translated.
    let settings_path = vykey_core::paths::settings_path();
    let settings = settings_path
        .as_deref()
        .map(Settings::load)
        .unwrap_or_default();
    ui.global::<Theme>().set_mode(theme_index(settings.theme));
    apply_language(settings.language.as_deref());
    ui.set_language_mode(language_index(settings.language.as_deref()));
    ui.set_language_names(language_names(&ui));

    let db_path = vykey_core::paths::default_db_path();
    let (store, store_error) = match db_path.as_deref() {
        Some(path) => match Store::open(path) {
            Ok(s) => (Some(s), None),
            Err(e) => (
                None,
                Some(format!(
                    "{}: {}",
                    path.display(),
                    text::error(&ui.global::<Tr>(), &e)
                )),
            ),
        },
        None => (
            None,
            Some(ui.global::<Tr>().invoke_db_path_unknown().into()),
        ),
    };

    let items = Rc::new(VecModel::<EntryItem>::default());
    let issues = Rc::new(VecModel::<Issue>::default());
    let totp_digits = Rc::new(VecModel::<i32>::default());
    let folder_items = Rc::new(VecModel::<FolderItem>::default());
    ui.set_folders(ModelRc::from(folder_items.clone()));
    let palette: Vec<slint::Color> = format::FOLDER_COLORS
        .iter()
        .map(|c| format::folder_color(c))
        .collect();
    ui.global::<FolderPalette>()
        .set_colors(ModelRc::new(VecModel::from(palette)));
    ui.set_totp_digits(ModelRc::from(totp_digits.clone()));
    ui.set_items(ModelRc::from(items.clone()));
    ui.set_issues(ModelRc::from(issues.clone()));

    APP.with_borrow_mut(|app| {
        *app = Some(App {
            ui: ui.as_weak(),
            store,
            vaults: Vec::new(),
            vault: None,
            entries: Vec::new(),
            folders: Vec::new(),
            folder_items,
            visible: Vec::new(),
            items,
            issues,
            totp_digits: totp_digits.clone(),
            query: String::new(),
            filter: 0,
            folder: None,
            folder_edit: None,
            sort_by_date: false,
            selected: None,
            deleting: None,
            last_activity: Instant::now(),
            lock_timeout: settings.lock_timeout(),
            clipboard: None,
            copied: None,
            toast_until: None,
            _timer: Timer::default(),
            fx_timer: Timer::default(),
            settings,
            settings_path,
            fp_support: Availability::Unsupported,
            fp_cancel: None,
            fp_round: 0,
            db_path,
            sync: SyncState::default(),
        });
    });
    ui.set_sync_public_server(PUBLIC_SERVER.unwrap_or("").into());
    ui.set_sync_public_host(PUBLIC_SERVER.map_or("", server_host).into());
    with_app(|app| {
        app.update_sync_ui();
        // Vault records (new vaults, renames) arrive even before an unlock.
        app.schedule_sync(Duration::ZERO);
    });
    with_app(App::load_vaults);
    with_app(|app| app.update_lock_choices());
    // A D-Bus round trip (and maybe starting fprintd): off the UI thread.
    std::thread::spawn(|| {
        let support = biometric::availability();
        let _ = slint::invoke_from_event_loop(move || {
            with_app(|app| {
                app.fp_support = support;
                app.ui().set_fp_support(match support {
                    Availability::Ready => 2,
                    Availability::NoFingers => 1,
                    Availability::NoReader | Availability::Unsupported => 0,
                });
                app.start_fingerprint();
                app.refresh_fp_enabled();
            })
        });
    });
    if let Some(err) = store_error {
        ui.set_unlock_error(err.into());
    }

    ui.global::<DeleteFx>().on_tile(snapshot_tile);

    let backend = ui.global::<Backend>();
    backend.on_password_strength(|pw| {
        if pw.is_empty() {
            0
        } else {
            password::strength(&pw).bars()
        }
    });
    backend.on_generate_password(|len| password::generate(len.max(0) as usize).into());
    backend.on_copy(|text| {
        with_app(|app| {
            app.touch();
            app.copy(&text);
        })
    });
    backend.on_card_brand(|number| card_fmt::brand(&number).unwrap_or_default().into());
    backend.on_card_valid(|number| {
        card_fmt::digits(&number).is_empty() || card_fmt::luhn_valid(&number)
    });
    backend.on_mask_input(|mask, text, cursor, prev| {
        let Some(mask) = format::Mask::from_index(mask) else {
            return MaskResult { cursor, text };
        };
        let (text, cursor) = format::mask_input(mask, &text, cursor.max(0) as usize, prev.as_str());
        MaskResult {
            text: text.into(),
            cursor: cursor as i32,
        }
    });
    backend.on_open_url(|url| {
        with_app(App::touch);
        let url = url.trim();
        let url = if url.contains("://") {
            url.to_owned()
        } else {
            format!("https://{url}")
        };
        if url.starts_with("http://") || url.starts_with("https://") {
            let _ = webbrowser::open(&url);
        }
    });

    ui.on_unlock(|name, pw| with_app(|app| app.start_unlock(&name, pw)));
    ui.on_create_vault(|name, pw| with_app(|app| app.start_create(&name, pw)));
    ui.on_fp_retry(|| with_app(App::start_fingerprint));
    ui.on_unlock_context_changed(|| with_app(App::start_fingerprint));
    ui.on_set_lock_timeout(|index| {
        with_app(|app| {
            app.touch();
            app.set_lock_timeout(index);
        })
    });
    ui.on_set_fingerprint(|on| {
        with_app(|app| {
            app.touch();
            app.set_fingerprint(on);
        })
    });
    ui.on_lock(|| with_app(App::lock));
    ui.on_activity(|| with_app(App::touch));
    ui.on_navigate(|page| {
        with_app(|app| {
            app.touch();
            if page == Page::Security {
                app.update_security();
            }
            app.ui().set_page(page);
        })
    });
    ui.on_set_theme(|mode| {
        with_app(|app| {
            app.touch();
            app.ui().global::<Theme>().set_mode(mode);
            app.settings.theme = theme_mode(mode);
            app.save_settings();
        })
    });
    ui.on_set_language(|index| {
        with_app(|app| {
            app.touch();
            let code = language_code(index);
            apply_language(code);
            let ui = app.ui();
            ui.set_language_mode(index);
            ui.set_language_names(language_names(&ui));
            app.settings.language = code.map(str::to_owned);
            app.update_lock_choices();
            app.refresh_texts();
            app.save_settings();
        })
    });
    ui.on_search(|q| {
        with_app(|app| {
            app.touch();
            app.query = q.to_string();
            app.ui().set_page(Page::Vault);
            app.update_list();
            app.ensure_selection();
        })
    });
    ui.on_select(|id| {
        with_app(|app| {
            app.touch();
            app.select(&id);
        })
    });
    ui.on_toggle_sort(|| {
        with_app(|app| {
            app.touch();
            app.sort_by_date = !app.sort_by_date;
            app.update_list();
        })
    });
    ui.on_select_filter(|filter| {
        with_app(|app| {
            app.touch();
            app.select_filter(filter);
        })
    });
    ui.on_select_folder(|id| {
        with_app(|app| {
            app.touch();
            app.select_folder(&id);
        })
    });
    ui.on_move_to_folder(|id, folder| {
        with_app(|app| {
            app.touch();
            app.move_to_folder(&id, &folder);
        })
    });
    ui.on_new_folder(|| {
        with_app(|app| {
            app.touch();
            app.new_folder();
        })
    });
    ui.on_folder_action(|id, action| {
        with_app(|app| {
            app.touch();
            app.folder_action(&id, action);
        })
    });
    // The id is tracked in `folder_edit`, so the dialog cannot retarget it.
    ui.on_save_folder(|_id, name, color| {
        with_app(|app| {
            app.touch();
            app.save_folder(&name, color);
        })
    });
    ui.on_confirm_delete_folder(|| {
        with_app(|app| {
            app.touch();
            app.confirm_delete_folder();
        })
    });
    ui.on_toggle_favorite(|id| {
        with_app(|app| {
            app.touch();
            app.toggle_favorite(&id);
        })
    });
    ui.on_new_entry(|kind| {
        with_app(|app| {
            app.touch();
            app.new_entry(kind);
        })
    });
    ui.on_open_form(|id| {
        with_app(|app| {
            app.touch();
            app.open_form(&id);
        })
    });
    ui.on_save_entry(|form| {
        with_app(|app| {
            app.touch();
            app.save(form);
        })
    });
    ui.on_request_delete(|id| {
        with_app(|app| {
            app.touch();
            app.request_delete(&id);
        })
    });
    ui.on_vault_action(|action| {
        with_app(|app| {
            app.touch();
            app.vault_action(action);
        })
    });
    ui.on_rename_vault(|name| {
        with_app(|app| {
            app.touch();
            app.rename_vault(&name);
        })
    });
    ui.on_sync_create(|server, invite| {
        with_app(|app| {
            app.touch();
            app.start_sync_create(&server, &invite);
        })
    });
    ui.on_sync_join(|server, token| {
        with_app(|app| {
            app.touch();
            app.start_sync_join(&server, &token);
        })
    });
    ui.on_sync_now(|| {
        with_app(|app| {
            app.touch();
            app.schedule_sync(Duration::ZERO);
        })
    });
    ui.on_sync_copy_token(|| {
        with_app(|app| {
            app.touch();
            app.copy_sync_token();
        })
    });
    ui.on_sync_disconnect(|| {
        with_app(|app| {
            app.touch();
            app.disconnect_sync();
        })
    });
    ui.on_sync_dialog_done(|| with_app(App::sync_dialog_done));
    ui.on_change_password(|current, new| {
        with_app(|app| {
            app.touch();
            app.start_change_password(current, new);
        })
    });
    ui.on_delete_vault(|password| {
        with_app(|app| {
            app.touch();
            app.start_delete_vault(password);
        })
    });
    ui.on_confirm_delete(|| {
        with_app(|app| {
            app.touch();
            app.confirm_delete();
        })
    });

    with_app(|app| {
        app._timer
            .start(TimerMode::Repeated, Duration::from_secs(1), || {
                with_app(App::tick)
            });
    });

    Ok(ui)
}

/// Wipes secrets (key, entries, our clipboard content) and drops the state.
pub fn shutdown() {
    APP.with_borrow_mut(|app| {
        if let Some((cancel, _)) = app.as_mut().and_then(|a| a.fp_cancel.take()) {
            cancel.cancel();
        }
        if let Some(app) = app.as_mut()
            && let Some((_, value)) = &app.copied
            && let Some(cb) = app.clipboard.as_mut()
            && cb.get_text().ok().as_deref() == Some(value.as_str())
        {
            let _ = cb.clear();
        }
        *app = None;
    });
}

/// Runs the application until the window is closed.
///
/// Uses the software renderer unless `SLINT_BACKEND` says otherwise
/// (e.g. `SLINT_BACKEND=winit-femtovg` for OpenGL).
pub fn run() -> Result<(), slint::PlatformError> {
    if std::env::var_os("SLINT_BACKEND").is_none() {
        slint::BackendSelector::new()
            .backend_name("winit".into())
            .renderer_name("software".into())
            .select()?;
    }
    let ui = create()?;
    let result = ui.run();
    shutdown();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_match_translations() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("translations");
        let mut bundled: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        bundled.sort();
        let mut listed: Vec<String> = LANGUAGES
            .iter()
            .filter(|(c, _)| *c != "en")
            .map(|(c, _)| (*c).to_owned())
            .collect();
        listed.sort();
        assert_eq!(bundled, listed, "LANGUAGES and translations/ disagree");
    }

    #[test]
    fn sync_status_host() {
        assert_eq!(server_host("https://sync.example.com"), "sync.example.com");
        assert_eq!(server_host("https://example.com/vykey"), "example.com");
        assert_eq!(server_host("http://127.0.0.1:8470"), "127.0.0.1:8470");
    }

    #[test]
    fn sync_retry_grows_and_is_capped() {
        let secs = |n| retry_delay(n).as_secs();
        assert!((15..20).contains(&secs(1)));
        assert!((30..35).contains(&secs(2)));
        assert!((300..305).contains(&secs(6)));
        assert!((300..305).contains(&secs(40)));
    }

    #[test]
    fn lock_choices() {
        assert_eq!(lock_options(300), [60, 300, 900, 1800, 3600, 0]);
        assert_eq!(lock_options(0), [60, 300, 900, 1800, 3600, 0]);
        assert_eq!(lock_options(120), [60, 120, 300, 900, 1800, 3600, 0]);
    }

    #[test]
    fn language_choice() {
        assert_eq!(language_index(None), 0);
        assert_eq!(language_index(Some("ru")), 2);
        assert_eq!(language_index(Some("xx")), 0);
        assert_eq!(language_code(0), None);
        assert_eq!(language_code(1), Some("en"));
        assert_eq!(language_code(99), None);
        assert_eq!(effective_language(Some("ru")), "ru");
        assert_eq!(effective_language(Some("xx")), "en");
    }
}
