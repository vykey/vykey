//! TUI state and key handling. Screens follow the Go `kyp` TUI: create
//! vault, unlock, entry list, entry details and the entry form.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use vykey_biometric::{self as biometric, Availability, Event as FpEvent, Retry, Verdict};
use vykey_core::card as card_fmt;
use vykey_core::{
    Card, Entry, EntryInput, EntryKind, Error, Folder, Store, Vault, VaultMeta, password, totp,
};
use zeroize::Zeroizing;

use super::input::Input;
use crate::clipboard::Clipboard;

/// Minimum master password length (same rule as the desktop app).
pub const MIN_PASSWORD_LEN: usize = 8;
/// Length of generated passwords (ctrl+g in the form).
const GENERATED_LEN: usize = 20;
const NOTICE_DURATION: Duration = Duration::from_secs(2);

pub enum Screen {
    Create(CreateScreen),
    Unlock(UnlockScreen),
    List,
    Detail(DetailScreen),
    Form(Box<FormScreen>),
}

pub struct CreateScreen {
    /// name, password, confirm
    pub inputs: [Input; 3],
    /// 0..=2 inputs, 3 = Create, 4 = Cancel
    pub focus: usize,
    pub error: Option<String>,
}

impl CreateScreen {
    /// The first vault is named "default" (as in the Go app) and the cursor
    /// starts on the password; further vaults start with the name.
    fn new(first: bool) -> Self {
        Self {
            inputs: [
                Input::new(if first { "default" } else { "" }),
                Input::new("").masked(),
                Input::new("").masked(),
            ],
            focus: if first { 1 } else { 0 },
            error: None,
        }
    }
}

pub struct UnlockScreen {
    pub selected: usize,
    /// Password step (after picking a vault).
    pub entering: bool,
    pub password: Input,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct ListScreen {
    pub filter: Input,
    /// The filter line has the keyboard.
    pub filtering: bool,
    /// Indices into `App::entries`, in display order.
    pub visible: Vec<usize>,
    pub state: ListState,
}

pub struct DetailScreen {
    pub id: String,
    pub reveal: bool,
    pub confirm_delete: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    Title,
    Username,
    Password,
    Url,
    Notes,
    TotpSecret,
    TotpIssuer,
    Holder,
    Number,
    Expiry,
    Cvv,
    Pin,
}

impl FieldId {
    pub fn label(self) -> &'static str {
        match self {
            Self::Title => "Title",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::Url => "URL",
            Self::Notes => "Notes",
            Self::TotpSecret => "TOTP secret",
            Self::TotpIssuer => "TOTP issuer",
            Self::Holder => "Cardholder",
            Self::Number => "Card number",
            Self::Expiry => "Expiry",
            Self::Cvv => "CVV",
            Self::Pin => "PIN",
        }
    }

    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Title => "e.g. GitHub",
            Self::Username => "Email or username",
            Self::Url => "https://",
            Self::Notes => "Optional",
            Self::TotpSecret => "Base32, optional",
            Self::TotpIssuer => "Optional",
            Self::Expiry => "MM/YY",
            _ => "",
        }
    }

    fn fields(kind: EntryKind) -> &'static [FieldId] {
        match kind {
            EntryKind::Login => &[
                Self::Title,
                Self::Username,
                Self::Password,
                Self::Url,
                Self::Notes,
                Self::TotpSecret,
                Self::TotpIssuer,
            ],
            EntryKind::Card => &[
                Self::Title,
                Self::Holder,
                Self::Number,
                Self::Expiry,
                Self::Cvv,
                Self::Pin,
                Self::Notes,
            ],
            EntryKind::Note => &[Self::Title, Self::Notes],
        }
    }

    fn input(self, value: &str) -> Input {
        let input = Input::new(value);
        match self {
            Self::Password | Self::Cvv | Self::Pin => input.masked(),
            Self::Notes => input.multiline(),
            _ => input,
        }
    }

    /// The field's value in an existing entry.
    fn value(self, e: &Entry) -> String {
        let card = e.card.clone().unwrap_or_default();
        let opt = |o: &Option<String>| o.clone().unwrap_or_default();
        match self {
            Self::Title => e.title.clone(),
            Self::Username => opt(&e.username),
            Self::Password => opt(&e.password),
            Self::Url => opt(&e.url),
            Self::Notes => opt(&e.notes),
            Self::TotpSecret => opt(&e.totp_secret),
            Self::TotpIssuer => opt(&e.totp_issuer),
            Self::Holder => card.holder.clone(),
            Self::Number => card_fmt::format_number(&card.number),
            Self::Expiry => card.expiry.clone(),
            Self::Cvv => card.cvv.clone(),
            Self::Pin => card.pin.clone(),
        }
    }
}

pub struct Field {
    pub id: FieldId,
    pub input: Input,
}

/// What a form row is: the type selector (new entries only), a field or a
/// button.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormRow {
    Kind,
    Field(usize),
    Save,
    Cancel,
}

pub struct FormScreen {
    /// `None` = new entry.
    pub id: Option<String>,
    pub kind: EntryKind,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub reveal: bool,
    pub error: Option<String>,
    // Kept as they are: the form does not edit them.
    favorite: bool,
    folder: Option<String>,
}

impl FormScreen {
    fn new_entry() -> Self {
        let mut f = Self {
            id: None,
            kind: EntryKind::Login,
            fields: Vec::new(),
            focus: 1,
            reveal: false,
            error: None,
            favorite: false,
            folder: None,
        };
        f.set_kind(EntryKind::Login);
        f
    }

    fn edit(e: &Entry) -> Self {
        Self {
            id: Some(e.id.clone()),
            kind: e.kind,
            fields: FieldId::fields(e.kind)
                .iter()
                .map(|&id| Field {
                    id,
                    input: id.input(&id.value(e)),
                })
                .collect(),
            focus: 0,
            reveal: false,
            error: None,
            favorite: e.favorite,
            folder: e.folder.clone(),
        }
    }

    /// Switches a new entry's type, keeping the values of shared fields.
    fn set_kind(&mut self, kind: EntryKind) {
        let old = std::mem::take(&mut self.fields);
        self.kind = kind;
        self.fields = FieldId::fields(kind)
            .iter()
            .map(|&id| {
                let value = old
                    .iter()
                    .find(|f| f.id == id)
                    .map_or("", |f| f.input.value());
                Field {
                    id,
                    input: id.input(value),
                }
            })
            .collect();
    }

    pub fn rows(&self) -> Vec<FormRow> {
        let mut rows = Vec::new();
        if self.id.is_none() {
            rows.push(FormRow::Kind);
        }
        rows.extend((0..self.fields.len()).map(FormRow::Field));
        rows.extend([FormRow::Save, FormRow::Cancel]);
        rows
    }

    pub fn focused(&self) -> FormRow {
        self.rows()[self.focus]
    }

    fn move_focus(&mut self, forward: bool) {
        let n = self.rows().len();
        self.focus = if forward {
            (self.focus + 1) % n
        } else {
            (self.focus + n - 1) % n
        };
    }

    fn value(&self, id: FieldId) -> &str {
        self.fields
            .iter()
            .find(|f| f.id == id)
            .map_or("", |f| f.input.value().trim())
    }

    /// Validated input for the store.
    fn to_input(&self) -> Result<EntryInput, String> {
        if self.value(FieldId::Title).is_empty() {
            return Err("Title is required".into());
        }
        let opt = |id| Some(self.value(id).to_owned()).filter(|s| !s.is_empty());
        let mut input = EntryInput::default();
        input.kind = self.kind;
        input.favorite = self.favorite;
        input.title = self.value(FieldId::Title).to_owned();
        input.notes = self
            .fields
            .iter()
            .find(|f| f.id == FieldId::Notes)
            .map(|f| f.input.value().to_owned())
            .filter(|s| !s.trim().is_empty());
        input.folder = self.folder.clone();
        match self.kind {
            EntryKind::Login => {
                let secret = self.value(FieldId::TotpSecret);
                if !secret.is_empty() && !totp::is_valid_secret(secret) {
                    return Err(
                        "The TOTP secret must be Base32 (letters A–Z and digits 2–7)".into(),
                    );
                }
                input.username = opt(FieldId::Username);
                input.password = opt(FieldId::Password);
                input.url = opt(FieldId::Url);
                input.totp_secret = opt(FieldId::TotpSecret);
                input.totp_issuer = opt(FieldId::TotpIssuer);
            }
            EntryKind::Card => {
                let expiry = self.value(FieldId::Expiry);
                let expiry = if expiry.is_empty() {
                    String::new()
                } else {
                    let (m, y) = card_fmt::parse_expiry(expiry)
                        .ok_or("Enter the expiry as MM/YY, e.g. 08/28")?;
                    format!("{m:02}/{:02}", y % 100)
                };
                input.card = Some(Card {
                    holder: self.value(FieldId::Holder).to_owned(),
                    number: card_fmt::digits(self.value(FieldId::Number)),
                    expiry,
                    cvv: self.value(FieldId::Cvv).to_owned(),
                    pin: self.value(FieldId::Pin).to_owned(),
                });
            }
            EntryKind::Note => {}
        }
        Ok(input)
    }
}

/// Slow work (Argon2) done right after the next frame, so the "Unlocking…"
/// state is visible first.
pub enum Pending {
    Unlock {
        name: String,
        password: Zeroizing<String>,
    },
    Create {
        name: String,
        password: Zeroizing<String>,
    },
}

enum FpMsg {
    Event(FpEvent),
    Done(FpOutcome),
}

enum FpOutcome {
    Opened(Vault),
    /// The stored key no longer opens the vault and was removed.
    Reset,
    NoMatch,
    TimedOut,
    Failed(biometric::Error),
}

/// Fingerprint check for one vault of the unlock screen, running in a
/// thread. It stays after it ends, so it is not restarted for the same
/// vault until ctrl+f drops it.
struct FpCheck {
    vault_id: String,
    cancel: biometric::Cancel,
    rx: mpsc::Receiver<FpMsg>,
}

impl Drop for FpCheck {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Fingerprint prompt under the password field.
pub struct FpLine {
    pub text: String,
    /// Waiting for a finger; otherwise the check is over (ctrl+f retries).
    pub waiting: bool,
}

fn fp_text(event: FpEvent) -> String {
    match event {
        FpEvent::Prompt {
            finger: Some(f),
            swipe: false,
        } => format!("Place your {} on the fingerprint reader", f.name()),
        FpEvent::Prompt {
            finger: Some(f),
            swipe: true,
        } => format!("Swipe your {} across the fingerprint reader", f.name()),
        FpEvent::Prompt {
            finger: None,
            swipe: false,
        } => "Place your finger on the fingerprint reader".into(),
        FpEvent::Prompt {
            finger: None,
            swipe: true,
        } => "Swipe your finger across the fingerprint reader".into(),
        FpEvent::Retry(Retry::Scan) => "Could not read the finger, try again".into(),
        FpEvent::Retry(Retry::SwipeTooShort) => "Swipe was too short, try again".into(),
        FpEvent::Retry(Retry::NotCentered) => "Finger was not centered, try again".into(),
        FpEvent::Retry(Retry::RemoveAndRetry) => "Remove your finger and try again".into(),
        FpEvent::NoMatch { attempts_left } => format!(
            "Fingerprint not recognized, {attempts_left} attempt{} left",
            if attempts_left == 1 { "" } else { "s" }
        ),
    }
}

/// Claims the reader and waits for a finger, then opens the vault with the
/// key from the keyring. Ends silently if the vault has no fingerprint
/// unlock.
fn spawn_fingerprint(meta: VaultMeta) -> FpCheck {
    let cancel = biometric::Cancel::new();
    let (tx, rx) = mpsc::channel();
    let check = FpCheck {
        vault_id: meta.id.clone(),
        cancel: cancel.clone(),
        rx,
    };
    std::thread::spawn(move || {
        // A search only: never shows a keyring prompt.
        if !biometric::is_enabled(&meta.id).unwrap_or(false) || cancel.is_cancelled() {
            return;
        }
        let _ = tx.send(FpMsg::Event(FpEvent::Prompt {
            finger: None,
            swipe: false,
        }));
        let verdict = biometric::verify(&cancel, biometric::VERIFY_TIMEOUT, |e| {
            let _ = tx.send(FpMsg::Event(e));
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
        let _ = tx.send(FpMsg::Done(outcome));
    });
    check
}

pub struct Notice {
    pub text: String,
    pub error: bool,
    until: Instant,
}

pub struct App {
    pub store: Store,
    pub vaults: Vec<VaultMeta>,
    pub vault: Option<Vault>,
    pub entries: Vec<Entry>,
    pub folders: Vec<Folder>,
    pub screen: Screen,
    pub list: ListScreen,
    pub notice: Option<Notice>,
    pub pending: Option<Pending>,
    pub quit: bool,
    clipboard: Clipboard,
    last_activity: Instant,
    lock_timeout: Option<Duration>,
    /// Fingerprint reader; `None` while probing or with fingerprint off.
    fp_support: Option<Availability>,
    fp_probe: Option<mpsc::Receiver<Availability>>,
    fp_check: Option<FpCheck>,
    pub fp_line: Option<FpLine>,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Error text as a sentence: "Invalid master password".
pub fn error_text(e: &Error) -> String {
    let s = e.to_string();
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

impl App {
    /// `fingerprint`: probe the reader and offer fingerprint unlock (off in
    /// tests, which must not touch D-Bus).
    pub fn new(store: Store, fingerprint: bool) -> Self {
        let fp_probe = fingerprint.then(|| {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(biometric::availability());
            });
            rx
        });
        let mut app = Self {
            store,
            vaults: Vec::new(),
            vault: None,
            entries: Vec::new(),
            folders: Vec::new(),
            screen: Screen::List,
            list: ListScreen::default(),
            notice: None,
            pending: None,
            quit: false,
            clipboard: Clipboard::default(),
            last_activity: Instant::now(),
            lock_timeout: vykey_core::settings::lock_timeout_from_env(),
            fp_support: None,
            fp_probe,
            fp_check: None,
            fp_line: None,
        };
        app.screen = app.start_screen(None);
        app
    }

    /// Unlock if there are vaults (pre-selecting `name`), else create one.
    fn start_screen(&mut self, name: Option<&str>) -> Screen {
        match self.store.list_vaults() {
            Ok(v) => self.vaults = v,
            Err(e) => self.error(&e),
        }
        if self.vaults.is_empty() {
            return Screen::Create(CreateScreen::new(true));
        }
        let selected = name
            .and_then(|n| self.vaults.iter().position(|v| v.name == n))
            .unwrap_or(0);
        Screen::Unlock(UnlockScreen {
            selected,
            entering: self.vaults.len() == 1,
            password: Input::new("").masked(),
            error: None,
        })
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn folder_name(&self, id: Option<&str>) -> Option<&str> {
        let id = id?;
        self.folders
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.name.as_str())
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
            until: Instant::now() + NOTICE_DURATION,
        });
    }

    fn error(&mut self, e: &Error) {
        self.notify(error_text(e), true);
    }

    // ---------- vault ----------

    pub fn run_pending(&mut self, job: Pending) {
        match job {
            Pending::Unlock { name, password } => {
                let result = self
                    .store
                    .vault_meta(&name)
                    .and_then(|meta| Vault::unlock(meta, &password));
                self.finish_open(result);
            }
            Pending::Create { name, password } => {
                let result = Vault::create(&name, &password)
                    .and_then(|v| self.store.insert_vault(&v).map(|()| v));
                self.finish_open(result);
            }
        }
    }

    fn finish_open(&mut self, result: vykey_core::Result<Vault>) {
        // Password and fingerprint may both succeed: the first one wins.
        if self.vault.is_some() {
            return;
        }
        let result = result.and_then(|v| self.store.prepare_vault(&v).map(|()| v));
        match result {
            Ok(vault) => {
                self.vault = Some(vault);
                self.list = ListScreen::default();
                self.reload();
                self.last_activity = Instant::now();
                self.screen = Screen::List;
            }
            Err(e) => {
                let text = error_text(&e);
                match &mut self.screen {
                    Screen::Unlock(s) => {
                        s.password.clear();
                        s.error = Some(text);
                    }
                    Screen::Create(s) => s.error = Some(text),
                    _ => self.notify(text, true),
                }
            }
        }
    }

    pub fn lock(&mut self) {
        let Some(vault) = self.vault.take() else {
            return;
        };
        let name = vault.meta().name.clone();
        drop(vault);
        self.entries.clear();
        self.folders.clear();
        self.list = ListScreen::default();
        self.clipboard.clear_if_ours();
        self.notice = None;
        self.screen = self.start_screen(Some(&name));
    }

    /// Closes the open vault and shows the vault list (pick, or `n` new).
    pub fn switch_vault(&mut self) {
        self.lock();
        if let Screen::Unlock(s) = &mut self.screen {
            s.entering = false;
        }
    }

    /// Reloads entries and folders after a change.
    fn reload(&mut self) {
        let Some(vault) = &self.vault else {
            return;
        };
        // Taken before `entries` changes: list indices refer to the old one.
        let keep = self.selected_id();
        match (
            self.store.list_entries(vault),
            self.store.list_folders(vault),
        ) {
            (Ok(mut entries), Ok(folders)) => {
                entries.sort_by_cached_key(|e| e.title.to_lowercase());
                self.entries = entries;
                self.folders = folders;
            }
            (Err(e), _) | (_, Err(e)) => self.error(&e),
        }
        self.refilter(keep);
    }

    fn apply_filter(&mut self) {
        let keep = self.selected_id();
        self.refilter(keep);
    }

    /// Rebuilds the visible list, keeping `keep` selected if still shown.
    fn refilter(&mut self, keep: Option<String>) {
        let q = self.list.filter.value().trim().to_lowercase();
        let has = |s: Option<&str>| s.is_some_and(|s| s.to_lowercase().contains(&q));
        self.list.visible = (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                q.is_empty()
                    || has(Some(&e.title))
                    || has(e.username.as_deref())
                    || has(e.url.as_deref())
                    || has(e.card.as_ref().map(|c| c.holder.as_str()))
                    || has(self.folder_name(e.folder.as_deref()))
            })
            .collect();
        let index = keep
            .and_then(|id| {
                self.list
                    .visible
                    .iter()
                    .position(|&i| self.entries[i].id == id)
            })
            .unwrap_or(0);
        self.list
            .state
            .select((!self.list.visible.is_empty()).then_some(index));
    }

    fn select_entry(&mut self, id: &str) {
        if let Some(pos) = self
            .list
            .visible
            .iter()
            .position(|&i| self.entries[i].id == id)
        {
            self.list.state.select(Some(pos));
        }
    }

    fn copy(&mut self, what: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        match self.clipboard.copy(value) {
            Ok(()) => self.notify(
                format!(
                    "✓ {what} copied · clears in {} s",
                    crate::clipboard::CLEAR_AFTER.as_secs()
                ),
                false,
            ),
            Err(e) => self.notify(format!("Could not copy: {e}"), true),
        }
    }

    // ---------- fingerprint ----------

    /// The vault whose password is being asked for, if a finger could open it.
    fn fp_wanted(&self) -> Option<&VaultMeta> {
        if self.vault.is_some() || self.fp_support != Some(Availability::Ready) {
            return None;
        }
        match &self.screen {
            Screen::Unlock(s) if s.entering => self.vaults.get(s.selected),
            _ => None,
        }
    }

    /// Starts or stops the fingerprint check to match the screen.
    fn sync_fingerprint(&mut self) {
        let wanted = self.fp_wanted().cloned();
        if self.fp_check.as_ref().map(|c| &c.vault_id) == wanted.as_ref().map(|m| &m.id) {
            return;
        }
        self.fp_check = wanted.map(spawn_fingerprint);
        self.fp_line = None;
    }

    fn poll_fingerprint(&mut self) {
        if let Some(rx) = &self.fp_probe {
            match rx.try_recv() {
                Ok(a) => {
                    self.fp_support = Some(a);
                    self.fp_probe = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.fp_probe = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.sync_fingerprint();
        let msgs: Vec<FpMsg> = self
            .fp_check
            .as_ref()
            .map(|c| c.rx.try_iter().collect())
            .unwrap_or_default();
        for msg in msgs {
            match msg {
                FpMsg::Event(e) => {
                    self.fp_line = Some(FpLine {
                        text: fp_text(e),
                        waiting: true,
                    })
                }
                FpMsg::Done(outcome) => self.finish_fingerprint(outcome),
            }
        }
    }

    fn finish_fingerprint(&mut self, outcome: FpOutcome) {
        let text = match outcome {
            FpOutcome::Opened(vault) => {
                self.fp_check = None;
                self.fp_line = None;
                self.finish_open(Ok(vault));
                return;
            }
            FpOutcome::Reset => {
                self.fp_line = None;
                if let Screen::Unlock(s) = &mut self.screen {
                    s.error = Some(
                        "The saved fingerprint key no longer fits this vault, \
                         enter the master password"
                            .into(),
                    );
                }
                return;
            }
            FpOutcome::NoMatch => "Fingerprint not recognized".to_owned(),
            FpOutcome::TimedOut => "Fingerprint check timed out".to_owned(),
            FpOutcome::Failed(e) => {
                let e = e.to_string();
                let mut chars = e.chars();
                chars
                    .next()
                    .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
            }
        };
        self.fp_line = Some(FpLine {
            text,
            waiting: false,
        });
    }

    // ---------- periodic work ----------

    pub fn tick(&mut self) {
        self.poll_fingerprint();
        self.clipboard.tick();
        if self
            .notice
            .as_ref()
            .is_some_and(|n| Instant::now() >= n.until)
        {
            self.notice = None;
        }
        if self.vault.is_some()
            && self
                .lock_timeout
                .is_some_and(|t| self.last_activity.elapsed() >= t)
        {
            self.lock();
        }
    }

    // ---------- keys ----------

    pub fn on_key(&mut self, key: KeyEvent) {
        self.last_activity = Instant::now();
        if self.pending.is_some() {
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if ctrl && key.code == KeyCode::Char('l') && self.vault.is_some() {
            self.lock();
            return;
        }
        let mut screen = std::mem::replace(&mut self.screen, Screen::List);
        let next = match &mut screen {
            Screen::Create(s) => self.key_create(s, key),
            Screen::Unlock(s) => self.key_unlock(s, key),
            Screen::List => self.key_list(key),
            Screen::Detail(s) => self.key_detail(s, key),
            Screen::Form(s) => self.key_form(s, key),
        };
        // A handler may have locked the vault (replacing `self.screen`).
        if matches!(self.screen, Screen::List) {
            self.screen = next.unwrap_or(screen);
        }
        self.sync_fingerprint();
    }

    fn key_create(&mut self, s: &mut CreateScreen, key: KeyEvent) -> Option<Screen> {
        match key.code {
            KeyCode::Tab | KeyCode::Down => s.focus = (s.focus + 1) % 5,
            KeyCode::BackTab | KeyCode::Up => s.focus = (s.focus + 4) % 5,
            KeyCode::Esc if !self.vaults.is_empty() => return Some(self.start_screen(None)),
            KeyCode::Enter => match s.focus {
                4 if self.vaults.is_empty() => self.quit = true,
                4 => return Some(self.start_screen(None)),
                3 => self.submit_create(s),
                _ => s.focus += 1,
            },
            _ if s.focus < 3 && s.inputs[s.focus].handle(key) => s.error = None,
            _ => {}
        }
        None
    }

    fn submit_create(&mut self, s: &mut CreateScreen) {
        let name = s.inputs[0].value().trim();
        let name = if name.is_empty() && self.vaults.is_empty() {
            "default"
        } else {
            name
        };
        let password = s.inputs[1].value();
        s.error = if name.is_empty() {
            Some("Enter a vault name".into())
        } else if password.chars().count() < MIN_PASSWORD_LEN {
            Some(format!(
                "The master password must be at least {MIN_PASSWORD_LEN} characters long"
            ))
        } else if password != s.inputs[2].value() {
            Some("Passwords do not match".into())
        } else if self.vaults.iter().any(|v| v.name == name) {
            Some(format!("Vault \"{name}\" already exists"))
        } else {
            None
        };
        if s.error.is_none() {
            self.pending = Some(Pending::Create {
                name: name.to_owned(),
                password: Zeroizing::new(password.to_owned()),
            });
        }
    }

    fn key_unlock(&mut self, s: &mut UnlockScreen, key: KeyEvent) -> Option<Screen> {
        if !s.entering {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => s.selected = s.selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    s.selected = (s.selected + 1).min(self.vaults.len().saturating_sub(1));
                }
                KeyCode::Enter => s.entering = true,
                KeyCode::Char('n') => return Some(Screen::Create(CreateScreen::new(false))),
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                _ => {}
            }
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Try the fingerprint again (sync_fingerprint starts a new check).
            KeyCode::Char('f') if ctrl => {
                if self.fp_line.as_ref().is_some_and(|l| !l.waiting) {
                    self.fp_check = None;
                    self.fp_line = None;
                }
            }
            KeyCode::Enter => {
                if let Some(v) = self.vaults.get(s.selected) {
                    self.pending = Some(Pending::Unlock {
                        name: v.name.clone(),
                        password: Zeroizing::new(s.password.value().to_owned()),
                    });
                }
            }
            // Back to the vault list, even with a single vault: it is
            // where a new vault is created.
            KeyCode::Esc => {
                s.entering = false;
                s.password.clear();
                s.error = None;
            }
            _ => {
                if s.password.handle(key) {
                    s.error = None;
                }
            }
        }
        None
    }

    fn key_list(&mut self, key: KeyEvent) -> Option<Screen> {
        if self.list.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.list.filtering = false;
                    self.list.filter.clear();
                    self.apply_filter();
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Tab => self.list.filtering = false,
                _ => {
                    if self.list.filter.handle(key) {
                        self.apply_filter();
                    }
                }
            }
            return None;
        }
        let len = self.list.visible.len();
        let current = self.list.state.selected().unwrap_or(0);
        let page = 10;
        let select = |i: usize| Some(i.min(len.saturating_sub(1)));
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('v') => self.switch_vault(),
            KeyCode::Esc if !self.list.filter.value().is_empty() => {
                self.list.filter.clear();
                self.apply_filter();
            }
            KeyCode::Char('/') => self.list.filtering = true,
            KeyCode::Char('n') => return Some(Screen::Form(Box::new(FormScreen::new_entry()))),
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                self.list.state.select(select(current.saturating_sub(1)));
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                self.list.state.select(select(current + 1));
            }
            KeyCode::PageUp if len > 0 => {
                self.list.state.select(select(current.saturating_sub(page)));
            }
            KeyCode::PageDown if len > 0 => self.list.state.select(select(current + page)),
            KeyCode::Home | KeyCode::Char('g') if len > 0 => self.list.state.select(Some(0)),
            KeyCode::End | KeyCode::Char('G') if len > 0 => self.list.state.select(select(len)),
            KeyCode::Enter => {
                let id = self.selected_id()?;
                return Some(Screen::Detail(DetailScreen {
                    id,
                    reveal: false,
                    confirm_delete: false,
                }));
            }
            _ => {}
        }
        None
    }

    pub fn selected_id(&self) -> Option<String> {
        let i = *self.list.visible.get(self.list.state.selected()?)?;
        Some(self.entries.get(i)?.id.clone())
    }

    fn key_detail(&mut self, s: &mut DetailScreen, key: KeyEvent) -> Option<Screen> {
        let Some(e) = self.entry(&s.id).cloned() else {
            return Some(Screen::List);
        };
        if s.confirm_delete {
            match key.code {
                KeyCode::Char('y') => {
                    let result = self
                        .vault
                        .as_ref()
                        .map(|v| self.store.delete_entry(v, &e.id));
                    match result {
                        Some(Ok(())) => {
                            self.notify(format!("“{}” deleted", e.title), false);
                            self.reload();
                            return Some(Screen::List);
                        }
                        Some(Err(err)) => self.error(&err),
                        None => {}
                    }
                    s.confirm_delete = false;
                }
                _ => s.confirm_delete = false,
            }
            return None;
        }
        let card = e.card.clone().unwrap_or_default();
        match (key.code, e.kind) {
            (KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace, _) => {
                return Some(Screen::List);
            }
            (KeyCode::Char('e'), _) => return Some(Screen::Form(Box::new(FormScreen::edit(&e)))),
            (KeyCode::Char('d'), _) => s.confirm_delete = true,
            (KeyCode::Char('p' | ' '), _) => s.reveal = !s.reveal,
            (KeyCode::Char('f'), _) => {
                if let Some(v) = &self.vault {
                    match self.store.set_favorite(v, &e.id, !e.favorite) {
                        Ok(()) => self.reload(),
                        Err(err) => self.error(&err),
                    }
                }
            }
            (KeyCode::Char('u'), EntryKind::Login) => {
                self.copy("Username", e.username.as_deref().unwrap_or_default());
            }
            (KeyCode::Char('c'), EntryKind::Login) => {
                self.copy("Password", e.password.as_deref().unwrap_or_default());
            }
            (KeyCode::Char('t'), EntryKind::Login) => {
                if let Some(code) = e.totp_secret.as_deref().and_then(|secret| {
                    totp::code(secret, now_unix() as u64, e.totp_digits, e.totp_period).ok()
                }) {
                    self.copy("TOTP code", &code);
                }
            }
            (KeyCode::Char('u'), EntryKind::Card) => self.copy("Cardholder", &card.holder),
            (KeyCode::Char('c'), EntryKind::Card) => self.copy("Card number", &card.number),
            (KeyCode::Char('v'), EntryKind::Card) => self.copy("CVV", &card.cvv),
            (KeyCode::Char('c'), EntryKind::Note) => {
                self.copy("Note", e.notes.as_deref().unwrap_or_default());
            }
            _ => {}
        }
        None
    }

    fn key_form(&mut self, s: &mut FormScreen, key: KeyEvent) -> Option<Screen> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let row = s.focused();
        let field_id = match row {
            FormRow::Field(i) => Some(s.fields[i].id),
            _ => None,
        };
        let in_notes = field_id == Some(FieldId::Notes);
        match key.code {
            KeyCode::Char('s') if ctrl => return self.save_form(s),
            KeyCode::Char('g') if ctrl && field_id == Some(FieldId::Password) => {
                if let FormRow::Field(i) = row {
                    s.fields[i].input.set(&password::generate(GENERATED_LEN));
                    s.reveal = true;
                }
            }
            KeyCode::Char('p') if ctrl => s.reveal = !s.reveal,
            KeyCode::Esc => return Some(self.leave_form(s)),
            KeyCode::Tab => s.move_focus(true),
            KeyCode::BackTab => s.move_focus(false),
            KeyCode::Down if !in_notes => s.move_focus(true),
            KeyCode::Up if !in_notes => s.move_focus(false),
            KeyCode::Left | KeyCode::Right if row == FormRow::Kind => {
                let kinds = [EntryKind::Login, EntryKind::Card, EntryKind::Note];
                let i = kinds.iter().position(|k| *k == s.kind).unwrap_or(0);
                let i = if key.code == KeyCode::Right {
                    (i + 1) % 3
                } else {
                    (i + 2) % 3
                };
                s.set_kind(kinds[i]);
            }
            KeyCode::Enter if !in_notes => match row {
                FormRow::Save => return self.save_form(s),
                FormRow::Cancel => return Some(self.leave_form(s)),
                _ => s.move_focus(true),
            },
            _ => {
                if let FormRow::Field(i) = row
                    && s.fields[i].input.handle(key)
                {
                    s.error = None;
                }
            }
        }
        None
    }

    /// Back from the form: to the entry when editing, else to the list.
    fn leave_form(&self, s: &FormScreen) -> Screen {
        match &s.id {
            Some(id) if self.entry(id).is_some() => Screen::Detail(DetailScreen {
                id: id.clone(),
                reveal: false,
                confirm_delete: false,
            }),
            _ => Screen::List,
        }
    }

    fn save_form(&mut self, s: &mut FormScreen) -> Option<Screen> {
        let input = match s.to_input() {
            Ok(i) => i,
            Err(e) => {
                s.error = Some(e);
                return None;
            }
        };
        let vault = self.vault.as_ref()?;
        let result = match &s.id {
            Some(id) => self
                .store
                .update_entry(vault, id, &input)
                .map(|()| id.clone()),
            None => self.store.create_entry(vault, &input),
        };
        match result {
            Ok(id) => {
                self.reload();
                self.select_entry(&id);
                self.notify("✓ Entry saved", false);
                Some(Screen::List)
            }
            Err(e) => {
                s.error = Some(error_text(&e));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
    }

    fn app() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("vykey.db")).unwrap();
        (dir, App::new(store, false))
    }

    fn run_pending(app: &mut App) {
        let job = app.pending.take().expect("pending job");
        app.run_pending(job);
    }

    #[test]
    fn create_add_edit_delete_lock() {
        let (_dir, mut app) = app();
        assert!(matches!(app.screen, Screen::Create(_)));

        // Too short, then mismatched, then valid.
        type_text(&mut app, "short");
        app.on_key(key(KeyCode::Tab));
        type_text(&mut app, "short");
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending.is_none());
        let Screen::Create(s) = &mut app.screen else {
            panic!()
        };
        assert!(s.error.as_deref().unwrap().contains("at least"));
        s.inputs[1].set("correct horse");
        s.inputs[2].set("correct horse");
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);
        assert!(matches!(app.screen, Screen::List));
        assert_eq!(app.vault.as_ref().unwrap().meta().name, "default");

        // New login.
        app.on_key(key(KeyCode::Char('n'))); // focus starts on the title
        type_text(&mut app, "GitHub");
        app.on_key(key(KeyCode::Down));
        type_text(&mut app, "alex");
        app.on_key(key(KeyCode::Down));
        app.on_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(app.screen, Screen::List));
        assert_eq!(app.entries.len(), 1);
        let e = &app.entries[0];
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.username.as_deref(), Some("alex"));
        assert_eq!(e.password.as_ref().map(String::len), Some(GENERATED_LEN));

        // Favourite, then edit: the flag survives the form.
        app.on_key(key(KeyCode::Enter));
        app.on_key(key(KeyCode::Char('f')));
        assert!(app.entries[0].favorite);
        app.on_key(key(KeyCode::Char('e')));
        type_text(&mut app, " Enterprise");
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert_eq!(app.entries[0].title, "GitHub Enterprise");
        assert!(app.entries[0].favorite);

        // Filter.
        app.on_key(key(KeyCode::Char('/')));
        type_text(&mut app, "zzz");
        assert!(app.list.visible.is_empty());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.list.visible.len(), 1);

        // Delete with confirmation.
        app.on_key(key(KeyCode::Enter));
        app.on_key(key(KeyCode::Char('d')));
        app.on_key(key(KeyCode::Char('y')));
        assert!(app.entries.is_empty());
        assert!(matches!(app.screen, Screen::List));

        // Lock and unlock again.
        app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert!(app.vault.is_none());
        assert!(matches!(app.screen, Screen::Unlock(_)));
        type_text(&mut app, "wrong password");
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);
        let Screen::Unlock(s) = &app.screen else {
            panic!()
        };
        assert_eq!(s.error.as_deref(), Some("Invalid master password"));
        type_text(&mut app, "correct horse");
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);
        assert!(app.vault.is_some());
    }

    #[test]
    fn switch_vaults() {
        let (_dir, mut app) = app();
        let Screen::Create(s) = &mut app.screen else {
            panic!()
        };
        s.inputs[0].set("Personal");
        s.inputs[1].set("correct horse");
        s.inputs[2].set("correct horse");
        s.focus = 3;
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);

        // `v` closes the vault and lists vaults; `n` creates another one.
        app.on_key(key(KeyCode::Char('v')));
        assert!(app.vault.is_none());
        let Screen::Unlock(s) = &app.screen else {
            panic!()
        };
        assert!(!s.entering);
        app.on_key(key(KeyCode::Char('n')));
        let Screen::Create(s) = &mut app.screen else {
            panic!()
        };
        assert_eq!((s.inputs[0].value(), s.focus), ("", 0));
        s.inputs[0].set("Work");
        s.inputs[1].set("battery staple");
        s.inputs[2].set("battery staple");
        s.focus = 3;
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);
        assert_eq!(app.vault.as_ref().unwrap().meta().name, "Work");

        // Back to "Personal": pick it, then enter its password; esc on the
        // password step returns to the list.
        app.on_key(key(KeyCode::Char('v')));
        let Screen::Unlock(s) = &app.screen else {
            panic!()
        };
        let personal = app
            .vaults
            .iter()
            .position(|v| v.name == "Personal")
            .unwrap();
        let work = app.vaults.iter().position(|v| v.name == "Work").unwrap();
        assert_eq!(s.selected, work);
        let step = if personal < work {
            KeyCode::Up
        } else {
            KeyCode::Down
        };
        app.on_key(key(step));
        app.on_key(key(KeyCode::Enter));
        app.on_key(key(KeyCode::Esc));
        assert!(matches!(&app.screen, Screen::Unlock(s) if !s.entering));
        app.on_key(key(KeyCode::Enter));
        type_text(&mut app, "correct horse");
        app.on_key(key(KeyCode::Enter));
        run_pending(&mut app);
        assert_eq!(app.vault.as_ref().unwrap().meta().name, "Personal");
    }

    #[test]
    fn card_form_validates_and_normalises() {
        let mut f = FormScreen::new_entry();
        f.set_kind(EntryKind::Card);
        let set = |f: &mut FormScreen, id, v: &str| {
            f.fields
                .iter_mut()
                .find(|x| x.id == id)
                .unwrap()
                .input
                .set(v);
        };
        set(&mut f, FieldId::Title, "Visa");
        set(&mut f, FieldId::Number, "4111 1111 1111 1111");
        set(&mut f, FieldId::Expiry, "13/28");
        assert!(f.to_input().is_err());
        set(&mut f, FieldId::Expiry, "8/28");
        let input = f.to_input().unwrap();
        let card = input.card.clone().unwrap();
        assert_eq!(card.number, "4111111111111111");
        assert_eq!(card.expiry, "08/28");
        assert_eq!(input.kind, EntryKind::Card);
    }

    #[test]
    fn switching_kind_keeps_shared_fields() {
        let mut f = FormScreen::new_entry();
        f.fields[0].input.set("Wi-Fi");
        f.set_kind(EntryKind::Note);
        assert_eq!(f.fields.len(), 2);
        assert_eq!(f.value(FieldId::Title), "Wi-Fi");
    }
}
