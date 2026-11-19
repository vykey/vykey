//! Rendering of the TUI screens with ratatui.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, Padding, Paragraph, Wrap};
use vykey_core::card::{self as card_fmt, ExpiryStatus};
use vykey_core::{Entry, EntryKind, totp};

use super::app::{
    App, CreateScreen, DetailScreen, FormRow, FormScreen, Pending, Screen, UnlockScreen, now_unix,
};
use super::input::Input;

const ACCENT: Color = Color::Indexed(99);
const LABEL_WIDTH: usize = 14;

fn accent() -> Style {
    Style::new().fg(ACCENT)
}

fn hint() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

fn button(text: &str, active: bool) -> Span<'static> {
    let text = format!("  {text}  ");
    if active {
        Span::styled(text, Style::new().bg(ACCENT).fg(Color::White).bold())
    } else {
        Span::styled(text, hint())
    }
}

fn title_bar(text: &str) -> Span<'static> {
    Span::styled(
        format!(" {text} "),
        Style::new().bg(ACCENT).fg(Color::White).bold(),
    )
}

fn hints(items: &[&str]) -> Line<'static> {
    Line::styled(items.join(" • "), hint())
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// Renders a single-line input at `area`; places the cursor when focused.
/// Long values scroll so the cursor stays visible.
fn draw_input(
    f: &mut Frame,
    area: Rect,
    input: &Input,
    placeholder: &str,
    focused: bool,
    reveal: bool,
) {
    let text: Vec<char> = input.display(reveal).chars().collect();
    let width = area.width.max(1) as usize;
    let (_, col) = input.cursor_line_col();
    let start = (col + 1).saturating_sub(width);
    let line = if text.is_empty() {
        Line::styled(placeholder.to_owned(), hint())
    } else {
        Line::raw(text[start..].iter().take(width).collect::<String>())
    };
    let style = if focused { accent() } else { Style::new() };
    f.render_widget(Paragraph::new(line).style(style), area);
    if focused {
        f.set_cursor_position(Position::new(area.x + (col - start) as u16, area.y));
    }
}

/// Multi-line input: shows the lines around the cursor.
fn draw_textarea(f: &mut Frame, area: Rect, input: &Input, placeholder: &str, focused: bool) {
    let (line, col) = input.cursor_line_col();
    let height = area.height.max(1) as usize;
    let top = (line + 1).saturating_sub(height);
    let text = if input.value().is_empty() {
        Text::styled(placeholder.to_owned(), hint())
    } else {
        Text::from(
            input
                .value()
                .split('\n')
                .skip(top)
                .take(height)
                .map(|l| Line::raw(l.to_owned()))
                .collect::<Vec<_>>(),
        )
    };
    let style = if focused { accent() } else { Style::new() };
    f.render_widget(Paragraph::new(text).style(style), area);
    if focused {
        let x = (col as u16).min(area.width.saturating_sub(1));
        f.set_cursor_position(Position::new(area.x + x, area.y + (line - top) as u16));
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    match &app.screen {
        Screen::Create(s) => draw_create(f, area, s, app.pending.is_some(), &app.vaults),
        Screen::Unlock(s) => draw_unlock(f, area, s, app),
        Screen::List => draw_list(f, area, app),
        Screen::Detail(s) => draw_detail(f, area, s, app),
        Screen::Form(s) => draw_form(f, area, s),
    }
    if let Some(n) = &app.notice {
        let style = if n.error {
            Style::new().fg(Color::Red)
        } else {
            Style::new().fg(Color::Green)
        };
        let width = (n.text.chars().count() as u16 + 2).min(area.width);
        let rect = Rect::new(
            area.x + area.width.saturating_sub(width + 1),
            area.y,
            width,
            1,
        );
        f.render_widget(Paragraph::new(format!(" {} ", n.text)).style(style), rect);
    }
}

fn header(subtitle: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled("vykey", accent().bold()),
            Span::styled(format!(" — {subtitle}"), hint()),
        ]),
        Line::raw(""),
    ]
}

fn draw_create(f: &mut Frame, area: Rect, s: &CreateScreen, busy: bool, vaults: &[impl Sized]) {
    let box_area = centered(area, 48, 16);
    let [head, name, pw, confirm, _, buttons, _, help, err] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(box_area);
    f.render_widget(Paragraph::new(header("create a vault")), head);
    for (i, (rect, label, placeholder)) in [
        (name, "Name", "Vault name"),
        (pw, "Password", "Master password"),
        (confirm, "Confirm", "Repeat master password"),
    ]
    .into_iter()
    .enumerate()
    {
        let [l, v] = Layout::horizontal([Constraint::Length(10), Constraint::Min(1)]).areas(rect);
        f.render_widget(Paragraph::new(label).style(hint()), l);
        draw_input(f, v, &s.inputs[i], placeholder, s.focus == i, false);
    }
    let cancel = if vaults.is_empty() { "Quit" } else { "Cancel" };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            button(if busy { "Creating…" } else { "Create" }, s.focus == 3),
            Span::raw("  "),
            button(cancel, s.focus == 4),
        ])),
        buttons,
    );
    f.render_widget(
        Paragraph::new(hints(&[
            "tab: next field",
            "enter: confirm",
            "ctrl+c: quit",
        ])),
        help,
    );
    if let Some(e) = &s.error {
        f.render_widget(
            Paragraph::new(e.as_str())
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: true }),
            err,
        );
    }
}

fn draw_unlock(f: &mut Frame, area: Rect, s: &UnlockScreen, app: &App) {
    let rows = if s.entering { 2 } else { app.vaults.len() + 1 };
    let box_h = rows as u16 + 2;
    // Title, hints and error are centred over a column wider than the box,
    // so long hint lines still fit (as in the Go TUI).
    let column = centered(area, 64, box_h + 6);
    let [head, body, help, err] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(box_h),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(column);
    let body = centered(body, 40, box_h);
    f.render_widget(
        Paragraph::new(header("Vault Your Keys")).alignment(Alignment::Center),
        head,
    );
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(accent())
        .padding(Padding::horizontal(1));
    let inner = block.inner(body);
    f.render_widget(block, body);

    if s.entering {
        let name = app.vaults.get(s.selected).map_or("", |v| v.name.as_str());
        let [l1, l2] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(inner);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Vault: ", hint()),
                Span::raw(name.to_owned()),
            ])),
            l1,
        );
        let [prompt, field] =
            Layout::horizontal([Constraint::Length(2), Constraint::Min(1)]).areas(l2);
        f.render_widget(Paragraph::new(">").style(accent()), prompt);
        if matches!(app.pending, Some(Pending::Unlock { .. })) {
            f.render_widget(Paragraph::new("Unlocking…").style(accent()), field);
        } else {
            draw_input(f, field, &s.password, "Enter master password", true, false);
        }
        let retry = app.fp_line.as_ref().is_some_and(|l| !l.waiting);
        let items: &[&str] = if retry {
            &[
                "enter: unlock",
                "ctrl+f: fingerprint",
                "esc: vaults",
                "ctrl+c: quit",
            ]
        } else {
            &["enter: unlock", "esc: vaults", "ctrl+c: quit"]
        };
        f.render_widget(
            Paragraph::new(hints(items)).alignment(Alignment::Center),
            help,
        );
    } else {
        let mut lines = vec![Line::styled("Select vault:", hint())];
        let width = inner.width as usize;
        lines.extend(app.vaults.iter().enumerate().map(|(i, v)| {
            let count = app.store.entry_count(&v.id).unwrap_or(0);
            let count = format!("{count} {}", if count == 1 { "item" } else { "items" });
            let marker = if i == s.selected { "> " } else { "  " };
            let name_width = width.saturating_sub(count.chars().count() + 3);
            let name: String = v.name.chars().take(name_width).collect();
            let pad = width.saturating_sub(2 + name.chars().count() + count.chars().count());
            let style = if i == s.selected {
                accent().bold()
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::styled(format!("{marker}{name}{}", " ".repeat(pad)), style),
                Span::styled(count, hint()),
            ])
        }));
        f.render_widget(Paragraph::new(lines), inner);
        f.render_widget(
            Paragraph::new(hints(&[
                "↑/↓: select",
                "enter: confirm",
                "n: new vault",
                "q: quit",
            ]))
            .alignment(Alignment::Center),
            help,
        );
    }
    let mut lines = Vec::new();
    if let Some(e) = &s.error {
        lines.push(Line::styled(e.as_str(), Style::new().fg(Color::Red)));
    }
    // Like pam_fprintd under sudo: the password works meanwhile.
    if let Some(fp) = app.fp_line.as_ref().filter(|_| s.entering) {
        let style = if fp.waiting { accent() } else { hint() };
        lines.push(Line::styled(format!("◉ {}", fp.text), style));
    }
    if !lines.is_empty() {
        f.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            err,
        );
    }
}

/// Second line of a list row.
fn subtitle(app: &App, e: &Entry) -> String {
    let mut parts: Vec<String> = Vec::new();
    match e.kind {
        EntryKind::Login => {
            parts.extend(e.username.clone());
            parts.extend(e.url.clone());
        }
        EntryKind::Card => {
            let card = e.card.clone().unwrap_or_default();
            let last4 = card_fmt::last4(&card.number);
            if !last4.is_empty() {
                let brand = card_fmt::brand(&card.number).unwrap_or("Card");
                parts.push(format!("{brand} •••• {last4}"));
            }
            if !card.holder.is_empty() {
                parts.push(card.holder);
            }
        }
        EntryKind::Note => {
            parts.extend(
                e.notes
                    .as_deref()
                    .and_then(|n| n.lines().map(str::trim).find(|l| !l.is_empty()))
                    .map(|l| l.chars().take(80).collect()),
            );
        }
    }
    if let Some(folder) = app.folder_name(e.folder.as_deref()) {
        parts.push(format!("[{folder}]"));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" • ")
    }
}

fn kind_tag(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Login => "",
        EntryKind::Card => "card  ",
        EntryKind::Note => "note  ",
    }
}

fn draw_list(f: &mut Frame, area: Rect, app: &mut App) {
    let area = area.inner(ratatui::layout::Margin::new(2, 1));
    let [head, filter, list_area, help] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(
            if app.list.filtering || !app.list.filter.value().is_empty() {
                2
            } else {
                0
            },
        ),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    let vault = app.vault.as_ref().map_or("", |v| v.meta().name.as_str());
    let count = app.list.visible.len();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            title_bar("vykey"),
            Span::styled(
                format!(
                    "  {vault} · {count} {}",
                    if count == 1 { "item" } else { "items" }
                ),
                hint(),
            ),
        ])),
        head,
    );
    if filter.height > 0 {
        let [p, v] = Layout::horizontal([Constraint::Length(2), Constraint::Min(1)])
            .areas(Rect::new(filter.x, filter.y, filter.width, 1));
        f.render_widget(Paragraph::new("/").style(accent()), p);
        draw_input(f, v, &app.list.filter, "", app.list.filtering, false);
    }

    if app.list.visible.is_empty() {
        let text = if app.entries.is_empty() {
            "No entries yet. Press n to add one."
        } else {
            "Nothing found."
        };
        f.render_widget(Paragraph::new(text).style(hint()), list_area);
    } else {
        let items: Vec<ListItem> = app
            .list
            .visible
            .iter()
            .map(|&i| {
                let e = &app.entries[i];
                let star = if e.favorite { "★ " } else { "" };
                ListItem::new(Text::from(vec![
                    Line::from(vec![
                        Span::styled(star, Style::new().fg(Color::Yellow)),
                        Span::raw(e.title.clone()),
                    ]),
                    Line::styled(format!("{}{}", kind_tag(e.kind), subtitle(app, e)), hint()),
                    Line::raw(""),
                ]))
            })
            .collect();
        let list = List::new(items)
            .highlight_style(accent().bold())
            .highlight_symbol("│ ");
        f.render_stateful_widget(list, list_area, &mut app.list.state);
    }

    let items: &[&str] = if app.list.filtering {
        &["type to filter", "enter: done", "esc: clear"]
    } else {
        &[
            "↑/↓: move",
            "enter: open",
            "/: filter",
            "n: new",
            "v: vaults",
            "ctrl+l: lock",
            "q: quit",
        ]
    };
    f.render_widget(Paragraph::new(hints(items)), help);
}

fn label(text: &str) -> Span<'static> {
    Span::styled(
        format!("{:<width$}", format!("{text}:"), width = LABEL_WIDTH + 2),
        hint(),
    )
}

fn row(name: &str, value: impl Into<String>, key: Option<&str>) -> Line<'static> {
    let value: String = value.into();
    let mut spans = vec![
        label(name),
        Span::raw(if value.is_empty() { "-".into() } else { value }),
    ];
    if let Some(k) = key {
        spans.push(Span::styled(format!("  [{k}: copy]"), hint()));
    }
    Line::from(spans)
}

fn multiline_rows(name: &str, value: &str) -> Vec<Line<'static>> {
    let mut lines = value.split('\n');
    let mut out = vec![row(name, lines.next().unwrap_or_default(), None)];
    let indent = " ".repeat(LABEL_WIDTH + 2);
    out.extend(lines.map(|l| Line::raw(format!("{indent}{l}"))));
    out
}

fn masked(value: &str, reveal: bool) -> String {
    if reveal || value.is_empty() {
        value.to_owned()
    } else {
        "•".repeat(value.chars().count())
    }
}

fn format_date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

fn totp_line(e: &Entry) -> Option<Line<'static>> {
    let secret = e.totp_secret.as_deref()?;
    let now = now_unix() as u64;
    let remaining = totp::remaining(now, e.totp_period);
    let code = match totp::code(secret, now, e.totp_digits, e.totp_period) {
        Ok(code) => {
            let mid = code.len() / 2;
            let grouped = if code.len() >= 6 {
                format!("{} {}", &code[..mid], &code[mid..])
            } else {
                code
            };
            let color = match remaining {
                0..=5 => Color::Red,
                6..=10 => Color::Yellow,
                _ => Color::Green,
            };
            Span::styled(grouped, Style::new().fg(color).bold())
        }
        Err(_) => Span::styled("invalid secret", Style::new().fg(Color::Red)),
    };
    let name = match &e.totp_issuer {
        Some(issuer) => format!("TOTP · {issuer}"),
        None => "TOTP".into(),
    };
    Some(Line::from(vec![
        label(&name),
        code,
        Span::styled(format!(" ({remaining}s)"), hint()),
        Span::styled("  [t: copy]", hint()),
    ]))
}

fn draw_detail(f: &mut Frame, area: Rect, s: &DetailScreen, app: &App) {
    let Some(e) = app.entry(&s.id) else {
        return;
    };
    let area = area.inner(ratatui::layout::Margin::new(2, 1));
    let mut lines = vec![
        Line::from(vec![
            title_bar(&e.title),
            Span::styled(if e.favorite { "  ★" } else { "" }, Color::Yellow),
        ]),
        Line::raw(""),
    ];
    let card = e.card.clone().unwrap_or_default();
    let mut keys: Vec<&str> = Vec::new();
    match e.kind {
        EntryKind::Login => {
            lines.push(row(
                "Username",
                e.username.clone().unwrap_or_default(),
                Some("u"),
            ));
            lines.push(row(
                "Password",
                masked(e.password.as_deref().unwrap_or_default(), s.reveal),
                Some("c"),
            ));
            lines.push(row("URL", e.url.clone().unwrap_or_default(), None));
            lines.extend(multiline_rows(
                "Notes",
                e.notes.as_deref().unwrap_or_default(),
            ));
            lines.extend(totp_line(e));
            keys.extend(["u: copy username", "c: copy password"]);
            if e.totp_secret.is_some() {
                keys.push("t: copy TOTP");
            }
        }
        EntryKind::Card => {
            let number = if s.reveal || card.number.is_empty() {
                card_fmt::format_number(&card.number)
            } else {
                format!("•••• •••• •••• {}", card_fmt::last4(&card.number))
            };
            let brand = card_fmt::brand(&card.number).unwrap_or_default();
            lines.push(row("Cardholder", card.holder.clone(), Some("u")));
            lines.push(row(
                "Number",
                format!("{number}  {brand}").trim_end().to_owned(),
                Some("c"),
            ));
            let status = card_fmt::parse_expiry(&card.expiry)
                .map(|(m, y)| card_fmt::expiry_status(m, y, now_unix()));
            let expiry = match status {
                Some(ExpiryStatus::Expired) => format!("{} (expired)", card.expiry),
                Some(ExpiryStatus::ExpiringSoon) => format!("{} (expires soon)", card.expiry),
                _ => card.expiry.clone(),
            };
            lines.push(row("Expiry", expiry, None));
            lines.push(row("CVV", masked(&card.cvv, s.reveal), Some("v")));
            lines.push(row("PIN", masked(&card.pin, s.reveal), None));
            lines.extend(multiline_rows(
                "Notes",
                e.notes.as_deref().unwrap_or_default(),
            ));
            keys.extend(["u: copy holder", "c: copy number", "v: copy CVV"]);
        }
        EntryKind::Note => {
            lines.extend(
                e.notes
                    .as_deref()
                    .unwrap_or_default()
                    .split('\n')
                    .map(|l| Line::raw(l.to_owned())),
            );
            keys.push("c: copy note");
        }
    }
    lines.push(Line::raw(""));
    let mut meta = Vec::new();
    if let Some(folder) = app.folder_name(e.folder.as_deref()) {
        meta.push(format!("Folder: {folder}"));
    }
    meta.push(format!("Created {}", format_date(e.created_at)));
    if e.updated_at - e.created_at >= 60 {
        meta.push(format!("modified {}", format_date(e.updated_at)));
    }
    lines.push(Line::styled(meta.join(" · "), hint()));
    lines.push(Line::raw(""));

    if s.confirm_delete {
        lines.push(Line::from(vec![
            Span::styled("Delete this entry? ", Style::new().fg(Color::Red)),
            Span::styled("[y] yes", Style::new().fg(Color::Green)),
            Span::styled("  [n/esc] no", hint()),
        ]));
    } else {
        if e.kind != EntryKind::Note {
            keys.push("p: show/hide");
        }
        keys.extend(["f: favourite", "e: edit", "d: delete", "esc: back"]);
        lines.push(hints(&keys));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn draw_form(f: &mut Frame, area: Rect, s: &FormScreen) {
    let area = area.inner(ratatui::layout::Margin::new(2, 1));
    let rows = s.rows();
    let focused = s.focused();
    let mut constraints = vec![Constraint::Length(2)];
    for r in &rows {
        constraints.push(match r {
            FormRow::Kind => Constraint::Length(2),
            FormRow::Field(i) if s.fields[*i].input.multiline => Constraint::Length(4),
            FormRow::Field(_) => Constraint::Length(1),
            FormRow::Save => Constraint::Length(2),
            FormRow::Cancel => Constraint::Length(0),
        });
    }
    constraints.extend([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ]);
    let areas = Layout::vertical(constraints).split(area);

    let title = if s.id.is_some() {
        "Edit entry"
    } else {
        "New entry"
    };
    f.render_widget(
        Paragraph::new(Span::styled(title, accent().bold())),
        areas[0],
    );

    for (n, r) in rows.iter().enumerate() {
        let rect = areas[n + 1];
        let [l, v] = Layout::horizontal([
            Constraint::Length(LABEL_WIDTH as u16 + 2),
            Constraint::Min(1),
        ])
        .areas(rect);
        let active = *r == focused;
        match r {
            FormRow::Kind => {
                f.render_widget(Paragraph::new("Type").style(hint()), l);
                let kinds = [
                    (EntryKind::Login, "Login"),
                    (EntryKind::Card, "Card"),
                    (EntryKind::Note, "Note"),
                ];
                let mut spans = Vec::new();
                for (k, name) in kinds {
                    spans.push(if k == s.kind {
                        if active {
                            button(name, true)
                        } else {
                            Span::styled(format!("  {name}  "), accent().bold())
                        }
                    } else {
                        button(name, false)
                    });
                }
                if active {
                    spans.push(Span::styled("  ←/→", hint()));
                }
                f.render_widget(Paragraph::new(Line::from(spans)), v);
            }
            FormRow::Field(i) => {
                let field = &s.fields[*i];
                let label_style = if active { accent() } else { hint() };
                f.render_widget(Paragraph::new(field.id.label()).style(label_style), l);
                if field.input.multiline {
                    draw_textarea(f, v, &field.input, field.id.placeholder(), active);
                } else {
                    draw_input(
                        f,
                        Rect::new(v.x, v.y, v.width, 1),
                        &field.input,
                        field.id.placeholder(),
                        active,
                        s.reveal,
                    );
                }
            }
            FormRow::Save => {
                let line = Line::from(vec![
                    button("Save", focused == FormRow::Save),
                    Span::raw("  "),
                    button("Cancel", focused == FormRow::Cancel),
                ]);
                f.render_widget(
                    Paragraph::new(line),
                    Rect::new(rect.x, rect.y + 1, rect.width, 1),
                );
            }
            FormRow::Cancel => {}
        }
    }

    let base = rows.len() + 1;
    f.render_widget(
        Paragraph::new(hints(&[
            "tab: next",
            "ctrl+s: save",
            "ctrl+g: generate password",
            "ctrl+p: show/hide",
            "esc: back",
        ])),
        areas[base + 1],
    );
    if let Some(e) = &s.error {
        f.render_widget(
            Paragraph::new(e.as_str()).style(Style::new().fg(Color::Red)),
            areas[base + 2],
        );
    }
}
