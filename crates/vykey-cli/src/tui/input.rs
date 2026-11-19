//! Editable text field: single line or multi-line, optionally masked.
//! The value is zeroized on drop because fields hold passwords.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroize;

#[derive(Default)]
pub struct Input {
    value: String,
    /// Cursor position in chars.
    cursor: usize,
    pub masked: bool,
    pub multiline: bool,
}

impl Drop for Input {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl Input {
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_owned(),
            cursor: value.chars().count(),
            ..Self::default()
        }
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    pub fn multiline(mut self) -> Self {
        self.multiline = true;
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set(&mut self, value: &str) {
        self.value.zeroize();
        self.value = value.to_owned();
        self.cursor = value.chars().count();
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map_or(self.value.len(), |(i, _)| i)
    }

    fn len(&self) -> usize {
        self.value.chars().count()
    }

    /// (line, column) of the cursor, both in chars.
    pub fn cursor_line_col(&self) -> (usize, usize) {
        let before: String = self.value.chars().take(self.cursor).collect();
        let line = before.matches('\n').count();
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count());
        (line, col)
    }

    /// Char offset where `line` starts, and that line's length.
    fn line_span(&self, line: usize) -> Option<(usize, usize)> {
        let mut start = 0;
        for (i, l) in self.value.split('\n').enumerate() {
            let len = l.chars().count();
            if i == line {
                return Some((start, len));
            }
            start += len + 1;
        }
        None
    }

    /// Text as shown: bullets instead of characters when masked.
    pub fn display(&self, reveal: bool) -> String {
        if self.masked && !reveal {
            "•".repeat(self.len())
        } else {
            self.value.clone()
        }
    }

    /// Applies an editing key. Returns false if the key is not an edit
    /// (navigation between fields, shortcuts), so the caller can handle it.
    pub fn handle(&mut self, key: KeyEvent) -> bool {
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match key.code {
            KeyCode::Char(c) if plain => {
                let at = self.byte_at(self.cursor);
                self.value.insert(at, c);
                self.cursor += 1;
            }
            KeyCode::Enter if self.multiline => {
                let at = self.byte_at(self.cursor);
                self.value.insert(at, '\n');
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
            }
            KeyCode::Backspace => {}
            KeyCode::Delete if self.cursor < self.len() => {
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
            }
            KeyCode::Delete => {}
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len()),
            KeyCode::Home | KeyCode::End if self.multiline => {
                let (line, _) = self.cursor_line_col();
                if let Some((start, len)) = self.line_span(line) {
                    self.cursor = if key.code == KeyCode::Home {
                        start
                    } else {
                        start + len
                    };
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len(),
            KeyCode::Up | KeyCode::Down if self.multiline => {
                let (line, col) = self.cursor_line_col();
                let target = if key.code == KeyCode::Up {
                    line.checked_sub(1)
                } else {
                    Some(line + 1)
                };
                if let Some((start, len)) = target.and_then(|l| self.line_span(l)) {
                    self.cursor = start + col.min(len);
                }
            }
            _ => return false,
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn editing() {
        let mut i = Input::new("añb");
        assert!(i.handle(key(KeyCode::Left)));
        assert!(i.handle(key(KeyCode::Backspace)));
        assert_eq!(i.value(), "ab");
        assert!(i.handle(key(KeyCode::Char('ü'))));
        assert_eq!(i.value(), "aüb");
        assert!(i.handle(key(KeyCode::Home)));
        assert!(i.handle(key(KeyCode::Delete)));
        assert_eq!(i.value(), "üb");
        assert!(!i.handle(key(KeyCode::Tab)));
        assert!(!i.handle(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)));
        assert!(!i.handle(key(KeyCode::Enter)));
    }

    #[test]
    fn multiline_navigation() {
        let mut i = Input::new("first\nab").multiline();
        assert_eq!(i.cursor_line_col(), (1, 2));
        assert!(i.handle(key(KeyCode::Up)));
        assert_eq!(i.cursor_line_col(), (0, 2));
        assert!(i.handle(key(KeyCode::End)));
        assert!(i.handle(key(KeyCode::Enter)));
        assert_eq!(i.value(), "first\n\nab");
        assert!(i.handle(key(KeyCode::Down)));
        assert_eq!(i.cursor_line_col(), (2, 0));
    }

    #[test]
    fn masking() {
        let i = Input::new("secret").masked();
        assert_eq!(i.display(false), "••••••");
        assert_eq!(i.display(true), "secret");
    }
}
