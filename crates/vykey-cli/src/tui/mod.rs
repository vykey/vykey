//! Full-screen terminal UI.

mod app;
mod input;
mod view;

use std::io;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyEventKind};
use vykey_core::Store;

use app::App;

/// Redraw interval while idle: TOTP countdown, notices, auto-lock.
const TICK: Duration = Duration::from_millis(250);

pub fn run(store: Store) -> io::Result<()> {
    let mut app = App::new(store, true);
    // Also installs a panic hook that restores the terminal.
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| view::draw(f, app))?;
        if let Some(job) = app.pending.take() {
            // Drawn with the busy state above; now do the slow part.
            app.run_pending(job);
            continue;
        }
        if app.quit {
            return Ok(());
        }
        if event::poll(TICK)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key);
        }
        app.tick();
    }
}
