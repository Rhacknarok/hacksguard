pub mod ui;

use ratatui::DefaultTerminal;

/// Set up the terminal for the TUI.
pub fn init() -> DefaultTerminal {
    ratatui::init()
}

/// Restore the terminal to its original state.
pub fn restore() {
    ratatui::restore();
}
