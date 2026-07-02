use crate::tui::ui;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::DefaultTerminal;
use std::time::Duration;

use crate::models::AnalysisResult;

pub struct App {
    pub result: AnalysisResult,
    pub current_tab: usize,
    pub scroll_offset: u16,
    pub should_quit: bool,
    pub tab_names: Vec<String>,
}

impl App {
    pub fn new(result: AnalysisResult) -> Self {
        let mut tab_names = vec!["Overview".to_string()];
        if result.pe.is_some() {
            tab_names.push("Headers".into());
            tab_names.push("Sections".into());
            tab_names.push("Imports".into());
            tab_names.push("Disasm".into());
        }
        tab_names.push("Hex View".into());
        tab_names.push("Strings".into());
        tab_names.push("Guide".into());

        Self {
            result,
            current_tab: 0,
            scroll_offset: 0,
            should_quit: false,
            tab_names,
        }
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|f| ui::draw(f, self))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                        KeyCode::Right | KeyCode::Tab => self.next_tab(),
                        KeyCode::Left | KeyCode::BackTab => self.prev_tab(),
                        KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
                        KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
                        KeyCode::Home | KeyCode::Char('g') => self.scroll_offset = 0,
                        KeyCode::PageDown => {
                            self.scroll_offset = self.scroll_offset.saturating_add(20)
                        }
                        KeyCode::PageUp => {
                            self.scroll_offset = self.scroll_offset.saturating_sub(20)
                        }
                        _ => {}
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    fn next_tab(&mut self) {
        self.current_tab = (self.current_tab + 1) % self.tab_names.len();
        self.scroll_offset = 0;
    }

    fn prev_tab(&mut self) {
        if self.current_tab == 0 {
            self.current_tab = self.tab_names.len() - 1;
        } else {
            self.current_tab -= 1;
        }
        self.scroll_offset = 0;
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }
}
