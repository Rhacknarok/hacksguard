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
    pub yara_rx: Option<std::sync::mpsc::Receiver<Vec<String>>>,
    pub yara_loading: bool,
    pub embedded_pe_rx: Option<std::sync::mpsc::Receiver<Option<crate::models::PeAnalysis>>>,
    pub embedded_pe_loading: bool,
    pub inspect_embedded: bool,
    pub spinner_tick: u32,
    pub search_query: String,
    pub is_searching: bool,
    pub string_category_filter: Option<crate::models::StringCategory>,
    pub status_message: Option<(String, std::time::Instant)>,
}

impl App {
    pub fn new(result: AnalysisResult) -> Self {
        let mut app = Self {
            result,
            current_tab: 0,
            scroll_offset: 0,
            should_quit: false,
            tab_names: Vec::new(),
            yara_rx: None,
            yara_loading: false,
            embedded_pe_rx: None,
            embedded_pe_loading: false,
            inspect_embedded: false,
            spinner_tick: 0,
            search_query: String::new(),
            is_searching: false,
            string_category_filter: None,
            status_message: None,
        };
        app.rebuild_tabs();
        app
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        loop {
            let mut tick = false;
            if self.yara_loading {
                tick = true;
                if let Some(ref rx) = self.yara_rx {
                    if let Ok(matches) = rx.try_recv() {
                        self.yara_loading = false;
                        self.result.yara_matches = matches;
                        
                        // Recompute risk score and level dynamically
                        let (score, level) = crate::analysis::compute_risk_from_checks(
                            &self.result.detection_checks,
                            &self.result.yara_matches,
                        );
                        self.result.risk_score = score;
                        self.result.risk_level = level;
                    }
                }
            }

            if self.embedded_pe_loading {
                tick = true;
                if let Some(ref rx) = self.embedded_pe_rx {
                    if let Ok(opt_pe) = rx.try_recv() {
                        self.embedded_pe_loading = false;
                        if let Some(pe) = opt_pe {
                            self.result.attach_embedded_pe(pe);
                            self.rebuild_tabs();
                        }
                    }
                }
            }

            if tick {
                self.spinner_tick = self.spinner_tick.wrapping_add(1);
            }

            terminal.draw(|f| ui::draw(f, self))?;

            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if self.is_searching {
                        match key.code {
                            KeyCode::Esc => {
                                self.search_query.clear();
                                self.is_searching = false;
                            }
                            KeyCode::Enter => {
                                self.is_searching = false;
                            }
                            KeyCode::Backspace => {
                                self.search_query.pop();
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char(c) => {
                                self.search_query.push(c);
                                self.scroll_offset = 0;
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // Category filters in Strings tab
                    if self.current_tab_name() == "Strings" {
                        let toggled = match key.code {
                            KeyCode::Char('u') => Some(crate::models::StringCategory::Url),
                            KeyCode::Char('i') => Some(crate::models::StringCategory::IpAddress),
                            KeyCode::Char('r') => Some(crate::models::StringCategory::RegistryKey),
                            KeyCode::Char('c') => Some(crate::models::StringCategory::Command),
                            KeyCode::Char('s') => Some(crate::models::StringCategory::Suspicious),
                            KeyCode::Char('p') => Some(crate::models::StringCategory::FilePath),
                            KeyCode::Char('a') => {
                                self.string_category_filter = None;
                                self.scroll_offset = 0;
                                continue;
                            }
                            _ => None,
                        };
                        if let Some(cat) = toggled {
                            self.string_category_filter = if self.string_category_filter == Some(cat.clone()) {
                                None
                            } else {
                                Some(cat)
                            };
                            self.scroll_offset = 0;
                            continue;
                        }
                    }

                    match key.code {
                        KeyCode::Char('q') => self.should_quit = true,
                        KeyCode::Esc => {
                            if !self.search_query.is_empty() {
                                self.search_query.clear();
                                self.scroll_offset = 0;
                            } else if self.string_category_filter.is_some() {
                                self.string_category_filter = None;
                                self.scroll_offset = 0;
                            } else {
                                self.should_quit = true;
                            }
                        }
                        KeyCode::Char('/') => {
                            self.is_searching = true;
                            self.scroll_offset = 0;
                        }
                        KeyCode::Char('y') => {
                            self.copy_to_clipboard();
                        }
                        KeyCode::Char('e') => {
                            if self.result.pe.as_ref().map_or(false, |pe| pe.embedded_pe.is_some()) {
                                self.inspect_embedded = !self.inspect_embedded;
                                self.rebuild_tabs();
                                self.current_tab = 0; // go to Overview on toggle
                            }
                        }
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

    pub fn rebuild_tabs(&mut self) {
        let mut tab_names = vec!["Overview".to_string()];
        if let Some(pe) = self.current_pe() {
            tab_names.push("Headers".into());
            tab_names.push("Sections".into());
            tab_names.push("Imports".into());
            tab_names.push("Disasm".into());
            if pe.manifest.is_some() {
                tab_names.push("Manifest".into());
            }
        } else if self.result.elf.is_some() {
            tab_names.push("Headers".into());
            tab_names.push("Segments".into());
            tab_names.push("Sections".into());
            tab_names.push("Imports".into());
            tab_names.push("Disasm".into());
        } else if self.result.macho.is_some() {
            tab_names.push("Headers".into());
            tab_names.push("Segments".into());
            tab_names.push("Sections".into());
            tab_names.push("Imports".into());
            tab_names.push("Disasm".into());
        }
        tab_names.push("Hex View".into());
        tab_names.push("Strings".into());
        tab_names.push("Entropy".into());
        tab_names.push("Guide".into());
        self.tab_names = tab_names;
    }

    pub fn current_pe(&self) -> Option<&crate::models::PeAnalysis> {
        let parent = self.result.pe.as_ref();
        if self.inspect_embedded {
            parent.and_then(|pe| pe.embedded_pe.as_ref().map(|b| &**b))
        } else {
            parent
        }
    }

    pub fn current_tab_name(&self) -> &str {
        self.tab_names.get(self.current_tab).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn copy_to_clipboard(&mut self) {
        let current_tab = self.current_tab_name().to_string();
        match current_tab.as_str() {
            "Overview" => {
                let sha256 = self.result.basic.sha256.clone();
                self.send_osc52(&sha256);
                let short = if sha256.len() > 12 { &sha256[..12] } else { &sha256 };
                self.status_message = Some((format!("Copied SHA-256: {}…", short), std::time::Instant::now()));
            }
            "Strings" => {
                let query = self.search_query.to_lowercase();
                let cat_filter = self.string_category_filter.as_ref();
                let matching = self.result.basic.strings.iter().find(|s| {
                    if let Some(cat) = cat_filter {
                        if s.category != *cat {
                            return false;
                        }
                    }
                    if !query.is_empty() {
                        let match_val = s.value.to_lowercase().contains(&query);
                        let match_dec = s.decoded.as_ref().map_or(false, |d| d.to_lowercase().contains(&query));
                        if !match_val && !match_dec {
                            return false;
                        }
                    }
                    true
                });
                if let Some(s) = matching {
                    self.send_osc52(&s.value);
                    let disp = if s.value.len() > 20 { format!("{}…", &s.value[..20]) } else { s.value.clone() };
                    self.status_message = Some((format!("Copied string: {}", disp), std::time::Instant::now()));
                }
            }
            "Headers" => {
                if let Some(pe) = self.current_pe() {
                    let (val, label) = if let Some(ref imp) = pe.imphash {
                        (imp.clone(), "Imphash")
                    } else if let Some(ref rich) = pe.rich_header {
                        (rich.rich_hash.clone(), "RichPE")
                    } else {
                        (self.result.basic.sha256.clone(), "SHA-256")
                    };
                    self.send_osc52(&val);
                    let short = if val.len() > 12 { &val[..12] } else { &val };
                    self.status_message = Some((format!("Copied {}: {}…", label, short), std::time::Instant::now()));
                } else {
                    let sha256 = self.result.basic.sha256.clone();
                    self.send_osc52(&sha256);
                    let short = if sha256.len() > 12 { &sha256[..12] } else { &sha256 };
                    self.status_message = Some((format!("Copied SHA-256: {}…", short), std::time::Instant::now()));
                }
            }
            _ => {
                let sha256 = self.result.basic.sha256.clone();
                self.send_osc52(&sha256);
                let short = if sha256.len() > 12 { &sha256[..12] } else { &sha256 };
                self.status_message = Some((format!("Copied SHA-256: {}…", short), std::time::Instant::now()));
            }
        }
    }

    pub fn format_osc52(text: &str) -> String {
        use base64::{Engine as _, engine::general_purpose};
        let b64 = general_purpose::STANDARD.encode(text);
        format!("\x1b]52;c;{}\x07", b64)
    }

    pub fn send_osc52(&self, text: &str) {
        let osc = Self::format_osc52(text);
        use std::io::Write;
        let _ = std::io::stdout().write_all(osc.as_bytes());
        let _ = std::io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osc52_formatting() {
        let payload = "hello world";
        let osc = App::format_osc52(payload);
        assert_eq!(osc, "\x1b]52;c;aGVsbG8gd29ybGQ=\x07");
    }
}
