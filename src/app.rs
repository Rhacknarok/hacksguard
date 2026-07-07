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
        tab_names.push("Entropy".into());
        tab_names.push("Guide".into());

        Self {
            result,
            current_tab: 0,
            scroll_offset: 0,
            should_quit: false,
            tab_names,
            yara_rx: None,
            yara_loading: false,
            embedded_pe_rx: None,
            embedded_pe_loading: false,
            inspect_embedded: false,
            spinner_tick: 0,
        }
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
                            // Add check
                            self.result.detection_checks.push(crate::models::DetectionCheck {
                                name: "Embedded PE executable found".into(),
                                triggered: true,
                                severity: crate::models::DetectionSeverity::Critical,
                            });

                            if self.result.pe.is_some() {
                                self.result.pe.as_mut().unwrap().embedded_pe = Some(Box::new(pe));
                            } else {
                                self.result.pe = Some(pe);
                            }

                            self.rebuild_tabs();

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
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
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
        if self.current_pe().is_some() {
            tab_names.push("Headers".into());
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
}
