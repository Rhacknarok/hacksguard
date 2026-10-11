use crate::models::{AnalysisResult, Result};
use crate::ui;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::DefaultTerminal;
use std::time::Duration;


#[derive(Clone, Debug)]
pub struct DumpTarget {
    pub label: String,
    pub filename: String,
    pub offset: usize,
    pub size: usize,
    pub xor_key: Option<u8>,
}

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
    pub show_dump_modal: bool,
    pub dump_targets: Vec<DumpTarget>,
    pub dump_selected_idx: usize,
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
            show_dump_modal: false,
            dump_targets: Vec::new(),
            dump_selected_idx: 0,
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
                    if self.show_dump_modal {
                        match key.code {
                            KeyCode::Esc => {
                                self.show_dump_modal = false;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if self.dump_selected_idx > 0 {
                                    self.dump_selected_idx -= 1;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if self.dump_selected_idx + 1 < self.dump_targets.len() {
                                    self.dump_selected_idx += 1;
                                }
                            }
                            KeyCode::Enter => {
                                if let Some(target) = self.dump_targets.get(self.dump_selected_idx).cloned() {
                                    self.show_dump_modal = false;
                                    match self.execute_dump(&target) {
                                        Ok(msg) => self.status_message = Some((msg, std::time::Instant::now())),
                                        Err(err) => self.status_message = Some((format!("Dump failed: {}", err), std::time::Instant::now())),
                                    }
                                }
                            }
                            _ => {}
                        }
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
                        KeyCode::Char('d') => {
                            let targets = self.get_dump_targets();
                            if targets.is_empty() {
                                self.status_message = Some(("No dumpable payloads identified in binary".into(), std::time::Instant::now()));
                            } else if targets.len() == 1 {
                                match self.execute_dump(&targets[0]) {
                                    Ok(msg) => self.status_message = Some((msg, std::time::Instant::now())),
                                    Err(err) => self.status_message = Some((format!("Dump failed: {}", err), std::time::Instant::now())),
                                }
                            } else {
                                self.dump_targets = targets;
                                self.dump_selected_idx = 0;
                                self.show_dump_modal = true;
                            }
                        }
                        KeyCode::Char('e') => {
                            if self.result.pe.as_ref().is_some_and(|pe| pe.embedded_pe.is_some()) {
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
            if !pe.resources.is_empty() {
                tab_names.push("Resources".into());
            }
            tab_names.push("Disasm".into());
            if pe.manifest.is_some() {
                tab_names.push("Manifest".into());
            }
        } else if self.result.elf.is_some() || self.result.macho.is_some() {
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
            parent.and_then(|pe| pe.embedded_pe.as_deref())
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
                        let match_dec = s.decoded.as_ref().is_some_and(|d| d.to_lowercase().contains(&query));
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
                    return;
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
                    return;
                }
            }
            _ => {}
        }

        let sha256 = self.result.basic.sha256.clone();
        self.send_osc52(&sha256);
        let short = if sha256.len() > 12 { &sha256[..12] } else { &sha256 };
        self.status_message = Some((format!("Copied SHA-256: {}…", short), std::time::Instant::now()));
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

    pub fn sanitize_filename_component(s: &str) -> String {
        let sanitized: String = s
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();
        let trimmed = sanitized.trim_matches('_');
        if trimmed.is_empty() {
            "item".to_string()
        } else {
            trimmed.to_string()
        }
    }

    pub fn get_dump_targets(&self) -> Vec<DumpTarget> {
        let mut targets = Vec::new();
        let file_size = self.result.file_info.size as usize;
        let raw_base = self.result.file_info.path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("sample");
        let base_name = Self::sanitize_filename_component(raw_base);

        if let Some(pe) = self.current_pe() {
            // 1. Unauthenticated Overlay
            if let (Some(off), Some(sz)) = (pe.overlay_offset, pe.overlay_size) {
                if sz > 0 && off < file_size {
                    targets.push(DumpTarget {
                        label: format!("Overlay Data (offset {:#x}, size {})", off, crate::ui::format_size(sz as u64)),
                        filename: format!("{}_overlay_{:#x}.bin", base_name, off),
                        offset: off,
                        size: sz,
                        xor_key: None,
                    });
                }
            }

            // 2. XOR Payloads
            for (i, p) in pe.xor_payloads.iter().enumerate() {
                let sz = (file_size.saturating_sub(p.offset)).min(1024 * 1024);
                if sz > 0 {
                    targets.push(DumpTarget {
                        label: format!("XOR Decrypted #{} (key {:#04x}, {})", i + 1, p.key, p.target_location),
                        filename: format!("{}_xor_key_{:#04x}_{:#x}.bin", base_name, p.key, p.offset),
                        offset: p.offset,
                        size: sz,
                        xor_key: Some(p.key),
                    });
                }
            }

            // 3. Embedded PE Executable
            if pe.embedded_pe.is_some() {
                if let Some(off) = pe.overlay_offset {
                    targets.push(DumpTarget {
                        label: format!("Embedded PE Executable (offset {:#x})", off),
                        filename: format!("{}_embedded_pe_{:#x}.exe", base_name, off),
                        offset: off,
                        size: file_size.saturating_sub(off),
                        xor_key: None,
                    });
                }
            }

            // 4. Resources
            for res in &pe.resources {
                let is_notable = res.type_id == 10 || res.magic_hint.is_some() || res.entropy > 6.5;
                if is_notable && res.size > 0 && res.file_offset < file_size {
                    let ext = if res.magic_hint.as_deref() == Some("PE (MZ)") { "exe" } else { "bin" };
                    let clean_id = Self::sanitize_filename_component(&res.name_or_id.replace('#', "id_"));
                    let clean_type = Self::sanitize_filename_component(&res.type_name);
                    targets.push(DumpTarget {
                        label: format!("Resource {}/{} ({} - ent: {:.2})", res.type_name, res.name_or_id, crate::ui::format_size(res.size as u64), res.entropy),
                        filename: format!("{}_rsrc_{}_{}.{}", base_name, clean_type, clean_id, ext),
                        offset: res.file_offset,
                        size: res.size,
                        xor_key: None,
                    });
                }
            }
        }

        targets
    }

    pub fn execute_dump(&self, target: &DumpTarget) -> std::result::Result<String, String> {
        let path = std::path::Path::new(&target.filename);
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err("Path traversal detected in target filename".into());
        }

        let data = std::fs::read(&self.result.file_info.path).map_err(|e| e.to_string())?;
        if target.offset >= data.len() {
            return Err("Offset out of bounds".into());
        }
        let end = (target.offset + target.size).min(data.len());
        let mut payload = data[target.offset..end].to_vec();
        if let Some(key) = target.xor_key {
            for b in &mut payload {
                *b ^= key;
            }
        }
        std::fs::write(&target.filename, &payload).map_err(|e| e.to_string())?;
        Ok(format!("Dumped {} bytes to {}", payload.len(), target.filename))
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

    #[test]
    fn test_execute_dump() {
        let temp_dir = std::env::temp_dir();
        let src_file = temp_dir.join(format!("test_src_{}.bin", std::process::id()));
        let out_file = temp_dir.join(format!("test_out_{}.bin", std::process::id()));

        let raw_data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        std::fs::write(&src_file, &raw_data).unwrap();

        let app = App::new(crate::models::AnalysisResult {
            file_info: crate::models::FileInfo {
                path: src_file.clone(),
                name: "test.bin".into(),
                size: raw_data.len() as u64,
                file_type: crate::models::FileType::Unknown,
                magic_bytes: vec![],
            },
            basic: crate::models::BasicAnalysis {
                md5: "".into(),
                sha1: "".into(),
                sha256: "".into(),
                entropy: 0.0,
                strings: vec![],
                is_packed: false,
                byte_distribution: vec![0; 256],
            },
            pe: None,
            elf: None,
            macho: None,
            risk_score: 0,
            risk_level: crate::models::RiskLevel::Clean,
            risk_breakdown: crate::models::RiskBreakdown {
                entropy_score: 0,
                api_score: 0,
                anomaly_score: 0,
                string_score: 0,
                packing_score: 0,
            },
            detection_checks: vec![],
            malware_pattern: None,
            yara_matches: vec![],
            entropy_graph: vec![],
        });

        let target = DumpTarget {
            label: "Test Dump".into(),
            filename: out_file.to_str().unwrap().into(),
            offset: 1,
            size: 3,
            xor_key: Some(0x20),
        };

        let result = app.execute_dump(&target);
        assert!(result.is_ok());

        let dumped = std::fs::read(&out_file).unwrap();
        // raw_data[1..4] = [0x20, 0x30, 0x40] ^ 0x20 = [0x00, 0x10, 0x60]
        assert_eq!(dumped, vec![0x00, 0x10, 0x60]);

        let _ = std::fs::remove_file(src_file);
        let _ = std::fs::remove_file(out_file);
    }

    #[test]
    fn test_sanitize_filename_component() {
        assert_eq!(App::sanitize_filename_component("../../../../etc/passwd"), "etc_passwd");
        assert_eq!(App::sanitize_filename_component(r"..\..\Windows\System32\calc.exe"), "Windows_System32_calc_exe");
        assert_eq!(App::sanitize_filename_component("valid-name_01"), "valid-name_01");
        assert_eq!(App::sanitize_filename_component("...///:::"), "item");
    }

    #[test]
    fn test_execute_dump_prevents_path_traversal() {
        let app = App::new(crate::models::AnalysisResult {
            file_info: crate::models::FileInfo {
                path: std::path::PathBuf::from("dummy.bin"),
                name: "dummy.bin".into(),
                size: 10,
                file_type: crate::models::FileType::Unknown,
                magic_bytes: vec![],
            },
            basic: crate::models::BasicAnalysis {
                md5: "".into(),
                sha1: "".into(),
                sha256: "".into(),
                entropy: 0.0,
                strings: vec![],
                is_packed: false,
                byte_distribution: vec![0; 256],
            },
            pe: None,
            elf: None,
            macho: None,
            risk_score: 0,
            risk_level: crate::models::RiskLevel::Clean,
            risk_breakdown: crate::models::RiskBreakdown {
                entropy_score: 0,
                api_score: 0,
                anomaly_score: 0,
                string_score: 0,
                packing_score: 0,
            },
            detection_checks: vec![],
            malware_pattern: None,
            yara_matches: vec![],
            entropy_graph: vec![],
        });

        let target = DumpTarget {
            label: "Malicious Traversal".into(),
            filename: "../../evil.bin".into(),
            offset: 0,
            size: 4,
            xor_key: None,
        };

        let result = app.execute_dump(&target);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal"));
    }
}
