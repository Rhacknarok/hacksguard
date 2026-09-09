use crate::app::App;
use crate::models::*;
use crate::theme;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter, Instruction};

// ─── Main draw ───────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // title
        Constraint::Length(3), // tabs
        Constraint::Min(0),   // content
        Constraint::Length(1), // status
    ])
    .split(frame.area());

    // Background fill
    let bg = Block::default().style(Style::default().bg(theme::BG_DARK));
    frame.render_widget(bg, frame.area());

    draw_title(frame, chunks[0], app);
    draw_tabs(frame, chunks[1], app);

    let tab_name = &app.tab_names[app.current_tab];
    match tab_name.as_str() {
        "Overview" => draw_overview(frame, chunks[2], app),
        "Headers" => {
            if app.current_pe().is_some() {
                draw_headers(frame, chunks[2], app);
            } else if app.result.elf.is_some() {
                draw_elf_headers(frame, chunks[2], app);
            } else if app.result.macho.is_some() {
                draw_macho_headers(frame, chunks[2], app);
            }
        }
        "Segments" => {
            if app.result.elf.is_some() {
                draw_elf_segments(frame, chunks[2], app);
            } else if app.result.macho.is_some() {
                draw_macho_segments(frame, chunks[2], app);
            }
        }
        "Sections" => {
            if app.current_pe().is_some() {
                draw_sections(frame, chunks[2], app);
            } else if app.result.elf.is_some() {
                draw_elf_sections(frame, chunks[2], app);
            } else if app.result.macho.is_some() {
                draw_macho_sections(frame, chunks[2], app);
            }
        }
        "Imports" => {
            if app.current_pe().is_some() {
                draw_imports(frame, chunks[2], app);
            } else if app.result.elf.is_some() {
                draw_elf_imports(frame, chunks[2], app);
            } else if app.result.macho.is_some() {
                draw_macho_imports(frame, chunks[2], app);
            }
        }
        "Manifest" => draw_manifest(frame, chunks[2], app),
        "Entropy" => draw_entropy(frame, chunks[2], app),
        "Disasm" => {
            if app.current_pe().is_some() {
                draw_disasm(frame, chunks[2], app);
            } else if app.result.elf.is_some() {
                draw_elf_disasm(frame, chunks[2], app);
            } else if app.result.macho.is_some() {
                draw_macho_disasm(frame, chunks[2], app);
            }
        }
        "Hex View" => draw_hexdump(frame, chunks[2], app),
        "Strings" => draw_strings(frame, chunks[2], app),
        "Guide" => draw_guide(frame, chunks[2], app),
        _ => {}
    }

    draw_status_bar(frame, chunks[3], app);
}

// ─── Title bar ───────────────────────────────────────────────────

fn draw_title(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![
        Span::styled("  ◆ ", Style::default().fg(theme::ORANGE)),
        Span::styled(
            "HACKSGUARD",
            Style::default()
                .fg(theme::ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ─  ", Style::default().fg(theme::BORDER)),
        Span::styled(
            &app.result.file_info.name,
            Style::default().fg(theme::TEXT),
        ),
        Span::styled(
            format!("  ({})", format_size(app.result.file_info.size)),
            Style::default().fg(theme::TEXT_DIM),
        ),
    ];

    if app.inspect_embedded {
        spans.push(Span::styled(
            "  [EMBEDDED PE VIEW]",
            Style::default().fg(theme::WARNING).add_modifier(Modifier::BOLD),
        ));
    }

    let title = Line::from(spans);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ORANGE_DARK))
        .style(Style::default().bg(theme::BG_DARK));

    frame.render_widget(Paragraph::new(title).block(block), area);
}

// ─── Tab bar ─────────────────────────────────────────────────────

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = app
        .tab_names
        .iter()
        .map(|t| Line::from(Span::raw(format!(" {} ", t))))
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.current_tab)
        .highlight_style(
            Style::default()
                .fg(theme::ORANGE)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .style(Style::default().fg(theme::TEXT_DIM))
        .divider("│")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .style(Style::default().bg(theme::BG_DARK)),
        );

    frame.render_widget(tabs, area);
}

// ─── Status bar ──────────────────────────────────────────────────

fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();

    if app.is_searching {
        spans.push(Span::styled(" Search: /", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(&app.search_query, Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled("█  ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("[Enter: Apply, Esc: Cancel]", Style::default().fg(theme::TEXT_DIM)));
    } else {
        if let Some((ref msg, instant)) = app.status_message {
            if instant.elapsed().as_secs() < 3 {
                spans.push(Span::styled(format!(" ✓ {}  ", msg), Style::default().fg(theme::SAFE).add_modifier(Modifier::BOLD)));
            }
        }

        if !app.search_query.is_empty() {
            spans.push(Span::styled(" Filter: ", Style::default().fg(theme::WARNING)));
            spans.push(Span::styled(format!("\"{}\" ", app.search_query), Style::default().fg(theme::TEXT)));
            spans.push(Span::styled("(Esc to clear)  ", Style::default().fg(theme::TEXT_DIM)));
        }

        spans.push(Span::styled("←/→ ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("Tab  ", Style::default().fg(theme::TEXT_DIM)));
        spans.push(Span::styled("↑/↓ ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("Scroll  ", Style::default().fg(theme::TEXT_DIM)));
        spans.push(Span::styled("/ ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("Search  ", Style::default().fg(theme::TEXT_DIM)));
        spans.push(Span::styled("y ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("Copy  ", Style::default().fg(theme::TEXT_DIM)));

        if app.current_tab_name() == "Strings" {
            spans.push(Span::styled("u/i/r/c/s/a ", Style::default().fg(theme::ORANGE)));
            spans.push(Span::styled("Category  ", Style::default().fg(theme::TEXT_DIM)));
        }

        if app.result.pe.as_ref().is_some_and(|pe| pe.embedded_pe.is_some()) {
            spans.push(Span::styled("e ", Style::default().fg(theme::ORANGE)));
            spans.push(Span::styled("Toggle PE  ", Style::default().fg(theme::TEXT_DIM)));
        }

        spans.push(Span::styled("q ", Style::default().fg(theme::ORANGE)));
        spans.push(Span::styled("Quit", Style::default().fg(theme::TEXT_DIM)));
    }

    let help = Line::from(spans);
    frame.render_widget(
        Paragraph::new(help).style(Style::default().bg(theme::BG_PANEL)),
        area,
    );
}

// ─── Overview tab ────────────────────────────────────────────────

fn draw_overview(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // verdict banner
        Constraint::Min(0),   // scrollable content
    ])
    .split(area);

    draw_verdict_banner(frame, chunks[0], app);
    draw_overview_body(frame, chunks[1], app);
}

fn draw_verdict_banner(frame: &mut Frame, area: Rect, app: &App) {
    let level = &app.result.risk_level;
    let score = app.result.risk_score;
    let color = theme::risk_color(level);

    let (icon, msg) = match level {
        RiskLevel::Clean => ("✓", "CLEAN — No threats detected"),
        RiskLevel::Low => ("◆", "LOW RISK — Minor indicators found"),
        RiskLevel::Medium => ("▲", "MEDIUM RISK — Suspicious indicators present"),
        RiskLevel::High => ("⚠", "HIGH RISK — Multiple threat indicators"),
        RiskLevel::Critical => ("!", "CRITICAL — Strong malware indicators detected"),
    };

    let line = Line::from(vec![
        Span::styled(
            format!("  {} ", icon),
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            msg.to_string(),
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  [{}/100]", score),
            Style::default().fg(color),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_overview_body(frame: &mut Frame, area: Rect, app: &App) {
    let block = panel_block("Dashboard");
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(inner_area);

    let mut left_lines: Vec<Line> = Vec::new();
    let mut right_lines: Vec<Line> = Vec::new();

    build_file_info_lines(&mut left_lines, app);
    build_risk_radar_lines(&mut left_lines, app);
    build_hashes_lines(&mut left_lines, app);
    build_detection_ratio_lines(&mut left_lines, app);
    build_packer_lines(&mut left_lines, app);

    build_yara_lines(&mut right_lines, app);
    build_embedded_pe_lines(&mut right_lines, app);
    build_entropy_histogram_lines(&mut right_lines, app);
    build_byte_distribution_lines(&mut right_lines, app);
    build_import_heatmap_lines(&mut right_lines, app);
    build_suspicious_strings_lines(&mut right_lines, app);
    build_malware_pattern_lines(&mut right_lines, app);
    build_anomalies_lines(&mut right_lines, app);

    frame.render_widget(
        Paragraph::new(left_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(right_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[1],
    );
}

fn build_file_info_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let info = &app.result.file_info;
    let file_type_str = if let Some(pe) = app.current_pe() {
        let arch = if pe.is_64bit { "PE32+" } else { "PE32" };
        let kind = if pe.is_dll { "DLL" } else { "EXE" };
        format!("{} {} ({})", arch, kind, pe.machine)
    } else if let Some(elf) = app.result.elf.as_ref() {
        format!("ELF {} {} ({})", elf.class, elf.elf_type, elf.machine)
    } else {
        info.file_type.to_string()
    };

    let magic_hex: String = info
        .magic_bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    lines.push(section_header("File Info"));
    lines.push(kv_line("Name", &info.name));
    lines.push(kv_line(
        "Size",
        &format!("{} ({})", format_size(info.size), info.size),
    ));
    lines.push(kv_line("Type", &file_type_str));
    lines.push(kv_line("Magic", &magic_hex));


    if let Some(pe) = app.current_pe() {
        lines.push(Line::from(""));
        lines.push(section_header("PE Metadata"));
        if let Some(ref cert) = pe.certificate {
            let status = if cert.is_self_signed {
                format!("✅ Signed (Self-Signed ⚠️ - {})", cert.subject)
            } else {
                format!("✅ Signed ({})", cert.subject)
            };
            lines.push(kv_line("Certificate", &status));
        } else if pe.has_authenticode {
            lines.push(kv_line("Authenticode", "✅ Present"));
        } else {
            lines.push(kv_line("Authenticode", "❌ Not signed"));
        }
        if !pe.xor_payloads.is_empty() {
            lines.push(kv_line("XOR Payloads", &format!("⚠️ {} detected", pe.xor_payloads.len())));
        }
        lines.push(kv_line(
            "Entry Point",
            &format!("{:#010x}", pe.entry_point),
        ));
        lines.push(kv_line(
            "Image Base",
            &format!("{:#010x}", pe.image_base),
        ));
        lines.push(kv_line("Subsystem", &pe.subsystem));
        lines.push(kv_line("Linker", &pe.linker_version));
        
        if let (Some(offset), Some(size)) = (pe.overlay_offset, pe.overlay_size) {
            lines.push(kv_line("Overlay", &format!("Offset {:#x}, Size {}", offset, size)));
        }

        let ts_color = if pe.timestamp_suspicious {
            theme::WARNING
        } else {
            theme::TEXT
        };
        let ts_flag = if pe.timestamp_suspicious {
            " ⚠"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(" Compiled:  ".to_string(), theme::label()),
            Span::styled(
                format!(
                    "{} ({}){}",
                    pe.timestamp_str, pe.compilation_age, ts_flag
                ),
                Style::default().fg(ts_color),
            ),
        ]));
        if let Some(ref pdb) = pe.pdb_path {
            lines.push(kv_line("PDB Path", pdb));
        }
    } else if let Some(elf) = app.result.elf.as_ref() {
        lines.push(Line::from(""));
        lines.push(section_header("ELF Metadata & Hardening"));
        lines.push(kv_line("Entry Point", &format!("{:#010x}", elf.entry_point)));
        lines.push(kv_line("Class", &format!("{} ({})", elf.class, elf.endianness)));
        if let Some(ref interp) = elf.interpreter {
            lines.push(kv_line("Interpreter", interp));
        }

        let nx_str = if elf.mitigations.nx { "✅ NX (Non-Exec Stack)" } else { "❌ No NX (Exec Stack!)" };
        let nx_color = if elf.mitigations.nx { theme::SAFE } else { theme::CRITICAL };
        lines.push(Line::from(vec![
            Span::styled(" NX:        ".to_string(), theme::label()),
            Span::styled(nx_str.to_string(), Style::default().fg(nx_color).add_modifier(Modifier::BOLD)),
        ]));

        let pie_str = if elf.mitigations.pie { "✅ PIE (Position Indep)" } else { "❌ No PIE" };
        let pie_color = if elf.mitigations.pie { theme::SAFE } else { theme::WARNING };
        lines.push(Line::from(vec![
            Span::styled(" PIE:       ".to_string(), theme::label()),
            Span::styled(pie_str.to_string(), Style::default().fg(pie_color)),
        ]));

        let relro_str = match elf.mitigations.relro {
            ElfRelro::Full => "✅ Full RELRO",
            ElfRelro::Partial => "⚠ Partial RELRO",
            ElfRelro::None => "❌ No RELRO",
        };
        let relro_color = match elf.mitigations.relro {
            ElfRelro::Full => theme::SAFE,
            ElfRelro::Partial => theme::WARNING,
            ElfRelro::None => theme::CRITICAL,
        };
        lines.push(Line::from(vec![
            Span::styled(" RELRO:     ".to_string(), theme::label()),
            Span::styled(relro_str.to_string(), Style::default().fg(relro_color)),
        ]));

        let canary_str = if elf.mitigations.stack_canary { "✅ Stack Canary" } else { "❌ No Canary" };
        let canary_color = if elf.mitigations.stack_canary { theme::SAFE } else { theme::WARNING };
        lines.push(Line::from(vec![
            Span::styled(" Canary:    ".to_string(), theme::label()),
            Span::styled(canary_str.to_string(), Style::default().fg(canary_color)),
        ]));
    }
    lines.push(Line::from(""));
}

fn build_risk_radar_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let rb = &app.result.risk_breakdown;
    lines.push(section_header("Risk Breakdown"));

    let categories: Vec<(&str, u32, u32)> = vec![
        ("Entropy  ", rb.entropy_score, 25),
        ("APIs     ", rb.api_score, 25),
        ("Anomalies", rb.anomaly_score, 25),
        ("Strings  ", rb.string_score, 15),
        ("Packing  ", rb.packing_score, 15),
    ];

    let bar_width = 20usize;
    for (name, score, max) in &categories {
        let ratio = if *max > 0 {
            *score as f64 / *max as f64
        } else {
            0.0
        };
        let filled = (ratio * bar_width as f64) as usize;
        let empty = bar_width.saturating_sub(filled);

        let color = if ratio > 0.7 {
            theme::CRITICAL
        } else if ratio > 0.4 {
            theme::WARNING
        } else if *score > 0 {
            theme::SAFE
        } else {
            theme::BORDER
        };

        lines.push(Line::from(vec![
            Span::styled(format!("   {} ", name), theme::label()),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled("░".repeat(empty), Style::default().fg(theme::BORDER)),
            Span::styled(
                format!("  {}/{}", score, max),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]));
    }

    let total = (rb.entropy_score + rb.api_score + rb.anomaly_score
        + rb.string_score + rb.packing_score)
        .min(100);
    let color = theme::risk_color(&app.result.risk_level);
    lines.push(Line::from(vec![
        Span::styled("   Total    ".to_string(), theme::label()),
        Span::styled(
            format!("{}/100 ", total),
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({})", app.result.risk_level),
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));
}

fn build_hashes_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let b = &app.result.basic;
    lines.push(section_header("Hashes"));
    lines.push(kv_line("MD5   ", &b.md5));
    lines.push(kv_line("SHA1  ", &b.sha1));
    lines.push(kv_line("SHA256", &b.sha256));
    if let Some(pe) = app.current_pe() {
        if let Some(ref imphash) = pe.imphash {
            lines.push(kv_line("Imphash", imphash));
        }
        if let Some(ref rich) = pe.rich_header {
            lines.push(kv_line("RichPE ", &rich.rich_hash));
        }
    }
    lines.push(Line::from(""));
}

fn build_detection_ratio_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let checks = &app.result.detection_checks;
    let total = checks.len();
    let triggered = checks.iter().filter(|c| c.triggered).count();

    lines.push(section_header(&format!("Detection Checks ({}/{})", triggered, total)));

    let bar_w = 30usize;
    let filled = if total > 0 {
        ((triggered as f64 / total as f64) * bar_w as f64) as usize
    } else {
        0
    };
    let empty = bar_w.saturating_sub(filled);

    let ratio_color = if total > 0 && triggered as f64 / total as f64 > 0.5 {
        theme::CRITICAL
    } else if triggered > 0 {
        theme::WARNING
    } else {
        theme::SAFE
    };

    lines.push(Line::from(vec![
        Span::styled(
            format!("   {}/{} triggered  ", triggered, total),
            Style::default()
                .fg(ratio_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("█".repeat(filled), Style::default().fg(ratio_color)),
        Span::styled("░".repeat(empty), Style::default().fg(theme::BORDER)),
    ]));

    let mut triggered_checks: Vec<&DetectionCheck> =
        checks.iter().filter(|c| c.triggered).collect();
    triggered_checks.sort_by_key(|c| detection_severity_priority(&c.severity));

    for check in triggered_checks.iter().take(8) {
        let color = detection_severity_color(&check.severity);
        let marker = match check.severity {
            DetectionSeverity::Critical => "●",
            DetectionSeverity::High => "◉",
            DetectionSeverity::Medium => "○",
            _ => "·",
        };
        lines.push(Line::from(vec![
            Span::styled(format!("   {} ", marker), Style::default().fg(color)),
            Span::styled(
                format!("[{}] ", check.severity),
                Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(check.name.clone(), Style::default().fg(theme::TEXT)),
        ]));
    }

    if triggered_checks.len() > 8 {
        lines.push(Line::from(vec![Span::styled(
            format!("   ... and {} more", triggered_checks.len() - 8),
            Style::default().fg(theme::TEXT_DIM),
        )]));
    }
    lines.push(Line::from(""));
}

fn build_packer_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    lines.push(section_header("Packer Detection"));
    let packer = if let Some(pe) = app.current_pe() {
        pe.packer_detected.as_deref()
    } else if let Some(elf) = app.result.elf.as_ref() {
        elf.packer_detected.as_deref()
    } else {
        None
    };

    if let Some(packer) = packer {
        lines.push(Line::from(vec![
            Span::styled(
                "   ⚠ ".to_string(),
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("Detected: {}", packer),
                Style::default().fg(theme::WARNING),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(
                "   ✓ ".to_string(),
                Style::default()
                    .fg(theme::SAFE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "No known packer detected".to_string(),
                Style::default().fg(theme::SAFE),
            ),
        ]));
    }
    lines.push(Line::from(""));
}

fn build_entropy_histogram_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    if let Some(pe) = app.current_pe() {
        lines.push(section_header("Entropy by Section"));

        let bar_w = 25usize;
        for section in &pe.sections {
            let filled = ((section.entropy / 8.0) * bar_w as f64) as usize;
            let empty = bar_w.saturating_sub(filled);

            let color = if section.entropy > 7.0 {
                theme::CRITICAL
            } else if section.entropy > 6.0 {
                theme::WARNING
            } else {
                theme::SAFE
            };

            let flag = if section.entropy > 7.0 { " ⚠" } else { "" };
            let name = format!("{:<8}", section.name);

            lines.push(Line::from(vec![
                Span::styled(format!("   {} ", name), theme::label()),
                Span::styled("█".repeat(filled), Style::default().fg(color)),
                Span::styled("░".repeat(empty), Style::default().fg(theme::BORDER)),
                Span::styled(
                    format!(" {:.2}{}", section.entropy, flag),
                    Style::default().fg(color),
                ),
            ]));
        }
        lines.push(Line::from(""));
    } else if let Some(elf) = app.result.elf.as_ref() {
        if !elf.sections.is_empty() {
            lines.push(section_header("Entropy by Section (ELF)"));

            let bar_w = 25usize;
            for section in &elf.sections {
                if section.raw_size == 0 {
                    continue;
                }
                let filled = ((section.entropy / 8.0) * bar_w as f64) as usize;
                let empty = bar_w.saturating_sub(filled);

                let color = if section.entropy > 7.0 {
                    theme::CRITICAL
                } else if section.entropy > 6.0 {
                    theme::WARNING
                } else {
                    theme::SAFE
                };

                let flag = if section.entropy > 7.0 { " ⚠" } else { "" };
                let display_name = if section.name.len() > 10 { &section.name[..10] } else { &section.name };
                let name = format!("{:<10}", display_name);

                lines.push(Line::from(vec![
                    Span::styled(format!("   {} ", name), theme::label()),
                    Span::styled("█".repeat(filled), Style::default().fg(color)),
                    Span::styled("░".repeat(empty), Style::default().fg(theme::BORDER)),
                    Span::styled(
                        format!(" {:.2}{}", section.entropy, flag),
                        Style::default().fg(color),
                    ),
                ]));
            }
            lines.push(Line::from(""));
        }
    }
}

fn build_byte_distribution_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let dist = &app.result.basic.byte_distribution;
    lines.push(section_header("Byte Distribution"));

    let mut buckets = [0u64; 32];
    for (i, &count) in dist.iter().enumerate() {
        buckets[i / 8] += count;
    }

    let max_bucket = *buckets.iter().max().unwrap_or(&1);
    let max_bucket = max_bucket.max(1);
    let spark_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    let spark: String = buckets
        .iter()
        .map(|&b| {
            let idx = ((b as f64 / max_bucket as f64) * 7.0) as usize;
            spark_chars[idx.min(7)]
        })
        .collect();

    lines.push(Line::from(vec![
        Span::styled("   0x00 ".to_string(), Style::default().fg(theme::TEXT_DIM)),
        Span::styled(spark, Style::default().fg(theme::INFO)),
        Span::styled(" 0xFF".to_string(), Style::default().fg(theme::TEXT_DIM)),
    ]));

    let total: u64 = dist.iter().sum();
    let ascii_printable: u64 = dist[32..=126].iter().sum();
    let null_bytes = dist[0];
    let ascii_ratio = if total > 0 {
        ascii_printable as f64 / total as f64
    } else {
        0.0
    };
    let null_ratio = if total > 0 {
        null_bytes as f64 / total as f64
    } else {
        0.0
    };

    let pattern = if ascii_ratio > 0.7 {
        "ASCII-heavy (text/code)"
    } else if null_ratio > 0.3 {
        "Null-heavy (sparse/padded)"
    } else if app.result.basic.entropy > 7.0 {
        "Uniform (encrypted/compressed)"
    } else {
        "Mixed (typical binary)"
    };

    lines.push(Line::from(vec![
        Span::styled("   Pattern: ".to_string(), theme::label()),
        Span::styled(pattern.to_string(), theme::value()),
        Span::styled(
            format!(
                "  ({:.0}% printable, {:.0}% null)",
                ascii_ratio * 100.0,
                null_ratio * 100.0
            ),
            Style::default().fg(theme::TEXT_DIM),
        ),
    ]));
    lines.push(Line::from(""));
}

fn build_import_heatmap_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    if let Some(pe) = app.current_pe() {
        if !pe.imports.is_empty() {
            lines.push(section_header("Import Risk Map"));

            for dll in pe.imports.iter().take(10) {
                let crit = dll
                    .functions
                    .iter()
                    .filter(|f| f.risk == ApiRisk::Critical)
                    .count();
                let high = dll
                    .functions
                    .iter()
                    .filter(|f| f.risk == ApiRisk::High)
                    .count();
                let med = dll
                    .functions
                    .iter()
                    .filter(|f| f.risk == ApiRisk::Medium)
                    .count();

                let has_risk = crit > 0 || high > 0 || med > 0;
                let dll_name = format!("{:<20}", dll.name);
                let mut spans = vec![Span::styled(
                    format!("   {} ", dll_name),
                    theme::label(),
                )];

                for _ in 0..crit {
                    spans.push(Span::styled(
                        "● ".to_string(),
                        Style::default().fg(theme::CRITICAL),
                    ));
                }
                for _ in 0..high {
                    spans.push(Span::styled(
                        "◉ ".to_string(),
                        Style::default().fg(theme::ORANGE),
                    ));
                }
                for _ in 0..med.min(4) {
                    spans.push(Span::styled(
                        "○ ".to_string(),
                        Style::default().fg(theme::WARNING),
                    ));
                }
                if med > 4 {
                    spans.push(Span::styled(
                        format!("(+{}) ", med - 4),
                        Style::default().fg(theme::WARNING),
                    ));
                }

                if !has_risk {
                    spans.push(Span::styled(
                        format!("{} fns", dll.functions.len()),
                        Style::default().fg(theme::TEXT_DIM),
                    ));
                }

                lines.push(Line::from(spans));
            }

            if pe.imports.len() > 10 {
                lines.push(Line::from(vec![Span::styled(
                    format!("   ... and {} more DLLs", pe.imports.len() - 10),
                    Style::default().fg(theme::TEXT_DIM),
                )]));
            }
            lines.push(Line::from(""));
        }
    } else if let Some(elf) = app.result.elf.as_ref() {
        if !elf.imported_symbols.is_empty() || !elf.libraries.is_empty() {
            lines.push(section_header("ELF Imported Symbols & Libraries"));
            if !elf.libraries.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("   Libraries: ".to_string(), theme::label()),
                    Span::styled(elf.libraries.join(", "), Style::default().fg(theme::INFO)),
                ]));
            }
            
            let crit = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Critical).count();
            let high = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::High).count();
            let med = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Medium).count();
            
            let mut spans = vec![Span::styled("   Symbols:   ".to_string(), theme::label())];
            for _ in 0..crit {
                spans.push(Span::styled("● ".to_string(), Style::default().fg(theme::CRITICAL)));
            }
            for _ in 0..high {
                spans.push(Span::styled("◉ ".to_string(), Style::default().fg(theme::ORANGE)));
            }
            for _ in 0..med.min(6) {
                spans.push(Span::styled("○ ".to_string(), Style::default().fg(theme::WARNING)));
            }
            spans.push(Span::styled(format!("({} total)", elf.imported_symbols.len()), Style::default().fg(theme::TEXT_DIM)));
            lines.push(Line::from(spans));
            lines.push(Line::from(""));
        }
    }
}

fn build_suspicious_strings_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let suspicious: Vec<&ExtractedString> = app
        .result
        .basic
        .strings
        .iter()
        .filter(|s| !matches!(s.category, StringCategory::Normal))
        .collect();

    if !suspicious.is_empty() {
        lines.push(section_header("Suspicious Strings"));

        let mut sorted = suspicious;
        sorted.sort_by_key(|s| category_priority(&s.category));

        for s in sorted.iter().take(5) {
            let color = match s.category {
                StringCategory::Url => theme::CRITICAL,
                StringCategory::IpAddress => theme::ORANGE,
                StringCategory::Command => theme::CRITICAL,
                StringCategory::Suspicious => theme::ORANGE,
                StringCategory::RegistryKey => theme::WARNING,
                StringCategory::FilePath => theme::INFO,
                StringCategory::Normal => theme::TEXT_DIM,
            };

            let display_val = if s.value.len() > 60 {
                format!("{}…", &s.value[..60])
            } else {
                s.value.clone()
            };

            lines.push(Line::from(vec![
                Span::styled(
                    format!("   [{:>4}] ", s.category),
                    Style::default()
                        .fg(color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(display_val, Style::default().fg(theme::TEXT)),
            ]));
        }

        if sorted.len() > 5 {
            lines.push(Line::from(vec![Span::styled(
                format!("   ... {} more (see Strings tab)", sorted.len() - 5),
                Style::default().fg(theme::TEXT_DIM),
            )]));
        }
        lines.push(Line::from(""));
    }
}

fn build_malware_pattern_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    lines.push(section_header("Malware Pattern"));
    if let Some(pattern) = &app.result.malware_pattern {
        let conf_color = match pattern.confidence.as_str() {
            "High" => theme::CRITICAL,
            "Medium" => theme::WARNING,
            _ => theme::INFO,
        };

        lines.push(Line::from(vec![
            Span::styled(
                "   ⚠ ".to_string(),
                Style::default()
                    .fg(conf_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                pattern.family.clone(),
                Style::default()
                    .fg(conf_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  [{} confidence]", pattern.confidence),
                Style::default().fg(conf_color),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("     ".to_string(), Style::default()),
            Span::styled(
                pattern.description.clone(),
                Style::default().fg(theme::TEXT),
            ),
        ]));

        if !pattern.matched_indicators.is_empty() {
            let indicators = pattern
                .matched_indicators
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(Line::from(vec![
                Span::styled("     Matched: ".to_string(), theme::label()),
                Span::styled(indicators, Style::default().fg(theme::TEXT_DIM)),
            ]));
        }
    } else {
        lines.push(Line::from(vec![
            Span::styled(
                "   ✓ ".to_string(),
                Style::default()
                    .fg(theme::SAFE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "No known malware pattern matched".to_string(),
                Style::default().fg(theme::SAFE),
            ),
        ]));
    }
    lines.push(Line::from(""));
}

fn build_yara_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    lines.push(section_header("YARA Analysis"));

    if app.yara_loading {
        let spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let idx = (app.spinner_tick as usize) % spinners.len();
        lines.push(Line::from(vec![
            Span::styled(format!(" {} Scanning with YARA...", spinners[idx]), Style::default().fg(theme::ORANGE)),
        ]));
    } else if app.result.yara_matches.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" No YARA rules matched", theme::label()),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(format!(" {} rules matched:", app.result.yara_matches.len()), Style::default().fg(theme::WARNING)),
        ]));
        for rule in &app.result.yara_matches {
            lines.push(Line::from(vec![
                Span::styled("  • ", theme::label()),
                Span::styled(rule.clone(), Style::default().fg(theme::CRITICAL)),
            ]));
        }
    }
    lines.push(Line::from(""));
}

fn build_embedded_pe_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    lines.push(section_header("Embedded Executable Scan"));

    if app.embedded_pe_loading {
        let spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let idx = (app.spinner_tick as usize) % spinners.len();
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} Scanning for embedded PE...", spinners[idx]),
                Style::default().fg(theme::ORANGE),
            ),
        ]));
    } else {
        let mut found = false;
        if let Some(pe) = &app.result.pe {
            if let Some(ref embedded) = pe.embedded_pe {
                lines.push(Line::from(vec![
                    Span::styled("  • ", theme::label()),
                    Span::styled(
                        format!(
                            "Embedded PE found in overlay (EP: {:#X}, {} sections)",
                            embedded.entry_point,
                            embedded.sections.len()
                        ),
                        Style::default().fg(theme::WARNING),
                    ),
                ]));
                found = true;
            }
        }

        if !found && app.result.file_info.file_type != FileType::PE && app.result.pe.is_some() {
            if let Some(pe) = &app.result.pe {
                lines.push(Line::from(vec![
                    Span::styled("  • ", theme::label()),
                    Span::styled(
                        format!(
                            "Embedded PE extracted & analyzed (EP: {:#X}, {} sections)",
                            pe.entry_point,
                            pe.sections.len()
                        ),
                        Style::default().fg(theme::WARNING),
                    ),
                ]));
                found = true;
            }
        }

        if !found {
            lines.push(Line::from(vec![
                Span::styled(" No embedded PE found", theme::label()),
            ]));
        }
    }
    lines.push(Line::from(""));
}

fn build_anomalies_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let anomalies = if let Some(pe) = app.current_pe() {
        &pe.anomalies
    } else if let Some(elf) = app.result.elf.as_ref() {
        &elf.anomalies
    } else {
        return;
    };

    if !anomalies.is_empty() {
        lines.push(section_header("Anomalies"));
        for a in anomalies {
            let color = theme::severity_color(&a.severity);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("   [{}] ", a.severity),
                    Style::default()
                        .fg(color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    a.description.clone(),
                    Style::default().fg(theme::TEXT),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }
}

// ─── Headers tab ─────────────────────────────────────────────────

fn draw_headers(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = app.current_pe() else {
        frame.render_widget(Paragraph::new(" No PE headers"), area);
        return;
    };

    let block = panel_block("PE Headers");
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::horizontal([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(inner_area);

    // Left Column: COFF Header & Characteristics
    let mut left_lines = vec![
        section_header("COFF Header"),
        kv_line("Machine", &pe.machine),
        kv_line("Timestamp", &pe.timestamp_str),
        kv_line("Is DLL", &pe.is_dll.to_string()),
        kv_line("64-bit", &pe.is_64bit.to_string()),
        Line::from(""),
        section_header("Characteristics"),
    ];

    let chars = [
        (0x0001, "Relocs Stripped"),
        (0x0002, "Executable Image"),
        (0x0004, "Line Nums Stripped"),
        (0x0008, "Local Syms Stripped"),
        (0x0010, "Aggressive Ws Trim"),
        (0x0020, "Large Address Aware"),
        (0x0080, "Bytes Reversed Lo"),
        (0x0100, "32-bit Machine"),
        (0x0200, "Debug Stripped"),
        (0x0400, "Removable Run From Swap"),
        (0x0800, "Net Run From Swap"),
        (0x1000, "System"),
        (0x2000, "DLL"),
        (0x4000, "UP System Only"),
        (0x8000, "Bytes Reversed Hi"),
    ];

    for (flag, name) in chars.iter() {
        if (pe.characteristics & flag) != 0 {
            left_lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(theme::SAFE)),
                Span::styled(name.to_string(), Style::default().fg(theme::TEXT)),
            ]));
        }
    }

    // Center Column: Optional Header & Exports
    let ep_str = match &pe.entry_point_section {
        Some(sec) => format!("{:#010x} ({})", pe.entry_point, sec),
        None => format!("{:#010x}", pe.entry_point),
    };

    let mut center_lines = vec![
        section_header("Optional Header"),
        kv_line("Entry Point", &ep_str),
        kv_line("Image Base", &format!("{:#010x}", pe.image_base)),
        kv_line("Subsystem", &pe.subsystem),
        kv_line("Linker", &pe.linker_version),
    ];
    if let Some(ref imphash) = pe.imphash {
        center_lines.push(kv_line("Imphash", imphash));
    }
    if let Some(ref pdb) = pe.pdb_path {
        center_lines.push(kv_line("PDB Path", pdb));
    }
    center_lines.push(Line::from(""));
    center_lines.push(section_header("Security Mitigations"));

    let aslr = (pe.dll_characteristics & 0x0040) != 0;
    let dep = (pe.dll_characteristics & 0x0100) != 0;
    let cfg = (pe.dll_characteristics & 0x4000) != 0;

    let fmt_mitigation = |name: &str, enabled: bool| {
        let (icon, color) = if enabled {
            ("✅", theme::SAFE)
        } else {
            ("❌", theme::CRITICAL)
        };
        Line::from(vec![
            Span::styled(format!("  {} ", name), theme::label()),
            Span::styled(icon.to_string(), Style::default().fg(color)),
        ])
    };

    center_lines.push(fmt_mitigation("ASLR", aslr));
    center_lines.push(fmt_mitigation("DEP ", dep));
    center_lines.push(fmt_mitigation("CFG ", cfg));

    center_lines.push(Line::from(""));
    center_lines.push(section_header("System Calls"));
    
    let fmt_syscall = |name: &str, detected: bool| {
        let (icon, color) = if detected {
            ("⚠  DETECTED", theme::CRITICAL)
        } else {
            ("NOT FOUND", theme::SAFE)
        };
        Line::from(vec![
            Span::styled(format!("  {:<9} ", name), theme::label()),
            Span::styled(icon.to_string(), Style::default().fg(color)),
        ])
    };

    center_lines.push(fmt_syscall("Direct", pe.direct_syscalls));
    center_lines.push(fmt_syscall("Indirect", pe.indirect_syscalls));

    if !pe.exports.is_empty() {
        center_lines.push(Line::from(""));
        center_lines.push(section_header("Exports"));
        for exp in pe.exports.iter().take(20) {
            center_lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(exp, theme::value()),
            ]));
        }
        if pe.exports.len() > 20 {
            center_lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more", pe.exports.len() - 20),
                Style::default().fg(theme::TEXT_DIM),
            )]));
        }
    }

    // Right Column: Data Directories & Rich Header
    let mut right_lines = vec![
        section_header("Data Directories"),
    ];

    for dir in &pe.data_directories {
        let is_empty = dir.size == 0 && dir.virtual_address == 0;
        let color = if is_empty { theme::TEXT_DIM } else { theme::TEXT };
        
        let name_trimmed: String = dir.name.chars().take(12).collect();
        right_lines.push(Line::from(vec![
            Span::styled(format!("  {:<12} ", name_trimmed), theme::label()),
            Span::styled(
                format!("RVA: {:#010x}  Size: {:#010x}", dir.virtual_address, dir.size),
                Style::default().fg(color),
            ),
        ]));
    }

    if let Some(rich) = &pe.rich_header {
        right_lines.push(Line::from(""));
        right_lines.push(section_header(&format!("Rich Header (XOR: {:#010x})", rich.xor_key)));
        right_lines.push(kv_line("Rich Hash", &rich.rich_hash));
        for rec in &rich.records {
            let tool = rec.tool_name.as_deref().unwrap_or("Unknown");
            right_lines.push(Line::from(vec![
                Span::styled(format!("  {:<12} ", tool), theme::label()),
                Span::styled(
                    format!("ID: {:<3} Build: {:<5} Count: {}", rec.prod_id, rec.build, rec.count),
                    Style::default().fg(theme::TEXT),
                ),
            ]));
        }
    }

    if let Some(cert) = &pe.certificate {
        right_lines.push(Line::from(""));
        let cert_title = if cert.is_self_signed {
            "Certificate (Self-Signed ⚠️)"
        } else {
            "Certificate (Authenticode)"
        };
        right_lines.push(section_header(cert_title));
        right_lines.push(kv_line("Subject", &cert.subject));
        right_lines.push(kv_line("Issuer", &cert.issuer));
        if let Some(ref alg) = cert.digest_algorithm {
            right_lines.push(kv_line("Digest Alg", alg));
        }
        if let (Some(ref nb), Some(ref na)) = (&cert.not_before, &cert.not_after) {
            right_lines.push(kv_line("Validity", &format!("{} -> {}", nb, na)));
        }
        if let Some(ref serial) = cert.serial_number {
            right_lines.push(kv_line("Serial", serial));
        }
    }

    if !pe.xor_payloads.is_empty() {
        right_lines.push(Line::from(""));
        right_lines.push(section_header(&format!("XOR Payloads Detected ({})", pe.xor_payloads.len())));
        for p in pe.xor_payloads.iter().take(10) {
            right_lines.push(Line::from(vec![
                Span::styled(format!("  [key {:#04x}] ", p.key), Style::default().fg(theme::CRITICAL)),
                Span::styled(format!("{}: {}", p.target_location, p.description), Style::default().fg(theme::TEXT)),
            ]));
            right_lines.push(Line::from(vec![
                Span::styled(format!("    └─ {} ", p.sample_preview), Style::default().fg(theme::TEXT_DIM)),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(left_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(center_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(right_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[2],
    );
}

// ─── Sections tab ────────────────────────────────────────────────

fn draw_sections(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = app.current_pe() else {
        frame.render_widget(Paragraph::new(" No sections"), area);
        return;
    };

    let header = Row::new(vec![
        Cell::from("Name").style(theme::header()),
        Cell::from("VSize").style(theme::header()),
        Cell::from("RawSize").style(theme::header()),
        Cell::from("Entropy").style(theme::header()),
        Cell::from("Flags").style(theme::header()),
        Cell::from("Anomalies").style(theme::header()),
    ])
    .height(1);

    let query_lower = app.search_query.to_lowercase();
    let rows: Vec<Row> = pe
        .sections
        .iter()
        .filter(|s| query_lower.is_empty() || s.name.to_lowercase().contains(&query_lower))
        .map(|s| {
            let ent_color = if s.entropy > 7.0 {
                theme::CRITICAL
            } else if s.entropy > 6.0 {
                theme::WARNING
            } else {
                theme::SAFE
            };

            let flag_color = if s.is_executable && s.is_writable {
                theme::CRITICAL
            } else if s.is_executable {
                theme::WARNING
            } else {
                theme::TEXT
            };

            let anomaly_str = if s.anomalies.is_empty() {
                "—".to_string()
            } else {
                s.anomalies.join(", ")
            };

            Row::new(vec![
                Cell::from(s.name.clone()).style(theme::value()),
                Cell::from(format!("{:#x}", s.virtual_size)).style(theme::value()),
                Cell::from(format!("{:#x}", s.raw_size)).style(theme::value()),
                Cell::from(format!("{:.2}", s.entropy)).style(Style::default().fg(ent_color)),
                Cell::from(s.flags_str.clone()).style(Style::default().fg(flag_color)),
                Cell::from(anomaly_str).style(Style::default().fg(theme::WARNING)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block("Sections"))
        .row_highlight_style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(table, area);
}

// ─── Imports tab ─────────────────────────────────────────────────

fn draw_imports(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = app.current_pe() else {
        frame.render_widget(Paragraph::new(" No imports"), area);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    // Summary
    let total_fns: usize = pe.imports.iter().map(|d| d.functions.len()).sum();
    let crit = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter(|f| f.risk == ApiRisk::Critical)
        .count();
    let high = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter(|f| f.risk == ApiRisk::High)
        .count();
    let med = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter(|f| f.risk == ApiRisk::Medium)
        .count();

    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} DLLs, {} functions  ", pe.imports.len(), total_fns),
            theme::value(),
        ),
        Span::styled(format!("● {} ", crit), Style::default().fg(theme::CRITICAL)),
        Span::styled(format!("● {} ", high), Style::default().fg(theme::ORANGE)),
        Span::styled(format!("● {} ", med), Style::default().fg(theme::WARNING)),
    ]));
    lines.push(Line::from(""));

    let query_lower = app.search_query.to_lowercase();

    // Obfuscated / Dynamically Resolved APIs
    let matching_obf: Vec<&String> = pe
        .obfuscated_apis
        .iter()
        .filter(|api| query_lower.is_empty() || api.to_lowercase().contains(&query_lower))
        .collect();

    if !matching_obf.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                " ⚠  Obfuscated / Dynamically Resolved APIs (Suspicious)",
                Style::default()
                    .fg(theme::CRITICAL)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        for api in matching_obf {
            lines.push(Line::from(vec![
                Span::styled("    ◉ ", Style::default().fg(theme::CRITICAL)),
                Span::styled(api, Style::default().fg(theme::TEXT)),
                Span::styled(
                    " [Obfuscated]",
                    Style::default()
                        .fg(theme::CRITICAL)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Per-DLL listing
    for dll in &pe.imports {
        let matching_funcs: Vec<&ImportFunction> = dll
            .functions
            .iter()
            .filter(|func| {
                query_lower.is_empty()
                    || func.name.to_lowercase().contains(&query_lower)
                    || dll.name.to_lowercase().contains(&query_lower)
            })
            .collect();

        if matching_funcs.is_empty() {
            continue;
        }

        lines.push(Line::from(vec![
            Span::styled(
                format!(" ▸ {} ", dll.name),
                Style::default()
                    .fg(theme::ORANGE_LIGHT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({}/{})", matching_funcs.len(), dll.functions.len()),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]));

        for func in matching_funcs {
            let color = theme::api_risk_color(&func.risk);
            let marker = match func.risk {
                ApiRisk::Critical => "●",
                ApiRisk::High => "◉",
                ApiRisk::Medium => "○",
                _ => "·",
            };
            let risk_tag = if func.risk != ApiRisk::None {
                format!(" [{}]", func.risk)
            } else {
                String::new()
            };

            lines.push(Line::from(vec![
                Span::styled(format!("    {} ", marker), Style::default().fg(color)),
                Span::styled(&func.name, Style::default().fg(theme::TEXT)),
                Span::styled(
                    risk_tag,
                    Style::default()
                        .fg(color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }

    let block = panel_block("Imports");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

// ─── Strings tab ─────────────────────────────────────────────────

fn draw_strings(frame: &mut Frame, area: Rect, app: &App) {
    let strings = &app.result.basic.strings;
    let query_lower = app.search_query.to_lowercase();
    let cat_filter = app.string_category_filter.as_ref();

    let mut filtered: Vec<&ExtractedString> = strings
        .iter()
        .filter(|s| {
            if let Some(cat) = cat_filter {
                if s.category != *cat {
                    return false;
                }
            }
            if !query_lower.is_empty() {
                let match_val = s.value.to_lowercase().contains(&query_lower);
                let match_dec = s.decoded.as_ref().is_some_and(|d| d.to_lowercase().contains(&query_lower));
                if !match_val && !match_dec {
                    return false;
                }
            }
            true
        })
        .collect();

    filtered.sort_by(|a, b| {
        let a_pri = category_priority(&a.category);
        let b_pri = category_priority(&b.category);
        a_pri.cmp(&b_pri)
    });

    let mut header_spans = vec![
        Span::styled(
            format!(" Showing {}/{} strings  |  Filters: ", filtered.len(), strings.len()),
            theme::label(),
        ),
    ];

    let cats = [
        (None, "a", "All"),
        (Some(StringCategory::Url), "u", "URL"),
        (Some(StringCategory::IpAddress), "i", "IP"),
        (Some(StringCategory::RegistryKey), "r", "Reg"),
        (Some(StringCategory::Command), "c", "Cmd"),
        (Some(StringCategory::Suspicious), "s", "Sus"),
        (Some(StringCategory::FilePath), "p", "Path"),
    ];

    for (cat, key, name) in cats {
        let is_active = cat_filter == cat.as_ref();
        let (bracket_col, text_col) = if is_active {
            (theme::ORANGE, theme::ORANGE_LIGHT)
        } else {
            (theme::BORDER, theme::TEXT_DIM)
        };
        header_spans.push(Span::styled("[", Style::default().fg(bracket_col)));
        header_spans.push(Span::styled(key, Style::default().fg(theme::ORANGE)));
        header_spans.push(Span::styled(format!(":{}", name), Style::default().fg(text_col)));
        header_spans.push(Span::styled("] ", Style::default().fg(bracket_col)));
    }

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(header_spans));
    lines.push(Line::from(""));

    for s in filtered.iter().take(500) {
        let cat_color = match s.category {
            StringCategory::Url => theme::CRITICAL,
            StringCategory::IpAddress => theme::ORANGE,
            StringCategory::RegistryKey => theme::WARNING,
            StringCategory::Command => theme::CRITICAL,
            StringCategory::Suspicious => theme::ORANGE,
            StringCategory::FilePath => theme::INFO,
            StringCategory::Normal => theme::TEXT_DIM,
        };

        let display_val = if s.value.len() > 100 {
            format!("{}…", &s.value[..100])
        } else {
            s.value.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" [{:>4}] ", s.category),
                Style::default()
                    .fg(cat_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if s.is_wide { "W " } else { "A " },
                Style::default().fg(if s.is_wide { theme::INFO } else { theme::TEXT_DIM }),
            ),
            Span::styled(
                format!("{:#08x} ", s.offset),
                Style::default().fg(theme::TEXT_DIM),
            ),
            Span::styled(display_val, Style::default().fg(theme::TEXT)),
        ]));

        if let Some(decoded) = &s.decoded {
            let decoded_display = if decoded.len() > 100 {
                format!("{}…", &decoded[..100])
            } else {
                decoded.clone()
            };
            let mut decoded_line = Vec::new();
            decoded_line.push(Span::styled(
                "        ↳ Base64 Decoded: ",
                Style::default().fg(theme::INFO),
            ));
            // Ensure no invalid control characters break the TUI
            let safe_decoded = decoded_display.replace(|c: char| c.is_control() && c != '\n' && c != '\t', ".");
            decoded_line.push(Span::styled(safe_decoded, Style::default().fg(theme::TEXT)));
            lines.push(Line::from(decoded_line));
        }
    }

    if strings.len() > 500 {
        lines.push(Line::from(vec![Span::styled(
            format!(" ... and {} more", strings.len() - 500),
            Style::default().fg(theme::TEXT_DIM),
        )]));
    }

    let block = panel_block("Strings");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

// ─── Helpers ─────────────────────────────────────────────────────

fn panel_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(
            format!(" {} ", title),
            theme::title(),
        ))
        .style(Style::default().bg(theme::BG_DARK))
}

fn kv_line(key: &str, val: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {}: ", key), theme::label()),
        Span::styled(val.to_string(), theme::value()),
    ])
}

fn section_header(text: &str) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!(" ─── {} ───", text),
        Style::default()
            .fg(theme::ORANGE_DARK)
            .add_modifier(Modifier::BOLD),
    )])
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn category_priority(cat: &StringCategory) -> u8 {
    match cat {
        StringCategory::Command => 0,
        StringCategory::Suspicious => 1,
        StringCategory::Url => 2,
        StringCategory::IpAddress => 3,
        StringCategory::RegistryKey => 4,
        StringCategory::FilePath => 5,
        StringCategory::Normal => 6,
    }
}

fn detection_severity_priority(sev: &DetectionSeverity) -> u8 {
    match sev {
        DetectionSeverity::Critical => 0,
        DetectionSeverity::High => 1,
        DetectionSeverity::Medium => 2,
        DetectionSeverity::Low => 3,
        DetectionSeverity::Info => 4,
    }
}

fn detection_severity_color(sev: &DetectionSeverity) -> Color {
    match sev {
        DetectionSeverity::Critical => theme::CRITICAL,
        DetectionSeverity::High => theme::ORANGE,
        DetectionSeverity::Medium => theme::WARNING,
        DetectionSeverity::Low => theme::INFO,
        DetectionSeverity::Info => theme::TEXT_DIM,
    }
}

// ─── Guide tab ───────────────────────────────────────────────────

fn draw_guide(frame: &mut Frame, area: Rect, app: &App) {
    let lines = vec![
        // Main Title
        Line::from(vec![
            Span::styled(" Hacksguard Analyst Guide ", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        ]),
        Line::from(""),

        // 1. Risk Score
        section_header("1. Risk Score"),
        Line::from(vec![Span::styled("The global score (0-100) indicates the probability that a file is malicious. It is calculated across 5 axes:", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • Entropy (25 pts) : ", theme::label()), Span::styled("Measures code compression or encryption.", theme::value())]),
        Line::from(vec![Span::styled(" • APIs (25 pts) : ", theme::label()), Span::styled("Critical imported functions (injection, keyloggers, etc).", theme::value())]),
        Line::from(vec![Span::styled(" • Anomalies (25 pts) : ", theme::label()), Span::styled("PE format violations (e.g. Entry Point outside of code).", theme::value())]),
        Line::from(vec![Span::styled(" • Strings (15 pts) : ", theme::label()), Span::styled("Suspicious strings (URLs, IPs, PowerShell cmds, system paths).", theme::value())]),
        Line::from(vec![Span::styled(" • Packing (15 pts) : ", theme::label()), Span::styled("Presence of a known packer (UPX, Themida, VMProtect).", theme::value())]),
        Line::from(""),

        // 2. Entropy & Overlay
        section_header("2. Entropy & Overlay Analysis"),
        Line::from(vec![Span::styled("Entropy measures data randomness on a scale of 0 to 8.", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • < 6.0 : ", theme::label()), Span::styled("Normal data (standard compiled code, plaintext).", theme::SAFE)]),
        Line::from(vec![Span::styled(" • 6.0 - 7.0 : ", theme::label()), Span::styled("Gray zone (possibly compressed or dense data).", theme::WARNING)]),
        Line::from(vec![Span::styled(" • > 7.0 : ", theme::label()), Span::styled("Highly suspicious. Code is very likely obfuscated, encrypted, or packed.", theme::CRITICAL)]),
        Line::from(vec![Span::styled("Tip : ", theme::label()), Span::styled("If an executable section (.text) has an entropy of 7.9+, a malware is trying to hide.", theme::value())]),
        Line::from(vec![Span::styled("Overlay : ", theme::label()), Span::styled("Data appended to the end of the binary. Often used by droppers or installers to hide payloads.", theme::value())]),
        Line::from(""),

        // 3. Packers & YARA
        section_header("3. Packers & YARA Analysis"),
        Line::from(vec![Span::styled("A 'packer' compresses or encrypts the executable to prevent static analysis.", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • UPX / MPRESS : ", theme::label()), Span::styled("Common packers, sometimes legitimate, but often abused.", theme::WARNING)]),
        Line::from(vec![Span::styled(" • Themida / VMProtect : ", theme::label()), Span::styled("Extremely powerful commercial obfuscation tools. High risk.", theme::CRITICAL)]),
        Line::from(vec![Span::styled("YARA : ", theme::label()), Span::styled("Hacksguard uses Elastic protections-artifacts and Neo23x0 signature-base YARA rules to detect specific malware families and behaviors.", theme::value())]),
        Line::from(""),

        // 4. Imports & APIs
        section_header("4. APIs & Imports (Import Address Table)"),
        Line::from(vec![Span::styled("Shows which system libraries (DLLs) the file interacts with.", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • Process Injection : ", theme::label()), Span::styled("VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Keylogging / Hooking : ", theme::label()), Span::styled("SetWindowsHookEx, GetAsyncKeyState.", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Anti-Debugging : ", theme::label()), Span::styled("IsDebuggerPresent, CheckRemoteDebuggerPresent.", theme::ORANGE)]),
        Line::from(vec![Span::styled(" • Ransomware : ", theme::label()), Span::styled("CryptEncrypt, WNetOpenEnum, DeleteFile.", theme::ORANGE)]),
        Line::from(""),

        // 5. PE Anomalies
        section_header("5. PE Format Anomalies"),
        Line::from(vec![Span::styled("Indicators that the file was manually manipulated or forged:", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • W+X (Write + Execute) : ", theme::label()), Span::styled("A section should never be writable AND executable (risk of injection/shellcode).", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Timestamp 0 or Future : ", theme::label()), Span::styled("The author forged or wiped the compilation date.", theme::WARNING)]),
        Line::from(vec![Span::styled(" • Entry Point out of bounds : ", theme::label()), Span::styled("Execution starts in an unusual area (outside of code).", theme::CRITICAL)]),
        Line::from(""),

        // 6. Strings & Decoding
        section_header("6. Strings & Auto-Decoding"),
        Line::from(vec![Span::styled("Raw text extracted from the file often reveals the author's intent.", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • URLs & IPs : ", theme::label()), Span::styled("Command & Control (C2) servers or download addresses (Droppers).", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Commands : ", theme::label()), Span::styled("Stealth execution via 'cmd.exe /c', 'powershell -enc', 'vssadmin delete shadows'.", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Base64 Decoding : ", theme::label()), Span::styled("Hacksguard automatically attempts to decode strings longer than 16 characters that match the Base64 alphabet.", theme::value())]),
        Line::from(""),

        // 7. Malware Patterns
        section_header("7. Malware Patterns"),
        Line::from(vec![Span::styled("Search for sets of indicators (heuristics) corresponding to known threats:", Style::default().fg(theme::TEXT))]),
        Line::from(vec![Span::styled(" • Ransomware : ", theme::label()), Span::styled("Encryption + backup deletion + shadow copies removal.", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Info Stealer : ", theme::label()), Span::styled("Browser hooking + network exfiltration.", theme::CRITICAL)]),
        Line::from(vec![Span::styled(" • Dropper : ", theme::label()), Span::styled("Small size + HTTP payload downloading + overlay execution.", theme::CRITICAL)]),
        Line::from(""),
    ];

    let block = panel_block("Analyst Guide");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

// ─── Disasm tab ──────────────────────────────────────────────────

fn render_disasm(
    frame: &mut Frame,
    area: Rect,
    scroll_offset: u16,
    title: &str,
    syscall_locations: &[crate::models::SyscallLocation],
    is_64bit: bool,
    is_arm64: bool,
    ep_bytes: &[u8],
    entry_point: u64,
) {
    let mut lines = Vec::new();

    if !syscall_locations.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" Detected System Call Instructions ", Style::default().fg(theme::CRITICAL).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(""));
        for loc in syscall_locations {
            let type_str = if loc.is_indirect { "Indirect" } else { "Direct" };
            lines.push(Line::from(vec![
                Span::styled("  Address: ", Style::default().fg(theme::TEXT_DIM)),
                Span::styled(format!("{:#010x}", loc.address), Style::default().fg(theme::INFO)),
                Span::styled(format!("  [{}]  ", type_str), Style::default().fg(theme::CRITICAL).add_modifier(Modifier::BOLD)),
                Span::styled(&loc.instruction_str, Style::default().fg(theme::TEXT)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" ────────────────────────────────────────────────────────────────────────", Style::default().fg(theme::TEXT_DIM))));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(vec![
        Span::styled(format!(" Disassembly at Entry Point ({:#010x}) ", entry_point), Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    if is_arm64 {
        for (chunk_idx, chunk) in ep_bytes.chunks_exact(4).enumerate() {
            let addr = entry_point + (chunk_idx * 4) as u64;
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let is_svc = (word & 0xFFE0_001F) == 0xD400_0001;
            let hex_bytes = format!("{:02x} {:02x} {:02x} {:02x}", chunk[0], chunk[1], chunk[2], chunk[3]);

            let (mnemonic, rest, color) = if is_svc {
                let imm = (word >> 5) & 0xFFFF;
                ("svc".to_string(), format!("{:#x}  ; DIRECT SYSCALL", imm), theme::CRITICAL)
            } else {
                (".word".to_string(), format!("{:#010x}  [{}]", word, hex_bytes), theme::TEXT)
            };

            let line = Line::from(vec![
                Span::styled(format!(" {:#010x} ", addr), theme::value()),
                Span::styled(format!("{:<8}", mnemonic), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(rest, Style::default().fg(if is_svc { theme::CRITICAL } else { theme::TEXT_DIM })),
            ]);
            lines.push(line);
        }
    } else {
        let bitness = if is_64bit { 64 } else { 32 };
        let mut decoder = Decoder::with_ip(bitness, ep_bytes, entry_point, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        formatter.options_mut().set_digit_separator("_");
        formatter.options_mut().set_first_operand_char_index(10);
        
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let mut output = String::new();
            formatter.format(&instruction, &mut output);

            let addr = format!("{:016X}", instruction.ip());
            let mnemonic_str = output.split_whitespace().next().unwrap_or("").to_string();
            let rest = output.strip_prefix(&mnemonic_str).unwrap_or("").to_string();

            let line = Line::from(vec![
                Span::styled(format!(" {} ", addr), Style::default().fg(theme::TEXT_DIM)),
                Span::styled(format!("{:<8}", mnemonic_str), Style::default().fg(theme::INFO).add_modifier(Modifier::BOLD)),
                Span::styled(rest, Style::default().fg(theme::TEXT)),
            ]);
            lines.push(line);
        }
    }

    if lines.len() <= 2 {
        lines.push(Line::from(Span::styled("  No valid instructions found.", Style::default().fg(theme::TEXT_DIM))));
    }

    let block = panel_block(title);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((scroll_offset, 0)),
        area,
    );
}

fn draw_disasm(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = app.current_pe() else {
        frame.render_widget(Paragraph::new(" No PE metadata for disassembly"), area);
        return;
    };
    render_disasm(
        frame,
        area,
        app.scroll_offset,
        "Disassembly",
        &pe.syscall_locations,
        pe.is_64bit,
        false,
        &pe.ep_bytes,
        pe.entry_point,
    );
}

// ─── Hex View tab ────────────────────────────────────────────────

fn draw_hexdump(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" Hex Dump (First 1024 bytes) ", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    let data = std::fs::read(&app.result.file_info.path).unwrap_or_default();
    let preview = &data[..data.len().min(1024)];

    for (i, chunk) in preview.chunks(16).enumerate() {
        let offset = format!("{:08X}", i * 16);
        
        let mut hex_part = String::new();
        let mut ascii_part = String::new();
        
        for (j, &b) in chunk.iter().enumerate() {
            if j == 8 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{:02X} ", b));
            
            if b.is_ascii_graphic() || b == b' ' {
                ascii_part.push(b as char);
            } else {
                ascii_part.push('.');
            }
        }
        
        let pad = 16 - chunk.len();
        for _ in 0..pad {
            hex_part.push_str("   ");
        }
        if chunk.len() <= 8 && pad > 0 {
            hex_part.push(' ');
        }
        
        let line = Line::from(vec![
            Span::styled(format!(" {}  ", offset), Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format!("{:<50} ", hex_part), Style::default().fg(theme::TEXT)),
            Span::styled(ascii_part, Style::default().fg(theme::SAFE)),
        ]);
        lines.push(line);
    }

    if preview.is_empty() {
        lines.push(Line::from(Span::styled("  File is empty or unreadable.", Style::default().fg(theme::TEXT_DIM))));
    }

    let block = panel_block("Hex View");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

// ─── Entropy tab ─────────────────────────────────────────────────

fn draw_entropy(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(7),
    ])
    .split(area);

    let max_val = app.result.entropy_graph.iter().max().copied().unwrap_or(0);
    let sparkline_color = if max_val > 750 {
        theme::CRITICAL
    } else if max_val > 700 {
        theme::ORANGE
    } else if max_val > 650 {
        theme::WARNING
    } else {
        theme::SAFE
    };

    // Render outer block
    let graph_block = panel_block("Full File Entropy Graph");
    let inner_area = graph_block.inner(chunks[0]);
    frame.render_widget(graph_block, chunks[0]);

    // Split inner area for Y-axis scale and Sparkline
    let graph_layout = Layout::horizontal([
        Constraint::Length(6), // Y-axis scale
        Constraint::Min(0),   // Sparkline
    ])
    .split(inner_area);

    let h = graph_layout[0].height as usize;
    if h >= 3 {
        let mut scale_lines = vec![Line::from(Span::styled("    │", theme::label())); h];
        scale_lines[0] = Line::from(Span::styled("8.0 ┐", theme::label()));
        let mid = h / 2;
        scale_lines[mid] = Line::from(Span::styled("4.0 ┤", theme::label()));
        scale_lines[h - 1] = Line::from(Span::styled("0.0 ┘", theme::label()));
        let scale_paragraph = Paragraph::new(scale_lines);
        frame.render_widget(scale_paragraph, graph_layout[0]);
    }

    let sparkline = ratatui::widgets::Sparkline::default()
        .data(&app.result.entropy_graph)
        .max(800)
        .style(Style::default().fg(sparkline_color));
    frame.render_widget(sparkline, graph_layout[1]);

    // Metadata panel
    let num_chunks = app.result.entropy_graph.len();
    let file_size = app.result.file_info.size;
    let global_entropy = app.result.basic.entropy;

    let mut peak_entropy = 0.0;
    let mut peak_range = String::from("N/A");
    if num_chunks > 0 && file_size > 0 {
        let mut max_idx = 0;
        let mut local_max = 0;
        for (i, &val) in app.result.entropy_graph.iter().enumerate() {
            if val > local_max {
                local_max = val;
                max_idx = i;
            }
        }
        peak_entropy = local_max as f64 / 100.0;
        let chunk_size = file_size.div_ceil(num_chunks as u64);
        let start_offset = max_idx as u64 * chunk_size;
        let end_offset = ((max_idx + 1) as u64 * chunk_size).min(file_size);
        peak_range = format!("{:#x}..{:#x}", start_offset, end_offset);
    }

    let status_str = if global_entropy > 7.2 {
        "Highly Packed / Encrypted"
    } else if global_entropy > 6.8 {
        "Suspicious (Possible Compression/Packing)"
    } else {
        "Normal"
    };

    let status_color = if global_entropy > 7.2 {
        theme::CRITICAL
    } else if global_entropy > 6.8 {
        theme::WARNING
    } else {
        theme::SAFE
    };

    let threshold_warning = if max_val > 700 {
        "  ⚠️ High entropy peaks detected (> 7.0). Likely obfuscated, compressed or packed payload."
    } else {
        "  ✓ Entropy levels are within normal bounds."
    };
    let warning_color = if max_val > 700 {
        theme::CRITICAL
    } else {
        theme::SAFE
    };

    let info_lines = vec![
        Line::from(vec![
            Span::styled("  Global Shannon Entropy:  ", theme::label()),
            Span::styled(format!("{:.4}", global_entropy), theme::value()),
            Span::styled("   [", theme::label()),
            Span::styled(status_str, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
            Span::styled("]", theme::label()),
        ]),
        Line::from(vec![
            Span::styled("  Peak Local Entropy:      ", theme::label()),
            Span::styled(format!("{:.4}", peak_entropy), theme::value()),
            Span::styled("  (at offset range: ", theme::label()),
            Span::styled(peak_range, theme::value()),
            Span::styled(")", theme::label()),
        ]),
        Line::from(vec![
            Span::styled("  File Size:               ", theme::label()),
            Span::styled(format!("{} bytes", file_size), theme::value()),
            Span::styled("  /  Graph Resolution: ", theme::label()),
            Span::styled(format!("{} chunks", num_chunks), theme::value()),
        ]),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled(threshold_warning, Style::default().fg(warning_color).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let info_paragraph = Paragraph::new(info_lines)
        .block(panel_block("Entropy Analysis Details"))
        .wrap(Wrap { trim: false });
    frame.render_widget(info_paragraph, chunks[1]);
}

fn draw_manifest(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = app.current_pe() else {
        frame.render_widget(Paragraph::new(" No PE manifest"), area);
        return;
    };
    let manifest_str = pe.manifest.as_deref().unwrap_or("No manifest found");

    let block = panel_block("Embedded XML Manifest");
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let lines: Vec<Line> = manifest_str
        .lines()
        .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(theme::TEXT))))
        .collect();

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        inner_area,
    );
}

// ─── ELF Tabs ────────────────────────────────────────────────────

fn draw_elf_headers(frame: &mut Frame, area: Rect, app: &App) {
    let Some(elf) = app.result.elf.as_ref() else {
        frame.render_widget(Paragraph::new(" No ELF headers"), area);
        return;
    };

    let block = panel_block("ELF Headers & Mitigations");
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::horizontal([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(inner_area);

    // Left Column: Header Information
    let mut left_lines = vec![
        section_header("ELF Header"),
        kv_line("Machine", &elf.machine),
        kv_line("Class", &elf.class),
        kv_line("Endianness", &elf.endianness),
        kv_line("Type", &elf.elf_type),
        kv_line("Entry Point", &format!("{:#010x}", elf.entry_point)),
        kv_line("Is 64-bit", &elf.is_64bit.to_string()),
        kv_line("Is PIE", &elf.is_pie.to_string()),
    ];
    if let Some(ref interp) = elf.interpreter {
        left_lines.push(kv_line("Interpreter", interp));
    }
    if let Some(ref soname) = elf.soname {
        left_lines.push(kv_line("SONAME", soname));
    }

    // Middle Column: Binary Hardening & Mitigations
    let mut center_lines = vec![
        section_header("Mitigations & Hardening"),
    ];

    let fmt_check = |label: &str, ok: bool, ok_text: &str, bad_text: &str, is_crit: bool| {
        let (icon, text, color) = if ok {
            ("✓", ok_text, theme::SAFE)
        } else if is_crit {
            ("!", bad_text, theme::CRITICAL)
        } else {
            ("⚠", bad_text, theme::WARNING)
        };
        Line::from(vec![
            Span::styled(format!("  {:<12} ", label), theme::label()),
            Span::styled(format!("{} ", icon), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(text.to_string(), Style::default().fg(color)),
        ])
    };

    center_lines.push(fmt_check("NX Stack", elf.mitigations.nx, "Enabled (Non-Exec Stack)", "Disabled (W+X Stack!)", true));
    center_lines.push(fmt_check("PIE", elf.mitigations.pie, "Enabled (DYN / ASLR)", "Disabled (Fixed Base)", false));
    
    let (relro_icon, relro_text, relro_color) = match elf.mitigations.relro {
        ElfRelro::Full => ("✓", "Full RELRO", theme::SAFE),
        ElfRelro::Partial => ("⚠", "Partial RELRO", theme::WARNING),
        ElfRelro::None => ("!", "No RELRO", theme::CRITICAL),
    };
    center_lines.push(Line::from(vec![
        Span::styled("  RELRO        ", theme::label()),
        Span::styled(format!("{} ", relro_icon), Style::default().fg(relro_color).add_modifier(Modifier::BOLD)),
        Span::styled(relro_text.to_string(), Style::default().fg(relro_color)),
    ]));

    center_lines.push(fmt_check("Canary", elf.mitigations.stack_canary, "Found (__stack_chk)", "Not Detected", false));
    center_lines.push(fmt_check("FORTIFY", elf.mitigations.fortified, "Found (_chk symbols)", "Not Detected", false));

    if let Some(ref rpath) = elf.mitigations.rpath {
        center_lines.push(Line::from(""));
        center_lines.push(section_header("RPATH (Injection Risk)"));
        center_lines.push(Line::from(Span::styled(format!("  {}", rpath), Style::default().fg(theme::WARNING))));
    }
    if let Some(ref runpath) = elf.mitigations.runpath {
        center_lines.push(Line::from(""));
        center_lines.push(section_header("RUNPATH"));
        center_lines.push(Line::from(Span::styled(format!("  {}", runpath), Style::default().fg(theme::TEXT))));
    }

    // Right Column: Shared Libraries & Direct Syscalls
    let mut right_lines = vec![
        section_header("System Calls"),
    ];
    let (sys_icon, sys_text, sys_color) = if elf.direct_syscalls {
        ("!", format!("FOUND ({} instances)", elf.syscall_locations.len()), theme::CRITICAL)
    } else {
        ("✓", "None Detected".to_string(), theme::SAFE)
    };
    right_lines.push(Line::from(vec![
        Span::styled("  Direct Sys:  ", theme::label()),
        Span::styled(format!("{} ", sys_icon), Style::default().fg(sys_color).add_modifier(Modifier::BOLD)),
        Span::styled(sys_text, Style::default().fg(sys_color)),
    ]));

    right_lines.push(Line::from(""));
    right_lines.push(section_header("Shared Libraries (DT_NEEDED)"));
    if elf.libraries.is_empty() {
        right_lines.push(Line::from(Span::styled("  (Static binary / No dynamic libs)", Style::default().fg(theme::TEXT_DIM))));
    } else {
        for lib in &elf.libraries {
            right_lines.push(Line::from(vec![
                Span::styled("  • ", theme::label()),
                Span::styled(lib, Style::default().fg(theme::INFO)),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(left_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(center_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(right_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[2],
    );
}

fn draw_elf_segments(frame: &mut Frame, area: Rect, app: &App) {
    let Some(elf) = app.result.elf.as_ref() else {
        frame.render_widget(Paragraph::new(" No ELF segments"), area);
        return;
    };

    let header = Row::new(vec![
        Cell::from("Type").style(theme::header()),
        Cell::from("Flags").style(theme::header()),
        Cell::from("VirtAddr").style(theme::header()),
        Cell::from("MemSize").style(theme::header()),
        Cell::from("Offset").style(theme::header()),
        Cell::from("FileSize").style(theme::header()),
        Cell::from("Align").style(theme::header()),
    ])
    .height(1);

    let rows: Vec<Row> = elf
        .program_headers
        .iter()
        .map(|ph| {
            let is_wx = ph.is_write && ph.is_exec;
            let flag_color = if is_wx {
                theme::CRITICAL
            } else if ph.is_exec {
                theme::WARNING
            } else {
                theme::TEXT
            };

            Row::new(vec![
                Cell::from(ph.ph_type.clone()).style(theme::value()),
                Cell::from(ph.flags.clone()).style(Style::default().fg(flag_color).add_modifier(if is_wx { Modifier::BOLD } else { Modifier::empty() })),
                Cell::from(format!("{:#010x}", ph.virtual_address)).style(theme::value()),
                Cell::from(format!("{:#x}", ph.memory_size)).style(theme::value()),
                Cell::from(format!("{:#x}", ph.file_offset)).style(theme::value()),
                Cell::from(format!("{:#x}", ph.file_size)).style(theme::value()),
                Cell::from(format!("{:#x}", ph.alignment)).style(Style::default().fg(theme::TEXT_DIM)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block("ELF Program Headers (Segments)"))
        .row_highlight_style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(table, area);
}

fn draw_elf_sections(frame: &mut Frame, area: Rect, app: &App) {
    let Some(elf) = app.result.elf.as_ref() else {
        frame.render_widget(Paragraph::new(" No ELF sections"), area);
        return;
    };

    let header = Row::new(vec![
        Cell::from("Name").style(theme::header()),
        Cell::from("Type").style(theme::header()),
        Cell::from("Addr").style(theme::header()),
        Cell::from("Size").style(theme::header()),
        Cell::from("Entropy").style(theme::header()),
        Cell::from("Flags").style(theme::header()),
        Cell::from("Anomalies").style(theme::header()),
    ])
    .height(1);

    let query_lower = app.search_query.to_lowercase();
    let rows: Vec<Row> = elf
        .sections
        .iter()
        .filter(|s| query_lower.is_empty() || s.name.to_lowercase().contains(&query_lower))
        .map(|s| {
            let ent_color = if s.entropy > 7.0 {
                theme::CRITICAL
            } else if s.entropy > 6.0 {
                theme::WARNING
            } else {
                theme::SAFE
            };

            let is_wx = s.is_executable && s.is_writable;
            let flag_color = if is_wx {
                theme::CRITICAL
            } else if s.is_executable {
                theme::WARNING
            } else {
                theme::TEXT
            };

            let anomaly_str = if s.anomalies.is_empty() {
                "—".to_string()
            } else {
                s.anomalies.join(", ")
            };

            Row::new(vec![
                Cell::from(s.name.clone()).style(theme::value()),
                Cell::from(s.section_type.clone()).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(format!("{:#010x}", s.virtual_address)).style(theme::value()),
                Cell::from(format!("{:#x}", s.raw_size)).style(theme::value()),
                Cell::from(format!("{:.2}", s.entropy)).style(Style::default().fg(ent_color)),
                Cell::from(s.flags_str.clone()).style(Style::default().fg(flag_color).add_modifier(if is_wx { Modifier::BOLD } else { Modifier::empty() })),
                Cell::from(anomaly_str).style(Style::default().fg(theme::WARNING)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block("ELF Sections"))
        .row_highlight_style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(table, area);
}

fn draw_elf_imports(frame: &mut Frame, area: Rect, app: &App) {
    let Some(elf) = app.result.elf.as_ref() else {
        frame.render_widget(Paragraph::new(" No ELF symbols"), area);
        return;
    };

    let mut lines = Vec::new();

    let crit = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Critical).count();
    let high = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::High).count();
    let med = elf.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Medium).count();

    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} Imported Functions across {} Shared Libraries  ", elf.imported_symbols.len(), elf.libraries.len()),
            theme::value(),
        ),
        Span::styled(format!("● {} ", crit), Style::default().fg(theme::CRITICAL)),
        Span::styled(format!("● {} ", high), Style::default().fg(theme::ORANGE)),
        Span::styled(format!("● {} ", med), Style::default().fg(theme::WARNING)),
    ]));
    lines.push(Line::from(""));

    if !elf.libraries.is_empty() {
        lines.push(section_header("Shared Libraries (DT_NEEDED)"));
        for lib in &elf.libraries {
            lines.push(Line::from(vec![
                Span::styled("   ▸ ", Style::default().fg(theme::ORANGE_LIGHT)),
                Span::styled(lib, Style::default().fg(theme::INFO)),
            ]));
        }
        lines.push(Line::from(""));
    }

    let query_lower = app.search_query.to_lowercase();
    lines.push(section_header("Imported Dynamic Symbols"));
    for sym in elf
        .imported_symbols
        .iter()
        .filter(|s| query_lower.is_empty() || s.name.to_lowercase().contains(&query_lower))
    {
        let color = theme::api_risk_color(&sym.risk);
        let marker = match sym.risk {
            ApiRisk::Critical => "●",
            ApiRisk::High => "◉",
            ApiRisk::Medium => "○",
            _ => "·",
        };
        let risk_tag = if sym.risk != ApiRisk::None {
            format!(" [{}]", sym.risk)
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("    {} ", marker), Style::default().fg(color)),
            Span::styled(&sym.name, Style::default().fg(theme::TEXT)),
            Span::styled(risk_tag, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]));
    }

    let block = panel_block("ELF Symbols & Imports");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

fn draw_binary_disasm(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    title: &'static str,
    arch: &str,
    syscall_locations: &[crate::models::SyscallLocation],
    is_64bit: bool,
    ep_bytes: &[u8],
    entry_point: u64,
) {
    let is_arm64 = arch.contains("ARM64") || arch.contains("AArch64");
    render_disasm(
        frame,
        area,
        app.scroll_offset,
        title,
        syscall_locations,
        is_64bit,
        is_arm64,
        ep_bytes,
        entry_point,
    );
}

fn draw_elf_disasm(frame: &mut Frame, area: Rect, app: &App) {
    let Some(elf) = app.result.elf.as_ref() else {
        frame.render_widget(Paragraph::new(" No ELF metadata for disassembly"), area);
        return;
    };
    draw_binary_disasm(
        frame,
        area,
        app,
        "ELF Disassembly",
        &elf.machine,
        &elf.syscall_locations,
        elf.is_64bit,
        &elf.ep_bytes,
        elf.entry_point,
    );
}

// ─── Mach-O UI Renderers ─────────────────────────────────────────

fn draw_macho_headers(frame: &mut Frame, area: Rect, app: &App) {
    let Some(macho) = app.result.macho.as_ref() else {
        frame.render_widget(Paragraph::new(" No Mach-O headers"), area);
        return;
    };

    let block = panel_block("Mach-O Headers & Mitigations");
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::horizontal([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(inner_area);

    // Left Column: Header Information
    let left_lines = vec![
        section_header("Mach-O Header"),
        kv_line("CPU Type", &macho.cpu_type),
        kv_line("File Type", &macho.file_type),
        kv_line("Flags", &macho.flags_str),
        kv_line("Entry Point", &format!("{:#010x}", macho.entry_point)),
        kv_line("Is 64-bit", &macho.is_64bit.to_string()),
        kv_line("Is PIE", &macho.is_pie.to_string()),
        kv_line("Code Signature", if macho.has_code_signature { "Signed (LC_CODE_SIGNATURE)" } else { "Unsigned" }),
    ];

    // Middle Column: Binary Hardening & Mitigations
    let fmt_check = |label: &str, ok: bool, ok_text: &str, bad_text: &str, is_crit: bool| {
        let (icon, text, color) = if ok {
            ("✓", ok_text, theme::SAFE)
        } else if is_crit {
            ("!", bad_text, theme::CRITICAL)
        } else {
            ("⚠", bad_text, theme::WARNING)
        };
        Line::from(vec![
            Span::styled(format!("  {:<14} ", label), theme::label()),
            Span::styled(format!("{} ", icon), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(text.to_string(), Style::default().fg(color)),
        ])
    };

    let mut center_lines = vec![
        section_header("Mitigations & Hardening"),
        fmt_check("PIE (ASLR)", macho.mitigations.pie, "Enabled (MH_PIE)", "Disabled (Fixed Base)", false),
        fmt_check("NX Stack", !macho.mitigations.allow_stack_execution, "Enforced (Non-Exec)", "Disabled (Stack Exec allowed!)", true),
        fmt_check("Heap NX", macho.mitigations.no_heap_execution, "Enforced (MH_NO_HEAP_EXEC)", "Unrestricted", false),
        fmt_check("Code Signature", macho.mitigations.has_code_signature, "Present (LC_CODE_SIGNATURE)", "Missing / Unsigned", false),
    ];

    if !macho.mitigations.rpaths.is_empty() {
        center_lines.push(Line::from(""));
        center_lines.push(section_header("RPATHs (Dylib Hijacking Risk)"));
        for rp in &macho.mitigations.rpaths {
            center_lines.push(Line::from(vec![
                Span::styled("  • ", theme::label()),
                Span::styled(rp, Style::default().fg(theme::WARNING)),
            ]));
        }
    }

    // Right Column: System Calls & Dependent Libraries
    let mut right_lines = vec![
        section_header("System Calls"),
    ];
    let (sys_icon, sys_text, sys_color) = if macho.direct_syscalls {
        ("!", format!("FOUND ({} instances)", macho.syscall_locations.len()), theme::CRITICAL)
    } else {
        ("✓", "None Detected".to_string(), theme::SAFE)
    };
    right_lines.push(Line::from(vec![
        Span::styled("  Direct Sys:    ", theme::label()),
        Span::styled(format!("{} ", sys_icon), Style::default().fg(sys_color).add_modifier(Modifier::BOLD)),
        Span::styled(sys_text, Style::default().fg(sys_color)),
    ]));

    right_lines.push(Line::from(""));
    right_lines.push(section_header("Dependent Dylibs (LC_LOAD_DYLIB)"));
    if macho.dylibs.is_empty() {
        right_lines.push(Line::from(Span::styled("  (Static binary / No dynamic libs)", Style::default().fg(theme::TEXT_DIM))));
    } else {
        for dylib in &macho.dylibs {
            right_lines.push(Line::from(vec![
                Span::styled("  • ", theme::label()),
                Span::styled(dylib, Style::default().fg(theme::INFO)),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(left_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(center_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(right_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        chunks[2],
    );
}

fn draw_macho_segments(frame: &mut Frame, area: Rect, app: &App) {
    let Some(macho) = app.result.macho.as_ref() else {
        frame.render_widget(Paragraph::new(" No Mach-O segments"), area);
        return;
    };

    let header = Row::new(vec![
        Cell::from("Segment").style(theme::header()),
        Cell::from("InitProt").style(theme::header()),
        Cell::from("MaxProt").style(theme::header()),
        Cell::from("VM Address").style(theme::header()),
        Cell::from("VM Size").style(theme::header()),
        Cell::from("File Offset").style(theme::header()),
        Cell::from("File Size").style(theme::header()),
    ])
    .height(1);

    let rows: Vec<Row> = macho
        .segments
        .iter()
        .map(|seg| {
            let is_wx = seg.is_write && seg.is_exec && seg.filesize > 0;
            let prot_color = if is_wx {
                theme::CRITICAL
            } else if seg.is_exec {
                theme::WARNING
            } else {
                theme::TEXT
            };

            Row::new(vec![
                Cell::from(seg.name.clone()).style(theme::value()),
                Cell::from(seg.initprot.clone()).style(Style::default().fg(prot_color).add_modifier(if is_wx { Modifier::BOLD } else { Modifier::empty() })),
                Cell::from(seg.maxprot.clone()).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(format!("{:#010x}", seg.vmaddr)).style(theme::value()),
                Cell::from(format!("{:#x}", seg.vmsize)).style(theme::value()),
                Cell::from(format!("{:#x}", seg.fileoff)).style(theme::value()),
                Cell::from(format!("{:#x}", seg.filesize)).style(theme::value()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Min(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block("Mach-O Segments"))
        .row_highlight_style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(table, area);
}

fn draw_macho_sections(frame: &mut Frame, area: Rect, app: &App) {
    let Some(macho) = app.result.macho.as_ref() else {
        frame.render_widget(Paragraph::new(" No Mach-O sections"), area);
        return;
    };

    let header = Row::new(vec![
        Cell::from("Section").style(theme::header()),
        Cell::from("Segment").style(theme::header()),
        Cell::from("Addr").style(theme::header()),
        Cell::from("Size").style(theme::header()),
        Cell::from("Entropy").style(theme::header()),
        Cell::from("Flags").style(theme::header()),
        Cell::from("Anomalies").style(theme::header()),
    ])
    .height(1);

    let query_lower = app.search_query.to_lowercase();
    let rows: Vec<Row> = macho
        .sections
        .iter()
        .filter(|s| query_lower.is_empty() || s.sectname.to_lowercase().contains(&query_lower) || s.segname.to_lowercase().contains(&query_lower))
        .map(|s| {
            let ent_color = if s.entropy > 7.0 {
                theme::CRITICAL
            } else if s.entropy > 6.0 {
                theme::WARNING
            } else {
                theme::SAFE
            };

            let is_wx = s.is_executable && s.is_writable;
            let (flags_str, flag_color) = if is_wx {
                ("W+X", theme::CRITICAL)
            } else if s.is_executable {
                ("X", theme::WARNING)
            } else if s.is_writable {
                ("W", theme::TEXT)
            } else {
                ("R", theme::TEXT_DIM)
            };

            let anomaly_str = if s.anomalies.is_empty() {
                "—".to_string()
            } else {
                s.anomalies.join(", ")
            };

            Row::new(vec![
                Cell::from(s.sectname.clone()).style(theme::value()),
                Cell::from(s.segname.clone()).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(format!("{:#010x}", s.addr)).style(theme::value()),
                Cell::from(format!("{:#x}", s.size)).style(theme::value()),
                Cell::from(format!("{:.2}", s.entropy)).style(Style::default().fg(ent_color)),
                Cell::from(flags_str).style(Style::default().fg(flag_color).add_modifier(if is_wx { Modifier::BOLD } else { Modifier::empty() })),
                Cell::from(anomaly_str).style(Style::default().fg(theme::WARNING)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(18),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block("Mach-O Sections"))
        .row_highlight_style(Style::default().bg(theme::BG_PANEL));

    frame.render_widget(table, area);
}

fn draw_macho_imports(frame: &mut Frame, area: Rect, app: &App) {
    let Some(macho) = app.result.macho.as_ref() else {
        frame.render_widget(Paragraph::new(" No Mach-O symbols"), area);
        return;
    };

    let mut lines = Vec::new();

    let crit = macho.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Critical).count();
    let high = macho.imported_symbols.iter().filter(|f| f.risk == ApiRisk::High).count();
    let med = macho.imported_symbols.iter().filter(|f| f.risk == ApiRisk::Medium).count();

    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} Imported Symbols across {} Dylibs  ", macho.imported_symbols.len(), macho.dylibs.len()),
            theme::value(),
        ),
        Span::styled(format!("● {} ", crit), Style::default().fg(theme::CRITICAL)),
        Span::styled(format!("● {} ", high), Style::default().fg(theme::ORANGE)),
        Span::styled(format!("● {} ", med), Style::default().fg(theme::WARNING)),
    ]));
    lines.push(Line::from(""));

    if !macho.dylibs.is_empty() {
        lines.push(section_header("Dependent Dynamic Libraries (LC_LOAD_DYLIB)"));
        for lib in &macho.dylibs {
            lines.push(Line::from(vec![
                Span::styled("   ▸ ", Style::default().fg(theme::ORANGE_LIGHT)),
                Span::styled(lib, Style::default().fg(theme::INFO)),
            ]));
        }
        lines.push(Line::from(""));
    }

    let query_lower = app.search_query.to_lowercase();
    lines.push(section_header("Imported Dynamic Symbols"));
    for sym in macho
        .imported_symbols
        .iter()
        .filter(|s| query_lower.is_empty() || s.name.to_lowercase().contains(&query_lower))
    {
        let color = theme::api_risk_color(&sym.risk);
        let marker = match sym.risk {
            ApiRisk::Critical => "●",
            ApiRisk::High => "◉",
            ApiRisk::Medium => "○",
            _ => "·",
        };
        let risk_tag = if sym.risk != ApiRisk::None {
            format!(" [{}]", sym.risk)
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("    {} ", marker), Style::default().fg(color)),
            Span::styled(&sym.name, Style::default().fg(theme::TEXT)),
            Span::styled(risk_tag, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]));
    }

    if !macho.exported_symbols.is_empty() {
        lines.push(Line::from(""));
        lines.push(section_header("Exported Symbols"));
        for exp in &macho.exported_symbols {
            if query_lower.is_empty() || exp.to_lowercase().contains(&query_lower) {
                lines.push(Line::from(vec![
                    Span::styled("    ▸ ", Style::default().fg(theme::ORANGE_LIGHT)),
                    Span::styled(exp, Style::default().fg(theme::TEXT)),
                ]));
            }
        }
    }

    let block = panel_block("Mach-O Symbols & Imports");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll_offset, 0)),
        area,
    );
}

fn draw_macho_disasm(frame: &mut Frame, area: Rect, app: &App) {
    let Some(macho) = app.result.macho.as_ref() else {
        frame.render_widget(Paragraph::new(" No Mach-O metadata for disassembly"), area);
        return;
    };
    draw_binary_disasm(
        frame,
        area,
        app,
        "Mach-O Disassembly",
        &macho.cpu_type,
        &macho.syscall_locations,
        macho.is_64bit,
        &macho.ep_bytes,
        macho.entry_point,
    );
}
