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
        "Headers" => draw_headers(frame, chunks[2], app),
        "Sections" => draw_sections(frame, chunks[2], app),
        "Imports" => draw_imports(frame, chunks[2], app),
        "Entropy" => draw_entropy(frame, chunks[2], app),
        "Disasm" => draw_disasm(frame, chunks[2], app),
        "Hex View" => draw_hexdump(frame, chunks[2], app),
        "Strings" => draw_strings(frame, chunks[2], app),
        "Guide" => draw_guide(frame, chunks[2], app),
        _ => {}
    }

    draw_status_bar(frame, chunks[3], app);
}

// ─── Title bar ───────────────────────────────────────────────────

fn draw_title(frame: &mut Frame, area: Rect, app: &App) {
    let title = Line::from(vec![
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
    ]);

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

fn draw_status_bar(frame: &mut Frame, area: Rect, _app: &App) {
    let help = Line::from(vec![
        Span::styled(" ←/→ ", Style::default().fg(theme::ORANGE)),
        Span::styled("Tab  ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("↑/↓ ", Style::default().fg(theme::ORANGE)),
        Span::styled("Scroll  ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("Home ", Style::default().fg(theme::ORANGE)),
        Span::styled("Top  ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("q ", Style::default().fg(theme::ORANGE)),
        Span::styled("Quit", Style::default().fg(theme::TEXT_DIM)),
    ]);
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
        RiskLevel::Critical => ("✖", "CRITICAL — Strong malware indicators detected"),
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

    build_entropy_histogram_lines(&mut right_lines, app);
    build_byte_distribution_lines(&mut right_lines, app);
    build_import_heatmap_lines(&mut right_lines, app);
    build_suspicious_strings_lines(&mut right_lines, app);
    build_malware_pattern_lines(&mut right_lines, app);
    build_yara_lines(&mut right_lines, app);
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
    let pe_type = if let Some(pe) = &app.result.pe {
        let arch = if pe.is_64bit { "PE32+" } else { "PE32" };
        let kind = if pe.is_dll { "DLL" } else { "EXE" };
        format!("{} {} ({})", arch, kind, pe.machine)
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
    lines.push(kv_line("Type", &pe_type));
    lines.push(kv_line("Magic", &magic_hex));


    if let Some(pe) = &app.result.pe {
        lines.push(Line::from(""));
        lines.push(section_header("PE Metadata"));
        lines.push(kv_line("Authenticode", if pe.has_authenticode { "✅" } else { "❌" }));
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
    if let Some(pe) = &app.result.pe {
        if let Some(packer) = &pe.packer_detected {
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
    } else {
        lines.push(Line::from(vec![
            Span::styled("   — ".to_string(), Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                "N/A (not a PE file)".to_string(),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]));
    }
    lines.push(Line::from(""));
}

fn build_entropy_histogram_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    if let Some(pe) = &app.result.pe {
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
    if let Some(pe) = &app.result.pe {
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
    lines.push(Line::from(""));
    lines.push(section_header("YARA Analysis"));

    if app.result.yara_matches.is_empty() {
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
}

fn build_anomalies_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    if let Some(pe) = &app.result.pe {
        if !pe.anomalies.is_empty() {
            lines.push(section_header("Anomalies"));
            for a in &pe.anomalies {
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
}

// ─── Headers tab ─────────────────────────────────────────────────

fn draw_headers(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = &app.result.pe else {
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
        Line::from(""),
        section_header("Security Mitigations"),
    ];

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

    // Right Column: Data Directories
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
    let Some(pe) = &app.result.pe else {
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

    let rows: Vec<Row> = pe
        .sections
        .iter()
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
    let Some(pe) = &app.result.pe else {
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

    // Per-DLL listing
    for dll in &pe.imports {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" ▸ {} ", dll.name),
                Style::default()
                    .fg(theme::ORANGE_LIGHT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({})", dll.functions.len()),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]));

        for func in &dll.functions {
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

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} strings extracted", strings.len()),
            theme::value(),
        ),
    ]));
    lines.push(Line::from(""));

    // Show suspicious/interesting strings first, then normal
    let mut sorted: Vec<&ExtractedString> = strings.iter().collect();
    sorted.sort_by(|a, b| {
        let a_pri = category_priority(&a.category);
        let b_pri = category_priority(&b.category);
        a_pri.cmp(&b_pri)
    });

    for s in sorted.iter().take(500) {
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
    let mut lines = Vec::new();
    
    // Main Title
    lines.push(Line::from(vec![
        Span::styled(" HacksGuard Analyst Guide ", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD | Modifier::REVERSED)),
    ]));
    lines.push(Line::from(""));

    // 1. Risk Score
    lines.push(section_header("1. Risk Score"));
    lines.push(Line::from(vec![Span::styled("The global score (0-100) indicates the probability that a file is malicious. It is calculated across 5 axes:", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • Entropy (25 pts) : ", theme::label()), Span::styled("Measures code compression or encryption.", theme::value())]));
    lines.push(Line::from(vec![Span::styled(" • APIs (25 pts) : ", theme::label()), Span::styled("Critical imported functions (injection, keyloggers, etc).", theme::value())]));
    lines.push(Line::from(vec![Span::styled(" • Anomalies (25 pts) : ", theme::label()), Span::styled("PE format violations (e.g. Entry Point outside of code).", theme::value())]));
    lines.push(Line::from(vec![Span::styled(" • Strings (15 pts) : ", theme::label()), Span::styled("Suspicious strings (URLs, IPs, PowerShell cmds, system paths).", theme::value())]));
    lines.push(Line::from(vec![Span::styled(" • Packing (15 pts) : ", theme::label()), Span::styled("Presence of a known packer (UPX, Themida, VMProtect).", theme::value())]));
    lines.push(Line::from(""));

    // 2. Entropy & Overlay
    lines.push(section_header("2. Entropy & Overlay Analysis"));
    lines.push(Line::from(vec![Span::styled("Entropy measures data randomness on a scale of 0 to 8.", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • < 6.0 : ", theme::label()), Span::styled("Normal data (standard compiled code, plaintext).", theme::SAFE)]));
    lines.push(Line::from(vec![Span::styled(" • 6.0 - 7.0 : ", theme::label()), Span::styled("Gray zone (possibly compressed or dense data).", theme::WARNING)]));
    lines.push(Line::from(vec![Span::styled(" • > 7.0 : ", theme::label()), Span::styled("Highly suspicious. Code is very likely obfuscated, encrypted, or packed.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled("Tip : ", theme::label()), Span::styled("If an executable section (.text) has an entropy of 7.9+, a malware is trying to hide.", theme::value())]));
    lines.push(Line::from(vec![Span::styled("Overlay : ", theme::label()), Span::styled("Data appended to the end of the binary. Often used by droppers or installers to hide payloads.", theme::value())]));
    lines.push(Line::from(""));

    // 3. Packers & YARA
    lines.push(section_header("3. Packers & YARA Analysis"));
    lines.push(Line::from(vec![Span::styled("A 'packer' compresses or encrypts the executable to prevent static analysis.", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • UPX / MPRESS : ", theme::label()), Span::styled("Common packers, sometimes legitimate, but often abused.", theme::WARNING)]));
    lines.push(Line::from(vec![Span::styled(" • Themida / VMProtect : ", theme::label()), Span::styled("Extremely powerful commercial obfuscation tools. High risk.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled("YARA : ", theme::label()), Span::styled("HacksGuard uses the Elastic protections-artifacts YARA rules to detect specific malware families and behaviors.", theme::value())]));
    lines.push(Line::from(""));

    // 4. Imports & APIs
    lines.push(section_header("4. APIs & Imports (Import Address Table)"));
    lines.push(Line::from(vec![Span::styled("Shows which system libraries (DLLs) the file interacts with.", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • Process Injection : ", theme::label()), Span::styled("VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Keylogging / Hooking : ", theme::label()), Span::styled("SetWindowsHookEx, GetAsyncKeyState.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Anti-Debugging : ", theme::label()), Span::styled("IsDebuggerPresent, CheckRemoteDebuggerPresent.", theme::ORANGE)]));
    lines.push(Line::from(vec![Span::styled(" • Ransomware : ", theme::label()), Span::styled("CryptEncrypt, WNetOpenEnum, DeleteFile.", theme::ORANGE)]));
    lines.push(Line::from(""));

    // 5. PE Anomalies
    lines.push(section_header("5. PE Format Anomalies"));
    lines.push(Line::from(vec![Span::styled("Indicators that the file was manually manipulated or forged:", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • W+X (Write + Execute) : ", theme::label()), Span::styled("A section should never be writable AND executable (risk of injection/shellcode).", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Timestamp 0 or Future : ", theme::label()), Span::styled("The author forged or wiped the compilation date.", theme::WARNING)]));
    lines.push(Line::from(vec![Span::styled(" • Entry Point out of bounds : ", theme::label()), Span::styled("Execution starts in an unusual area (outside of code).", theme::CRITICAL)]));
    lines.push(Line::from(""));

    // 6. Strings & Decoding
    lines.push(section_header("6. Strings & Auto-Decoding"));
    lines.push(Line::from(vec![Span::styled("Raw text extracted from the file often reveals the author's intent.", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • URLs & IPs : ", theme::label()), Span::styled("Command & Control (C2) servers or download addresses (Droppers).", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Commands : ", theme::label()), Span::styled("Stealth execution via 'cmd.exe /c', 'powershell -enc', 'vssadmin delete shadows'.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Base64 Decoding : ", theme::label()), Span::styled("HacksGuard automatically attempts to decode strings longer than 16 characters that match the Base64 alphabet.", theme::value())]));
    lines.push(Line::from(""));

    // 7. Malware Patterns
    lines.push(section_header("7. Malware Patterns"));
    lines.push(Line::from(vec![Span::styled("Search for sets of indicators (heuristics) corresponding to known threats:", Style::default().fg(theme::TEXT))]));
    lines.push(Line::from(vec![Span::styled(" • Ransomware : ", theme::label()), Span::styled("Encryption + backup deletion + shadow copies removal.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Info Stealer : ", theme::label()), Span::styled("Browser hooking + network exfiltration.", theme::CRITICAL)]));
    lines.push(Line::from(vec![Span::styled(" • Dropper : ", theme::label()), Span::styled("Small size + HTTP payload downloading + overlay execution.", theme::CRITICAL)]));
    lines.push(Line::from(""));

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

fn draw_disasm(frame: &mut Frame, area: Rect, app: &App) {
    let Some(pe) = &app.result.pe else {
        frame.render_widget(Paragraph::new(" No PE metadata for disassembly"), area);
        return;
    };

    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(format!(" Disassembly at Entry Point ({:#010x}) ", pe.entry_point), Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    let bitness = if pe.is_64bit { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bitness, &pe.ep_bytes, pe.entry_point as u64, DecoderOptions::NONE);
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

    if lines.len() == 2 {
        lines.push(Line::from(Span::styled("  No valid instructions found.", Style::default().fg(theme::TEXT_DIM))));
    }

    let block = panel_block("Disassembly");
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.scroll_offset, 0)),
        area,
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
    let sparkline = ratatui::widgets::Sparkline::default()
        .block(
            Block::default()
                .title(" Full File Entropy Graph ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .data(&app.result.entropy_graph)
        .max(800)
        .style(Style::default().fg(theme::ORANGE));
    frame.render_widget(sparkline, area);
}
