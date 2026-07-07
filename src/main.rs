// Copyright (c) 2026 Rhacknarok - https://github.com/Rhacknarok/hacksguard

mod analysis;
mod app;
mod models;
mod theme;
mod tui;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use color_eyre::Result;
use std::path::PathBuf;

/// HACKSGUARD — TUI malware analysis tool
#[derive(Parser)]
#[command(name = "hacksguard", version, about)]
struct Cli {
    /// Path to the file to analyze
    file: PathBuf,
    /// Output JSON analysis to stdout instead of launching the TUI
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    if !cli.file.exists() {
        eprintln!("[!] File not found: {}", cli.file.display());
        std::process::exit(1);
    }

    if cli.json {
        let result = analysis::analyze_file(&cli.file, None, true)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    let mut terminal = tui::init();

    let (tx, rx) = std::sync::mpsc::channel();
    let (prog_tx, prog_rx) = std::sync::mpsc::channel();
    let file_path = cli.file.clone();

    std::thread::spawn(move || {
        let res = analysis::analyze_file(&file_path, Some(prog_tx), false);
        let _ = tx.send(res);
    });

    let mut tasks_done = 0;

    let result = loop {
        while let Ok(_) = prog_rx.try_recv() {
            tasks_done += 1;
        }

        if let Ok(res) = rx.try_recv() {
            break res?;
        }

        terminal.draw(|f| {
            use ratatui::widgets::{Block, Borders, Gauge, Clear};
            use ratatui::style::{Style, Modifier};
            
            // Fill background with app's dark theme
            f.render_widget(Block::default().style(Style::default().bg(crate::theme::BG_DARK)), f.area());
            
            let pct = (tasks_done * 100) / 3;
            let text = format!("{}% ({} / 3 tâches) - Analyzing...", pct, tasks_done);
            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(crate::theme::BORDER))
                        .title(" HACKSGUARD ")
                        .title_style(Style::default().fg(crate::theme::ORANGE).add_modifier(Modifier::BOLD))
                        .style(Style::default().bg(crate::theme::BG_PANEL))
                )
                .gauge_style(Style::default().fg(crate::theme::ORANGE).bg(crate::theme::BG_DARK))
                .percent(pct as u16)
                .label(text);
                
            let width = 50.min(f.area().width);
            let height = 3;
            let x = (f.area().width.saturating_sub(width)) / 2;
            let y = (f.area().height.saturating_sub(height)) / 2;
            
            let area = ratatui::layout::Rect::new(x, y, width, height);
            f.render_widget(Clear, area);
            f.render_widget(gauge, area);
        })?;

        std::thread::sleep(std::time::Duration::from_millis(50));

        if crossterm::event::poll(std::time::Duration::from_millis(0))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if key.code == crossterm::event::KeyCode::Char('q') || key.code == crossterm::event::KeyCode::Esc {
                    tui::restore();
                    std::process::exit(0);
                }
            }
        }
    };

    let mut app = app::App::new(result);

    let (yara_tx, yara_rx) = std::sync::mpsc::channel();
    let yara_file_path = cli.file.clone();
    std::thread::spawn(move || {
        let data = std::fs::read(&yara_file_path).unwrap_or_default();
        let matches = analysis::load_or_compile_yara(&data);
        let _ = yara_tx.send(matches);
    });

    app.yara_rx = Some(yara_rx);
    app.yara_loading = true;

    let res = app.run(&mut terminal);
    tui::restore();
    res
}
