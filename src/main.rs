// Copyright (c) 2026 Rhacknarok - https://github.com/Rhacknarok/hacksguard

mod analysis;
mod app;
mod models;
mod theme;
mod tui;

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

    if !cli.json {
        eprintln!("[*] Analyzing {}...", cli.file.display());
    }
    
    let result = analysis::analyze_file(&cli.file)?;
    
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    
    eprintln!(
        "[+] Risk: {}/100 ({})",
        result.risk_score, result.risk_level
    );

    let mut app = app::App::new(result);
    let mut terminal = tui::init();

    let res = app.run(&mut terminal);
    tui::restore();
    res
}
