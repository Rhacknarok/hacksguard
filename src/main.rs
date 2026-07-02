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
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    if !cli.file.exists() {
        eprintln!("[!] File not found: {}", cli.file.display());
        std::process::exit(1);
    }

    eprintln!("[*] Analyzing {}...", cli.file.display());
    let result = analysis::analyze_file(&cli.file)?;
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
