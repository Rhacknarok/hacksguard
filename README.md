# HacksGuard

HacksGuard is a blazingly fast Terminal UI (TUI) static analysis tool designed for malware analysts and reverse engineers. Built in Rust, it provides an intuitive dashboard for quick triage and deep inspection of Portable Executable (PE) files.

## Features

- **Dashboard Overview**: Automatically calculates a Risk Score based on entropy, APIs, anomalies, strings, and packing. Includes an intuitive heuristics radar.
- **YARA Integration**: Built-in YARA scanning via the `boreal` engine to detect common malware patterns and anti-analysis tricks.
- **VirusTotal API**: Fetches real-time community scores (requires `VT_API_KEY` environment variable).
- **Deep PE Parsing**: Inspects Sections, Imports (grouped by risk), Exports, Anomalies, Data Directories, and Security Mitigations (ASLR, DEP, CFG) and Authenticode signatures.
- **Disassembler**: Raw x86/x64 instruction preview at the Entry Point via `iced-x86`.
- **Hex Dump**: Built-in hex viewer for quick binary inspection.
- **String Extraction**: Fast string dumping and filtering.
- **Built-in Guide**: Included analyst guide to help interpret the results correctly.

## Installation

Ensure you have Rust installed. Clone the repository and build:

```bash
git clone https://github.com/yourusername/hacksguard.git
cd hacksguard
cargo build --release
```

## Usage

Run HacksGuard by providing the path to the executable you want to analyze:

```bash
cargo run --release -- <path/to/binary.exe>
```

### Keyboard Shortcuts

- `Tab` / `Right Arrow`: Next Tab
- `Shift+Tab` / `Left Arrow`: Previous Tab
- `Up` / `Down` / `k` / `j`: Scroll
- `PageUp` / `PageDown`: Fast Scroll
- `q` / `Esc`: Quit

## Dependencies

- `ratatui` & `crossterm` - TUI rendering
- `goblin` - PE/ELF parsing
- `boreal` - Pure Rust YARA engine
- `iced-x86` - Disassembler
- `reqwest` - VirusTotal API client
