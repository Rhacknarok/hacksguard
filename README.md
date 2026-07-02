# HacksGuard

HacksGuard is a blazingly fast Terminal UI (TUI) static analysis tool designed for malware analysts and reverse engineers. Built in Rust, it provides an intuitive dashboard for quick triage and deep inspection of Portable Executable (PE) files.

## Features

- **Dashboard Overview**: Automatically calculates a Risk Score based on entropy, APIs, anomalies, strings, and packing. Includes an intuitive heuristics radar and a visual **Entropy Graph (Sparkline)**.
- **YARA Integration**: Dynamically loads YARA rules from the `rules/` directory (e.g. Elastic protections-artifacts) via the `boreal` engine.
- **VirusTotal API**: Fetches real-time community scores (requires `VT_API_KEY` environment variable).
- **Deep PE Parsing**: Inspects Sections, Imports (grouped by risk), Exports, Anomalies, Data Directories, Security Mitigations (ASLR, DEP, CFG), and Authenticode signatures.
- **Overlay Analysis**: Detects appended data (overlay) at the end of the binary, often used by droppers or installers.
- **Disassembler**: Raw x86/x64 instruction preview at the Entry Point via `iced-x86`.
- **Hex Dump**: Built-in hex viewer for quick binary inspection.
- **String Extraction & Auto-Decoding**: Fast string dumping with automatic Base64 decryption for suspicious strings.
- **CLI Export**: Run with `--json` to bypass the TUI and export the full analysis report as a JSON object to stdout.
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
