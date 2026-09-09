# Hacksguard 0.4 - Blazing Fast TUI Malware Analysis Tool 🛡️

![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square&logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey?style=flat-square)

![Hacksguard TUI Malware Analysis Dashboard](assets/hacksguard.gif)

Hacksguard is a blazingly fast, multi-threaded Terminal UI (TUI) static analysis tool designed for SOC analysts, threat hunters, and reverse engineers. Built entirely in Rust, it provides an intuitive dashboard for quick triage and deep inspection of Windows (PE), Linux (ELF), and macOS (Mach-O & Universal Fat) binaries right from your terminal.

## 🌟 Key Features

- **Blazing Fast & Multi-Threaded**: The core analysis pipeline runs concurrently. This ensures zero UI latency, even when analyzing large executables.
- **Multi-Format Static Analysis**: Native deep inspection of Portable Executable (PE), Linux (ELF), and macOS (Mach-O / Fat containers) formats.
- **Advanced Risk Scoring**: Hacksguard automatically compiles a 0-100% Risk Score based on 5 heuristic axes (Entropy, Suspicious APIs, Format Anomalies, Strings, and Packing), visualized through an interactive radar chart.
- **Integrated YARA Engine**: Powered by the `boreal` crate, Hacksguard dynamically loads local YARA rules (e.g., Elastic protections-artifacts and Neo23x0 signature-base) to detect known threats, packers, and evasion techniques.
- **Deep PE, ELF & Mach-O Inspection**: Headers, Sections/Segments, Imports & Exports, Security Mitigations (ASLR/PIE, DEP/NX, RELRO, CodeSign, RPATHs), Mandiant Imphash, and Rich Header parsing (toolchain ID decoding & RichPE hash).
- **Authenticode Certificate Decoding**: Zero-dependency ASN.1 DER and PKCS#7 parser extracting X.509 leaf certificate details (Subject, Issuer, Validity window, Digest Algorithm, Serial Number) and flagging self-signed certificates.
- **1-Byte XOR Payload Brute-Forcer**: High-speed single-pass scanner detecting obfuscated PE binaries (`MZ...PE`), DOS stubs, and URLs hidden inside overlays or high-entropy sections.
- **Direct & Indirect Syscall Detection**: Automated scanning for evasion techniques including x86/x64 direct/indirect syscalls (`syscall`, `sysenter`, `int 0x80`) and ARM64 supervisor calls (`svc #0` on Linux AArch64, `svc #0x80` on macOS ARM64).
- **Visual Entropy Graph**: A dedicated Entropy tab plots the Shannon entropy distribution of the file using sparklines, allowing analysts to visually spot encrypted or packed payloads instantly.
- **ASCII & UTF-16LE Strings**: Automatically extracts and categorizes ASCII and UTF-16LE wide strings (IPs, URLs, Registry keys, commands) with live interactive filtering (`/`) and category shortcuts (`u/i/r/c/s/p/a`).
- **Built-in Disassembler & Hex View**: Inspect Entry Point instructions (x86/x64 decoded via `iced-x86`, ARM64 instruction word formatting with syscall highlighting) or dive into raw bytes with the Hex Dump viewer.
- **Overlay Detection**: Automatically detects appended hidden data at the end of the binary, a technique commonly used by droppers and malicious installers.
- **Clipboard Integration (`y`)**: Instant zero-dependency copy of hashes and strings to system clipboard via ANSI OSC 52 sequences.
- **CLI Mode / CI-CD Ready**: Run `hacksguard --json <file>` to bypass the terminal UI and export the full analysis report as a structured JSON object for SIEM/SOAR integrations.

## 📦 Installation

### Building from source

Make sure you have Rust and Cargo installed. Clone the repository with its submodules:

```bash
git clone --recursive https://github.com/Rhacknarok/hacksguard.git
cd hacksguard
cargo build --release
```

If already cloned without submodules:

```bash
git submodule update --init --recursive
cargo build --release
```

The compiled binary will be available at `target/release/hacksguard`.

### Nixpkgs

For Nix or NixOS users is a [package](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&type=packages&query=hacksguard)
available in Nixpkgs. Keep in mind that the lastest releases might only
be present in the ``unstable`` channel.

```bash
$ nix-env -iA nixos.hacksguard
```

## 🚀 Usage

Run Hacksguard by providing the path to the executable you want to analyze:

```bash
cargo run --release -- <path/to/binary.exe>
```

### Keyboard Shortcuts

- `Tab` / `Right Arrow`: Next Tab
- `Shift+Tab` / `Left Arrow`: Previous Tab
- `Up` / `Down` / `k` / `j`: Scroll
- `PageUp` / `PageDown`: Fast Scroll
- `/`: Interactive Search (live filter across Strings, Imports, Sections)
- `y`: Copy to Clipboard (OSC 52 - copies active hash or string)
- `u` / `i` / `r` / `c` / `s` / `p` / `a`: Quick category filter in Strings view (URLs, IPs, Reg, Cmd, Suspicious, Path, All)
- `Esc`: Clear search / category filter (or Quit if clean)
- `q`: Quit

## Dependencies

- `ratatui` & `crossterm` - TUI rendering
- `goblin` - PE/ELF/Mach-O parsing
- `boreal` - Pure Rust YARA engine
- `iced-x86` - Disassembler


## 🔗 Related Projects

- [Elastic Protections Artifacts](https://github.com/elastic/protections-artifacts) - YARA rules
- [Neo23x0 Signature Base](https://github.com/Neo23x0/signature-base) - YARA rules

## 📸 Screenshots

### Overview
![Overview](assets/screenshots/1%20-%20overview.png)

### PE Headers
![PE Headers](assets/screenshots/2%20-%20headers.png)

### Sections
![Sections](assets/screenshots/3%20-%20sections.png)

### Imports
![Imports](assets/screenshots/4%20-%20imports.png)

### Disassembly
![Disassembly](assets/screenshots/5%20-%20disasm.png)

### Hex View
![Hex View](assets/screenshots/6%20-%20hex.png)

### Strings
![Strings](assets/screenshots/7%20-%20strings.png)

### Entropy
![Entropy](assets/screenshots/8%20-%20entropy.png)

### Analyst Guide
![Analyst Guide](assets/screenshots/9%20-%20guide.png)
