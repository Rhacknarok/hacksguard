# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added
- **YARA Rule Caching**: Implemented a binary caching system (`.yara_cache`) using SHA-256 fingerprinting for YARA rules, eliminating re-compilation overhead and significantly speeding up subsequent program executions.
- **TUI Loading Screen**: Added a styled progress bar (`Gauge`) displayed during the background analysis phase instead of blocking standard output.

### Changed
- **Threading Optimization**: Decoupled basic analysis and entropy calculation into separate independent threads to maximize parallel execution.
- Completely removed VirusTotal integration, API requirements, and `reqwest` dependency.

## [0.1.0] - 2025-07-03

### Added

- TUI dashboard with multi-tab navigation (`ratatui` + `crossterm`)
- PE static analysis: headers, sections, imports, exports, security mitigations (ASLR, DEP, CFG), Authenticode
- Multi-threaded analysis pipeline via `std::thread::scope` (basic + entropy, PE parsing, YARA scan)
- Risk scoring engine (0-100%) across 5 heuristic axes: entropy, suspicious APIs, PE anomalies, strings, packing
- Integrated YARA engine (`boreal`) with 750 Elastic protections-artifacts rules

- x86/x64 entry point disassembler (`iced-x86`)
- Hex dump viewer
- Shannon entropy sparkline graph (64-byte block size)
- Automatic string extraction and categorization (IPs, URLs, registry keys)
- Base64 auto-decoding for suspicious strings
- Overlay / appended data detection
- File hashing: MD5, SHA-1, SHA-256
- CLI JSON export mode (`--json`) for SIEM/SOAR integration
- Cross-platform support (Linux, Windows, macOS)
