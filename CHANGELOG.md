# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added
- **Git Submodules for YARA rules**: Replaced local YARA rules with `elastic/protections-artifacts` and `Neo23x0/signature-base` repositories as git submodules to easily track latest threat intelligence.
- **YARA Rule Caching**: Implemented a binary caching system (`.yara_cache`) using SHA-256 fingerprinting for YARA rules, eliminating re-compilation overhead and significantly speeding up subsequent program executions.
- **TUI Loading Screen**: Added a styled progress bar (`Gauge`) displayed during the background analysis phase instead of blocking standard output.
- **Entropy Graph Enhancements**: Added Y-axis scale (8.0, 4.0, 0.0) and a metadata details panel (global/peak values, peak offset range, warning labels) to the Entropy tab.
- **Dynamic Graph Color Coding**: Sparkline colors now adjust dynamically based on peak entropy severity.
- **TUI Demo Recording**: Replaced static screenshot in README with an animated GIF in assets.
- **Advanced PE Evasion Detection**: Implemented three new high-fidelity detection checks:
  - **IAT Spoofing / Hidden IAT**: Detects executables attempting to hide imports by dynamically loading libraries with minimal/no static imports.
  - **PEB Walking (API Hashing)**: Scans entry point disassembly via `iced-x86` for segment-relative accesses (`FS:[0x30]` or `GS:[0x60]`) to locate the Process Environment Block.
  - **Selective API Obfuscation**: Detects executables referencing sensitive process injection or anti-debugging APIs in strings without importing them statically.

### Fixed
- **Compiler Warnings**: Removed unused `AMBER` color constant in theme.
- **TUI Emoji Rendering**: Replaced heavy cross emoji (`✖`) in Critical verdict banner with an ASCII exclamation mark (`!`) to prevent purple emoji fallback rendering on Windows Terminal.


### Changed
- **Asynchronous YARA Scanning**: Offloaded YARA rule scanning to a background thread, launching the TUI dashboard immediately once basic analysis is complete rather than blocking on the rule engine.
- **TUI YARA Spinner**: Added an animated Unicode braille spinner to the YARA panel in the TUI indicating scan progress in real-time, dynamically updating the global risk score upon scan completion.
- **Optimized YARA Cache Fingerprinting**: Shifted cache verification from full file content hashing to metadata (size, mtime) validation, accelerating startup speed on large rulesets.
- **Jemalloc Integration (Linux)**: Added target-gated `tikv-jemallocator` as the global allocator on Linux to optimize heap performance during YARA scanning.
- **YARA Rules Path**: Modified the core analysis scanner to recursively load YARA signatures from the submodules inside `rules/` directory instead of a single local folder.
- **YARA Matches Risk Override**: Overrode risk score to 100 and level to Critical (displayed as red in UI) if any YARA rule matches.
- **TUI Section Ordering**: Rearranged the dashboard's right column on the Overview tab to display YARA Analysis at the very top.
- **Naming Standard**: Renamed all code and UI guide occurrences of HacksGuard to Hacksguard.
- **Analyst Guide**: Updated in-app documentation to reflect new YARA rule sources.

## [0.2.0] - 2026-07-05

### Changed
- **Performance (Data Parallelism)**: Integrated `rayon` to parallelize internal stages of basic analysis. MD5, SHA-1, SHA-256, byte distribution, and string extraction now all compute concurrently on the same memory-mapped buffer.
- **Performance (Parallel Entropy)**: Shannon entropy sparkline graph is now computed in parallel using `rayon::par_chunks`, utilizing all available CPU cores.
- **Performance (Zero-Copy I/O)**: Replaced `std::fs::read` with `memmap2` for zero-copy file reading. The OS now manages virtual memory paging, allowing all parallel threads to read without loading the entire file into RAM.
- **Threading Optimization**: Decoupled basic analysis and entropy calculation into separate independent threads to maximize parallel execution.
- Completely removed VirusTotal integration, API requirements, and `reqwest` dependency.

## [0.1.0] - 2026-07-03

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
