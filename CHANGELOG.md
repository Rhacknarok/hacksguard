# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added
- **Direct & Indirect Syscall Detection**: Added static analysis checks using `iced-x86` to scan executable sections for the `syscall`/`sysenter` opcode (direct syscalls) and `mov eax/rax, SSN + jmp/call register` sequences (indirect syscalls).
- **Syscall API Name Resolution**: Added resolution of System Service Numbers (SSNs) to likely NT API names (e.g. `possibly NtProtectVirtualMemory`), marking them as "possibly" since syscall mappings vary by Windows build.
- **TUI Syscall Info Box**: Added a dedicated "System Calls" section inside the PE Headers tab of the TUI to display the detection status of direct and indirect syscall stubs.
- **Critical Severity Alerts**: Trigger Critical-severity alarms when direct or indirect syscall signatures are detected.
- **XML Manifest Extraction**: Implemented manual traversal of the PE resource directory tree (`IMAGE_RESOURCE_DIRECTORY` and `IMAGE_RESOURCE_DATA_ENTRY`) to parse and extract the embedded XML manifest (`RT_MANIFEST`).
- **XML Manifest UI Tab**: Added a dedicated dynamic tab to render the raw XML manifest formatting in the TUI when present.
- **XML Manifest Heuristics & Privilege Checks**: Added detection rules checking for high UAC privilege requests (`requireAdministrator`) and UAC auto-elevation parameters.
- **PDB Path Extraction**: Added extraction of CodeView PDB paths (PDB 2.0 and PDB 7.0 structures) from the PE Debug Directory.
- **PDB Path UI Rendering**: Rendered the extracted PDB path in the TUI general metadata block and the Optional Header section.
- **PDB Path Evasion & Detection Checks**: Added detection rules to check for the presence of a PDB path and trigger a High-severity warning if the path contains suspicious keywords (e.g., malware, exploit, stealer).
- **Nested PE / Overlay Executable Scan**: Implemented generic detection and extraction of embedded PE binaries in raw payloads and overlays, running in a parallel background thread.
- **TUI Embedded PE View Toggle**: Added a toggle button (`e` key) in the TUI to switch dynamic analysis tabs (Headers, Sections, Imports, Disasm) between the parent PE and the extracted embedded PE payload.
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
