# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-09

### Added
- **Authenticode DER Certificate Decoding (X.509 & PKCS#7)**:
  - Implemented zero-dependency ASN.1 DER and PKCS#7 `SignedData` parser (`src/analysis/authenticode.rs`) decoding leaf X.509 certificates from the PE Security Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`).
  - Extracted certificate Subject, Issuer, Validity window (parsed from UTCTime / GeneralizedTime), Digest Algorithm (SHA-256, SHA-1, SHA-384, SHA-512, ECDSA), Serial Number, and self-signed verification (`Subject == Issuer`).
  - Added Critical anomaly and detection check for self-signed Authenticode certificates.
  - Rendered certificate details and warnings in both the Overview metadata panel and PE Headers tab.
- **1-Byte XOR Payload Brute-Force Scanner**:
  - Implemented single-pass O(N) 1-byte XOR scanner (`scan_xor_payloads`) targeting overlay regions (with certificate table offset disambiguation) and high-entropy sections ($\ge 6.0$).
  - Detects obfuscated PE binaries (`MZ` header + `e_lfanew` + `PE\0\0` signature), DOS stub strings (`This program cannot be run in DOS mode`), and embedded URLs (`http://`, `https://`).
  - Added Critical anomaly and detection check for XOR-encrypted payloads.
  - Rendered detected XOR keys, target locations, descriptions, and decrypted sample previews in both the Overview dashboard and PE Headers tab.
- **macOS Mach-O & Universal Fat Binary Static Analysis**:
  - Implemented full Mach-O analysis engine (`src/analysis/macho.rs`) parsing single architecture and Universal Fat Mach-O containers (prioritizing ARM64, fallback to x86-64).
  - Added binary mitigation checks: Position-Independent Executable (`MH_PIE`), Non-Executable Stack (`MH_ALLOW_STACK_EXECUTION`), Heap execution restrictions (`MH_NO_HEAP_EXECUTION`), code signature verification (`LC_CODE_SIGNATURE`), and `RPATH` library search path hijacking risks.
  - Added segment and section inspection with Shannon entropy calculation, flagging W+X permissions and high-entropy packed sections.
  - Added Darwin symbol and API classification (`task_for_pid`, `mach_vm_write`, `NSCreateObjectFileImageFromMemory`, `CGEventTapCreate`, `SecKeychainItemCopyAttributesAndData`, `posix_spawn`).
  - Added macOS malware heuristic pattern detection (`Spyware.macOS`, `Stealer.macOS`, `Injector.macOS`).
  - Added dynamic TUI tabs for Mach-O binaries (`Headers`, `Segments`, `Sections`, `Imports`, `Disasm`).
- **Cross-Platform ARM64 Direct Syscall Scanner (`svc`)**:
  - Implemented zero-dependency bitmask scanner for ARM64 `svc #imm` instructions (`(word & 0xFFE0_001F) == 0xD400_0001`), supporting `svc #0` (Linux AArch64) and `svc #0x80` / `svc #0` (macOS Darwin ARM64).
  - Integrated ARM64 syscall detection across both ELF (`EM_AARCH64`) and Mach-O (`CPU_TYPE_ARM64`).
  - Updated TUI disassembly view (`render_disasm`) to display 4-byte instruction words with highlighted syscall stubs on ARM64 architectures without invoking x86 decoders.
- **Interactive Search (`/`)**:
  - Implemented live substring filtering across Strings, Imports, Sections, and ELF Symbols tabs.
  - Added dedicated status bar input prompt (`/query█`), with `Enter` to apply filter and `Esc` to cancel/clear.
- **Strings Category Filters**:
  - Added single-key category toggles in the Strings view: `u` (URLs), `i` (IPs), `r` (Registry keys), `c` (Commands), `s` (Suspicious), `p` (File paths), and `a` (All).
  - Added interactive category filter bar in the Strings tab header displaying active filters and matching counts.
- **OSC 52 Clipboard Copy (`y`)**:
  - Implemented zero-dependency clipboard copying via standard ANSI OSC 52 escape sequences (`\x1b]52;c;...`).
  - Context-aware copying: copies active hashes (SHA-256, Imphash, RichPE) or filtered strings, displaying temporary confirmation toasts.
- **UTF-16LE Wide String Extraction**:
  - Implemented dual-alignment UTF-16LE string scanner detecting wide string sequences alongside standard ASCII.
  - Added automatic overlap detection and trimming between adjacent ASCII and wide strings.
  - Added `W` (wide) and `A` (ascii) visual indicators in the TUI Strings view.
- **Mandiant Imphash**:
  - Implemented standard Mandiant/VirusTotal Imphash MD5 hash computation over import tables (case folding, extension stripping, ordinal normalization).
  - Rendered Imphash in both Overview (Hashes) and PE Headers tabs.
- **Rich PE Header & RichPE Hash**:
  - Implemented bit-exact Rich Header parser with XOR key detection, `DanS` magic verification, and padding validation.
  - Decoded CompID build records with MSVC toolchain identifier mapping (Linker, C/C++ Compiler, MASM, Cvtomf, Resource).
  - Computed standard RichPE header MD5 hash, rendered in Overview and PE Headers tabs.
- **Linux ELF Static Analysis Support**:
  - Implemented full ELF parsing module (`src/analysis/elf.rs`) supporting x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC, and s390x binaries.
  - Added binary hardening & mitigation inspection: Non-Executable stack (`NX` via `PT_GNU_STACK`), Position-Independent Executable (`PIE` via `ET_DYN`), `RELRO` (`None`, `Partial`, `Full`), Stack Canary (`__stack_chk_fail`), Fortified Source, and `RPATH`/`RUNPATH` library hijacking detection.
  - Added section & segment inspection with Shannon entropy calculation, flagging W+X permissions (`PT_LOAD` / sections) and stripped header anomalies.
  - Added dynamic symbol categorization and API risk scoring for Linux APIs (`ptrace`, `memfd_create`, `process_vm_writev`, `init_module`, etc.).
  - Added direct system call opcode scan (`syscall`, `sysenter`, `int 0x80`) via `iced-x86`.
  - Added Linux malware heuristic pattern detection (`Rootkit.Linux`, `Dropper.Fileless.Linux`, `Botnet.IoT.Linux`).
  - Added dynamic TUI tabs for ELF binaries (`Headers`, `Segments`, `Sections`, `Imports`, `Disasm`) and integrated metadata into the Overview dashboard.

### Changed
- **Dependency Elimination**:
  - Removed `color-eyre = "0.6"` and ~15 transitive crates (`eyre`, `indenter`, `owo-colors`, `tracing-error`, etc.) in favor of standard library `std::error::Error`.
- **Codebase Simplification & Performance (Ponytail Audit)**:
  - Deduplicated detection check construction (simplified 40+ verbose instantiations via helper) and unified scoring loops for `ApiRisk` and `Anomaly` across PE, ELF, and Mach-O formats (-330 LOC).
  - Replaced multiple passes over file bytes with single-pass byte frequency distribution, deriving Shannon entropy directly from frequency tables.
  - Flattened TUI module layout (`src/tui/ui.rs` moved to `src/ui.rs`, removed redundant `src/tui/mod.rs`).
  - Unified PE, ELF, and Mach-O disassembly rendering into a single shared helper (`draw_binary_disasm`).
  - Merged duplicate ELF/Mach-O tab dispatch branches in `src/app.rs`.
  - Simplified TUI initialization and restoration to standard `ratatui::init` / `ratatui::restore`.
  - Replaced custom endian reading functions with native stdlib slice conversions (`try_into`).

### Fixed
- **Cross-Platform YARA Cache & Path Resolution**: Fixed `.yara_cache` loading failures on non-Windows platforms:
  - Normalized rule file path separators to `/` across OSes during SHA-256 fingerprint generation.
  - Hashed rule file content and size instead of unstable filesystem timestamps (`mtime`).
  - Added fallback path resolution to `current_exe().parent()` when running the binary outside the repository root directory.

## [0.3.0] - 2026-07-10

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
