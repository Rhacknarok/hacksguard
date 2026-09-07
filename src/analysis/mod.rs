pub mod basic;
pub mod pe;
pub mod elf;

use crate::models::*;
use color_eyre::Result;
use std::path::Path;

/// Run the full analysis pipeline on a file.
pub fn analyze_file(path: &Path, progress_tx: Option<std::sync::mpsc::Sender<()>>, run_yara: bool) -> Result<AnalysisResult> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
    let data = &mmap[..];

    let magic: Vec<u8> = data.iter().take(16).copied().collect();
    let file_type = detect_type(&magic);

    let file_info = FileInfo {
        path: path.to_path_buf(),
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into()),
        size: data.len() as u64,
        file_type: file_type.clone(),
        magic_bytes: magic,
    };

    let data_ref = &data;
    let (basic_result, entropy_graph, pe_result, elf_result, yara_matches) = std::thread::scope(|s| {
        let tx1 = progress_tx.clone();
        let basic_handle = s.spawn(move || {
            let res = basic::analyze(data_ref);
            if let Some(tx) = &tx1 { let _ = tx.send(()); }
            res
        });
        
        let tx2 = progress_tx.clone();
        let entropy_handle = s.spawn(move || {
            let res = compute_entropy_graph(data_ref, 64);
            if let Some(tx) = &tx2 { let _ = tx.send(()); }
            res
        });

        let tx3 = progress_tx.clone();
        let binary_handle = s.spawn(move || {
            let (pe, elf) = match file_type {
                FileType::PE => (pe::analyze(data_ref).ok(), None),
                FileType::ELF => (None, elf::analyze(data_ref).ok()),
                _ => (None, None),
            };
            if let Some(tx) = &tx3 { let _ = tx.send(()); }
            (pe, elf)
        });

        let yara_handle = if run_yara {
            let tx4 = progress_tx.clone();
            Some(s.spawn(move || {
                let res = load_or_compile_yara(data_ref);
                if let Some(tx) = &tx4 { let _ = tx.send(()); }
                res
            }))
        } else {
            None
        };

        let basic = basic_handle.join().unwrap();
        let entropy = entropy_handle.join().unwrap();
        let (pe, elf) = binary_handle.join().unwrap();
        let yara = if let Some(h) = yara_handle {
            h.join().unwrap()
        } else {
            Vec::new()
        };

        (basic, entropy, pe, elf, yara)
    });

    let mut pe_result = pe_result;
    if let Some(ref mut pe) = pe_result {
        let has_dyn_loading = pe.imports.iter().any(|dll| {
            dll.functions.iter().any(|f| {
                let name = f.name.to_lowercase();
                name.contains("loadlibrary") || name.contains("getprocaddress") || name.contains("ldrloaddll")
            })
        });

        let mut peb_walking = false;
        let mut api_hashing = false;
        let mut direct_syscalls = false;
        let mut indirect_syscalls = false;
        let mut syscall_locations = Vec::new();

        let bitness = if pe.is_64bit { 64 } else { 32 };

        for section in &pe.sections {
            if section.is_executable && section.raw_size > 0 {
                let start = section.raw_offset as usize;
                let end = (start + section.raw_size as usize).min(data.len());
                if start < end {
                    let section_data = &data[start..end];
                    let (sec_peb, sec_hashing, sec_direct, sec_indirect, sec_locations) = scan_peb_and_hashing(bitness, section_data, section.virtual_address);
                    if sec_peb {
                        peb_walking = true;
                    }
                    if sec_hashing {
                        api_hashing = true;
                    }
                    if sec_direct {
                        direct_syscalls = true;
                    }
                    if sec_indirect {
                        indirect_syscalls = true;
                    }
                    syscall_locations.extend(sec_locations);
                }
            }
        }

        pe.peb_walking = peb_walking;
        pe.api_hashing = api_hashing;
        pe.direct_syscalls = direct_syscalls;
        pe.indirect_syscalls = indirect_syscalls;
        pe.syscall_locations = syscall_locations;

        if has_dyn_loading || pe.peb_walking || pe.api_hashing {
            let sensitive_apis = [
                "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext",
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
            ];

            let imported_apis: std::collections::HashSet<String> = pe.imports.iter()
                .flat_map(|dll| dll.functions.iter().map(|f| f.name.to_lowercase()))
                .collect();

            let mut obfuscated = Vec::new();
            for &api in &sensitive_apis {
                let api_lower = api.to_lowercase();
                if imported_apis.contains(&api_lower) {
                    continue;
                }
                let in_strings = basic_result.strings.iter().any(|s| {
                    s.value.to_lowercase().contains(&api_lower) || 
                    s.decoded.as_ref().map_or(false, |d| d.to_lowercase().contains(&api_lower))
                });
                if in_strings {
                    obfuscated.push(api.to_string());
                }
            }
            pe.obfuscated_apis = obfuscated;
        }
    }

    let detection_checks = build_detection_checks(&basic_result, &pe_result, &elf_result, file_info.size);
    let (risk_score, risk_level) = compute_risk_from_checks(&detection_checks, &yara_matches);
    let risk_breakdown = compute_risk_breakdown(&basic_result, &pe_result, &elf_result);
    let malware_pattern = detect_malware_pattern(&basic_result, &pe_result, &elf_result);

    Ok(AnalysisResult {
        file_info,
        basic: basic_result,
        pe: pe_result,
        elf: elf_result,
        risk_score,
        risk_level,
        risk_breakdown,
        detection_checks,
        malware_pattern,
        yara_matches,
        entropy_graph,
    })
}

fn compute_entropy_graph(data: &[u8], num_chunks: usize) -> Vec<u64> {
    if data.is_empty() {
        return vec![0; num_chunks];
    }
    let chunk_size = (data.len() + num_chunks - 1) / num_chunks;
    
    use rayon::prelude::*;
    let mut graph: Vec<u64> = data.par_chunks(chunk_size)
        .map(|chunk| {
            let entropy = basic::shannon_entropy(chunk);
            // Scale 0.0-8.0 to 0-800 for better visual resolution
            (entropy * 100.0) as u64
        })
        .collect();
    
    while graph.len() < num_chunks {
        graph.push(0);
    }
    graph
}

// ─── File type detection via magic bytes ─────────────────────────

// ─── YARA persistent cache ───────────────────────────────────────

const YARA_CACHE_PATH: &str = ".yara_cache";

fn resolve_app_path(name: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(name);
    if p.exists() {
        return p.to_path_buf();
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| p.to_path_buf())
}

fn visit_dirs(dir: &std::path::Path, paths: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, paths);
            } else if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                paths.push(path);
            }
        }
    }
}

/// Compute a SHA-256 fingerprint over all rule file paths + their contents.
/// Any change in file names, order, or content will invalidate the cache.
fn compute_rules_fingerprint(rules_dir: &std::path::Path) -> Vec<u8> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    let mut paths: Vec<std::path::PathBuf> = Vec::new();

    visit_dirs(rules_dir, &mut paths);
    // Sort for deterministic ordering
    paths.sort();

    for path in &paths {
        let rel_path = path.strip_prefix(rules_dir).unwrap_or(path);
        let normalized = rel_path.to_string_lossy().replace('\\', "/");
        hasher.update(normalized.as_bytes());

        if let Ok(content) = std::fs::read(path) {
            hasher.update(&(content.len() as u64).to_le_bytes());
            hasher.update(&content);
        }
    }

    hasher.finalize().to_vec()
}

/// Load a cached YARA Scanner from disk, or compile from source rules and cache.
///
/// Cache format: [32 bytes fingerprint][boreal-serialized Scanner]
pub fn load_or_compile_yara(data: &[u8]) -> Vec<String> {
    let rules_dir = resolve_app_path("rules");
    let cache_path = resolve_app_path(YARA_CACHE_PATH);
    let fingerprint = compute_rules_fingerprint(&rules_dir);

    // Try loading from cache
    if let Ok(cache_bytes) = std::fs::read(&cache_path) {
        if cache_bytes.len() > 32 && cache_bytes[..32] == fingerprint[..] {
            let params = boreal::scanner::DeserializeParams::default();
            if let Ok(scanner) = boreal::scanner::Scanner::from_bytes_unchecked(&cache_bytes[32..], params) {
                let res = match scanner.scan_mem(data) {
                    Ok(res) => res,
                    Err((_, res)) => res,
                };
                return res.rules.iter().map(|r| r.name.to_string()).collect();
            }
        }
    }

    // Cache miss or invalid → recompile
    let mut compiler = boreal::Compiler::new();
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    visit_dirs(&rules_dir, &mut paths);
    paths.sort();
    for path in &paths {
        let _ = compiler.add_rules_file(path);
    }
    let scanner = compiler.finalize();

    // Save cache
    let mut serialized = Vec::new();
    if scanner.to_bytes(&mut serialized).is_ok() {
        let mut cache = Vec::with_capacity(32 + serialized.len());
        cache.extend_from_slice(&fingerprint);
        cache.extend_from_slice(&serialized);
        let _ = std::fs::write(&cache_path, &cache);
    }

    let res = match scanner.scan_mem(data) {
        Ok(res) => res,
        Err((_, res)) => res,
    };
    res.rules.iter().map(|r| r.name.to_string()).collect()
}

fn detect_type(magic: &[u8]) -> FileType {
    if magic.len() >= 2 && magic[0] == 0x4D && magic[1] == 0x5A {
        FileType::PE
    } else if magic.len() >= 4 && magic[0..4] == [0x7F, b'E', b'L', b'F'] {
        FileType::ELF
    } else if magic.len() >= 4
        && ((magic[0..4] == [0xFE, 0xED, 0xFA, 0xCE])
            || (magic[0..4] == [0xFE, 0xED, 0xFA, 0xCF])
            || (magic[0..4] == [0xCE, 0xFA, 0xED, 0xFE])
            || (magic[0..4] == [0xCF, 0xFA, 0xED, 0xFE]))
    {
        FileType::MachO
    } else {
        FileType::Unknown
    }
}

// ─── Risk scoring ────────────────────────────────────────────────

pub fn compute_risk_from_checks(checks: &[DetectionCheck], yara_matches: &[String]) -> (u32, RiskLevel) {
    let mut score = 0;
    
    // Add points for triggered checks
    for check in checks {
        if check.triggered {
            match check.severity {
                DetectionSeverity::Critical => score += 35,
                DetectionSeverity::High => score += 20,
                DetectionSeverity::Medium => score += 10,
                DetectionSeverity::Low => score += 5,
                DetectionSeverity::Info => {}
            }
        }
    }
    
    // Add points for YARA matches
    for rule in yara_matches {
        match yara_severity(rule) {
            DetectionSeverity::Critical => {
                score = 100;
            }
            DetectionSeverity::High => {
                score += 40;
            }
            DetectionSeverity::Medium => {
                score += 20;
            }
            _ => {
                score += 10;
            }
        }
    }
    
    let score = score.min(100);
    let level = match score {
        0..=20 => RiskLevel::Clean,
        21..=40 => RiskLevel::Low,
        41..=60 => RiskLevel::Medium,
        61..=80 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };
    
    (score, level)
}

fn compute_risk_breakdown(basic: &BasicAnalysis, pe: &Option<PeAnalysis>, elf: &Option<ElfAnalysis>) -> RiskBreakdown {
    let entropy_score = if basic.entropy > 7.5 {
        25
    } else if basic.entropy > 7.0 {
        15
    } else if basic.entropy > 6.5 {
        5
    } else {
        0
    };

    let is_packed = basic.is_packed || pe.as_ref().map_or(false, |p| p.packer_detected.is_some()) || elf.as_ref().map_or(false, |e| e.packer_detected.is_some());
    let packing_score = if is_packed { 15 } else { 0 };

    let sus = basic
        .strings
        .iter()
        .filter(|s| !matches!(s.category, StringCategory::Normal))
        .count() as u32;
    let string_score = sus.min(15);

    let mut api_score: u32 = 0;
    let mut anomaly_score: u32 = 0;

    if let Some(pe) = pe {
        for dll in &pe.imports {
            for func in &dll.functions {
                match func.risk {
                    ApiRisk::Critical => api_score += 8,
                    ApiRisk::High => api_score += 4,
                    ApiRisk::Medium => api_score += 1,
                    _ => {}
                }
            }
        }
        for a in &pe.anomalies {
            match a.severity {
                AnomalySeverity::Critical => anomaly_score += 12,
                AnomalySeverity::Warning => anomaly_score += 4,
                AnomalySeverity::Info => {}
            }
        }
    } else if let Some(elf) = elf {
        for func in &elf.imported_symbols {
            match func.risk {
                ApiRisk::Critical => api_score += 8,
                ApiRisk::High => api_score += 4,
                ApiRisk::Medium => api_score += 1,
                _ => {}
            }
        }
        for a in &elf.anomalies {
            match a.severity {
                AnomalySeverity::Critical => anomaly_score += 12,
                AnomalySeverity::Warning => anomaly_score += 4,
                AnomalySeverity::Info => {}
            }
        }
    }

    RiskBreakdown {
        entropy_score,
        api_score: api_score.min(25),
        anomaly_score: anomaly_score.min(25),
        string_score,
        packing_score,
    }
}

// ─── Detection checks ───────────────────────────────────────────

fn has_imported_api(pe: &Option<PeAnalysis>, elf: &Option<ElfAnalysis>, names: &[&str]) -> bool {
    if let Some(pe) = pe {
        if pe.imports.iter().any(|dll| {
            dll.functions.iter().any(|f| {
                names.iter().any(|n| f.name.eq_ignore_ascii_case(n))
            })
        }) {
            return true;
        }
    }
    if let Some(elf) = elf {
        if elf.imported_symbols.iter().any(|f| {
            names.iter().any(|n| f.name.eq_ignore_ascii_case(n))
        }) {
            return true;
        }
    }
    false
}

fn has_all_imported_apis(pe: &Option<PeAnalysis>, elf: &Option<ElfAnalysis>, names: &[&str]) -> bool {
    if let Some(pe) = pe {
        names.iter().all(|name| {
            pe.imports.iter().any(|dll| {
                dll.functions.iter().any(|f| f.name.eq_ignore_ascii_case(name))
            })
        })
    } else if let Some(elf) = elf {
        names.iter().all(|name| {
            elf.imported_symbols.iter().any(|f| f.name.eq_ignore_ascii_case(name))
        })
    } else {
        false
    }
}

fn build_detection_checks(basic: &BasicAnalysis, pe: &Option<PeAnalysis>, elf: &Option<ElfAnalysis>, file_size: u64) -> Vec<DetectionCheck> {
    let mut checks = Vec::with_capacity(35);

    let has_category = |cat: &StringCategory| basic.strings.iter().any(|s| &s.category == cat);
    let has_non_normal = basic
        .strings
        .iter()
        .any(|s| !matches!(s.category, StringCategory::Normal));

    let has_api = |names: &[&str]| has_imported_api(pe, elf, names);
    let has_all_apis = |names: &[&str]| has_all_imported_apis(pe, elf, names);

    // 1. High entropy (>7.0)
    checks.push(DetectionCheck {
        name: "High entropy (>7.0)".into(),
        triggered: basic.entropy > 7.0,
        severity: DetectionSeverity::High,
    });

    // 2. Very high entropy (>7.5)
    checks.push(DetectionCheck {
        name: "Very high entropy (>7.5)".into(),
        triggered: basic.entropy > 7.5,
        severity: DetectionSeverity::High,
    });

    // 3. Packed binary
    checks.push(DetectionCheck {
        name: "Packed binary".into(),
        triggered: basic.is_packed,
        severity: DetectionSeverity::High,
    });

    // 4. Suspicious strings found
    checks.push(DetectionCheck {
        name: "Suspicious strings found".into(),
        triggered: has_non_normal,
        severity: DetectionSeverity::Low,
    });

    // 5. URLs in strings
    checks.push(DetectionCheck {
        name: "URLs in strings".into(),
        triggered: has_category(&StringCategory::Url),
        severity: DetectionSeverity::Medium,
    });

    // 6. IP addresses in strings
    checks.push(DetectionCheck {
        name: "IP addresses in strings".into(),
        triggered: has_category(&StringCategory::IpAddress),
        severity: DetectionSeverity::Medium,
    });

    // 7. Commands in strings
    checks.push(DetectionCheck {
        name: "Commands in strings".into(),
        triggered: has_category(&StringCategory::Command),
        severity: DetectionSeverity::Medium,
    });

    // 8. Registry keys in strings
    checks.push(DetectionCheck {
        name: "Registry keys in strings".into(),
        triggered: has_category(&StringCategory::RegistryKey),
        severity: DetectionSeverity::Low,
    });

    // 9. Suspicious keywords
    checks.push(DetectionCheck {
        name: "Suspicious keywords".into(),
        triggered: has_category(&StringCategory::Suspicious),
        severity: DetectionSeverity::Low,
    });

    // 10. Process injection APIs
    let process_injection = has_all_apis(&[
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]);
    checks.push(DetectionCheck {
        name: "Process injection APIs".into(),
        triggered: process_injection,
        severity: DetectionSeverity::Critical,
    });

    // 11. Anti-debug APIs
    let anti_debug = has_api(&[
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
    ]);
    checks.push(DetectionCheck {
        name: "Anti-debug APIs".into(),
        triggered: anti_debug,
        severity: DetectionSeverity::High,
    });

    // 12. Network APIs
    let network_apis = has_api(&[
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "WSAStartup",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
    ]);
    checks.push(DetectionCheck {
        name: "Network APIs".into(),
        triggered: network_apis,
        severity: DetectionSeverity::Medium,
    });

    // 13. Crypto APIs
    let crypto_apis = has_api(&[
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptGenKey",
    ]);
    checks.push(DetectionCheck {
        name: "Crypto APIs".into(),
        triggered: crypto_apis,
        severity: DetectionSeverity::Medium,
    });

    // 14. Service manipulation APIs
    let service_apis = has_api(&[
        "CreateServiceA",
        "CreateServiceW",
        "OpenServiceA",
        "OpenServiceW",
        "StartServiceA",
        "StartServiceW",
        "ChangeServiceConfigA",
        "ChangeServiceConfigW",
    ]);
    checks.push(DetectionCheck {
        name: "Service manipulation APIs".into(),
        triggered: service_apis,
        severity: DetectionSeverity::Low,
    });

    // PE-specific checks
    let wx_section = pe
        .as_ref()
        .map(|p| p.sections.iter().any(|s| s.is_writable && s.is_executable))
        .unwrap_or(false);

    let high_entropy_section = pe
        .as_ref()
        .map(|p| p.sections.iter().any(|s| s.entropy > 7.0))
        .unwrap_or(false);

    let suspicious_section_name = pe
        .as_ref()
        .map(|p| {
            let bad_names = [".upx", ".themida", ".vmp", ".aspack", ".nsp", ".enigma"];
            p.sections
                .iter()
                .any(|s| bad_names.iter().any(|b| s.name.to_lowercase().starts_with(b)))
        })
        .unwrap_or(false);

    let zeroed_timestamp = pe.as_ref().map(|p| p.timestamp == 0).unwrap_or(false);

    let future_timestamp = pe
        .as_ref()
        .map(|p| p.timestamp_suspicious && p.timestamp > 0)
        .unwrap_or(false);

    let no_imports = pe
        .as_ref()
        .map(|p| p.imports.is_empty())
        .unwrap_or(false);

    let entry_point_anomaly = pe
        .as_ref()
        .map(|p| {
            if let Some(first) = p.sections.first() {
                let section_end = first.virtual_size;
                p.entry_point > p.image_base + section_end
            } else {
                false
            }
        })
        .unwrap_or(false);

    let packer_detected = pe
        .as_ref()
        .map(|p| p.packer_detected.is_some())
        .unwrap_or(false);

    // 15. W+X section
    checks.push(DetectionCheck {
        name: "W+X section".into(),
        triggered: wx_section,
        severity: DetectionSeverity::Critical,
    });

    // 16. High entropy section
    checks.push(DetectionCheck {
        name: "High entropy section".into(),
        triggered: high_entropy_section,
        severity: DetectionSeverity::High,
    });

    // 17. Suspicious section name
    checks.push(DetectionCheck {
        name: "Suspicious section name".into(),
        triggered: suspicious_section_name,
        severity: DetectionSeverity::High,
    });

    // 18. Zeroed timestamp
    checks.push(DetectionCheck {
        name: "Zeroed timestamp".into(),
        triggered: zeroed_timestamp,
        severity: DetectionSeverity::Low,
    });

    // 19. Future timestamp
    checks.push(DetectionCheck {
        name: "Future timestamp".into(),
        triggered: future_timestamp,
        severity: DetectionSeverity::Low,
    });

    // 20. No imports
    checks.push(DetectionCheck {
        name: "No imports".into(),
        triggered: no_imports,
        severity: DetectionSeverity::Info,
    });

    // 21. Entry point anomaly
    checks.push(DetectionCheck {
        name: "Entry point anomaly".into(),
        triggered: entry_point_anomaly,
        severity: DetectionSeverity::Low,
    });

    // 22. Known packer detected
    checks.push(DetectionCheck {
        name: "Known packer detected".into(),
        triggered: packer_detected,
        severity: DetectionSeverity::High,
    });

    // 23. File paths in strings
    checks.push(DetectionCheck {
        name: "File paths in strings".into(),
        triggered: has_category(&StringCategory::FilePath),
        severity: DetectionSeverity::Info,
    });

    // 24. IAT Spoofing / Hidden IAT
    let iat_spoofing = pe.as_ref().map(|p| {
        let total_imports: usize = p.imports.iter().map(|dll| dll.functions.len()).sum();
        let has_dyn_loading = p.imports.iter().any(|dll| {
            dll.functions.iter().any(|f| {
                let name = f.name.to_lowercase();
                name.contains("loadlibrary") || name.contains("getprocaddress") || name.contains("ldrloaddll") || name.contains("ldrgetprocedureaddress")
            })
        });
        
        let is_suspicious_no_imports = total_imports == 0 && file_size > 15360;
        let is_suspicious_dyn_loading = total_imports > 0 && total_imports <= 5 && has_dyn_loading && file_size > 15360;
        
        is_suspicious_no_imports || is_suspicious_dyn_loading
    }).unwrap_or(false);

    checks.push(DetectionCheck {
        name: "IAT Spoofing / Hidden IAT".into(),
        triggered: iat_spoofing,
        severity: DetectionSeverity::High,
    });

    // 25. PEB Walking (API Hashing)
    let peb_walking = pe.as_ref().map(|p| p.peb_walking).unwrap_or(false);

    checks.push(DetectionCheck {
        name: "PEB Walking (API Hashing)".into(),
        triggered: peb_walking,
        severity: DetectionSeverity::High,
    });

    // API Hashing loop detected
    let api_hashing = pe.as_ref().map(|p| p.api_hashing).unwrap_or(false);

    checks.push(DetectionCheck {
        name: "API Hashing loop detected".into(),
        triggered: api_hashing,
        severity: DetectionSeverity::High,
    });

    // 26. Selective API Obfuscation
    let selective_api_obfuscation = pe.as_ref().map_or(false, |p| !p.obfuscated_apis.is_empty());

    checks.push(DetectionCheck {
        name: "Selective API Obfuscation".into(),
        triggered: selective_api_obfuscation,
        severity: DetectionSeverity::High,
    });

    let has_pdb = pe.as_ref().map(|p| p.pdb_path.is_some()).unwrap_or(false);
    checks.push(DetectionCheck {
        name: "PDB path found".into(),
        triggered: has_pdb,
        severity: DetectionSeverity::Info,
    });

    let pdb_suspicious = pe.as_ref().map(|p| {
        if let Some(ref path) = p.pdb_path {
            let path_lower = path.to_lowercase();
            ["malware", "trojan", "exploit", "hack", "stealer", "bypass", "inject"].iter().any(|&k| path_lower.contains(k))
        } else {
            false
        }
    }).unwrap_or(false);

    checks.push(DetectionCheck {
        name: "Suspicious PDB path".into(),
        triggered: pdb_suspicious,
        severity: DetectionSeverity::High,
    });

    let (manifest_admin, manifest_autoelevate) = pe.as_ref().map(|p| {
        if let Some(ref m) = p.manifest {
            let m_lower = m.to_lowercase();
            let admin = m_lower.contains("requireadministrator");
            let autoelevate = m_lower.contains("autoelevate") && m_lower.contains("true");
            (admin, autoelevate)
        } else {
            (false, false)
        }
    }).unwrap_or((false, false));

    checks.push(DetectionCheck {
        name: "Admin privileges requested (Manifest)".into(),
        triggered: manifest_admin,
        severity: DetectionSeverity::Medium,
    });

    checks.push(DetectionCheck {
        name: "UAC AutoElevate requested (Manifest)".into(),
        triggered: manifest_autoelevate,
        severity: DetectionSeverity::High,
    });

    let direct_sys = pe.as_ref().map(|p| p.direct_syscalls).unwrap_or(false);
    checks.push(DetectionCheck {
        name: "Direct Syscalls Detected".into(),
        triggered: direct_sys,
        severity: DetectionSeverity::Critical,
    });

    let indirect_sys = pe.as_ref().map(|p| p.indirect_syscalls).unwrap_or(false);
    checks.push(DetectionCheck {
        name: "Indirect Syscalls Detected".into(),
        triggered: indirect_sys,
        severity: DetectionSeverity::Critical,
    });

    // 34. Stealth C2 Agent Profile (Evasive Loading / API Hashing)
    let stealth_c2 = pe.as_ref().map(|p| {
        let has_evasive_calls = p.api_hashing || p.peb_walking || p.direct_syscalls || p.indirect_syscalls;
        let total_imports: usize = p.imports.iter().map(|dll| dll.functions.len()).sum();
        has_evasive_calls && (total_imports <= 35 || p.imports.len() <= 3)
    }).unwrap_or(false);

    checks.push(DetectionCheck {
        name: "Stealth C2 Agent Profile (Evasive Loading + Sparse IAT)".into(),
        triggered: stealth_c2,
        severity: DetectionSeverity::Critical,
    });

    // ─── ELF-Specific Detection Checks ───
    if let Some(elf) = elf {
        let has_wx_ph = elf.program_headers.iter().any(|ph| ph.is_write && ph.is_exec);
        let has_wx_sh = elf.sections.iter().any(|s| s.is_writable && s.is_executable);
        checks.push(DetectionCheck {
            name: "W+X Segment / Section (ELF)".into(),
            triggered: has_wx_ph || has_wx_sh,
            severity: DetectionSeverity::Critical,
        });

        checks.push(DetectionCheck {
            name: "Executable Stack (NX Disabled)".into(),
            triggered: !elf.mitigations.nx,
            severity: DetectionSeverity::High,
        });

        let fileless_exec = has_api(&["memfd_create"]) && (has_api(&["fexecve", "execveat"]) || has_category(&StringCategory::Command));
        checks.push(DetectionCheck {
            name: "Fileless execution (memfd_create)".into(),
            triggered: fileless_exec,
            severity: DetectionSeverity::Critical,
        });

        let linux_injection = has_api(&["ptrace", "process_vm_writev"]);
        checks.push(DetectionCheck {
            name: "Linux process injection (ptrace)".into(),
            triggered: linux_injection,
            severity: DetectionSeverity::Critical,
        });

        checks.push(DetectionCheck {
            name: "Direct Syscalls (ELF)".into(),
            triggered: elf.direct_syscalls,
            severity: DetectionSeverity::Critical,
        });

        checks.push(DetectionCheck {
            name: "Kernel module manipulation".into(),
            triggered: has_api(&["init_module", "finit_module", "delete_module", "kexec_load"]),
            severity: DetectionSeverity::Critical,
        });

        checks.push(DetectionCheck {
            name: "Known packer detected".into(),
            triggered: elf.packer_detected.is_some(),
            severity: DetectionSeverity::High,
        });
    }

    checks
}

// ─── Malware pattern matching ────────────────────────────────────

fn detect_malware_pattern(
    basic: &BasicAnalysis,
    pe: &Option<PeAnalysis>,
    elf: &Option<ElfAnalysis>,
) -> Option<MalwarePattern> {
    let has_api = |names: &[&str]| has_imported_api(pe, elf, names);
    let has_all_apis = |names: &[&str]| has_all_imported_apis(pe, elf, names);

    let has_category = |cat: &StringCategory| basic.strings.iter().any(|s| &s.category == cat);

    let has_string_containing = |needles: &[&str]| -> bool {
        basic.strings.iter().any(|s| {
            let lower = s.value.to_lowercase();
            needles.iter().any(|n| lower.contains(n))
        })
    };

    let network_apis = has_api(&[
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "WSAStartup",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "sendto",
        "recvfrom",
    ]);

    let process_injection = has_all_apis(&[
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]) || has_api(&["ptrace", "process_vm_writev"]);

    let crypto_apis = has_api(&[
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
    ]);

    let anti_debug = has_api(&[
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ptrace",
    ]);

    let service_apis = has_api(&[
        "CreateServiceA",
        "CreateServiceW",
        "OpenServiceA",
        "OpenServiceW",
    ]);

    // ─── Linux-specific Malware Patterns ───
    if let Some(elf_info) = elf {
        // Linux.Rootkit
        let rootkit_apis = has_api(&["init_module", "finit_module", "kexec_load", "bpf"]);
        let preload_strings = has_string_containing(&["ld.so.preload", "/etc/ld.so.preload"]);
        if rootkit_apis || preload_strings {
            return Some(MalwarePattern {
                family: "Rootkit.Linux".into(),
                confidence: "High".into(),
                description: "Kernel module loading or dynamic linker preload hijacking detected".into(),
                matched_indicators: vec![
                    if rootkit_apis { "Kernel module API (init_module/kexec/bpf)".into() } else { "ld.so.preload path reference".into() },
                ],
            });
        }

        // Linux.FilelessDropper
        if has_api(&["memfd_create"]) && (has_api(&["fexecve", "execveat", "execve"]) || network_apis) {
            return Some(MalwarePattern {
                family: "Dropper.Fileless.Linux".into(),
                confidence: "High".into(),
                description: "In-memory fileless binary execution via memfd_create and fexecve".into(),
                matched_indicators: vec![
                    "memfd_create API import".into(),
                    "Execution/Network primitives".into(),
                ],
            });
        }

        // Linux.Botnet (Mirai / Gafgyt / Tsunami family)
        let botnet_strings = has_string_containing(&["/bin/busybox", "telnet", "wget", "tftp", "iptables -F", "/proc/net/tcp"]);
        let is_embedded_arch = elf_info.machine == "ARM" || elf_info.machine == "MIPS" || elf_info.machine == "RISC-V";
        if network_apis && (botnet_strings || is_embedded_arch) {
            return Some(MalwarePattern {
                family: "Botnet.IoT.Linux".into(),
                confidence: if botnet_strings && is_embedded_arch { "High" } else { "Medium" }.into(),
                description: "IoT/Linux botnet signatures (network primitives, busybox/telnet payload strings or embedded architecture)".into(),
                matched_indicators: vec![
                    "Network socket APIs".into(),
                    format!("Architecture: {}", elf_info.machine),
                ],
            });
        }
    }

    // 1. Trojan.Injector — process injection + network (High)
    if process_injection && network_apis {
        return Some(MalwarePattern {
            family: "Trojan.Injector".into(),
            confidence: "High".into(),
            description: "Process injection combined with network communication capabilities"
                .into(),
            matched_indicators: vec![
                "Process injection APIs (VirtualAllocEx / ptrace)".into(),
                "Network API imports".into(),
            ],
        });
    }

    // 2. Ransomware.Generic — crypto + ransom strings (Medium)
    let ransom_strings =
        has_string_containing(&["ransom", "bitcoin", "wallet", "encrypt", "decrypt", ".onion"]);
    if crypto_apis && ransom_strings {
        return Some(MalwarePattern {
            family: "Ransomware.Generic".into(),
            confidence: "Medium".into(),
            description: "Cryptographic APIs paired with ransom-related strings".into(),
            matched_indicators: vec![
                "Crypto API imports".into(),
                "Ransom/cryptocurrency-related strings".into(),
            ],
        });
    }

    // 3. Packed.Evasive — anti-debug + packed + high entropy (Medium)
    if anti_debug && basic.is_packed && basic.entropy > 7.0 {
        return Some(MalwarePattern {
            family: "Packed.Evasive".into(),
            confidence: "Medium".into(),
            description: "Packed binary with anti-debugging and high entropy suggesting evasion"
                .into(),
            matched_indicators: vec![
                "Anti-debug API imports".into(),
                "Binary packing detected".into(),
                format!("High entropy: {:.2}", basic.entropy),
            ],
        });
    }

    // 4. Trojan.Downloader — network + commands + URLs (Medium)
    let has_commands = has_category(&StringCategory::Command);
    let has_urls = has_category(&StringCategory::Url);
    if network_apis && has_commands && has_urls {
        return Some(MalwarePattern {
            family: "Trojan.Downloader".into(),
            confidence: "Medium".into(),
            description: "Network APIs with command execution and URL references".into(),
            matched_indicators: vec![
                "Network API imports".into(),
                "Command strings found".into(),
                "URLs found in strings".into(),
            ],
        });
    }

    // 5. Spyware.Keylogger — keylog string + network (Low)
    let keylog_strings = has_string_containing(&["keylog", "getasynckeystate", "keystroke"]);
    if keylog_strings && network_apis {
        return Some(MalwarePattern {
            family: "Spyware.Keylogger".into(),
            confidence: "Low".into(),
            description: "Keylogging indicators with network exfiltration capability".into(),
            matched_indicators: vec![
                "Keylogger-related strings".into(),
                "Network API imports".into(),
            ],
        });
    }

    // 6. Trojan.Persistence — service + registry + auto-run (Medium)
    let has_registry = has_category(&StringCategory::RegistryKey);
    let autorun_strings = has_string_containing(&[
        "currentversion\\run",
        "currentversion\\runonce",
        "software\\microsoft\\windows\\currentversion\\run",
    ]);
    if service_apis && has_registry && autorun_strings {
        return Some(MalwarePattern {
            family: "Trojan.Persistence".into(),
            confidence: "Medium".into(),
            description: "Service manipulation with registry auto-run persistence mechanisms"
                .into(),
            matched_indicators: vec![
                "Service manipulation API imports".into(),
                "Registry key references".into(),
                "Auto-run registry paths".into(),
            ],
        });
    }

    // 7. Trojan.C2Agent — API hashing / dynamic resolution with hidden/sparse imports (High)
    if let Some(pe) = pe {
        let total_imports: usize = pe.imports.iter().map(|dll| dll.functions.len()).sum();
        let is_sparse_imports = total_imports <= 35 || pe.imports.len() <= 3;
        let has_stealth_loading = pe.api_hashing || pe.peb_walking || pe.direct_syscalls || pe.indirect_syscalls;

        if has_stealth_loading && is_sparse_imports {
            let mut indicators = Vec::new();
            if pe.api_hashing {
                indicators.push("API Hashing loop detected (dynamic export resolution)".into());
            }
            if pe.peb_walking {
                indicators.push("PEB Walking detected (FS/GS segment access)".into());
            }
            if pe.direct_syscalls || pe.indirect_syscalls {
                indicators.push("Custom Syscall stubs detected".into());
            }
            indicators.push(format!("Sparse/hidden import table ({} imported APIs across {} DLLs)", total_imports, pe.imports.len()));

            return Some(MalwarePattern {
                family: "Trojan.C2Agent".into(),
                confidence: "High".into(),
                description: "Stealth implant / C2 agent utilizing API hashing or evasive system calls with minimal import table footprint".into(),
                matched_indicators: indicators,
            });
        }
    }

    None
}

fn yara_severity(rule_name: &str) -> DetectionSeverity {
    let lower = rule_name.to_lowercase();
    let critical_keywords = ["malware", "trojan", "backdoor", "ransomware", "exploit", "keylogger", "stealer", "apt", "webshell", "rootkit", "bypass"];
    let high_keywords = ["hacktool", "agent", "rat", "bot", "injector", "execution", "defense_evasion", "credential_access"];
    
    if critical_keywords.iter().any(|&k| lower.contains(k)) {
        DetectionSeverity::Critical
    } else if high_keywords.iter().any(|&k| lower.contains(k)) {
        DetectionSeverity::High
    } else {
        DetectionSeverity::Medium
    }
}

pub fn find_embedded_pe(data: &[u8], parent_is_pe: bool) -> Option<PeAnalysis> {
    pe::find_embedded_pe(data, parent_is_pe)
}

pub fn resolve_syscall_name(ssn: u32) -> &'static str {
    match ssn {
        0x01 => "possibly NtWorkerFactoryWorkerReady",
        0x02 => "possibly NtAcceptConnectPort",
        0x03 => "possibly NtMapUserPhysicalPagesScatter",
        0x07 => "possibly NtDeviceIoControlFile",
        0x08 => "possibly NtWriteFile",
        0x0f => "possibly NtClose",
        0x10 => "possibly NtQueryObject",
        0x16 => "possibly NtQueryKey",
        0x18 => "possibly NtAllocateVirtualMemory",
        0x20 => "possibly NtReleaseMutant",
        0x25 => "possibly NtQueryInformationThread",
        0x26 => "possibly NtOpenProcess",
        0x28 => "possibly NtMapViewOfSection",
        0x2a => "possibly NtUnmapViewOfSection",
        0x2b => "possibly NtReplyWaitReceivePortEx",
        0x2d => "possibly NtSetEventBoostPriority",
        0x30 => "possibly NtOpenProcessTokenEx",
        0x36 => "possibly NtQuerySystemInformation",
        0x3a => "possibly NtWriteVirtualMemory",
        0x45 => "possibly NtQueueApcThread",
        0x50 | 0x4F => "possibly NtProtectVirtualMemory",
        0x52 => "possibly NtResumeThread",
        0x78 => "possibly NtAlpcCancelMessage",
        0xbc => "possibly NtSuspendThread",
        0xbd | 0xc2 | 0xc7 => "possibly NtCreateThreadEx",
        _ => "unknown NT API",
    }
}

pub fn scan_peb_and_hashing(bitness: u32, section_data: &[u8], virtual_address: u64) -> (bool, bool, bool, bool, Vec<SyscallLocation>) {
    use iced_x86::{Decoder, DecoderOptions, Register, OpKind, Mnemonic, NasmFormatter, Formatter};
    let mut peb_walking = false;
    let mut api_hashing = false;
    let mut direct_syscalls = false;
    let mut indirect_syscalls = false;
    let mut syscall_locations = Vec::new();

    let mut decoder = Decoder::with_ip(bitness, section_data, virtual_address, DecoderOptions::NONE);
    let mut instructions = Vec::with_capacity(section_data.len() / 4);
    let mut instruction = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        instructions.push(instruction.clone());
    }

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("_");
    formatter.options_mut().set_first_operand_char_index(10);

    // 1. Scan for PEB access and direct syscalls
    for (idx, instr) in instructions.iter().enumerate() {
        let mn = instr.mnemonic();
        if mn == Mnemonic::Syscall || mn == Mnemonic::Sysenter {
            direct_syscalls = true;

            // Search back for EAX / RAX loader to find the SSN
            let mut ssn = None;
            let start_check = idx.saturating_sub(10);
            for prev_instr in &instructions[start_check..idx] {
                if prev_instr.mnemonic() == Mnemonic::Mov {
                    if prev_instr.op0_kind() == OpKind::Register {
                        let dest_reg = prev_instr.op0_register();
                        if dest_reg == Register::EAX || dest_reg == Register::RAX {
                            let op1 = prev_instr.op1_kind();
                            if op1 == OpKind::Immediate8 || op1 == OpKind::Immediate8to32 || op1 == OpKind::Immediate8to64 || op1 == OpKind::Immediate32 || op1 == OpKind::Immediate32to64 || op1 == OpKind::Immediate64 {
                                ssn = Some(prev_instr.immediate32());
                            }
                        }
                    }
                }
            }

            let mut inst_str = String::new();
            formatter.format(instr, &mut inst_str);

            let display_str = if let Some(val) = ssn {
                format!("mov eax, {:#x}; {} ({})", val, inst_str, resolve_syscall_name(val))
            } else {
                inst_str
            };

            syscall_locations.push(SyscallLocation {
                address: instr.ip(),
                is_indirect: false,
                instruction_str: display_str,
            });
        }

        for i in 0..instr.op_count() {
            if instr.op_kind(i) == OpKind::Memory {
                let seg = instr.memory_segment();
                let disp = instr.memory_displacement64();
                if bitness == 32 && seg == Register::FS && (disp == 0x30 || disp == 0x18) {
                    peb_walking = true;
                }
                if bitness == 64 && seg == Register::GS && (disp == 0x60 || disp == 0x30) {
                    peb_walking = true;
                }
            }
        }
    }

    // 2. Scan for API Hashing Loop Patterns and Indirect Syscalls
    for (idx, instr) in instructions.iter().enumerate() {
        let mnemonic = instr.mnemonic();

        // Check for Indirect Syscalls
        // Valid indirect syscall pattern:
        // 1. mov r10, rcx (fastcall conversion) within close proximity (<= 6 instrs)
        // 2. mov eax/rax, <SSN> (0 < SSN < 0x300)
        // 3. jmp reg (NOT call, to maintain kernel return stack alignment)
        if mnemonic == Mnemonic::Jmp {
            let op0 = instr.op0_kind();
            if op0 == OpKind::Register {
                let reg = instr.op0_register();
                if reg != Register::RSP && reg != Register::RBP && reg != Register::ESP && reg != Register::EBP && reg != Register::RIP {
                    let start_check = idx.saturating_sub(6);
                    let preceding = &instructions[start_check..idx];

                    let mut found_r10_rcx = false;
                    let mut found_ssn: Option<(u32, &iced_x86::Instruction)> = None;

                    for prev_instr in preceding {
                        let prev_mn = prev_instr.mnemonic();

                        // Check `mov r10, rcx` or `mov r10d, ecx`
                        if prev_mn == Mnemonic::Mov
                            && prev_instr.op0_kind() == OpKind::Register
                            && (prev_instr.op0_register() == Register::R10 || prev_instr.op0_register() == Register::R10D)
                            && prev_instr.op1_kind() == OpKind::Register
                            && (prev_instr.op1_register() == Register::RCX || prev_instr.op1_register() == Register::ECX)
                        {
                            found_r10_rcx = true;
                        }

                        // Check `mov eax/rax, <SSN>`
                        if prev_mn == Mnemonic::Mov
                            && prev_instr.op0_kind() == OpKind::Register
                        {
                            let dest_reg = prev_instr.op0_register();
                            if dest_reg == Register::EAX || dest_reg == Register::RAX {
                                let op1 = prev_instr.op1_kind();
                                if matches!(
                                    op1,
                                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64
                                        | OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64
                                ) {
                                    let imm = prev_instr.immediate32();
                                    if imm > 0 && imm < 0x400 {
                                        found_ssn = Some((imm, prev_instr));
                                    }
                                }
                            }
                        }
                    }

                    // Strict criteria: requires SSN load AND r10<-rcx setup in same stub
                    if let Some((ssn, ssn_instr)) = found_ssn {
                        if found_r10_rcx {
                            indirect_syscalls = true;

                            let mut mov_str = String::new();
                            formatter.format(ssn_instr, &mut mov_str);
                            let mut jmp_str = String::new();
                            formatter.format(instr, &mut jmp_str);

                            syscall_locations.push(SyscallLocation {
                                address: instr.ip(),
                                is_indirect: true,
                                instruction_str: format!("{}; {} ({})", mov_str, jmp_str, resolve_syscall_name(ssn)),
                            });
                        }
                    }
                }
            }
        }

        let is_jcc = matches!(
            mnemonic,
            Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb | Mnemonic::Jbe |
            Mnemonic::Je | Mnemonic::Jg | Mnemonic::Jge | Mnemonic::Jl | Mnemonic::Jle |
            Mnemonic::Jne | Mnemonic::Jno | Mnemonic::Jnp | Mnemonic::Jns |
            Mnemonic::Jo | Mnemonic::Jp | Mnemonic::Js
        );
        if mnemonic == Mnemonic::Jmp || is_jcc {
            let target_ip = instr.near_branch_target();
            if target_ip < instr.ip() && target_ip >= virtual_address {
                let mut loop_instrs = Vec::new();
                for prev_instr in instructions[..idx].iter().rev() {
                    if prev_instr.ip() >= target_ip {
                        loop_instrs.push(prev_instr);
                    } else {
                        break;
                    }
                }

                if !loop_instrs.is_empty() && loop_instrs.len() < 100 {
                    let mut has_byte_load = false;
                    let mut has_hash_op = false;

                    for li in &loop_instrs {
                        if li.mnemonic() == Mnemonic::Movzx {
                            has_byte_load = true;
                        }
                        for i in 0..li.op_count() {
                            if li.op_kind(i) == OpKind::Memory && li.memory_size().size() == 1 {
                                has_byte_load = true;
                            }
                        }

                        let mn = li.mnemonic();
                        if mn == Mnemonic::Shl || mn == Mnemonic::Shr || mn == Mnemonic::Ror || mn == Mnemonic::Rol {
                            if li.op_count() > 1 {
                                let op_k = li.op_kind(1);
                                if op_k == OpKind::Immediate8 || op_k == OpKind::Immediate8to32 {
                                    let shift = li.immediate8();
                                    if shift == 5 || shift == 13 || shift == 7 || shift == 19 {
                                        has_hash_op = true;
                                    }
                                }
                            }
                        } else if mn == Mnemonic::Imul {
                            if li.op_count() > 2 {
                                let op_k = li.op_kind(2);
                                if op_k == OpKind::Immediate32 || op_k == OpKind::Immediate8to32 || op_k == OpKind::Immediate8 || op_k == OpKind::Immediate8to64 || op_k == OpKind::Immediate32to64 {
                                    let val = if op_k == OpKind::Immediate8to32 { li.immediate8to32() as u32 } else { li.immediate32() };
                                    if val == 33 || val == 131 || val == 16777619 || val == 65599 {
                                        has_hash_op = true;
                                    }
                                }
                            } else if li.op_count() > 1 {
                                let op_k = li.op_kind(1);
                                if op_k == OpKind::Immediate32 || op_k == OpKind::Immediate8to32 || op_k == OpKind::Immediate8 || op_k == OpKind::Immediate8to64 || op_k == OpKind::Immediate32to64 {
                                    let val = if op_k == OpKind::Immediate8to32 { li.immediate8to32() as u32 } else { li.immediate32() };
                                    if val == 33 || val == 131 || val == 16777619 || val == 65599 {
                                        has_hash_op = true;
                                    }
                                }
                            }
                        }
                    }

                    if has_byte_load && has_hash_op {
                        api_hashing = true;
                    }
                }
            }
        }
    }

    (peb_walking, api_hashing, direct_syscalls, indirect_syscalls, syscall_locations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_peb_and_hashing() {
        let hash_loop_code = [0x0F, 0xB6, 0x06, 0x6B, 0xC0, 0x21, 0x75, 0xF8];
        


        let (peb, hashing, _, _, _) = scan_peb_and_hashing(64, &hash_loop_code, 0x1000);
        assert!(!peb);
        assert!(hashing);

        let peb_code = [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let (peb, hashing, _, _, _) = scan_peb_and_hashing(64, &peb_code, 0x1000);
        assert!(peb);
        assert!(!hashing);

        // Direct Syscall test
        let direct_code = [0x0F, 0x05]; // syscall
        let (_, _, direct, indirect, locations) = scan_peb_and_hashing(64, &direct_code, 0x1000);
        assert!(direct);
        assert!(!indirect);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].is_indirect, false);

        // Indirect Syscall test
        let indirect_code = [
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0x41, 0xFF, 0xE3,             // jmp r11
        ];
        let (_, _, direct, indirect, locations) = scan_peb_and_hashing(64, &indirect_code, 0x1000);
        assert!(!direct);
        assert!(indirect);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].is_indirect, true);
    }
}
