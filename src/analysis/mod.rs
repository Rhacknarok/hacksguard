pub mod basic;
pub mod pe;

use crate::models::*;
use color_eyre::Result;
use std::path::Path;

/// Run the full analysis pipeline on a file.
pub fn analyze_file(path: &Path) -> Result<AnalysisResult> {
    let data = std::fs::read(path)?;

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

    let basic_result = basic::analyze(&data);

    let pe_result = if file_type == FileType::PE {
        pe::analyze(&data).ok()
    } else {
        None
    };

    let (risk_score, risk_level, risk_breakdown) = compute_risk(&basic_result, &pe_result);
    let detection_checks = build_detection_checks(&basic_result, &pe_result);
    let malware_pattern = detect_malware_pattern(&basic_result, &pe_result);

    let mut yara_matches = Vec::new();
    let mut compiler = boreal::Compiler::new();
    
    // Load all YARA rules from the `rules` directory
    if let Ok(entries) = std::fs::read_dir("rules") {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                let _ = compiler.add_rules_file(&path);
            }
        }
    }
    let scanner = compiler.finalize();
    let res = match scanner.scan_mem(&data) {
        Ok(res) => res,
        Err((_, res)) => res,
    };
    yara_matches.extend(res.rules.iter().map(|r| r.name.to_string()));

    let mut vt_score = None;
    if let Ok(api_key) = std::env::var("VT_API_KEY") {
        if let Ok(client) = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(3)).build() {
            let url = format!("https://www.virustotal.com/api/v3/files/{}", basic_result.sha256);
            if let Ok(res) = client.get(&url).header("x-apikey", api_key).send() {
                if let Ok(json) = res.json::<serde_json::Value>() {
                    if let Some(stats) = json["data"]["attributes"]["last_analysis_stats"].as_object() {
                        let malicious = stats["malicious"].as_u64().unwrap_or(0);
                        let total = malicious + stats["undetected"].as_u64().unwrap_or(0) + stats["harmless"].as_u64().unwrap_or(0);
                        vt_score = Some(format!("{}/{}", malicious, total));
                    }
                }
            }
        }
    }

    Ok(AnalysisResult {
        file_info,
        basic: basic_result,
        pe: pe_result,
        risk_score,
        risk_level,
        risk_breakdown,
        detection_checks,
        malware_pattern,
        vt_score,
        yara_matches,
    })
}

// ─── File type detection via magic bytes ─────────────────────────

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

fn compute_risk(basic: &BasicAnalysis, pe: &Option<PeAnalysis>) -> (u32, RiskLevel, RiskBreakdown) {
    let mut score: u32 = 0;

    // Entropy
    let entropy_score = if basic.entropy > 7.5 {
        25
    } else if basic.entropy > 7.0 {
        15
    } else if basic.entropy > 6.5 {
        5
    } else {
        0
    };
    score += entropy_score;

    // Packing
    let packing_score = if basic.is_packed { 15 } else { 0 };
    score += packing_score;

    // Suspicious strings
    let sus = basic
        .strings
        .iter()
        .filter(|s| !matches!(s.category, StringCategory::Normal))
        .count() as u32;
    let string_score = sus.min(15);
    score += string_score;

    // API risk + anomalies (PE-only)
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
        api_score = api_score.min(25);
        score += api_score;

        for a in &pe.anomalies {
            match a.severity {
                AnomalySeverity::Critical => anomaly_score += 12,
                AnomalySeverity::Warning => anomaly_score += 4,
                AnomalySeverity::Info => {}
            }
        }
        anomaly_score = anomaly_score.min(25);
        score += anomaly_score;
    }

    let score = score.min(100);
    let level = match score {
        0..=20 => RiskLevel::Clean,
        21..=40 => RiskLevel::Low,
        41..=60 => RiskLevel::Medium,
        61..=80 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    let breakdown = RiskBreakdown {
        entropy_score,
        api_score,
        anomaly_score,
        string_score,
        packing_score,
    };

    (score, level, breakdown)
}

// ─── Detection checks ───────────────────────────────────────────

fn build_detection_checks(basic: &BasicAnalysis, pe: &Option<PeAnalysis>) -> Vec<DetectionCheck> {
    let mut checks = Vec::with_capacity(23);

    // Helper: check if any string matches a category
    let has_category = |cat: &StringCategory| basic.strings.iter().any(|s| &s.category == cat);
    let has_non_normal = basic
        .strings
        .iter()
        .any(|s| !matches!(s.category, StringCategory::Normal));

    // Helper: check if any imported function name matches (case-insensitive)
    let has_api = |names: &[&str]| -> bool {
        if let Some(pe) = pe {
            pe.imports.iter().any(|dll| {
                dll.functions.iter().any(|f| {
                    let lower = f.name.to_lowercase();
                    names.iter().any(|n| lower == n.to_lowercase())
                })
            })
        } else {
            false
        }
    };

    let has_all_apis = |names: &[&str]| -> bool {
        if let Some(pe) = pe {
            names.iter().all(|name| {
                pe.imports.iter().any(|dll| {
                    dll.functions
                        .iter()
                        .any(|f| f.name.eq_ignore_ascii_case(name))
                })
            })
        } else {
            false
        }
    };

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

    checks
}

// ─── Malware pattern matching ────────────────────────────────────

fn detect_malware_pattern(
    basic: &BasicAnalysis,
    pe: &Option<PeAnalysis>,
) -> Option<MalwarePattern> {
    // Helper closures
    let has_api = |names: &[&str]| -> bool {
        if let Some(pe) = pe {
            pe.imports.iter().any(|dll| {
                dll.functions.iter().any(|f| {
                    names
                        .iter()
                        .any(|n| f.name.eq_ignore_ascii_case(n))
                })
            })
        } else {
            false
        }
    };

    let has_all_apis = |names: &[&str]| -> bool {
        if let Some(pe) = pe {
            names.iter().all(|name| {
                pe.imports.iter().any(|dll| {
                    dll.functions
                        .iter()
                        .any(|f| f.name.eq_ignore_ascii_case(name))
                })
            })
        } else {
            false
        }
    };

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
    ]);

    let process_injection = has_all_apis(&[
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]);

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
    ]);

    let service_apis = has_api(&[
        "CreateServiceA",
        "CreateServiceW",
        "OpenServiceA",
        "OpenServiceW",
    ]);

    // 1. Trojan.Injector — process injection + network (High)
    if process_injection && network_apis {
        return Some(MalwarePattern {
            family: "Trojan.Injector".into(),
            confidence: "High".into(),
            description: "Process injection combined with network communication capabilities"
                .into(),
            matched_indicators: vec![
                "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread".into(),
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

    None
}
