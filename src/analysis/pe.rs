use crate::analysis::basic::shannon_entropy;
use crate::models::*;
use color_eyre::Result;
use goblin::Object;
use std::collections::BTreeMap;
use std::time::SystemTime;

/// Parse PE headers, sections, imports, exports and detect anomalies.
pub fn analyze(data: &[u8]) -> Result<PeAnalysis> {
    let pe = match Object::parse(data)? {
        Object::PE(pe) => pe,
        _ => color_eyre::eyre::bail!("Not a PE file"),
    };

    let coff = &pe.header.coff_header;
    let machine = match coff.machine {
        0x014C => "x86 (i386)".into(),
        0x8664 => "x86-64 (AMD64)".into(),
        0x01C0 => "ARM".into(),
        0xAA64 => "ARM64".into(),
        other => format!("Unknown ({:#06x})", other),
    };

    let timestamp = coff.time_date_stamp;
    let timestamp_str = format_timestamp(timestamp);

    let is_dll = pe.is_lib;
    let is_64bit = pe.is_64;

    let (entry_point, image_base, subsystem, linker_version) =
        if let Some(opt) = pe.header.optional_header {
            let ep = opt.standard_fields.address_of_entry_point as u64;
            let ib = opt.windows_fields.image_base;
            let ss = match opt.windows_fields.subsystem {
                1 => "Native",
                2 => "Windows GUI",
                3 => "Windows CUI (Console)",
                5 => "OS/2 CUI",
                7 => "POSIX CUI",
                10 => "EFI Application",
                _ => "Unknown",
            }
            .to_string();
            let lv = format!(
                "{}.{}",
                opt.standard_fields.major_linker_version,
                opt.standard_fields.minor_linker_version,
            );
            (ep, ib, ss, lv)
        } else {
            (0, 0, "Unknown".into(), "?".into())
        };

    // ── Sections ──
    let mut sections = Vec::new();
    for section in &pe.sections {
        let name = String::from_utf8_lossy(
            &section.name[..section.name.iter().position(|&b| b == 0).unwrap_or(8)],
        )
        .to_string();

        let vsize = section.virtual_size as u64;
        let raw_size = section.size_of_raw_data as u64;
        let chars = section.characteristics;
        let is_exec = chars & 0x2000_0000 != 0;
        let is_write = chars & 0x8000_0000 != 0;
        let is_read = chars & 0x4000_0000 != 0;

        let mut flags = String::new();
        if is_read {
            flags.push('R');
        }
        if is_write {
            flags.push('W');
        }
        if is_exec {
            flags.push('X');
        }

        let start = section.pointer_to_raw_data as usize;
        let end = (start + section.size_of_raw_data as usize).min(data.len());
        let section_entropy = if start < data.len() {
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };

        let mut anomalies = Vec::new();
        if is_exec && is_write {
            anomalies.push("W+X (writable + executable)".into());
        }
        if section_entropy > 7.0 {
            anomalies.push(format!("High entropy ({:.2}) — likely packed/encrypted", section_entropy));
        }
        if vsize > 0 && raw_size == 0 {
            anomalies.push("Raw size 0 with non-zero virtual size".into());
        }
        // Suspicious section names
        let name_lower = name.to_lowercase();
        let sus_names = [".upx", ".themida", ".vmp", ".aspack", ".adata", ".nsp"];
        if sus_names.iter().any(|n| name_lower.starts_with(n)) {
            anomalies.push(format!("Suspicious name: {}", name));
        }

        sections.push(SectionInfo {
            name,
            virtual_address: section.virtual_address as u64,
            virtual_size: vsize,
            raw_size,
            entropy: section_entropy,
            characteristics: chars,
            flags_str: flags,
            is_executable: is_exec,
            is_writable: is_write,
            anomalies,
        });
    }

    let mut last_section_end = 0;
    for sec in &pe.sections {
        let sec_end = (sec.pointer_to_raw_data + sec.size_of_raw_data) as usize;
        if sec_end > last_section_end {
            last_section_end = sec_end;
        }
    }

    let (overlay_offset, overlay_size) = if data.len() > last_section_end && last_section_end > 0 {
        (Some(last_section_end), Some(data.len() - last_section_end))
    } else {
        (None, None)
    };

    // ── Imports (group by DLL) ──
    let mut dll_map: BTreeMap<String, Vec<ImportFunction>> = BTreeMap::new();
    for import in &pe.imports {
        let dll_name = import.dll.to_string();
        let fn_name = if import.name.is_empty() {
            format!("ordinal_{}", import.ordinal)
        } else {
            import.name.to_string()
        };
        let risk = classify_api(&fn_name);
        dll_map
            .entry(dll_name)
            .or_default()
            .push(ImportFunction {
                name: fn_name,
                risk,
            });
    }
    let imports: Vec<ImportDll> = dll_map
        .into_iter()
        .map(|(name, mut functions)| {
            functions.sort_by(|a, b| b.risk.cmp(&a.risk));
            ImportDll { name, functions }
        })
        .collect();

    // ── Exports ──
    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| n.to_string()))
        .collect();

    // ── Global anomalies ──
    let mut anomalies = Vec::new();

    // Entry point outside first section
    if let Some(first) = pe.sections.first() {
        let sec_start = first.virtual_address as u64;
        let sec_end = sec_start + first.virtual_size as u64;
        if entry_point < sec_start || entry_point >= sec_end {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Warning,
                description: format!(
                    "Entry point {:#x} outside first section ({:#x}..{:#x})",
                    entry_point, sec_start, sec_end
                ),
            });
        }
    }

    // Suspicious timestamp
    if timestamp == 0 {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Zeroed timestamp (stripped/forged)".into(),
        });
    } else if timestamp > 2_000_000_000 {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Timestamp in the far future".into(),
        });
    }

    // No imports at all
    if imports.is_empty() {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "No imports — possibly packed or hand-crafted".into(),
        });
    }

    // Collect section anomalies into global list
    for sec in &sections {
        for a in &sec.anomalies {
            let sev = if a.contains("W+X") {
                AnomalySeverity::Critical
            } else if a.contains("High entropy") || a.contains("Suspicious name") {
                AnomalySeverity::Warning
            } else {
                AnomalySeverity::Info
            };
            anomalies.push(Anomaly {
                severity: sev,
                description: format!("[{}] {}", sec.name, a),
            });
        }
    }

    // High-risk API combinations
    let has_alloc = imports.iter().any(|d| {
        d.functions
            .iter()
            .any(|f| f.name == "VirtualAllocEx" || f.name == "VirtualAlloc")
    });
    let has_write = imports
        .iter()
        .any(|d| d.functions.iter().any(|f| f.name == "WriteProcessMemory"));
    let has_thread = imports.iter().any(|d| {
        d.functions
            .iter()
            .any(|f| f.name == "CreateRemoteThread" || f.name == "NtCreateThreadEx")
    });
    if has_alloc && has_write && has_thread {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Classic process injection pattern: VirtualAlloc + WriteProcessMemory + CreateRemoteThread".into(),
        });
    }

    // ── New fields ──
    let characteristics = coff.characteristics;
    let dll_characteristics = pe.header.optional_header.map(|o| o.windows_fields.dll_characteristics).unwrap_or(0);

    let data_directories = if let Some(opt) = pe.header.optional_header {
        opt.data_directories.data_directories.iter().enumerate().map(|(i, dir_opt)| {
            let name = match i {
                0 => "Export", 1 => "Import", 2 => "Resource", 3 => "Exception",
                4 => "Security", 5 => "Base Relocation", 6 => "Debug", 7 => "Architecture",
                8 => "Global Ptr", 9 => "TLS", 10 => "Load Config", 11 => "Bound Import",
                12 => "IAT", 13 => "Delay Import", 14 => "COM Descriptor", _ => "Reserved",
            }.to_string();
            let (va, sz) = dir_opt.as_ref().map(|(_, dir)| (dir.virtual_address, dir.size)).unwrap_or((0, 0));
            DataDirectory { name, virtual_address: va, size: sz }
        }).collect()
    } else {
        Vec::new()
    };

    let mut entry_point_section = None;
    for sec in &sections {
        if entry_point >= sec.virtual_address as u64 && entry_point < (sec.virtual_address + sec.virtual_size) as u64 {
            entry_point_section = Some(sec.name.clone());
            break;
        }
    }

    let packer_detected = detect_packer(&sections, data, &imports);
    let compilation_age = format_compilation_age(timestamp);
    let timestamp_suspicious = is_timestamp_suspicious(timestamp);

    let has_authenticode = if let Some(opt) = pe.header.optional_header {
        let dirs = opt.data_directories.data_directories;
        if let Some(Some((_, sec_dir))) = dirs.get(4) {
            sec_dir.virtual_address != 0 && sec_dir.size != 0
        } else {
            false
        }
    } else {
        false
    };

    let mut ep_bytes = Vec::new();
    // Try to get 100 bytes at the entry point for disassembly
    // Since entry_point is a Virtual Address (RVA), we need to map it to file offset.
    if let Some(opt) = pe.header.optional_header {
        let ep_offset = goblin::pe::utils::find_offset(
            entry_point as usize,
            &pe.sections,
            opt.windows_fields.file_alignment,
            &goblin::pe::options::ParseOptions::default(),
        ).unwrap_or(0);
        
        if ep_offset > 0 && ep_offset < data.len() {
            let end = (ep_offset + 100).min(data.len());
            ep_bytes.extend_from_slice(&data[ep_offset..end]);
        }
    }

    Ok(PeAnalysis {
        machine,
        timestamp,
        timestamp_str,
        entry_point,
        image_base,
        subsystem,
        is_dll,
        is_64bit,
        linker_version,
        sections,
        imports,
        exports,
        anomalies,
        packer_detected,
        compilation_age,
        timestamp_suspicious,
        characteristics,
        dll_characteristics,
        data_directories,
        entry_point_section,
        has_authenticode,
        ep_bytes,
        overlay_offset,
        overlay_size,
    })
}

// ─── API risk classification ─────────────────────────────────────

fn classify_api(name: &str) -> ApiRisk {
    match name {
        // ── Critical: process injection / hooking ──
        "VirtualAllocEx" | "WriteProcessMemory" | "CreateRemoteThread"
        | "NtUnmapViewOfSection" | "QueueUserAPC" | "NtQueueApcThread"
        | "RtlCreateUserThread" | "NtCreateThreadEx" | "NtWriteVirtualMemory"
        | "SetWindowsHookExA" | "SetWindowsHookExW" | "SetWinEventHook" => ApiRisk::Critical,

        // ── High: anti-debug / code manipulation ──
        "IsDebuggerPresent" | "CheckRemoteDebuggerPresent"
        | "NtQueryInformationProcess" | "NtSetInformationThread"
        | "OutputDebugStringA" | "OutputDebugStringW"
        | "VirtualProtect" | "VirtualProtectEx"
        | "GetThreadContext" | "SetThreadContext"
        | "SuspendThread" | "ResumeThread"
        | "NtSuspendProcess" | "NtResumeProcess" => ApiRisk::High,

        // ── Medium: network / crypto / persistence ──
        "InternetOpenA" | "InternetOpenW"
        | "InternetConnectA" | "InternetConnectW"
        | "HttpOpenRequestA" | "HttpOpenRequestW"
        | "HttpSendRequestA" | "HttpSendRequestW"
        | "InternetOpenUrlA" | "InternetOpenUrlW"
        | "URLDownloadToFileA" | "URLDownloadToFileW"
        | "WSAStartup" | "connect" | "send" | "recv" | "socket" | "bind" | "listen"
        | "CryptEncrypt" | "CryptDecrypt" | "BCryptEncrypt" | "BCryptDecrypt"
        | "CryptHashData" | "CryptDeriveKey"
        | "RegSetValueExA" | "RegSetValueExW"
        | "RegCreateKeyExA" | "RegCreateKeyExW"
        | "CreateServiceA" | "CreateServiceW"
        | "StartServiceA" | "StartServiceW"
        | "OpenSCManagerA" | "OpenSCManagerW" => ApiRisk::Medium,

        // ── Low: file/registry reads, process queries ──
        "CreateFileA" | "CreateFileW"
        | "ReadFile" | "WriteFile"
        | "DeleteFileA" | "DeleteFileW"
        | "MoveFileA" | "MoveFileW"
        | "CopyFileA" | "CopyFileW"
        | "RegOpenKeyExA" | "RegOpenKeyExW"
        | "RegQueryValueExA" | "RegQueryValueExW"
        | "FindFirstFileA" | "FindFirstFileW"
        | "FindNextFileA" | "FindNextFileW"
        | "GetModuleHandleA" | "GetModuleHandleW"
        | "LoadLibraryA" | "LoadLibraryW"
        | "GetProcAddress"
        | "OpenProcess" | "TerminateProcess"
        | "CreateProcessA" | "CreateProcessW" => ApiRisk::Low,

        _ => ApiRisk::None,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

fn format_timestamp(ts: u32) -> String {
    if ts == 0 {
        return "0 (invalid/stripped)".into();
    }
    // Simple UTC conversion (seconds since 1970-01-01)
    let secs = ts as u64;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Rough date calc (no leap-second precision needed for malware analysis)
    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let month_days: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            month = i + 1;
            break;
        }
        remaining_days -= md;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ─── Packer detection ────────────────────────────────────────────

fn detect_packer(sections: &[SectionInfo], data: &[u8], imports: &[ImportDll]) -> Option<String> {
    // Check section names
    for sec in sections {
        let lower = sec.name.to_lowercase();
        match lower.as_str() {
            ".upx0" | ".upx1" | "upx!" => return Some("UPX".into()),
            ".themida" => return Some("Themida".into()),
            ".vmp0" | ".vmp1" => return Some("VMProtect".into()),
            ".aspack" => return Some("ASPack".into()),
            ".nsp0" | ".nsp1" => return Some("NsPack".into()),
            ".petite" => return Some("Petite".into()),
            ".mpress" => return Some("MPRESS".into()),
            _ => {}
        }
    }

    // Scan first 1024 bytes for byte signatures
    let scan_len = data.len().min(1024);
    let header = &data[..scan_len];
    if header.windows(4).any(|w| w == b"UPX!") {
        return Some("UPX".into());
    }
    if header.windows(4).any(|w| w == b"PEC2") {
        return Some("PECompact".into());
    }

    // Heuristic: high entropy in most sections + no imports
    if !sections.is_empty() {
        let high_ent_count = sections.iter().filter(|s| s.entropy > 7.0).count();
        let majority = high_ent_count > sections.len() / 2;
        if majority && imports.is_empty() {
            return Some("Unknown packer (high entropy, no imports)".into());
        }
    }

    None
}

// ─── Compilation age ─────────────────────────────────────────────

fn format_compilation_age(timestamp: u32) -> String {
    if timestamp == 0 {
        return "Unknown (stripped)".into();
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = timestamp as u64;

    if ts > now {
        return "Future date (!)".into();
    }

    let diff = now - ts;
    if diff < 60 {
        "just now".into()
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else if diff < 2_592_000 {
        format!("{} days ago", diff / 86400)
    } else if diff < 31_536_000 {
        format!("{} months ago", diff / 2_592_000)
    } else {
        format!("{} years ago", diff / 31_536_000)
    }
}

// ─── Timestamp suspicious check ──────────────────────────────────

fn is_timestamp_suspicious(timestamp: u32) -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = timestamp as u64;

    if timestamp == 0 {
        return true;
    }
    if ts > now {
        return true;
    }
    // Before year 2000
    if ts < 946_684_800 {
        return true;
    }
    // Timestamp year > current year
    let ts_year = 1970 + ts / 31_536_000; // rough
    let cur_year = 1970 + now / 31_536_000;
    if ts_year > cur_year {
        return true;
    }

    false
}
