use crate::analysis::basic::shannon_entropy;
use crate::models::*;
use goblin::Object;
use md5::{Digest, Md5};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// Parse PE headers, sections, imports, exports and detect anomalies.
pub fn analyze(data: &[u8]) -> Result<PeAnalysis> {
    let pe = match Object::parse(data)? {
        Object::PE(pe) => pe,
        _ => return Err("Not a PE file".into()),
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
            let ep = opt.standard_fields.address_of_entry_point;
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
            raw_offset: section.pointer_to_raw_data as u64,
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

    let (has_authenticode, certificate) = if let Some(opt) = pe.header.optional_header {
        let dirs = opt.data_directories.data_directories;
        if let Some(Some((_, sec_dir))) = dirs.get(4) {
            if sec_dir.virtual_address != 0 && sec_dir.size != 0 {
                let cert = crate::analysis::authenticode::parse_authenticode(data, sec_dir.virtual_address as usize, sec_dir.size as usize);
                (true, cert)
            } else {
                (false, None)
            }
        } else {
            (false, None)
        }
    } else {
        (false, None)
    };

    if let Some(ref cert) = certificate {
        if cert.is_self_signed {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Critical,
                description: format!("Self-signed Authenticode certificate ({})", cert.subject),
            });
        }
    }

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

    let (resources, manifest) = if let Some(opt) = pe.header.optional_header {
        let file_alignment = opt.windows_fields.file_alignment;
        let dirs = opt.data_directories.data_directories;
        if let Some(Some((_, rsrc_dir))) = dirs.get(2) {
            let rva = rsrc_dir.virtual_address as usize;
            let size = rsrc_dir.size as usize;
            let offset = goblin::pe::utils::find_offset(
                rva,
                &pe.sections,
                file_alignment,
                &goblin::pe::options::ParseOptions::default(),
            ).unwrap_or(0);

            if offset > 0 && offset < data.len() {
                let actual_size = size.min(data.len() - offset);
                parse_resources_and_manifest(&data[offset..offset + actual_size], &pe.sections, file_alignment, data)
            } else {
                (Vec::new(), None)
            }
        } else {
            (Vec::new(), None)
        }
    } else {
        (Vec::new(), None)
    };

    let tls_info = if let Some(opt) = pe.header.optional_header {
        let dirs = opt.data_directories.data_directories;
        if let Some(Some((_, tls_dir))) = dirs.get(9) {
            parse_tls_directory(
                data,
                tls_dir.virtual_address as usize,
                tls_dir.size as usize,
                &pe.sections,
                opt.windows_fields.file_alignment,
                image_base,
                is_64bit,
            )
        } else {
            None
        }
    } else {
        None
    };

    if let Some(ref tls) = tls_info {
        if !tls.callbacks.is_empty() {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Warning,
                description: format!("TLS directory contains {} callback(s) (potential pre-EP execution)", tls.callbacks.len()),
            });
        }
    }

    for res in &resources {
        if res.magic_hint.as_deref() == Some("PE (MZ)") {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Critical,
                description: format!("Embedded PE executable in resource {} ({})", res.type_name, res.name_or_id),
            });
        } else if res.entropy > 7.2 && res.type_id == 10 {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Warning,
                description: format!("High-entropy RCDATA resource {} (size {}, entropy {:.2})", res.name_or_id, res.size, res.entropy),
            });
        }
    }

    let pdb_path = pe.debug_data.and_then(|debug_data| {
        if let Some(pdb_info) = debug_data.codeview_pdb70_debug_info {
            let filename_bytes = pdb_info.filename;
            let len = filename_bytes.iter().position(|&b| b == 0).unwrap_or(filename_bytes.len());
            let path_str = String::from_utf8_lossy(&filename_bytes[..len]).into_owned();
            if !path_str.trim().is_empty() {
                return Some(path_str);
            }
        }
        if let Some(pdb_info) = debug_data.codeview_pdb20_debug_info {
            let filename_bytes = pdb_info.filename;
            let len = filename_bytes.iter().position(|&b| b == 0).unwrap_or(filename_bytes.len());
            let path_str = String::from_utf8_lossy(&filename_bytes[..len]).into_owned();
            if !path_str.trim().is_empty() {
                return Some(path_str);
            }
        }
        None
    });

    let imphash = compute_imphash(&pe.imports);
    let rich_header = parse_rich_header(data);

    // ── 1-byte XOR brute-force scanner on overlay and high-entropy sections ──
    let mut xor_payloads = Vec::new();
    if let (Some(off), Some(sz)) = (overlay_offset, overlay_size) {
        let mut scan_off = off;
        let mut scan_sz = sz;
        if let Some(opt) = pe.header.optional_header {
            if let Some(Some((_, sec_dir))) = opt.data_directories.data_directories.get(4) {
                let cert_off = sec_dir.virtual_address as usize;
                let cert_sz = sec_dir.size as usize;
                if cert_off == off && cert_sz <= sz {
                    scan_off = off + cert_sz;
                    scan_sz = sz - cert_sz;
                }
            }
        }
        if scan_sz >= 64 {
            let scan_end = (scan_off + scan_sz).min(scan_off + 1024 * 1024).min(data.len());
            if scan_off < scan_end {
                xor_payloads.extend(scan_xor_payloads(&data[scan_off..scan_end], scan_off, "Overlay"));
            }
        }
    }
    for sec in &sections {
        if sec.entropy >= 6.0 && sec.raw_size >= 64 {
            let start = sec.raw_offset as usize;
            let end = (start + sec.raw_size as usize).min(start + 512 * 1024).min(data.len());
            if start < end {
                xor_payloads.extend(scan_xor_payloads(&data[start..end], start, &format!("Section {}", sec.name)));
            }
        }
    }

    for p in &xor_payloads {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: format!("1-byte XOR encrypted payload in {} (key {:#04x}: {})", p.target_location, p.key, p.description),
        });
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
        obfuscated_apis: Vec::new(),
        embedded_pe: None,
        peb_walking: false,
        api_hashing: false,
        pdb_path,
        manifest,
        direct_syscalls: false,
        indirect_syscalls: false,
        syscall_locations: Vec::new(),
        imphash,
        rich_header,
        certificate,
        xor_payloads,
        tls_info,
        resources,
    })
}

// ─── Imphash & Rich Header ───────────────────────────────────────

pub fn compute_imphash(imports: &[goblin::pe::import::Import]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut entries = Vec::with_capacity(imports.len());
    for import in imports {
        let dll_lower = import.dll.to_lowercase();
        let lib_name = dll_lower
            .strip_suffix(".dll")
            .or_else(|| dll_lower.strip_suffix(".sys"))
            .or_else(|| dll_lower.strip_suffix(".ocx"))
            .unwrap_or(&dll_lower);

        let func_name = if import.name.is_empty() {
            format!("ord{}", import.ordinal)
        } else {
            import.name.to_lowercase()
        };
        entries.push(format!("{}.{}", lib_name, func_name));
    }
    Some(format!("{:x}", Md5::digest(entries.join(",").as_bytes())))
}

fn lookup_tool_name(prod_id: u16) -> Option<&'static str> {
    match prod_id {
        1 => Some("Import0"),
        2 | 4 | 10 | 27 | 39 | 60 | 95 | 109 | 131 | 149 | 179 | 201 | 224 | 257 | 261 => Some("Linker"),
        3 | 5 | 12 | 28 | 40 | 61 | 96 | 110 | 132 | 150 | 180 | 202 | 225 | 258 | 262 => Some("Cvtomf"),
        6 | 13 => Some("Cvpack"),
        14 | 25 | 37 | 58 | 93 | 107 | 129 | 147 | 177 | 199 | 222 | 255 | 259 => Some("C Compiler"),
        15 | 26 | 38 | 59 | 94 | 108 | 130 | 148 | 178 | 200 | 223 | 256 | 260 => Some("C++ Compiler"),
        16 | 29 | 41 | 62 | 97 | 111 | 133 | 151 | 181 | 203 | 226 => Some("Resource"),
        17 | 30 | 42 | 63 | 98 | 112 | 134 | 152 | 182 | 204 | 227 => Some("MASM"),
        _ => None,
    }
}

pub fn parse_rich_header(data: &[u8]) -> Option<RichHeaderInfo> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew < 0x40 || e_lfanew > data.len() {
        return None;
    }

    let search_area = &data[0x40..e_lfanew];
    for (i, _) in search_area.windows(4).enumerate().rev() {
        if &search_area[i..i + 4] != b"Rich" {
            continue;
        }
        let rich_offset = 0x40 + i;
        if rich_offset + 8 > e_lfanew {
            continue;
        }

        let xor_key = u32::from_le_bytes(data[rich_offset + 4..rich_offset + 8].try_into().ok()?);
        let dans_masked = 0x536E_6144u32 ^ xor_key;

        let mut dans_offset = None;
        let mut cur = rich_offset;
        while cur >= 0x40 + 4 {
            cur -= 4;
            if let Ok(bytes) = data[cur..cur + 4].try_into() {
                if u32::from_le_bytes(bytes) == dans_masked {
                    dans_offset = Some(cur);
                    break;
                }
            }
        }

        let Some(dans_off) = dans_offset else {
            continue;
        };

        if dans_off + 16 > rich_offset {
            continue;
        }
        let mut pad_ok = true;
        for pad_idx in 0..3 {
            let start = dans_off + 4 + pad_idx * 4;
            if let Ok(bytes) = data[start..start + 4].try_into() {
                if u32::from_le_bytes(bytes) != xor_key {
                    pad_ok = false;
                    break;
                }
            } else {
                pad_ok = false;
                break;
            }
        }
        if !pad_ok {
            continue;
        }

        let mut clear_data = Vec::with_capacity(rich_offset - dans_off);
        for chunk in data[dans_off..rich_offset].chunks_exact(4) {
            if let Ok(bytes) = chunk.try_into() {
                let val = u32::from_le_bytes(bytes) ^ xor_key;
                clear_data.extend_from_slice(&val.to_le_bytes());
            }
        }

        let rich_hash: String = Md5::digest(&clear_data)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let records_data = &clear_data[16..];
        let mut records = Vec::new();
        for chunk in records_data.chunks_exact(8) {
            let comp_id = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
            let count = u32::from_le_bytes(chunk[4..8].try_into().ok()?);
            let prod_id = (comp_id >> 16) as u16;
            let build = (comp_id & 0xFFFF) as u16;
            let tool_name = lookup_tool_name(prod_id).map(String::from);
            records.push(RichRecord {
                prod_id,
                build,
                count,
                tool_name,
            });
        }

        return Some(RichHeaderInfo {
            xor_key,
            rich_hash,
            records,
        });
    }

    None
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
    let z = (ts as i64) / 86400 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }

    let tod = (ts as u64) % 86400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60
    )
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

// ─── Find embedded PE ────────────────────────────────────────────

pub fn find_embedded_pe(data: &[u8], parent_is_pe: bool) -> Option<PeAnalysis> {
    let start_offset = if parent_is_pe { 64 } else { 0 };
    if data.len() < start_offset + 64 {
        return None;
    }

    let max_scan = data.len().min(64 * 1024 * 1024);
    let mut offset = start_offset;
    while offset + 64 <= max_scan {
        if data[offset] == 0x4D && data[offset + 1] == 0x5A { // 'MZ'
            let e_lfanew = u32::from_le_bytes([
                data[offset + 0x3C],
                data[offset + 0x3D],
                data[offset + 0x3E],
                data[offset + 0x3F],
            ]) as usize;

            if (0x40..=0x1000).contains(&e_lfanew) && offset.saturating_add(e_lfanew).saturating_add(4) <= data.len() {
                if data[offset + e_lfanew] == 0x50
                    && data[offset + e_lfanew + 1] == 0x45
                    && data[offset + e_lfanew + 2] == 0x00
                    && data[offset + e_lfanew + 3] == 0x00
                {
                    if let Ok(pe_analysis) = analyze(&data[offset..]) {
                        return Some(pe_analysis);
                    }
                }
            }
        }
        offset += 1;
    }
    None
}

/// Brute-force single-pass 1-byte XOR scanner for hidden PEs, DOS stubs, and URLs.
pub fn scan_xor_payloads(data: &[u8], base_offset: usize, location: &str) -> Vec<XorPayloadMatch> {
    let mut results = Vec::new();
    if data.len() < 8 {
        return results;
    }

    const DOS_STUB: &[u8] = b"This program cannot be run in DOS mode";
    const HTTP: &[u8] = b"http://";
    const HTTPS: &[u8] = b"https://";

    let mut i = 0;
    while i < data.len() {
        // 1. Check for XOR-encoded PE executable (MZ header + e_lfanew + PE signature)
        if i + 64 <= data.len() {
            let key = data[i] ^ b'M';
            if key != 0 && (data[i + 1] ^ key) == b'Z' {
                let e_lfanew = u32::from_le_bytes([
                    data[i + 0x3c] ^ key,
                    data[i + 0x3d] ^ key,
                    data[i + 0x3e] ^ key,
                    data[i + 0x3f] ^ key,
                ]) as usize;

                if (0x40..=0x1000).contains(&e_lfanew) && i + e_lfanew + 4 <= data.len() {
                    if (data[i + e_lfanew] ^ key) == b'P'
                        && (data[i + e_lfanew + 1] ^ key) == b'E'
                        && (data[i + e_lfanew + 2] ^ key) == 0
                        && (data[i + e_lfanew + 3] ^ key) == 0
                    {
                        results.push(XorPayloadMatch {
                            key,
                            offset: base_offset + i,
                            target_location: location.to_string(),
                            description: "XOR-encoded PE executable (MZ...PE)".to_string(),
                            sample_preview: format!("MZ header at offset {:#x}, e_lfanew={:#x}", base_offset + i, e_lfanew),
                        });
                        i += 64;
                        continue;
                    }
                }
            }
        }

        // 2. Check for XOR-encoded DOS stub
        if i + DOS_STUB.len() <= data.len() {
            let key = data[i] ^ b'T';
            if key != 0 {
                let matches_stub = data[i..i + DOS_STUB.len()]
                    .iter()
                    .zip(DOS_STUB.iter())
                    .all(|(&b, &expected)| (b ^ key) == expected);

                if matches_stub {
                    let already_found_pe = results.iter().any(|r| {
                        r.key == key && r.description.contains("PE executable") && (base_offset + i).saturating_sub(r.offset) < 0x200
                    });
                    if !already_found_pe {
                        results.push(XorPayloadMatch {
                            key,
                            offset: base_offset + i,
                            target_location: location.to_string(),
                            description: "XOR-encoded DOS stub".to_string(),
                            sample_preview: "This program cannot be run in DOS mode".to_string(),
                        });
                    }
                    i += DOS_STUB.len();
                    continue;
                }
            }
        }

        // 3. Check for XOR-encoded URLs (http:// or https://)
        if i + 7 <= data.len() {
            let key = data[i] ^ b'h';
            if key != 0 {
                let is_https = i + 8 <= data.len()
                    && data[i..i + 8]
                        .iter()
                        .zip(HTTPS.iter())
                        .all(|(&b, &expected)| (b ^ key) == expected);

                let is_http = !is_https
                    && data[i..i + 7]
                        .iter()
                        .zip(HTTP.iter())
                        .all(|(&b, &expected)| (b ^ key) == expected);

                if is_https || is_http {
                    let mut url_bytes = Vec::new();
                    let max_scan = 128.min(data.len() - i);
                    for &b in &data[i..i + max_scan] {
                        let dec = b ^ key;
                        if (0x21..=0x7e).contains(&dec) && dec != b'"' && dec != b'\'' && dec != b'<' && dec != b'>' && dec != b'`' {
                            url_bytes.push(dec);
                        } else {
                            break;
                        }
                    }
                    if url_bytes.len() >= 10 {
                        let url_str = String::from_utf8_lossy(&url_bytes).to_string();
                        results.push(XorPayloadMatch {
                            key,
                            offset: base_offset + i,
                            target_location: location.to_string(),
                            description: "XOR-encoded URL".to_string(),
                            sample_preview: url_str,
                        });
                        i += url_bytes.len();
                        continue;
                    }
                }
            }
        }

        i += 1;
    }

    results
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)?.try_into().ok().map(u16::from_le_bytes)
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)?.try_into().ok().map(u32::from_le_bytes)
}

fn iter_rsrc_entries(rsrc: &[u8], dir_offset: usize) -> impl Iterator<Item = (u32, u32)> + '_ {
    let num_named = read_u16(rsrc, dir_offset.saturating_add(12)).unwrap_or(0) as usize;
    let num_id = read_u16(rsrc, dir_offset.saturating_add(14)).unwrap_or(0) as usize;
    let max_entries = (rsrc.len() / 8).min(2048);
    let total = num_named.saturating_add(num_id).min(max_entries);
    (0..total).filter_map(move |i| {
        let entry = dir_offset.checked_add(16 + i.checked_mul(8)?)?;
        Some((read_u32(rsrc, entry)?, read_u32(rsrc, entry.checked_add(4)?)?))
    })
}

fn read_rsrc_string(rsrc: &[u8], offset: usize) -> Option<String> {
    let len = read_u16(rsrc, offset)? as usize;
    let bytes_start = offset.checked_add(2)?;
    let byte_len = len.checked_mul(2)?;
    let bytes_end = bytes_start.checked_add(byte_len)?;
    if bytes_end <= rsrc.len() {
        let u16s: Vec<u16> = rsrc[bytes_start..bytes_end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    } else {
        None
    }
}

fn format_resource_type(type_id: u32, name: Option<&str>) -> String {
    if let Some(n) = name {
        return n.to_string();
    }
    match type_id {
        1 => "Cursor".into(),
        2 => "Bitmap".into(),
        3 => "Icon".into(),
        4 => "Menu".into(),
        5 => "Dialog".into(),
        6 => "StringTable".into(),
        7 => "FontDir".into(),
        8 => "Font".into(),
        9 => "Accelerator".into(),
        10 => "RCDATA".into(),
        11 => "MessageTable".into(),
        12 => "GroupCursor".into(),
        14 => "GroupIcon".into(),
        16 => "Version".into(),
        23 => "HTML".into(),
        24 => "Manifest".into(),
        _ => format!("Type_{}", type_id),
    }
}

fn detect_magic_hint(data: &[u8]) -> Option<String> {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        Some("PE (MZ)".into())
    } else if data.len() >= 4 && data[0..4] == [0x7F, b'E', b'L', b'F'] {
        Some("ELF".into())
    } else if data.len() >= 4 && (data[0..4] == [0x50, 0x4B, 0x03, 0x04] || data[0..4] == [0x50, 0x4B, 0x05, 0x06]) {
        Some("ZIP".into())
    } else if data.len() >= 4 && data[0..4] == [0x4D, 0x53, 0x43, 0x46] {
        Some("CAB".into())
    } else if data.len() >= 3 && data[0..3] == [0x1F, 0x8B, 0x08] {
        Some("GZIP".into())
    } else {
        None
    }
}

fn parse_resources_and_manifest(
    rsrc_bytes: &[u8],
    sections: &[goblin::pe::section_table::SectionTable],
    file_alignment: u32,
    full_data: &[u8],
) -> (Vec<ResourceEntry>, Option<String>) {
    let mut resources = Vec::new();
    let mut manifest = None;
    let mut visited_dirs = std::collections::HashSet::new();
    visited_dirs.insert(0);

    const MAX_RESOURCES: usize = 2048;

    // Level 1: Type
    for (type_id_raw, off1) in iter_rsrc_entries(rsrc_bytes, 0) {
        if resources.len() >= MAX_RESOURCES {
            break;
        }
        let (type_id, type_name_custom) = if (type_id_raw & 0x8000_0000) != 0 {
            let str_off = (type_id_raw & 0x7FFF_FFFF) as usize;
            (type_id_raw, read_rsrc_string(rsrc_bytes, str_off))
        } else {
            (type_id_raw, None)
        };
        let type_name = format_resource_type(type_id, type_name_custom.as_deref());

        if (off1 & 0x8000_0000) != 0 {
            let dir2_off = (off1 & 0x7FFF_FFFF) as usize;
            if dir2_off >= rsrc_bytes.len() || !visited_dirs.insert(dir2_off) {
                continue;
            }
            // Level 2: Name or ID
            for (name_id_raw, off2) in iter_rsrc_entries(rsrc_bytes, dir2_off) {
                if resources.len() >= MAX_RESOURCES {
                    break;
                }
                let name_or_id = if (name_id_raw & 0x8000_0000) != 0 {
                    let str_off = (name_id_raw & 0x7FFF_FFFF) as usize;
                    read_rsrc_string(rsrc_bytes, str_off).unwrap_or_else(|| format!("{:#x}", name_id_raw))
                } else {
                    format!("#{}", name_id_raw)
                };

                if (off2 & 0x8000_0000) != 0 {
                    let dir3_off = (off2 & 0x7FFF_FFFF) as usize;
                    if dir3_off >= rsrc_bytes.len() || !visited_dirs.insert(dir3_off) {
                        continue;
                    }
                    // Level 3: Language
                    for (lang_raw, data_off_raw) in iter_rsrc_entries(rsrc_bytes, dir3_off) {
                        if resources.len() >= MAX_RESOURCES {
                            break;
                        }
                        if (data_off_raw & 0x8000_0000) == 0 {
                            let leaf_off = data_off_raw as usize;
                            if let (Some(rva), Some(size)) = (read_u32(rsrc_bytes, leaf_off), read_u32(rsrc_bytes, leaf_off.saturating_add(4))) {
                                let rva = rva as usize;
                                let size = size as usize;
                                let file_offset = goblin::pe::utils::find_offset(
                                    rva,
                                    sections,
                                    file_alignment,
                                    &goblin::pe::options::ParseOptions::default(),
                                ).unwrap_or(0);

                                if file_offset > 0 && file_offset < full_data.len() {
                                    let end = file_offset.saturating_add(size).min(full_data.len());
                                    let actual_slice = &full_data[file_offset..end];
                                    let entropy = shannon_entropy(actual_slice);
                                    let magic_hint = detect_magic_hint(actual_slice);

                                    if type_id == 24 && manifest.is_none() {
                                        manifest = Some(String::from_utf8_lossy(actual_slice).to_string());
                                    }

                                    resources.push(ResourceEntry {
                                        type_id,
                                        type_name: type_name.clone(),
                                        name_or_id: name_or_id.clone(),
                                        lang: lang_raw as u16,
                                        rva: rva as u32,
                                        file_offset,
                                        size,
                                        entropy,
                                        magic_hint,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (resources, manifest)
}

fn parse_tls_directory(
    data: &[u8],
    tls_rva: usize,
    tls_size: usize,
    sections: &[goblin::pe::section_table::SectionTable],
    file_alignment: u32,
    image_base: u64,
    is_64bit: bool,
) -> Option<TlsInfo> {
    if tls_rva == 0 || tls_size == 0 {
        return None;
    }
    let tls_offset = goblin::pe::utils::find_offset(
        tls_rva,
        sections,
        file_alignment,
        &goblin::pe::options::ParseOptions::default(),
    )?;

    if tls_offset >= data.len() {
        return None;
    }

    let (raw_data_start_va, raw_data_end_va, index_va, callbacks_va, zero_fill_size, characteristics) =
        if is_64bit {
            if tls_offset + 40 > data.len() {
                return None;
            }
            let start = u64::from_le_bytes(data[tls_offset..tls_offset + 8].try_into().ok()?);
            let end = u64::from_le_bytes(data[tls_offset + 8..tls_offset + 16].try_into().ok()?);
            let idx = u64::from_le_bytes(data[tls_offset + 16..tls_offset + 24].try_into().ok()?);
            let cb = u64::from_le_bytes(data[tls_offset + 24..tls_offset + 32].try_into().ok()?);
            let zf = u32::from_le_bytes(data[tls_offset + 32..tls_offset + 36].try_into().ok()?);
            let ch = u32::from_le_bytes(data[tls_offset + 36..tls_offset + 40].try_into().ok()?);
            (start, end, idx, cb, zf, ch)
        } else {
            if tls_offset + 24 > data.len() {
                return None;
            }
            let start = u32::from_le_bytes(data[tls_offset..tls_offset + 4].try_into().ok()?) as u64;
            let end = u32::from_le_bytes(data[tls_offset + 4..tls_offset + 8].try_into().ok()?) as u64;
            let idx = u32::from_le_bytes(data[tls_offset + 8..tls_offset + 12].try_into().ok()?) as u64;
            let cb = u32::from_le_bytes(data[tls_offset + 12..tls_offset + 16].try_into().ok()?) as u64;
            let zf = u32::from_le_bytes(data[tls_offset + 16..tls_offset + 20].try_into().ok()?);
            let ch = u32::from_le_bytes(data[tls_offset + 20..tls_offset + 24].try_into().ok()?);
            (start, end, idx, cb, zf, ch)
        };

    let mut callbacks = Vec::new();
    if callbacks_va != 0 && callbacks_va >= image_base {
        let cb_rva = (callbacks_va - image_base) as usize;
        if let Some(cb_offset) = goblin::pe::utils::find_offset(
            cb_rva,
            sections,
            file_alignment,
            &goblin::pe::options::ParseOptions::default(),
        ) {
            let mut cur = cb_offset;
            let ptr_size = if is_64bit { 8 } else { 4 };
            for _ in 0..128 {
                if cur + ptr_size > data.len() {
                    break;
                }
                let ptr = if is_64bit {
                    u64::from_le_bytes(data[cur..cur + 8].try_into().unwrap_or_default())
                } else {
                    u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap_or_default()) as u64
                };
                if ptr == 0 {
                    break;
                }
                callbacks.push(ptr);
                cur += ptr_size;
            }
        }
    }

    Some(TlsInfo {
        raw_data_start_va,
        raw_data_end_va,
        index_va,
        callbacks_va,
        zero_fill_size,
        characteristics,
        callbacks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_embedded_pe() {
        let dummy = vec![0x90; 200];
        assert!(find_embedded_pe(&dummy, false).is_none());
    }

    #[test]
    fn test_compute_imphash_empty() {
        assert!(compute_imphash(&[]).is_none());
    }

    #[test]
    fn test_compute_imphash_populated() {
        let imports = vec![
            goblin::pe::import::Import {
                name: "ExitProcess".into(),
                dll: "KERNEL32.DLL",
                ordinal: 0,
                offset: 0,
                rva: 0,
                size: 0,
            },
            goblin::pe::import::Import {
                name: "".into(),
                dll: "user32.dll",
                ordinal: 42,
                offset: 0,
                rva: 0,
                size: 0,
            },
        ];
        let hash = compute_imphash(&imports).unwrap();
        let expected: String = Md5::digest(b"kernel32.exitprocess,user32.ord42")
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_parse_rich_header() {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes()); // e_lfanew = 128

        let xor_key = 0x1234_5678u32;
        let dans_masked = 0x536E_6144u32 ^ xor_key;
        let dans_off = 0x40; // 64
        data[dans_off..dans_off + 4].copy_from_slice(&dans_masked.to_le_bytes());
        // 3 padding dwords
        data[dans_off + 4..dans_off + 8].copy_from_slice(&xor_key.to_le_bytes());
        data[dans_off + 8..dans_off + 12].copy_from_slice(&xor_key.to_le_bytes());
        data[dans_off + 12..dans_off + 16].copy_from_slice(&xor_key.to_le_bytes());
        // 1 record: prod_id = 14 (Utc C compiler), build = 1234, count = 5
        let comp_id = (14u32 << 16) | 1234u32;
        data[dans_off + 16..dans_off + 20].copy_from_slice(&(comp_id ^ xor_key).to_le_bytes());
        data[dans_off + 20..dans_off + 24].copy_from_slice(&(5u32 ^ xor_key).to_le_bytes());
        // Rich signature and key at 88
        let rich_off = dans_off + 24;
        data[rich_off..rich_off + 4].copy_from_slice(b"Rich");
        data[rich_off + 4..rich_off + 8].copy_from_slice(&xor_key.to_le_bytes());

        let res = parse_rich_header(&data).expect("Should parse rich header");
        assert_eq!(res.xor_key, 0x1234_5678);
        assert_eq!(res.records.len(), 1);
        assert_eq!(res.records[0].prod_id, 14);
        assert_eq!(res.records[0].build, 1234);
        assert_eq!(res.records[0].count, 5);
        assert_eq!(res.records[0].tool_name.as_deref(), Some("C Compiler"));
        assert_eq!(res.rich_hash.len(), 32);
    }

    #[test]
    fn test_scan_xor_payloads_pe() {
        let key = 0x5a;
        let mut raw_pe = vec![0u8; 256];
        raw_pe[0] = b'M';
        raw_pe[1] = b'Z';
        raw_pe[0x3c] = 0x80; // e_lfanew = 128
        raw_pe[0x80] = b'P';
        raw_pe[0x81] = b'E';
        raw_pe[0x82] = 0;
        raw_pe[0x83] = 0;

        let xored: Vec<u8> = raw_pe.iter().map(|b| b ^ key).collect();
        let matches = scan_xor_payloads(&xored, 0x1000, "Overlay");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, 0x5a);
        assert_eq!(matches[0].offset, 0x1000);
        assert!(matches[0].description.contains("PE executable"));
    }

    #[test]
    fn test_scan_xor_payloads_url() {
        let key = 0x42;
        let mut raw = vec![0x00; 64];
        raw.extend_from_slice(b"https://c2-malware-domain.xyz/payload.bin\0");
        raw.extend_from_slice(&[0x00; 32]);
        let buffer: Vec<u8> = raw.iter().map(|b| b ^ key).collect();

        let matches = scan_xor_payloads(&buffer, 0x500, "Section .data");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, 0x42);
        assert_eq!(matches[0].sample_preview, "https://c2-malware-domain.xyz/payload.bin");
    }

    #[test]
    fn test_scan_xor_payloads_dos_stub() {
        let key = 0x77;
        let stub = b"This program cannot be run in DOS mode";
        let xored_stub: Vec<u8> = stub.iter().map(|b| b ^ key).collect();

        let matches = scan_xor_payloads(&xored_stub, 0x200, "Overlay");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, 0x77);
        assert_eq!(matches[0].description, "XOR-encoded DOS stub");
    }

    #[test]
    fn test_scan_xor_payloads_plaintext_ignored() {
        let url = b"https://legitimate.org/test";
        let matches = scan_xor_payloads(url, 0, "Overlay");
        // Key 0 is plaintext, must be ignored by XOR brute-forcer
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detect_magic_hint() {
        assert_eq!(detect_magic_hint(b"MZ\x90\x00"), Some("PE (MZ)".into()));
        assert_eq!(detect_magic_hint(b"\x7FELF"), Some("ELF".into()));
        assert_eq!(detect_magic_hint(b"PK\x03\x04"), Some("ZIP".into()));
        assert_eq!(detect_magic_hint(b"PK\x05\x06"), Some("ZIP".into()));
        assert_eq!(detect_magic_hint(b"MSCF"), Some("CAB".into()));
        assert_eq!(detect_magic_hint(b"\x1F\x8B\x08"), Some("GZIP".into()));
        assert_eq!(detect_magic_hint(b"plain text data"), None);
    }

    #[test]
    fn test_format_resource_type() {
        assert_eq!(format_resource_type(10, None), "RCDATA");
        assert_eq!(format_resource_type(24, None), "Manifest");
        assert_eq!(format_resource_type(3, None), "Icon");
        assert_eq!(format_resource_type(999, None), "Type_999");
        assert_eq!(format_resource_type(10, Some("CUSTOM")), "CUSTOM");
    }

    #[test]
    fn test_parse_resources_and_manifest() {
        // Build synthetic 3-level .rsrc directory table
        let mut rsrc = vec![0u8; 128];
        // Level 1: Root directory at 0. 1 ID entry.
        rsrc[14..16].copy_from_slice(&1u16.to_le_bytes()); // NumberOfIdEntries = 1
        rsrc[16..20].copy_from_slice(&10u32.to_le_bytes()); // Type = 10 (RCDATA)
        rsrc[20..24].copy_from_slice(&(0x8000_0000 | 0x20u32).to_le_bytes()); // Subdirectory at 0x20

        // Level 2: Type directory at 0x20. 1 ID entry.
        rsrc[0x20 + 14..0x20 + 16].copy_from_slice(&1u16.to_le_bytes());
        rsrc[0x20 + 16..0x20 + 20].copy_from_slice(&1u32.to_le_bytes()); // Name ID = 1
        rsrc[0x20 + 20..0x20 + 24].copy_from_slice(&(0x8000_0000 | 0x40u32).to_le_bytes()); // Subdirectory at 0x40

        // Level 3: Name directory at 0x40. 1 ID entry (Lang).
        rsrc[0x40 + 14..0x40 + 16].copy_from_slice(&1u16.to_le_bytes());
        rsrc[0x40 + 16..0x40 + 20].copy_from_slice(&1033u32.to_le_bytes()); // Lang = 1033
        rsrc[0x40 + 20..0x40 + 24].copy_from_slice(&0x60u32.to_le_bytes()); // Data entry at 0x60

        // Leaf Data entry at 0x60
        rsrc[0x60..0x64].copy_from_slice(&0x1000u32.to_le_bytes()); // RVA = 0x1000
        rsrc[0x64..0x68].copy_from_slice(&16u32.to_le_bytes()); // Size = 16

        // Section table mapping RVA 0x1000 to file offset 0x200
        let sec = goblin::pe::section_table::SectionTable {
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            pointer_to_raw_data: 0x200,
            size_of_raw_data: 0x1000,
            ..Default::default()
        };

        // Full binary data with embedded MZ header at 0x200
        let mut full_data = vec![0u8; 0x1000];
        full_data[0x200] = b'M';
        full_data[0x201] = b'Z';
        full_data[0x202..0x210].copy_from_slice(&[0x90; 14]);

        let (resources, manifest) = parse_resources_and_manifest(&rsrc, &[sec], 0x200, &full_data);

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].type_id, 10);
        assert_eq!(resources[0].type_name, "RCDATA");
        assert_eq!(resources[0].name_or_id, "#1");
        assert_eq!(resources[0].lang, 1033);
        assert_eq!(resources[0].rva, 0x1000);
        assert_eq!(resources[0].file_offset, 0x200);
        assert_eq!(resources[0].size, 16);
        assert_eq!(resources[0].magic_hint, Some("PE (MZ)".to_string()));
        assert!(manifest.is_none());
    }

    #[test]
    fn test_parse_tls_directory() {
        let sec = goblin::pe::section_table::SectionTable {
            virtual_address: 0x2000,
            virtual_size: 0x1000,
            pointer_to_raw_data: 0x400,
            size_of_raw_data: 0x1000,
            ..Default::default()
        };

        let image_base = 0x140000000u64;
        let mut data = vec![0u8; 0x2000];

        // TLS directory 64-bit at offset 0x400:
        // raw_data_start_va (u64): 0x140003000
        // raw_data_end_va (u64): 0x140003100
        // index_va (u64): 0x140002800
        // callbacks_va (u64): 0x140002500 (RVA 0x2500 -> file offset 0x900)
        // zero_fill_size (u32): 0x10
        // characteristics (u32): 0x0
        data[0x400..0x408].copy_from_slice(&0x140003000u64.to_le_bytes());
        data[0x408..0x410].copy_from_slice(&0x140003100u64.to_le_bytes());
        data[0x410..0x418].copy_from_slice(&0x140002800u64.to_le_bytes());
        data[0x418..0x420].copy_from_slice(&0x140002500u64.to_le_bytes());
        data[0x420..0x424].copy_from_slice(&0x10u32.to_le_bytes());
        data[0x424..0x428].copy_from_slice(&0u32.to_le_bytes());

        // Callbacks array at RVA 0x2500 (offset 0x400 + 0x500 = 0x900)
        // Callback 1: 0x140001050
        // Callback 2: 0x140001080
        // Terminator: 0x0
        data[0x900..0x908].copy_from_slice(&0x140001050u64.to_le_bytes());
        data[0x908..0x910].copy_from_slice(&0x140001080u64.to_le_bytes());
        data[0x910..0x918].copy_from_slice(&0u64.to_le_bytes());

        let tls_opt = parse_tls_directory(&data, 0x2000, 40, &[sec], 0x200, image_base, true);
        assert!(tls_opt.is_some());
        let tls = tls_opt.unwrap();
        assert_eq!(tls.raw_data_start_va, 0x140003000);
        assert_eq!(tls.raw_data_end_va, 0x140003100);
        assert_eq!(tls.index_va, 0x140002800);
        assert_eq!(tls.callbacks_va, 0x140002500);
        assert_eq!(tls.zero_fill_size, 0x10);
        assert_eq!(tls.callbacks.len(), 2);
        assert_eq!(tls.callbacks[0], 0x140001050);
        assert_eq!(tls.callbacks[1], 0x140001080);
    }
}
