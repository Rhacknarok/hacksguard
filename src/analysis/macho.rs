use crate::analysis::basic::shannon_entropy;
use crate::models::*;
use goblin::mach::{constants::cputype, header, load_command::CommandVariant, Mach, MachO, SingleArch};

/// Analyze Mach-O binary (single architecture or Fat container).
pub fn analyze(data: &[u8]) -> Result<MachoAnalysis> {
    match Mach::parse(data)? {
        Mach::Binary(macho) => analyze_single(&macho, data),
        Mach::Fat(fat) => {
            let mut best_idx = 0;
            let mut best_score = -1;
            let mut best_slice: &[u8] = data;

            for (i, arch_res) in fat.iter_arches().enumerate() {
                if let Ok(arch) = arch_res {
                    let score = if arch.cputype == cputype::CPU_TYPE_ARM64 {
                        3
                    } else if arch.cputype == cputype::CPU_TYPE_X86_64 {
                        2
                    } else {
                        1
                    };
                    if score > best_score {
                        best_score = score;
                        best_idx = i;
                        best_slice = arch.slice(data);
                    }
                }
            }

            match fat.get(best_idx)? {
                SingleArch::MachO(macho) => analyze_single(&macho, best_slice),
                _ => return Err("Selected fat entry is not a Mach-O binary".into()),
            }
        }
    }
}

fn analyze_single(macho: &MachO, data: &[u8]) -> Result<MachoAnalysis> {
    let cpu_type = match macho.header.cputype {
        cputype::CPU_TYPE_X86 => "x86 (32-bit)".into(),
        cputype::CPU_TYPE_X86_64 => "x86-64 (AMD64)".into(),
        cputype::CPU_TYPE_ARM => "ARM (32-bit)".into(),
        cputype::CPU_TYPE_ARM64 => "ARM64 (AArch64)".into(),
        cputype::CPU_TYPE_ARM64_32 => "ARM64_32 (ILP32)".into(),
        cputype::CPU_TYPE_POWERPC => "PowerPC (32-bit)".into(),
        cputype::CPU_TYPE_POWERPC64 => "PowerPC 64-bit".into(),
        other => format!("Unknown ({:#010x})", other),
    };

    let file_type = match macho.header.filetype {
        header::MH_OBJECT => "Relocatable Object (MH_OBJECT)".into(),
        header::MH_EXECUTE => "Executable (MH_EXECUTE)".into(),
        header::MH_DYLIB => "Dynamic Library (MH_DYLIB)".into(),
        header::MH_BUNDLE => "Bundle (MH_BUNDLE)".into(),
        header::MH_DYLINKER => "Dynamic Linker (MH_DYLINKER)".into(),
        header::MH_DSYM => "Debug Symbols (MH_DSYM)".into(),
        header::MH_KEXT_BUNDLE => "Kernel Extension (MH_KEXT_BUNDLE)".into(),
        other => format!("Other ({:#x})", other),
    };

    let flags = macho.header.flags;
    let mut flag_parts = Vec::new();
    if flags & header::MH_PIE != 0 { flag_parts.push("PIE"); }
    if flags & header::MH_NO_HEAP_EXECUTION != 0 { flag_parts.push("NO_HEAP_EXEC"); }
    if flags & header::MH_ALLOW_STACK_EXECUTION != 0 { flag_parts.push("ALLOW_STACK_EXEC"); }
    if flags & header::MH_TWOLEVEL != 0 { flag_parts.push("TWOLEVEL"); }
    if flags & header::MH_BINDATLOAD != 0 { flag_parts.push("BINDATLOAD"); }
    if flags & header::MH_DYLDLINK != 0 { flag_parts.push("DYLDLINK"); }
    let flags_str = if flag_parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        flag_parts.join(" | ")
    };

    let is_pie = flags & header::MH_PIE != 0;
    let allow_stack_execution = flags & header::MH_ALLOW_STACK_EXECUTION != 0;
    let no_heap_execution = flags & header::MH_NO_HEAP_EXECUTION != 0;
    let entry_point = macho.entry;
    let is_64bit = macho.is_64;

    let mut has_code_signature = false;
    for lc in &macho.load_commands {
        if let CommandVariant::CodeSignature(_) = &lc.command {
            has_code_signature = true;
        }
    }

    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut has_wx_segment = false;
    let mut has_wx_section = false;

    for seg in &macho.segments {
        let seg_name = seg.name().unwrap_or("").to_string();
        let is_read = (seg.initprot & 0x01) != 0;
        let is_write = (seg.initprot & 0x02) != 0;
        let is_exec = (seg.initprot & 0x04) != 0;

        if is_write && is_exec && seg.filesize > 0 {
            has_wx_segment = true;
        }

        segments.push(MachoSegment {
            name: seg_name,
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            fileoff: seg.fileoff,
            filesize: seg.filesize,
            maxprot: prot_to_str(seg.maxprot),
            initprot: prot_to_str(seg.initprot),
            is_read,
            is_write,
            is_exec,
        });

        if let Ok(sections_iter) = seg.sections() {
            for (sect, _) in sections_iter {
                let sect_name = sect.name().unwrap_or("").to_string();
                let parent_seg = sect.segname().unwrap_or("").to_string();
                let addr = sect.addr;
                let size = sect.size;
                let offset = sect.offset as u64;

                let is_sect_exec = (sect.flags & 0x80000400) != 0 || is_exec;
                let is_sect_write = is_write;

                let start = offset as usize;
                let end = (start + size as usize).min(data.len());

                let mut sec_anomalies = Vec::new();
                let is_zerofill = (sect.flags & 0xff) == 1; // S_ZEROFILL
                let entropy = if !is_zerofill && start < end && start < data.len() {
                    let sec_data = &data[start..end];
                    let ent = shannon_entropy(sec_data);
                    if ent > 7.2 && is_sect_exec {
                        sec_anomalies.push(format!("High entropy ({:.2}) in executable section", ent));
                    }
                    ent
                } else {
                    0.0
                };

                if is_sect_write && is_sect_exec {
                    has_wx_section = true;
                    sec_anomalies.push("Writable and Executable section (W+X)".to_string());
                }

                sections.push(MachoSection {
                    sectname: sect_name,
                    segname: parent_seg,
                    addr,
                    size,
                    offset,
                    entropy,
                    is_executable: is_sect_exec,
                    is_writable: is_sect_write,
                    anomalies: sec_anomalies,
                });
            }
        }
    }

    let dylibs: Vec<String> = macho.libs.iter().map(|s| s.to_string()).collect();
    let rpaths: Vec<String> = macho.rpaths.iter().map(|s| s.to_string()).collect();

    let mut imported_symbols = Vec::new();
    if let Ok(imports) = macho.imports() {
        for imp in imports {
            if imp.name.is_empty() {
                continue;
            }
            let clean_name = imp.name.strip_prefix('_').unwrap_or(imp.name);
            let risk = classify_macho_api(clean_name);
            imported_symbols.push(ImportFunction {
                name: imp.name.to_string(),
                risk,
            });
        }
    }

    let mut exported_symbols = Vec::new();
    if let Ok(exports) = macho.exports() {
        for exp in exports {
            if !exp.name.is_empty() {
                exported_symbols.push(exp.name.to_string());
            }
        }
    }

    // Direct Syscalls scan
    let is_arm64 = macho.header.cputype == cputype::CPU_TYPE_ARM64
        || macho.header.cputype == cputype::CPU_TYPE_ARM64_32;
    let is_x86_64 = macho.header.cputype == cputype::CPU_TYPE_X86_64;
    let is_x86_32 = macho.header.cputype == cputype::CPU_TYPE_X86;

    let mut syscall_locations = Vec::new();

    for seg in &macho.segments {
        let is_exec = (seg.initprot & 0x04) != 0;
        if is_exec && seg.filesize > 0 {
            let start = seg.fileoff as usize;
            let end = (start + seg.filesize as usize).min(data.len());
            if start < end {
                let code = &data[start..end];
                if is_arm64 {
                    let locs = scan_arm64_buffer(code, seg.vmaddr);
                    syscall_locations.extend(locs);
                } else if is_x86_64 {
                    let locs = scan_x86_buffer(code, seg.vmaddr, 64);
                    syscall_locations.extend(locs);
                } else if is_x86_32 {
                    let locs = scan_x86_buffer(code, seg.vmaddr, 32);
                    syscall_locations.extend(locs);
                }
            }
        }
    }

    let direct_syscalls = !syscall_locations.is_empty();

    // Anomalies
    let mut anomalies = Vec::new();
    if has_wx_segment {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Executable and Writable segment detected (W+X)".into(),
        });
    }
    if has_wx_section {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Executable and Writable section detected (W+X)".into(),
        });
    }
    if !is_pie {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "PIE (Position Independent Executable) disabled".into(),
        });
    }
    if allow_stack_execution {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Executable stack allowed (MH_ALLOW_STACK_EXECUTION)".into(),
        });
    }
    if !no_heap_execution {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Heap execution not explicitly restricted (MH_NO_HEAP_EXECUTION missing)".into(),
        });
    }
    if !has_code_signature {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Missing code signature (LC_CODE_SIGNATURE absent)".into(),
        });
    }
    if direct_syscalls {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: format!("Direct syscall instructions found ({} instances)", syscall_locations.len()),
        });
    }

    let mitigations = MachoMitigations {
        pie: is_pie,
        allow_stack_execution,
        no_heap_execution,
        has_code_signature,
        rpaths: rpaths.clone(),
    };

    let ep_bytes = extract_macho_ep_bytes(data, macho);

    Ok(MachoAnalysis {
        cpu_type,
        file_type,
        flags_str,
        entry_point,
        is_64bit,
        is_pie,
        segments,
        sections,
        dylibs,
        rpaths,
        imported_symbols,
        exported_symbols,
        mitigations,
        anomalies,
        has_code_signature,
        ep_bytes,
        direct_syscalls,
        syscall_locations,
    })
}

fn prot_to_str(prot: u32) -> String {
    let mut s = String::with_capacity(3);
    s.push(if prot & 0x01 != 0 { 'r' } else { '-' });
    s.push(if prot & 0x02 != 0 { 'w' } else { '-' });
    s.push(if prot & 0x04 != 0 { 'x' } else { '-' });
    s
}

fn extract_macho_ep_bytes(data: &[u8], macho: &MachO) -> Vec<u8> {
    let ep = macho.entry;
    if ep == 0 {
        return Vec::new();
    }

    for seg in &macho.segments {
        if ep >= seg.vmaddr && ep < seg.vmaddr + seg.vmsize {
            let offset = (ep - seg.vmaddr + seg.fileoff) as usize;
            if offset < data.len() {
                let end = (offset + 32).min(data.len());
                return data[offset..end].to_vec();
            }
        }
    }

    if (ep as usize) < data.len() {
        let end = ((ep as usize) + 32).min(data.len());
        return data[(ep as usize)..end].to_vec();
    }

    Vec::new()
}

/// Scan ARM64 byte buffer for `svc #imm` instructions.
/// Format: `1101 0100 0000 xxxx xxxx xxxx xxx0 0001`
/// Mask `0xFFE0_001F == 0xD400_0001`, `imm = (word >> 5) & 0xFFFF`.
pub fn scan_arm64_buffer(code: &[u8], base_vaddr: u64) -> Vec<SyscallLocation> {
    let mut locations = Vec::new();
    for (chunk_idx, chunk) in code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if (word & 0xFFE0_001F) == 0xD400_0001 {
            let imm = (word >> 5) & 0xFFFF;
            locations.push(SyscallLocation {
                address: base_vaddr + (chunk_idx * 4) as u64,
                is_indirect: false,
                instruction_str: format!("svc {:#x}", imm),
            });
        }
    }
    locations
}

/// Scan x86/x64 byte buffer for `syscall`, `sysenter`, and `int 0x80`.
pub fn scan_x86_buffer(code: &[u8], base_vaddr: u64, bitness: u32) -> Vec<SyscallLocation> {
    let mut locations = Vec::new();
    let mut decoder = iced_x86::Decoder::with_ip(bitness, code, base_vaddr, iced_x86::DecoderOptions::NONE);
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            continue;
        }
        let mnemonic = instr.mnemonic();
        let is_syscall = match mnemonic {
            iced_x86::Mnemonic::Syscall | iced_x86::Mnemonic::Sysenter => true,
            iced_x86::Mnemonic::Int => instr.immediate8() == 0x80,
            _ => false,
        };
        if is_syscall {
            locations.push(SyscallLocation {
                address: instr.ip(),
                is_indirect: false,
                instruction_str: format!("{:?}", mnemonic).to_lowercase(),
            });
        }
    }
    locations
}

fn classify_macho_api(name: &str) -> ApiRisk {
    match name {
        // Critical: Process injection, Mach task manipulation, memory patching
        "task_for_pid"
        | "mach_vm_write"
        | "mach_vm_read"
        | "mach_vm_allocate"
        | "mach_vm_protect"
        | "mach_vm_deallocate"
        | "thread_create_running"
        | "thread_set_state"
        | "thread_get_state"
        | "thread_resume"
        | "thread_suspend"
        | "ptrace"
        | "process_vm_writev"
        | "process_vm_readv"
        | "NSCreateObjectFileImageFromMemory"
        | "NSLinkModule"
        | "CGEventTapCreate"
        | "IOHIDManagerOpen"
        | "AuthorizationExecuteWithPrivileges" => ApiRisk::Critical,

        // High: Execution, dynamic loading, credentials, screen capture
        "system"
        | "popen"
        | "execve"
        | "execv"
        | "posix_spawn"
        | "posix_spawnp"
        | "fork"
        | "dlopen"
        | "dlsym"
        | "NSAppleScript"
        | "SMJobBless"
        | "SecItemCopyMatching"
        | "SecKeychainItemCopyAttributesAndData"
        | "CGWindowListCreateImage" => ApiRisk::High,

        // Medium: Networking, file access, permissions
        "socket"
        | "connect"
        | "bind"
        | "listen"
        | "sendto"
        | "recvfrom"
        | "getaddrinfo"
        | "chmod"
        | "chown"
        | "unlink"
        | "remove"
        | "open"
        | "read"
        | "write" => ApiRisk::Medium,

        _ => ApiRisk::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm64_syscall_scanner() {
        // svc #0:  0x01, 0x00, 0x00, 0xd4
        // nop:     0x1f, 0x20, 0x03, 0xd5
        // svc #0x80: 0x01, 0x10, 0x00, 0xd4
        let code = [
            0x01, 0x00, 0x00, 0xd4, // svc 0x0
            0x1f, 0x20, 0x03, 0xd5, // nop
            0x01, 0x10, 0x00, 0xd4, // svc 0x80
        ];
        let locs = scan_arm64_buffer(&code, 0x1000);
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].address, 0x1000);
        assert_eq!(locs[0].instruction_str, "svc 0x0");
        assert_eq!(locs[1].address, 0x1008);
        assert_eq!(locs[1].instruction_str, "svc 0x80");
    }

    #[test]
    fn test_macho_api_classification() {
        assert_eq!(classify_macho_api("task_for_pid"), ApiRisk::Critical);
        assert_eq!(classify_macho_api("mach_vm_write"), ApiRisk::Critical);
        assert_eq!(classify_macho_api("posix_spawn"), ApiRisk::High);
        assert_eq!(classify_macho_api("connect"), ApiRisk::Medium);
        assert_eq!(classify_macho_api("printf"), ApiRisk::Low);
    }

    #[test]
    fn test_prot_to_str() {
        assert_eq!(prot_to_str(0x01), "r--");
        assert_eq!(prot_to_str(0x03), "rw-");
        assert_eq!(prot_to_str(0x07), "rwx");
        assert_eq!(prot_to_str(0x05), "r-x");
    }
}


