use crate::analysis::basic::shannon_entropy;
use crate::models::*;
use goblin::elf::header::*;
use goblin::elf::program_header::*;
use goblin::elf::section_header::*;
use goblin::Object;

/// Parse ELF headers, program headers, sections, symbols, mitigations and detect anomalies.
pub fn analyze(data: &[u8]) -> Result<ElfAnalysis> {
    let elf = match Object::parse(data)? {
        Object::Elf(elf) => elf,
        _ => return Err("Not an ELF file".into()),
    };

    let machine = match elf.header.e_machine {
        EM_386 => "x86 (i386)".into(),
        EM_X86_64 => "x86-64 (AMD64)".into(),
        EM_ARM => "ARM".into(),
        EM_AARCH64 => "AArch64 (ARM64)".into(),
        EM_MIPS => "MIPS".into(),
        EM_RISCV => "RISC-V".into(),
        EM_PPC => "PowerPC".into(),
        EM_PPC64 => "PowerPC 64".into(),
        EM_S390 => "IBM S/390".into(),
        EM_SPARC => "SPARC".into(),
        EM_SPARCV9 => "SPARC V9".into(),
        other => format!("Unknown ({:#06x})", other),
    };

    let class = if elf.is_64 { "64-bit".into() } else { "32-bit".into() };
    let endianness = if elf.little_endian { "Little Endian".into() } else { "Big Endian".into() };

    let elf_type = match elf.header.e_type {
        ET_EXEC => "Executable (ET_EXEC)".into(),
        ET_DYN => if elf.is_lib { "Shared Object (ET_DYN)".into() } else { "Position-Independent Executable (ET_DYN)".into() },
        ET_REL => "Relocatable (ET_REL)".into(),
        ET_CORE => "Core Dump (ET_CORE)".into(),
        other => format!("Other ({:#06x})", other),
    };

    let entry_point = elf.header.e_entry;
    let is_64bit = elf.is_64;
    let is_pie = elf.header.e_type == ET_DYN;
    let interpreter = elf.interpreter.map(|s| s.to_string());
    let soname = elf.soname.map(|s| s.to_string());

    // ── Program Headers ──
    let mut program_headers = Vec::new();
    let mut has_wx_segment = false;
    let mut gnu_stack_ph = None;
    let mut gnu_relro_ph = None;

    for ph in &elf.program_headers {
        let ph_type = match ph.p_type {
            PT_NULL => "PT_NULL",
            PT_LOAD => "PT_LOAD",
            PT_DYNAMIC => "PT_DYNAMIC",
            PT_INTERP => "PT_INTERP",
            PT_NOTE => "PT_NOTE",
            PT_SHLIB => "PT_SHLIB",
            PT_PHDR => "PT_PHDR",
            PT_TLS => "PT_TLS",
            PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
            PT_GNU_STACK => "PT_GNU_STACK",
            PT_GNU_RELRO => "PT_GNU_RELRO",
            PT_GNU_PROPERTY => "PT_GNU_PROPERTY",
            _ => "OTHER",
        }
        .to_string();

        let is_read = ph.p_flags & PF_R != 0;
        let is_write = ph.p_flags & PF_W != 0;
        let is_exec = ph.p_flags & PF_X != 0;

        let mut flags = String::new();
        if is_read { flags.push('R'); }
        if is_write { flags.push('W'); }
        if is_exec { flags.push('X'); }

        if ph.p_type == PT_LOAD && is_write && is_exec {
            has_wx_segment = true;
        }

        if ph.p_type == PT_GNU_STACK {
            gnu_stack_ph = Some(ph.clone());
        }
        if ph.p_type == PT_GNU_RELRO {
            gnu_relro_ph = Some(ph.clone());
        }

        program_headers.push(ElfProgramHeader {
            ph_type,
            flags,
            is_read,
            is_write,
            is_exec,
            virtual_address: ph.p_vaddr,
            memory_size: ph.p_memsz,
            file_offset: ph.p_offset,
            file_size: ph.p_filesz,
            alignment: ph.p_align,
        });
    }

    // ── Sections ──
    let mut sections = Vec::new();
    let mut has_wx_section = false;
    let mut anomalies = Vec::new();

    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();

        let sec_type = match sh.sh_type {
            SHT_NULL => "SHT_NULL",
            SHT_PROGBITS => "SHT_PROGBITS",
            SHT_SYMTAB => "SHT_SYMTAB",
            SHT_STRTAB => "SHT_STRTAB",
            SHT_RELA => "SHT_RELA",
            SHT_HASH => "SHT_HASH",
            SHT_DYNAMIC => "SHT_DYNAMIC",
            SHT_NOTE => "SHT_NOTE",
            SHT_NOBITS => "SHT_NOBITS",
            SHT_REL => "SHT_REL",
            SHT_SHLIB => "SHT_SHLIB",
            SHT_DYNSYM => "SHT_DYNSYM",
            SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            SHT_GNU_HASH => "SHT_GNU_HASH",
            SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
            _ => "OTHER",
        }
        .to_string();

        let flags_raw = sh.sh_flags;
        let is_write = flags_raw & (SHF_WRITE as u64) != 0;
        let is_exec = flags_raw & (SHF_EXECINSTR as u64) != 0;
        let is_alloc = flags_raw & (SHF_ALLOC as u64) != 0;

        let mut flags_str = String::new();
        if is_alloc { flags_str.push('A'); }
        if is_write { flags_str.push('W'); }
        if is_exec { flags_str.push('X'); }

        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        let end = (start + size).min(data.len());

        let mut sec_anomalies = Vec::new();
        let entropy = if sh.sh_type != SHT_NOBITS && start < end && start < data.len() {
            let sec_data = &data[start..end];
            let ent = shannon_entropy(sec_data);
            if ent > 7.2 && is_exec {
                sec_anomalies.push(format!("High entropy ({:.2}) in executable section", ent));
            }
            ent
        } else {
            0.0
        };

        if is_write && is_exec {
            has_wx_section = true;
            sec_anomalies.push("Writable and Executable section (W+X)".to_string());
        }

        let bad_prefixes = [".upx", "UPX", ".packed"];
        if bad_prefixes.iter().any(|b| name.starts_with(b)) {
            sec_anomalies.push("Suspicious packed section name".to_string());
        }

        sections.push(ElfSectionInfo {
            name,
            section_type: sec_type,
            virtual_address: sh.sh_addr,
            raw_size: sh.sh_size,
            raw_offset: sh.sh_offset,
            entropy,
            flags_str,
            is_executable: is_exec,
            is_writable: is_write,
            anomalies: sec_anomalies,
        });
    }

    // ── Libraries ──
    let libraries: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

    // ── Symbols & Imports ──
    let mut imported_symbols = Vec::new();
    let mut exported_symbols = Vec::new();
    let mut has_stack_canary = false;
    let mut is_fortified = false;

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.is_empty() {
                continue;
            }
            if name.contains("__stack_chk_fail") || name.contains("__stack_chk_guard") {
                has_stack_canary = true;
            }
            if name.contains("_chk") {
                is_fortified = true;
            }

            // Undefined section index => imported from shared library
            if sym.st_shndx == SHN_UNDEF as usize {
                let risk = classify_elf_api(name);
                imported_symbols.push(ImportFunction {
                    name: name.to_string(),
                    risk,
                });
            } else if sym.is_function() {
                exported_symbols.push(name.to_string());
            }
        }
    }

    // Check normal symbol table for stack canary if not found in dynsyms
    if !has_stack_canary {
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name.contains("__stack_chk_fail") || name.contains("__stack_chk_guard") {
                    has_stack_canary = true;
                    break;
                }
            }
        }
    }

    // ── Mitigations ──
    let nx = if let Some(ref ph) = gnu_stack_ph {
        ph.p_flags & PF_X == 0
    } else {
        false
    };

    let mut bind_now = false;
    let mut rpath = None;
    let mut runpath = None;

    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            match dyn_entry.d_tag {
                goblin::elf::dynamic::DT_BIND_NOW => bind_now = true,
                goblin::elf::dynamic::DT_FLAGS => {
                    if dyn_entry.d_val & 0x1 != 0 {
                        bind_now = true;
                    }
                }
                goblin::elf::dynamic::DT_FLAGS_1 => {
                    if dyn_entry.d_val & 0x1 != 0 {
                        bind_now = true;
                    }
                }
                goblin::elf::dynamic::DT_RPATH => {
                    rpath = elf.dynstrtab.get_at(dyn_entry.d_val as usize).map(|s| s.to_string());
                }
                goblin::elf::dynamic::DT_RUNPATH => {
                    runpath = elf.dynstrtab.get_at(dyn_entry.d_val as usize).map(|s| s.to_string());
                }
                _ => {}
            }
        }
    }

    let relro = if gnu_relro_ph.is_some() {
        if bind_now {
            ElfRelro::Full
        } else {
            ElfRelro::Partial
        }
    } else {
        ElfRelro::None
    };

    let mitigations = ElfMitigations {
        nx,
        pie: is_pie,
        relro,
        stack_canary: has_stack_canary,
        fortified: is_fortified,
        rpath,
        runpath,
    };

    // ── Anomalies & Packer Detection ──
    if has_wx_segment {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Executable and Writable PT_LOAD segment detected (W+X)".into(),
        });
    }
    if has_wx_section {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: "Executable and Writable section detected (W+X)".into(),
        });
    }
    if !nx {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Executable stack enabled (NX Disabled)".into(),
        });
    }
    if elf.header.e_shnum == 0 || sections.is_empty() {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "Section header table missing or stripped (Anti-Reversing)".into(),
        });
    }

    let mut packer_detected = None;
    if sections.iter().any(|s| s.name.contains("UPX")) || data.windows(3).any(|w| w == b"UPX") {
        packer_detected = Some("UPX (Ultimate Packer for eXecutables)".into());
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Warning,
            description: "UPX packer signature detected in binary".into(),
        });
    }

    // ── Entry Point Bytes ──
    let ep_bytes = extract_ep_bytes(data, &elf);

    // ── Direct Syscalls Scan (x86 / x86_64) ──
    let (direct_syscalls, syscall_locations) = scan_elf_syscalls(data, &elf);

    if direct_syscalls {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::Critical,
            description: format!("Direct syscall instructions found ({} instances)", syscall_locations.len()),
        });
    }

    Ok(ElfAnalysis {
        machine,
        class,
        endianness,
        elf_type,
        entry_point,
        is_64bit,
        is_pie,
        interpreter,
        soname,
        program_headers,
        sections,
        libraries,
        imported_symbols,
        exported_symbols,
        mitigations,
        anomalies,
        packer_detected,
        ep_bytes,
        direct_syscalls,
        syscall_locations,
    })
}

fn extract_ep_bytes(data: &[u8], elf: &goblin::elf::Elf) -> Vec<u8> {
    let ep = elf.header.e_entry;
    if ep == 0 {
        return Vec::new();
    }

    // Find file offset for entry point via program headers (PT_LOAD)
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD && ep >= ph.p_vaddr && ep < ph.p_vaddr + ph.p_filesz {
            let offset = (ep - ph.p_vaddr + ph.p_offset) as usize;
            if offset < data.len() {
                let end = (offset + 32).min(data.len());
                return data[offset..end].to_vec();
            }
        }
    }

    // Fallback search in sections
    for sh in &elf.section_headers {
        if ep >= sh.sh_addr && ep < sh.sh_addr + sh.sh_size {
            let offset = (ep - sh.sh_addr + sh.sh_offset) as usize;
            if offset < data.len() {
                let end = (offset + 32).min(data.len());
                return data[offset..end].to_vec();
            }
        }
    }

    Vec::new()
}

fn scan_elf_syscalls(data: &[u8], elf: &goblin::elf::Elf) -> (bool, Vec<SyscallLocation>) {
    let mut locations = Vec::new();
    let is_aarch64 = elf.header.e_machine == EM_AARCH64;
    let bitness = if elf.header.e_machine == EM_X86_64 {
        Some(64)
    } else if elf.header.e_machine == EM_386 {
        Some(32)
    } else {
        None
    };

    if !is_aarch64 && bitness.is_none() {
        return (false, locations);
    }

    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD && (ph.p_flags & PF_X != 0) && ph.p_filesz > 0 {
            let start = ph.p_offset as usize;
            let end = (start + ph.p_filesz as usize).min(data.len());
            if start >= end {
                continue;
            }

            let code = &data[start..end];
            if is_aarch64 {
                locations.extend(crate::analysis::macho::scan_arm64_buffer(code, ph.p_vaddr));
            } else if let Some(b) = bitness {
                locations.extend(crate::analysis::macho::scan_x86_buffer(code, ph.p_vaddr, b));
            }
        }
    }

    let found = !locations.is_empty();
    (found, locations)
}

fn classify_elf_api(name: &str) -> ApiRisk {
    match name {
        // Critical: In-memory exec, process tampering, kernel manipulation, eBPF
        "ptrace"
        | "process_vm_writev"
        | "process_vm_readv"
        | "memfd_create"
        | "fexecve"
        | "execveat"
        | "init_module"
        | "finit_module"
        | "delete_module"
        | "kexec_load"
        | "kexec_file_load"
        | "bpf"
        | "userfaultfd" => ApiRisk::Critical,

        // High: Execution, memory permissions, sockets, anti-debug/signals
        "mprotect"
        | "mmap"
        | "execve"
        | "execl"
        | "execlp"
        | "execle"
        | "execv"
        | "execvp"
        | "execvpe"
        | "fork"
        | "clone"
        | "vfork"
        | "prctl"
        | "socket"
        | "connect"
        | "bind"
        | "listen"
        | "accept"
        | "sendto"
        | "recvfrom"
        | "pcap_open_live"
        | "pcap_loop"
        | "pcap_next" => ApiRisk::High,

        // Medium: Dynamic loading, privilege, file permissions, shell commands
        "dlopen"
        | "dlsym"
        | "setuid"
        | "setgid"
        | "seteuid"
        | "setegid"
        | "setresuid"
        | "setresgid"
        | "chroot"
        | "kill"
        | "chmod"
        | "chown"
        | "system"
        | "popen" => ApiRisk::Medium,

        // Low: Standard file/process primitives
        "open"
        | "openat"
        | "read"
        | "write"
        | "stat"
        | "lstat"
        | "fstat"
        | "unlink"
        | "unlinkat"
        | "rename"
        | "renameat"
        | "getpid"
        | "getppid"
        | "pipe"
        | "pipe2"
        | "dup"
        | "dup2"
        | "dup3" => ApiRisk::Low,

        _ => ApiRisk::None,
    }
}
