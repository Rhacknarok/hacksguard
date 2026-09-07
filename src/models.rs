use std::fmt;
use std::path::PathBuf;

// ─── Top-level result ────────────────────────────────────────────

/// Complete analysis result for a single file.
#[derive(serde::Serialize)]
pub struct AnalysisResult {
    pub file_info: FileInfo,
    pub basic: BasicAnalysis,
    pub pe: Option<PeAnalysis>,
    pub elf: Option<ElfAnalysis>,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub risk_breakdown: RiskBreakdown,
    pub detection_checks: Vec<DetectionCheck>,
    pub malware_pattern: Option<MalwarePattern>,
    pub yara_matches: Vec<String>,
    pub entropy_graph: Vec<u64>,
}

impl AnalysisResult {
    pub fn attach_embedded_pe(&mut self, pe: PeAnalysis) {
        self.detection_checks.push(DetectionCheck {
            name: "Embedded PE executable found".into(),
            triggered: true,
            severity: DetectionSeverity::Critical,
        });

        if let Some(ref mut parent_pe) = self.pe {
            parent_pe.embedded_pe = Some(Box::new(pe));
        } else {
            self.pe = Some(pe);
        }

        let (score, level) = crate::analysis::compute_risk_from_checks(
            &self.detection_checks,
            &self.yara_matches,
        );
        self.risk_score = score;
        self.risk_level = level;
    }
}

// ─── File info ───────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub file_type: FileType,
    pub magic_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum FileType {
    PE,
    ELF,
    MachO,
    Unknown,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PE => write!(f, "PE"),
            Self::ELF => write!(f, "ELF"),
            Self::MachO => write!(f, "Mach-O"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Basic analysis ──────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct BasicAnalysis {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub entropy: f64,
    pub strings: Vec<ExtractedString>,
    pub is_packed: bool,
    pub byte_distribution: Vec<u64>,
}

#[derive(serde::Serialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub category: StringCategory,
    pub decoded: Option<String>,
    pub is_wide: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum StringCategory {
    Url,
    IpAddress,
    FilePath,
    RegistryKey,
    Command,
    Suspicious,
    Normal,
}

impl fmt::Display for StringCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => write!(f, "URL"),
            Self::IpAddress => write!(f, "IP"),
            Self::FilePath => write!(f, "PATH"),
            Self::RegistryKey => write!(f, "REG"),
            Self::Command => write!(f, "CMD"),
            Self::Suspicious => write!(f, "SUS"),
            Self::Normal => write!(f, "STR"),
        }
    }
}

// ─── PE analysis ─────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct PeAnalysis {
    pub machine: String,
    pub timestamp: u32,
    pub timestamp_str: String,
    pub entry_point: u64,
    pub image_base: u64,
    pub subsystem: String,
    pub is_dll: bool,
    pub is_64bit: bool,
    pub linker_version: String,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportDll>,
    pub exports: Vec<String>,
    pub anomalies: Vec<Anomaly>,
    pub packer_detected: Option<String>,
    pub compilation_age: String,
    pub timestamp_suspicious: bool,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub data_directories: Vec<DataDirectory>,
    pub entry_point_section: Option<String>,
    pub has_authenticode: bool,
    pub ep_bytes: Vec<u8>,
    pub overlay_offset: Option<usize>,
    pub overlay_size: Option<usize>,
    pub obfuscated_apis: Vec<String>,
    pub embedded_pe: Option<Box<PeAnalysis>>,
    pub peb_walking: bool,
    pub api_hashing: bool,
    pub pdb_path: Option<String>,
    pub manifest: Option<String>,
    pub direct_syscalls: bool,
    pub indirect_syscalls: bool,
    pub syscall_locations: Vec<SyscallLocation>,
    pub imphash: Option<String>,
    pub rich_header: Option<RichHeaderInfo>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct RichRecord {
    pub prod_id: u16,
    pub build: u16,
    pub count: u32,
    pub tool_name: Option<String>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct RichHeaderInfo {
    pub xor_key: u32,
    pub rich_hash: String,
    pub records: Vec<RichRecord>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct SyscallLocation {
    pub address: u64,
    pub is_indirect: bool,
    pub instruction_str: String,
}

#[derive(serde::Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub raw_offset: u64,
    pub entropy: f64,
    pub characteristics: u32,
    pub flags_str: String,
    pub is_executable: bool,
    pub is_writable: bool,
    pub anomalies: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct ImportDll {
    pub name: String,
    pub functions: Vec<ImportFunction>,
}

#[derive(serde::Serialize)]
pub struct DataDirectory {
    pub name: String,
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct ImportFunction {
    pub name: String,
    pub risk: ApiRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(serde::Serialize)]
pub enum ApiRisk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ApiRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::None => write!(f, "-"),
        }
    }
}

// ─── ELF analysis ────────────────────────────────────────────────

#[derive(serde::Serialize, Clone)]
pub struct ElfAnalysis {
    pub machine: String,
    pub class: String,
    pub endianness: String,
    pub elf_type: String,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub is_pie: bool,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub program_headers: Vec<ElfProgramHeader>,
    pub sections: Vec<ElfSectionInfo>,
    pub libraries: Vec<String>,
    pub imported_symbols: Vec<ImportFunction>,
    pub exported_symbols: Vec<String>,
    pub mitigations: ElfMitigations,
    pub anomalies: Vec<Anomaly>,
    pub packer_detected: Option<String>,
    pub ep_bytes: Vec<u8>,
    pub direct_syscalls: bool,
    pub syscall_locations: Vec<SyscallLocation>,
}

#[derive(serde::Serialize, Clone)]
pub struct ElfProgramHeader {
    pub ph_type: String,
    pub flags: String,
    pub is_read: bool,
    pub is_write: bool,
    pub is_exec: bool,
    pub virtual_address: u64,
    pub memory_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub alignment: u64,
}

#[derive(serde::Serialize, Clone)]
pub struct ElfSectionInfo {
    pub name: String,
    pub section_type: String,
    pub virtual_address: u64,
    pub raw_size: u64,
    pub raw_offset: u64,
    pub entropy: f64,
    pub flags_str: String,
    pub is_executable: bool,
    pub is_writable: bool,
    pub anomalies: Vec<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct ElfMitigations {
    pub nx: bool,
    pub pie: bool,
    pub relro: ElfRelro,
    pub stack_canary: bool,
    pub fortified: bool,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ElfRelro {
    None,
    Partial,
    Full,
}

// ─── Risk scoring ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Anomalies ───────────────────────────────────────────────────

#[derive(serde::Serialize, Clone, Debug)]
pub struct Anomaly {
    pub severity: AnomalySeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum AnomalySeverity {
    Critical,
    Warning,
    Info,
}

impl fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRIT"),
            Self::Warning => write!(f, "WARN"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

// ─── Risk breakdown (radar chart) ────────────────────────────────

#[derive(serde::Serialize)]
pub struct RiskBreakdown {
    pub entropy_score: u32,
    pub api_score: u32,
    pub anomaly_score: u32,
    pub string_score: u32,
    pub packing_score: u32,
}

// ─── Detection checks ───────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct DetectionCheck {
    pub name: String,
    pub triggered: bool,
    pub severity: DetectionSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum DetectionSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for DetectionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRIT"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MED"),
            Self::Low => write!(f, "LOW"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

// ─── Malware pattern matching ────────────────────────────────────

#[derive(serde::Serialize)]
pub struct MalwarePattern {
    pub family: String,
    pub confidence: String,
    pub description: String,
    pub matched_indicators: Vec<String>,
}
