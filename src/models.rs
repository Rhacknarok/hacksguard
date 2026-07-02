use std::fmt;
use std::path::PathBuf;

// ─── Top-level result ────────────────────────────────────────────

/// Complete analysis result for a single file.
pub struct AnalysisResult {
    pub file_info: FileInfo,
    pub basic: BasicAnalysis,
    pub pe: Option<PeAnalysis>,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub risk_breakdown: RiskBreakdown,
    pub detection_checks: Vec<DetectionCheck>,
    pub malware_pattern: Option<MalwarePattern>,
    pub yara_matches: Vec<String>,
    pub vt_score: Option<String>,
}

// ─── File info ───────────────────────────────────────────────────

pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub file_type: FileType,
    pub magic_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub struct BasicAnalysis {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub entropy: f64,
    pub strings: Vec<ExtractedString>,
    pub is_packed: bool,
    pub byte_distribution: [u64; 256],
}

pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub category: StringCategory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
    pub flags_str: String,
    pub is_executable: bool,
    pub is_writable: bool,
    pub anomalies: Vec<String>,
}

pub struct ImportDll {
    pub name: String,
    pub functions: Vec<ImportFunction>,
}

pub struct DataDirectory {
    pub name: String,
    pub virtual_address: u32,
    pub size: u32,
}

pub struct ImportFunction {
    pub name: String,
    pub risk: ApiRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

// ─── Risk scoring ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct Anomaly {
    pub severity: AnomalySeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct RiskBreakdown {
    pub entropy_score: u32,
    pub api_score: u32,
    pub anomaly_score: u32,
    pub string_score: u32,
    pub packing_score: u32,
}

// ─── Detection checks ───────────────────────────────────────────

pub struct DetectionCheck {
    pub name: String,
    pub triggered: bool,
    pub severity: DetectionSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct MalwarePattern {
    pub family: String,
    pub confidence: String,
    pub description: String,
    pub matched_indicators: Vec<String>,
}
