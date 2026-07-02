use crate::models::*;
use sha2::{Digest, Sha256};

/// Run basic (format-agnostic) analysis: hashes, entropy, strings.
pub fn analyze(data: &[u8]) -> BasicAnalysis {
    let md5 = compute_hash::<md5::Md5>(data);
    let sha1 = compute_hash::<sha1::Sha1>(data);
    let sha256 = compute_hash::<Sha256>(data);
    let entropy = shannon_entropy(data);
    let strings = extract_strings(data, 4);
    let is_packed = entropy > 7.0;

    let mut byte_distribution = [0u64; 256];
    for &b in data {
        byte_distribution[b as usize] += 1;
    }

    BasicAnalysis {
        md5,
        sha1,
        sha256,
        entropy,
        strings,
        is_packed,
        byte_distribution,
    }
}

// ─── Hashing ─────────────────────────────────────────────────────

fn compute_hash<D: Digest>(data: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(data);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

// ─── Entropy ─────────────────────────────────────────────────────

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ─── String extraction ───────────────────────────────────────────

fn extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(b);
        } else {
            if current.len() >= min_len {
                let s = String::from_utf8_lossy(&current).to_string();
                let category = categorize_string(&s);
                results.push(ExtractedString {
                    value: s,
                    offset: start_offset,
                    category,
                });
            }
            current.clear();
        }
    }
    // flush remaining
    if current.len() >= min_len {
        let s = String::from_utf8_lossy(&current).to_string();
        let category = categorize_string(&s);
        results.push(ExtractedString {
            value: s,
            offset: start_offset,
            category,
        });
    }

    results
}

fn categorize_string(s: &str) -> StringCategory {
    let lower = s.to_lowercase();

    // URLs
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return StringCategory::Url;
    }

    // IP addresses (simple pattern)
    if is_ip_like(&lower) {
        return StringCategory::IpAddress;
    }

    // Registry keys
    if lower.starts_with("hkey_")
        || lower.starts_with("hklm\\")
        || lower.starts_with("hkcu\\")
        || lower.contains("\\software\\")
        || lower.contains("\\currentversion\\run")
    {
        return StringCategory::RegistryKey;
    }

    // File paths
    if (lower.contains(":\\") || lower.starts_with("\\\\"))
        && (lower.contains(".exe")
            || lower.contains(".dll")
            || lower.contains(".sys")
            || lower.contains(".bat")
            || lower.contains(".tmp"))
    {
        return StringCategory::FilePath;
    }

    // Commands
    if lower.starts_with("cmd")
        || lower.starts_with("powershell")
        || lower.starts_with("wscript")
        || lower.starts_with("cscript")
        || lower.starts_with("net ")
        || lower.starts_with("sc ")
        || lower.starts_with("reg ")
        || lower.starts_with("schtasks")
        || lower.starts_with("bitsadmin")
    {
        return StringCategory::Command;
    }

    // Suspicious keywords
    let suspicious_kw = [
        "password",
        "passwd",
        "credential",
        "encrypt",
        "decrypt",
        "ransom",
        "bitcoin",
        "wallet",
        "keylog",
        "shellcode",
        "payload",
        "inject",
        "backdoor",
        "trojan",
        "rootkit",
        "exploit",
        "privilege",
        "escalat",
    ];
    if suspicious_kw.iter().any(|kw| lower.contains(kw)) {
        return StringCategory::Suspicious;
    }

    StringCategory::Normal
}

fn is_ip_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.parse::<u8>().is_ok() && !p.is_empty())
}
