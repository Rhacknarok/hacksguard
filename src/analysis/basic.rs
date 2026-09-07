use crate::models::*;
use sha2::{Digest, Sha256};

/// Run basic (format-agnostic) analysis: hashes, entropy, strings.
pub fn analyze(data: &[u8]) -> BasicAnalysis {
    let (((md5, sha1), (sha256, entropy)), (strings, byte_distribution)) = rayon::join(
        || rayon::join(
            || rayon::join(
                || compute_hash::<md5::Md5>(data),
                || compute_hash::<sha1::Sha1>(data),
            ),
            || rayon::join(
                || compute_hash::<Sha256>(data),
                || shannon_entropy(data),
            )
        ),
        || rayon::join(
            || extract_strings(data, 4),
            || {
                let mut dist = [0u64; 256];
                for &b in data {
                    dist[b as usize] += 1;
                }
                dist.to_vec()
            }
        )
    );

    let is_packed = entropy > 7.0;

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
    D::digest(data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
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

    let mut push_entry = |buf: &mut Vec<u8>, offset: usize, is_wide: bool| {
        if buf.len() >= min_len {
            let s = String::from_utf8_lossy(buf).to_string();
            let category = categorize_string(&s);
            let decoded = if is_base64_like(&s) {
                use base64::{Engine as _, engine::general_purpose};
                general_purpose::STANDARD.decode(&s).ok().and_then(|b| String::from_utf8(b).ok())
            } else {
                None
            };
            results.push(ExtractedString {
                value: s,
                offset,
                category,
                decoded,
                is_wide,
            });
        }
        buf.clear();
    };

    let mut ascii_occupied = vec![false; data.len()];

    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(b);
        } else {
            if current.len() >= min_len {
                for off in start_offset..start_offset + current.len() {
                    ascii_occupied[off] = true;
                }
            }
            push_entry(&mut current, start_offset, false);
        }
    }
    if current.len() >= min_len {
        for off in start_offset..start_offset + current.len() {
            ascii_occupied[off] = true;
        }
    }
    push_entry(&mut current, start_offset, false);

    if data.len() >= 2 {
        for align in 0..=1 {
            let mut i = align;
            while i + 1 < data.len() {
                let b0 = data[i];
                let b1 = data[i + 1];
                if b1 == 0 && (b0.is_ascii_graphic() || b0 == b' ') {
                    if current.is_empty() {
                        start_offset = i;
                    }
                    current.push(b0);
                } else {
                    while !current.is_empty() && start_offset < data.len() && ascii_occupied[start_offset] {
                        current.remove(0);
                        start_offset += 2;
                    }
                    push_entry(&mut current, start_offset, true);
                }
                i += 2;
            }
            while !current.is_empty() && start_offset < data.len() && ascii_occupied[start_offset] {
                current.remove(0);
                start_offset += 2;
            }
            push_entry(&mut current, start_offset, true);
        }
    }

    results.sort_by_key(|s| s.offset);
    results
}

fn is_base64_like(s: &str) -> bool {
    if s.len() <= 16 { return false; }
    let mut equals_count = 0;
    for (i, c) in s.chars().enumerate() {
        if c == '=' {
            equals_count += 1;
            if equals_count > 2 || i < s.len() - 2 {
                return false;
            }
        } else if !c.is_ascii_alphanumeric() && c != '+' && c != '/' {
            return false;
        }
    }
    s.len() % 4 == 0
}

fn categorize_string(s: &str) -> StringCategory {
    let lower = s.to_lowercase();

    // URLs
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return StringCategory::Url;
    }

    // IP addresses
    if lower.parse::<std::net::Ipv4Addr>().is_ok() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_and_wide_strings() {
        let mut buf = Vec::new();
        // ASCII string at offset 0
        buf.extend_from_slice(b"http://malware.evil/test\0");
        let wide_offset = buf.len();
        // UTF-16LE string "powershell.exe"
        for &b in b"powershell.exe" {
            buf.push(b);
            buf.push(0);
        }
        buf.push(0);
        buf.push(0);

        let res = extract_strings(&buf, 4);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].value, "http://malware.evil/test");
        assert!(!res[0].is_wide);
        assert_eq!(res[0].category, StringCategory::Url);
        assert_eq!(res[0].offset, 0);

        assert_eq!(res[1].value, "powershell.exe");
        assert!(res[1].is_wide);
        assert_eq!(res[1].category, StringCategory::Command);
        assert_eq!(res[1].offset, wide_offset);
    }
}
