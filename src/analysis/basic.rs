use crate::models::*;
use sha2::{Digest, Sha256};

/// Run basic (format-agnostic) analysis: hashes, entropy, strings.
pub fn analyze(data: &[u8]) -> BasicAnalysis {
    let ((md5, sha1, sha256), (strings, (byte_distribution, entropy))) = rayon::join(
        || (compute_hash::<md5::Md5>(data), compute_hash::<sha1::Sha1>(data), compute_hash::<Sha256>(data)),
        || rayon::join(
            || extract_strings(data, 4),
            || {
                let freq = byte_frequencies(data);
                let ent = entropy_from_frequencies(&freq, data.len());
                (freq.to_vec(), ent)
            },
        ),
    );

    BasicAnalysis {
        md5,
        sha1,
        sha256,
        entropy,
        strings,
        is_packed: entropy > 7.0,
        byte_distribution,
    }
}

// ─── Hashing ─────────────────────────────────────────────────────

fn compute_hash<D: Digest>(data: &[u8]) -> String {
    use std::fmt::Write;
    D::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{:02x}", b);
        s
    })
}

// ─── Entropy ─────────────────────────────────────────────────────

pub fn byte_frequencies(data: &[u8]) -> [u64; 256] {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    freq
}

pub fn entropy_from_frequencies(freq: &[u64; 256], total_len: usize) -> f64 {
    if total_len == 0 {
        return 0.0;
    }
    let len = total_len as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    entropy_from_frequencies(&byte_frequencies(data), data.len())
}

// ─── String extraction ───────────────────────────────────────────

fn extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    const MAX_STRINGS: usize = 20_000;
    let push_entry = |results: &mut Vec<ExtractedString>, buf: &mut Vec<u8>, offset: usize, is_wide: bool| {
        if results.len() >= MAX_STRINGS {
            buf.clear();
            return;
        }
        if buf.len() >= min_len {
            let s = String::from_utf8_lossy(buf).to_string();
            let category = categorize_string(&s);
            let decoded = if is_base64_like(&s) {
                use base64::{Engine as _, engine::general_purpose};
                general_purpose::STANDARD.decode(&s).ok().and_then(|b| String::from_utf8(b).ok())
            } else {
                None
            };
            let category = decoded
                .as_deref()
                .map(categorize_string)
                .filter(|category| *category != StringCategory::Normal)
                .unwrap_or(category);
            let network = decoded
                .as_deref()
                .and_then(extract_network_indicator)
                .or_else(|| extract_network_indicator(&s));
            results.push(ExtractedString {
                value: s,
                offset,
                category,
                decoded,
                network,
                is_wide,
            });
        }
        buf.clear();
    };

    let occ_len = data.len().min(64 * 1024 * 1024);
    let mut ascii_occupied = vec![false; occ_len];

    for (i, &b) in data.iter().enumerate() {
        if results.len() >= MAX_STRINGS {
            break;
        }
        if b.is_ascii_graphic() || b == b' ' {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(b);
        } else {
            if current.len() >= min_len && start_offset < occ_len {
                let fill_end = (start_offset + current.len()).min(occ_len);
                ascii_occupied[start_offset..fill_end].fill(true);
            }
            push_entry(&mut results, &mut current, start_offset, false);
        }
    }
    if current.len() >= min_len && start_offset < occ_len {
        let fill_end = (start_offset + current.len()).min(occ_len);
        ascii_occupied[start_offset..fill_end].fill(true);
    }
    push_entry(&mut results, &mut current, start_offset, false);

    if data.len() >= 2 && results.len() < MAX_STRINGS {
        for align in 0..=1 {
            let mut i = align;
            while i + 1 < data.len() && results.len() < MAX_STRINGS {
                let b0 = data[i];
                let b1 = data[i + 1];
                if b1 == 0 && (b0.is_ascii_graphic() || b0 == b' ') {
                    if current.is_empty() {
                        start_offset = i;
                    }
                    current.push(b0);
                } else {
                    while !current.is_empty() && start_offset < occ_len && ascii_occupied[start_offset] {
                        current.remove(0);
                        start_offset += 2;
                    }
                    push_entry(&mut results, &mut current, start_offset, true);
                }
                i += 2;
            }
            while !current.is_empty() && start_offset < occ_len && ascii_occupied[start_offset] {
                current.remove(0);
                start_offset += 2;
            }
            push_entry(&mut results, &mut current, start_offset, true);
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
    s.len().is_multiple_of(4)
}

fn extract_network_indicator(s: &str) -> Option<NetworkIndicator> {
    let lower = s.to_ascii_lowercase();
    for scheme in ["https://", "http://", "ftp://"] {
        for (start, _) in lower.match_indices(scheme) {
            let tail = &s[start..];
            let end = tail
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
                .unwrap_or(tail.len());
            let candidate = tail[..end].trim_end_matches(|c| matches!(c, '.' | ',' | ';' | '!' | '?' | ')'));
            if let Some(indicator) = parse_endpoint(candidate, true) {
                return Some(indicator);
            }
        }
    }

    s.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '=' | '(' | ')' | '{' | '}' | ',' | ';' | '\\')
    })
    .filter_map(|candidate| {
        let candidate = candidate.trim_end_matches(|c| matches!(c, '.' | '!' | '?'));
        parse_endpoint(candidate, false)
    })
    .next()
}

fn parse_endpoint(candidate: &str, has_scheme: bool) -> Option<NetworkIndicator> {
    if candidate.is_empty() {
        return None;
    }
    let authority_start = if has_scheme { candidate.find("://")? + 3 } else { 0 };
    let remainder = &candidate[authority_start..];
    let authority_end = remainder.find(|c| matches!(c, '/' | '?' | '#')).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let suffix = &remainder[authority_end..];
    let path = suffix.starts_with('/').then(|| suffix.to_string());
    let (host, port) = parse_authority(authority)?;
    if !has_scheme && port.is_none() && path.is_none() && host.parse::<std::net::IpAddr>().is_err() && !is_common_domain(&host) {
        return None;
    }

    Some(NetworkIndicator {
        value: candidate.to_string(),
        host,
        port,
        path,
    })
}

fn is_common_domain(host: &str) -> bool {
    let tld = host.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();
    matches!(
        tld.as_str(),
        "com" | "net" | "org" | "edu" | "gov" | "mil" | "info" | "biz" | "name" | "pro"
            | "io" | "co" | "me" | "tv" | "cc" | "app" | "dev" | "ai" | "cloud" | "online"
            | "site" | "xyz" | "top" | "club" | "shop" | "store" | "live" | "tech" | "network"
            | "systems" | "support" | "services" | "solutions" | "email" | "link" | "click"
            | "work" | "website" | "space" | "host" | "press" | "vip" | "win" | "download"
            | "review" | "stream" | "trade" | "cam" | "ru" | "cn" | "su" | "uk" | "de" | "fr"
            | "nl" | "pl" | "ua" | "tr" | "au" | "ca" | "us" | "br" | "jp" | "kr" | "in"
            | "sg" | "hk" | "tw" | "example" | "test"
    )
}

fn parse_authority(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = &bracketed[..end];
        host.parse::<std::net::Ipv6Addr>().ok()?;
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?.parse().ok()?)
        };
        return Some((host.to_string(), port));
    }

    if authority.parse::<std::net::IpAddr>().is_ok() {
        return Some((authority.to_string(), None));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port.parse().ok()?)),
        Some(_) => return None,
        None => (authority, None),
    };
    if host.parse::<std::net::Ipv4Addr>().is_ok() || is_valid_domain(host) {
        Some((host.to_string(), port))
    } else {
        None
    }
}

fn is_valid_domain(host: &str) -> bool {
    if host.len() > 253 || !host.contains('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
    }) {
        return false;
    }
    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    if !(tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        || tld.strip_prefix("xn--").is_some_and(|rest| !rest.is_empty()))
    {
        return false;
    }
    !matches!(
        tld.as_str(),
        "exe" | "dll" | "sys" | "bat" | "cmd" | "tmp" | "msi" | "scr" | "cpl" | "ocx"
            | "drv" | "pdb" | "lib" | "obj" | "so" | "dylib" | "bin" | "dat" | "ini" | "cfg"
            | "log" | "txt" | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "png" | "jpg" | "jpeg"
            | "gif" | "zip" | "rar" | "7z" | "gz" | "jar" | "vbs" | "ps1"
    )
}

fn categorize_string(s: &str) -> StringCategory {
    let lower = s.to_lowercase();

    if let Some(indicator) = extract_network_indicator(s) {
        if indicator.value.contains("://") {
            return StringCategory::Url;
        }
        return if indicator.host.parse::<std::net::IpAddr>().is_ok() {
            StringCategory::IpAddress
        } else {
            StringCategory::Domain
        };
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

    #[test]
    fn test_extract_decoded_network_indicators() {
        use base64::{Engine as _, engine::general_purpose};

        assert_eq!(categorize_string("endpoint=https://c2.example/gate"), StringCategory::Url);
        assert_eq!(categorize_string("host=192.0.2.10:8080"), StringCategory::IpAddress);

        let encoded = general_purpose::STANDARD.encode("https://c2.example/gate");
        let res = extract_strings(encoded.as_bytes(), 4);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].decoded.as_deref(), Some("https://c2.example/gate"));
        assert_eq!(res[0].category, StringCategory::Url);
        assert_eq!(res[0].network.as_ref().unwrap().host, "c2.example");
    }

    #[test]
    fn test_extract_domains_without_file_false_positives() {
        let indicator = extract_network_indicator("host=c2.example:8443/gate").unwrap();
        assert_eq!(categorize_string("host=c2.example:8443/gate"), StringCategory::Domain);
        assert_eq!(indicator.value, "c2.example:8443/gate");
        assert_eq!(indicator.host, "c2.example");
        assert_eq!(indicator.port, Some(8443));
        assert_eq!(indicator.path.as_deref(), Some("/gate"));

        assert_eq!(categorize_string("c2.example"), StringCategory::Domain);
        assert_eq!(categorize_string("c2.evil:443"), StringCategory::Domain);
        for value in [
            "kernel32.dll",
            "1.2.3",
            "archive.tar.gz",
            "C:\\Windows\\System32\\kernel32.dll",
            "src\\analysis\\basic.rs",
            "b.Ay",
            "c2.evil",
        ] {
            assert!(extract_network_indicator(value).is_none(), "{value}");
            assert_ne!(categorize_string(value), StringCategory::Domain);
        }
    }

    #[test]
    fn test_extract_ipv6_and_http_endpoint_parts() {
        for value in ["host=2001:db8::1", "host=[2001:db8::1]"] {
            let indicator = extract_network_indicator(value).unwrap();
            assert_eq!(categorize_string(value), StringCategory::IpAddress);
            assert_eq!(indicator.host, "2001:db8::1");
            assert_eq!(indicator.port, None);
        }

        let ipv6 = extract_network_indicator("host=[2001:db8::1]:4444").unwrap();
        assert_eq!(ipv6.port, Some(4444));
        let url = extract_network_indicator("endpoint=https://[2001:db8::10]:8443/gate?id=7").unwrap();
        assert_eq!(url.host, "2001:db8::10");
        assert_eq!(url.port, Some(8443));
        assert_eq!(url.path.as_deref(), Some("/gate?id=7"));
    }
}
