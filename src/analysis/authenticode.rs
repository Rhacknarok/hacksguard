use crate::models::CertificateInfo;

#[derive(Debug, Clone, Copy)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

/// Read a single ASN.1 DER Tag-Length-Value (TLV) element from input.
pub fn read_der_tlv<'a>(input: &mut &'a [u8]) -> Option<DerElement<'a>> {
    if input.is_empty() {
        return None;
    }
    let tag = input[0];
    *input = &input[1..];
    if input.is_empty() {
        return None;
    }
    let len_byte = input[0];
    *input = &input[1..];
    let len = if len_byte < 0x80 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || input.len() < num_bytes {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[..num_bytes] {
            l = (l << 8) | (b as usize);
        }
        *input = &input[num_bytes..];
        l
    };
    if input.len() < len {
        return None;
    }
    let value = &input[..len];
    *input = &input[len..];
    Some(DerElement { tag, value })
}

/// Parse WIN_CERTIFICATE structure and decode the leaf X.509 certificate.
pub fn parse_authenticode(data: &[u8], offset: usize, size: usize) -> Option<CertificateInfo> {
    if offset + 8 > data.len() || size < 8 {
        return None;
    }

    let dw_length = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    let w_certificate_type = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

    // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
    if w_certificate_type != 0x0002 || dw_length < 8 {
        return None;
    }

    let end = (offset + dw_length).min(data.len()).min(offset + size);
    if offset + 8 >= end {
        return None;
    }
    let der_bytes = &data[offset + 8..end];
    parse_pkcs7_der(der_bytes)
}

/// Parse PKCS#7 SignedData DER structure to locate and decode the leaf certificate.
pub fn parse_pkcs7_der(der_bytes: &[u8]) -> Option<CertificateInfo> {
    let mut cur = der_bytes;
    let outer_seq = read_der_tlv(&mut cur)?;
    if outer_seq.tag != 0x30 {
        return scan_for_x509_cert(der_bytes);
    }

    let mut outer_body = outer_seq.value;
    let _content_type = read_der_tlv(&mut outer_body)?;
    let content = read_der_tlv(&mut outer_body)?;

    // Tag 0xa0 is [0] EXPLICIT
    if content.tag == 0xa0 {
        let mut content_body = content.value;
        if let Some(signed_data_seq) = read_der_tlv(&mut content_body) {
            if signed_data_seq.tag == 0x30 {
                let mut sd_body = signed_data_seq.value;
                // version (INTEGER)
                let _ = read_der_tlv(&mut sd_body);
                // digestAlgorithms (SET)
                let _ = read_der_tlv(&mut sd_body);
                // encapContentInfo (SEQUENCE)
                let _ = read_der_tlv(&mut sd_body);

                // certificates is tagged [0] IMPLICIT (0xa0)
                while let Some(elem) = read_der_tlv(&mut sd_body) {
                    if elem.tag == 0xa0 {
                        let mut certs_body = elem.value;
                        if let Some(cert_seq) = read_der_tlv(&mut certs_body) {
                            if cert_seq.tag == 0x30 {
                                if let Some(info) = parse_x509_certificate(cert_seq.value) {
                                    return Some(info);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback scanner if strict PKCS#7 envelope navigation misses
    scan_for_x509_cert(der_bytes)
}

/// Fallback: Scan buffer for any embedded SEQUENCE that parses as a valid X.509 certificate.
fn scan_for_x509_cert(der_bytes: &[u8]) -> Option<CertificateInfo> {
    let mut offset = 0;
    while offset + 32 < der_bytes.len() {
        if der_bytes[offset] == 0x30 {
            let mut cur = &der_bytes[offset..];
            if let Some(elem) = read_der_tlv(&mut cur) {
                if elem.tag == 0x30 && elem.value.len() >= 64 {
                    if let Some(info) = parse_x509_certificate(elem.value) {
                        return Some(info);
                    }
                }
            }
        }
        offset += 1;
    }
    None
}

/// Parse X.509 Certificate body (inside outer SEQUENCE 0x30).
pub fn parse_x509_certificate(cert_body: &[u8]) -> Option<CertificateInfo> {
    let mut cur = cert_body;
    let tbs_elem = read_der_tlv(&mut cur)?;
    if tbs_elem.tag != 0x30 {
        return None;
    }

    let sig_alg_elem = read_der_tlv(&mut cur);
    let digest_algorithm = sig_alg_elem.and_then(|s| extract_algorithm_name(s.value));

    let mut tbs_cur = tbs_elem.value;

    // Optional version [0] EXPLICIT (tag 0xa0)
    let mut first = read_der_tlv(&mut tbs_cur)?;
    if first.tag == 0xa0 {
        first = read_der_tlv(&mut tbs_cur)?;
    }

    // Serial number (tag 0x02)
    let serial_number = if first.tag == 0x02 {
        Some(first.value.iter().map(|b| format!("{:02X}", b)).collect::<String>())
    } else {
        None
    };

    // Signature algorithm inside TBS (tag 0x30)
    let _ = read_der_tlv(&mut tbs_cur)?;

    // Issuer (tag 0x30)
    let issuer_elem = read_der_tlv(&mut tbs_cur)?;
    let issuer = parse_name(issuer_elem.value);

    // Validity (tag 0x30)
    let validity_elem = read_der_tlv(&mut tbs_cur)?;
    let (not_before, not_after) = parse_validity(validity_elem.value);

    // Subject (tag 0x30)
    let subject_elem = read_der_tlv(&mut tbs_cur)?;
    let subject = parse_name(subject_elem.value);

    let is_self_signed = !subject.is_empty() && subject == issuer;

    if subject.is_empty() && issuer.is_empty() {
        return None;
    }

    Some(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        digest_algorithm,
        serial_number,
        is_self_signed,
    })
}

/// Parse X.509 Name sequence to RFC 4514-like string format (CN=..., O=..., C=...).
pub fn parse_name(name_der: &[u8]) -> String {
    let mut cur = name_der;
    let mut parts = Vec::new();

    while let Some(rdn_set) = read_der_tlv(&mut cur) {
        if rdn_set.tag == 0x31 {
            let mut rdn_cur = rdn_set.value;
            while let Some(atv_seq) = read_der_tlv(&mut rdn_cur) {
                if atv_seq.tag == 0x30 {
                    let mut atv_cur = atv_seq.value;
                    if let (Some(oid_elem), Some(val_elem)) = (read_der_tlv(&mut atv_cur), read_der_tlv(&mut atv_cur)) {
                        if oid_elem.tag == 0x06 {
                            let prefix = match oid_elem.value {
                                &[0x55, 0x04, 0x03] => "CN",
                                &[0x55, 0x04, 0x0A] => "O",
                                &[0x55, 0x04, 0x0B] => "OU",
                                &[0x55, 0x04, 0x06] => "C",
                                &[0x55, 0x04, 0x08] => "ST",
                                &[0x55, 0x04, 0x07] => "L",
                                _ => "",
                            };

                            let val_str = match val_elem.tag {
                                0x1e => {
                                    // BMPString (UTF-16BE)
                                    let chars: Vec<u16> = val_elem
                                        .value
                                        .chunks_exact(2)
                                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                                        .collect();
                                    String::from_utf16_lossy(&chars)
                                }
                                _ => String::from_utf8_lossy(val_elem.value).trim().to_string(),
                            };

                            if !val_str.is_empty() {
                                if !prefix.is_empty() {
                                    parts.push(format!("{}={}", prefix, val_str));
                                } else {
                                    parts.push(val_str);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    parts.join(", ")
}

/// Parse Validity sequence into (not_before, not_after) strings.
pub fn parse_validity(validity_der: &[u8]) -> (Option<String>, Option<String>) {
    let mut cur = validity_der;
    let not_before = read_der_tlv(&mut cur).and_then(|e| parse_time(e.value, e.tag == 0x18));
    let not_after = read_der_tlv(&mut cur).and_then(|e| parse_time(e.value, e.tag == 0x18));
    (not_before, not_after)
}

/// Parse ASN.1 UTCTime (0x17) or GeneralizedTime (0x18).
pub fn parse_time(time_bytes: &[u8], is_generalized: bool) -> Option<String> {
    let s = std::str::from_utf8(time_bytes).ok()?;
    if is_generalized {
        // YYYYMMDDHHMMSSZ (at least 14 chars)
        if s.len() >= 14 {
            let year = &s[0..4];
            let month = &s[4..6];
            let day = &s[6..8];
            let hour = &s[8..10];
            let min = &s[10..12];
            let sec = &s[12..14];
            return Some(format!("{}-{}-{} {}:{}:{} UTC", year, month, day, hour, min, sec));
        }
    } else {
        // YYMMDDHHMMSSZ (at least 12 chars)
        if s.len() >= 12 {
            let y: u32 = s[0..2].parse().ok()?;
            let year = if y >= 50 { 1900 + y } else { 2000 + y };
            let month = &s[2..4];
            let day = &s[4..6];
            let hour = &s[6..8];
            let min = &s[8..10];
            let sec = &s[10..12];
            return Some(format!("{:04}-{}-{} {}:{}:{} UTC", year, month, day, hour, min, sec));
        }
    }
    None
}

/// Extract algorithm name from AlgorithmIdentifier SEQUENCE.
pub fn extract_algorithm_name(sig_alg_der: &[u8]) -> Option<String> {
    let mut cur = sig_alg_der;
    let oid_elem = read_der_tlv(&mut cur)?;
    if oid_elem.tag != 0x06 {
        return None;
    }

    let name = match oid_elem.value {
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B] => "SHA-256 (RSA)".into(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05] => "SHA-1 (RSA)".into(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C] => "SHA-384 (RSA)".into(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D] => "SHA-512 (RSA)".into(),
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] => "SHA-256 (ECDSA)".into(),
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => "SHA-384 (ECDSA)".into(),
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => "SHA-256".into(),
        &[0x2B, 0x0E, 0x03, 0x02, 0x1A] => "SHA-1".into(),
        _ => "Unknown".into(),
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_tlv_reader() {
        // Tag 0x02 (INTEGER), length 3, bytes 0x01, 0x02, 0x03
        let data = [0x02, 0x03, 0x01, 0x02, 0x03];
        let mut cur = &data[..];
        let elem = read_der_tlv(&mut cur).unwrap();
        assert_eq!(elem.tag, 0x02);
        assert_eq!(elem.value, &[0x01, 0x02, 0x03]);
        assert!(cur.is_empty());
    }

    #[test]
    fn test_parse_time_utc_and_generalized() {
        let utc = b"240115123000Z";
        let parsed_utc = parse_time(utc, false).unwrap();
        assert_eq!(parsed_utc, "2024-01-15 12:30:00 UTC");

        let gen = b"20251231235959Z";
        let parsed_gen = parse_time(gen, true).unwrap();
        assert_eq!(parsed_gen, "2025-12-31 23:59:59 UTC");
    }

    #[test]
    fn test_parse_name() {
        // SET { SEQUENCE { OID 2.5.4.3 (CN), UTF8String "Microsoft Corporation" } }
        let mut der = Vec::new();
        // ATV sequence
        let mut atv = Vec::new();
        atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID CN
        let cn_val = b"Microsoft Test";
        atv.push(0x0C); // UTF8String
        atv.push(cn_val.len() as u8);
        atv.extend_from_slice(cn_val);

        // Wrap in SET
        let mut rdn = Vec::new();
        rdn.push(0x30); // SEQUENCE
        rdn.push(atv.len() as u8);
        rdn.extend_from_slice(&atv);

        der.push(0x31); // SET
        der.push(rdn.len() as u8);
        der.extend_from_slice(&rdn);

        let name = parse_name(&der);
        assert_eq!(name, "CN=Microsoft Test");
    }
}
