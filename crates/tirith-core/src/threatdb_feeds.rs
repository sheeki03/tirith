use std::io::{Read, Seek};
use std::net::Ipv4Addr;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FeedEntries {
    pub hostnames: Vec<String>,
    pub ips: Vec<Ipv4Addr>,
}

impl FeedEntries {
    pub fn sort_and_dedup(&mut self) {
        self.hostnames.sort();
        self.hostnames.dedup();
        self.ips.sort();
        self.ips.dedup();
    }
}

pub fn extract_hostname_from_url(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    parsed.host_str().map(|host| host.to_ascii_lowercase())
}

pub fn parse_urlhaus_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);
    let headers = csv
        .headers()
        .map_err(|e| format!("URLhaus headers: {e}"))?
        .clone();

    let url_idx = headers
        .iter()
        .position(|header| matches!(header, "url" | "urlhaus_link"))
        .unwrap_or(2);

    let mut entries = FeedEntries::default();
    for record in csv.records() {
        let record = match record {
            Ok(record) => record,
            Err(_) => continue,
        };
        let raw = record.get(url_idx).or_else(|| {
            record
                .iter()
                .find(|value| value.starts_with("http://") || value.starts_with("https://"))
        });
        if let Some(host) = raw.and_then(extract_hostname_from_url) {
            entries.hostnames.push(host);
        }
    }
    entries.sort_and_dedup();
    Ok(entries)
}

pub fn parse_threatfox_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);
    let headers = csv
        .headers()
        .map_err(|e| format!("ThreatFox headers: {e}"))?
        .clone();

    let ioc_idx = headers.iter().position(|header| header == "ioc");
    let ioc_type_idx = headers.iter().position(|header| header == "ioc_type");

    let mut entries = FeedEntries::default();
    for record in csv.records() {
        let record = match record {
            Ok(record) => record,
            Err(_) => continue,
        };

        let raw_ioc = ioc_idx.and_then(|idx| record.get(idx)).or_else(|| {
            record.iter().find(|value| {
                value.contains('.') || value.starts_with("http://") || value.starts_with("https://")
            })
        });
        let raw_ioc = match raw_ioc {
            Some(value) if !value.is_empty() => value.trim(),
            _ => continue,
        };

        let ioc_type = ioc_type_idx
            .and_then(|idx| record.get(idx))
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();

        if raw_ioc.starts_with("http://") || raw_ioc.starts_with("https://") {
            if let Some(host) = extract_hostname_from_url(raw_ioc) {
                entries.hostnames.push(host);
            }
            continue;
        }

        if matches!(ioc_type.as_str(), "ip:port" | "ip_port") {
            let ip_part = raw_ioc.split(':').next().unwrap_or(raw_ioc);
            if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                entries.ips.push(ip);
            }
            continue;
        }

        if let Ok(ip) = raw_ioc.parse::<Ipv4Addr>() {
            entries.ips.push(ip);
            continue;
        }

        if !raw_ioc.contains('/') && raw_ioc.contains('.') {
            entries.hostnames.push(raw_ioc.to_ascii_lowercase());
        }
    }

    entries.sort_and_dedup();
    Ok(entries)
}

pub fn parse_threatfox_zip<R: Read + Seek>(reader: R) -> Result<FeedEntries, String> {
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| format!("ThreatFox ZIP open failed: {e}"))?;
    for idx in 0..archive.len() {
        let mut file = archive
            .by_index(idx)
            .map_err(|e| format!("ThreatFox ZIP read failed: {e}"))?;
        if !file.name().ends_with(".csv") {
            continue;
        }

        // Cap decompressed size to prevent zip bombs (compressed feed may
        // expand far beyond the download size limit).
        const MAX_DECOMPRESSED: u64 = 512 * 1024 * 1024;
        let mut csv_bytes = Vec::new();
        file.by_ref()
            .take(MAX_DECOMPRESSED + 1)
            .read_to_end(&mut csv_bytes)
            .map_err(|e| format!("ThreatFox ZIP extraction failed: {e}"))?;
        if csv_bytes.len() as u64 > MAX_DECOMPRESSED {
            return Err(format!(
                "ThreatFox CSV exceeds {} MiB decompressed size limit",
                MAX_DECOMPRESSED / (1024 * 1024)
            ));
        }
        return parse_threatfox_csv(std::io::Cursor::new(csv_bytes))
            .map_err(|e| format!("ThreatFox CSV parse failed: {e}"));
    }

    Err("ThreatFox ZIP did not contain a CSV payload".to_string())
}

pub fn parse_phishtank_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);
    let headers = csv
        .headers()
        .map_err(|e| format!("PhishTank headers: {e}"))?
        .clone();
    let url_idx = headers
        .iter()
        .position(|header| header == "url")
        .unwrap_or(1);

    let mut entries = FeedEntries::default();
    for record in csv.records() {
        let record = match record {
            Ok(record) => record,
            Err(_) => continue,
        };
        if let Some(host) = record.get(url_idx).and_then(extract_hostname_from_url) {
            entries.hostnames.push(host);
        }
    }
    entries.sort_and_dedup();
    Ok(entries)
}

pub fn parse_domain_blocklist(contents: &str) -> FeedEntries {
    let mut entries = FeedEntries::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip inline comments: everything from '#' onward is ignored.
        // Then take the last non-comment token (handles "0.0.0.0 bad.example" format).
        let token = line
            .split_whitespace()
            .take_while(|value| !value.starts_with('#'))
            .last()
            .unwrap_or(line);

        if token.eq_ignore_ascii_case("localhost") || token.starts_with("127.") {
            continue;
        }

        if token.contains('.') && !token.contains('/') {
            entries.hostnames.push(token.to_ascii_lowercase());
        }
    }
    entries.sort_and_dedup();
    entries
}

pub fn parse_tor_exit_list(contents: &str) -> FeedEntries {
    let mut entries = FeedEntries::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            entries.ips.push(ip);
        }
    }
    entries.sort_and_dedup();
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn urlhaus_csv_extracts_hostnames() {
        let csv = "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n1,2024-01-01,https://evil.example/path,online,2024-01-01,payload,,https://urlhaus.abuse.ch/url/1/,test\n";
        let entries = parse_urlhaus_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.hostnames, vec!["evil.example".to_string()]);
    }

    #[test]
    fn threatfox_csv_extracts_domains_and_ips() {
        let csv = "ioc,ioc_type\nbad.example,domain\n203.0.113.25,ip\n198.51.100.9:443,ip:port\nhttps://c2.example/payload,url\n";
        let entries = parse_threatfox_csv(csv.as_bytes()).unwrap();
        assert!(entries.hostnames.contains(&"bad.example".to_string()));
        assert!(entries.hostnames.contains(&"c2.example".to_string()));
        assert!(entries.ips.contains(&Ipv4Addr::new(203, 0, 113, 25)));
        assert!(entries.ips.contains(&Ipv4Addr::new(198, 51, 100, 9)));
    }

    #[test]
    fn threatfox_zip_extracts_domains_and_ips() {
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("full.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                b"ioc,ioc_type\nbad.example,domain\n203.0.113.25,ip\nhttps://c2.example/payload,url\n",
            )
            .unwrap();
        let cursor = writer.finish().unwrap();

        let entries = parse_threatfox_zip(Cursor::new(cursor.into_inner())).unwrap();
        assert!(entries.hostnames.contains(&"bad.example".to_string()));
        assert!(entries.hostnames.contains(&"c2.example".to_string()));
        assert!(entries.ips.contains(&Ipv4Addr::new(203, 0, 113, 25)));
    }

    #[test]
    fn phishtank_csv_extracts_url_column() {
        let csv = "phish_id,url,detail_url\n1,https://phish.example/login,https://phishtank.org/phish/1\n";
        let entries = parse_phishtank_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.hostnames, vec!["phish.example".to_string()]);
    }

    #[test]
    fn domain_blocklist_parses_hosts_like_lines() {
        let contents = "# comment\n0.0.0.0 bad.example\nphish.example\n127.0.0.1 localhost\n";
        let entries = parse_domain_blocklist(contents);
        assert_eq!(
            entries.hostnames,
            vec!["bad.example".to_string(), "phish.example".to_string()]
        );
    }

    #[test]
    fn tor_exit_list_parses_ipv4_lines() {
        let contents = "# generated\n203.0.113.10\n198.51.100.12\n";
        let entries = parse_tor_exit_list(contents);
        assert_eq!(
            entries.ips,
            vec![
                Ipv4Addr::new(198, 51, 100, 12),
                Ipv4Addr::new(203, 0, 113, 10),
            ]
        );
    }
}
