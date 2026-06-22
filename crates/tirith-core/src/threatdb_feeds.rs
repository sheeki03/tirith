use std::io::{Read, Seek};
use std::net::Ipv4Addr;

use crate::threatdb::BehaviorTag;

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

        // Cap decompressed size to prevent zip bombs.
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

        // Strip inline `#` comments, then take the last token (handles the
        // "0.0.0.0 bad.example" hosts format).
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

/// Parse a curated exfiltration-endpoint / webhook-catcher hostname list.
///
/// The on-disk format is a plain domain-per-line blocklist (one hostname per
/// line, `#` comments and blank lines ignored, hosts-file `0.0.0.0 host` lines
/// tolerated), so this is a thin wrapper over [`parse_domain_blocklist`]. It
/// exists as a distinct entry point so the compiler call site reads clearly and
/// the feed can grow its own parsing rules later without disturbing the shared
/// blocklist parser. Output goes into `FeedEntries.hostnames`.
pub fn parse_exfil_endpoint_list(contents: &str) -> FeedEntries {
    parse_domain_blocklist(contents)
}

/// Registry-provenance marker for one curated file-hash record.
///
/// The plan sources removal/yank state "from a registry-provenance feed (not
/// assumed OpenSSF)", so a record can attest either that the bytes are a
/// known-malicious analysis/file artifact (OSSF-derived) or that a registry
/// has yanked/removed the distribution the bytes came from. Both are carried
/// on the same v2 file-hash record (there is no separate on-disk yank section
/// and G1 must not bump the format); the marker only records WHERE the
/// provenance came from for the compile-time log and so the two feeds stay
/// distinguishable at ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHashProvenance {
    /// Derived from the OpenSSF malicious-packages corpus / a curated analysis
    /// feed: the file content itself is known-malicious.
    OssfMalicious,
    /// Sourced from a registry-provenance (yank/removal) feed: the registry
    /// pulled the distribution these bytes belong to.
    RegistryYank,
}

/// One parsed entry from the curated file-hash companion feed.
///
/// `behavior_tags` and `campaign` are taken ONLY from the explicit structured
/// `tags=` / `campaign=` fields of the feed line. They are never inferred from
/// free text: the OSV `details`/`summary` prose is deliberately not a source
/// here (the plan forbids scraping behavior tags from advisory prose). The
/// `sha256` is the validated 32-byte content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuratedFileHash {
    pub sha256: [u8; 32],
    pub behavior_tags: Vec<BehaviorTag>,
    pub campaign: Option<String>,
    pub provenance: FileHashProvenance,
}

/// Outcome of parsing a curated file-hash feed: the accepted records plus the
/// counts of lines dropped for a bad digest or an unrecognized tag token. The
/// caller logs the drop counts (so a malformed feed is observable, not silent).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CuratedFileHashes {
    pub records: Vec<CuratedFileHash>,
    /// Lines dropped because the first field was not a 64-char hex SHA-256.
    pub skipped_bad_sha: usize,
    /// Tag tokens dropped because no `BehaviorTag` matched the name.
    pub skipped_unknown_tags: usize,
}

fn decode_feed_sha256(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse the curated malicious file-hash companion feed.
///
/// Format (one record per line; `#` comments and blank lines ignored):
///
/// ```text
/// <sha256-hex>  tags=process_spawn,network_exfil  campaign=miasma  source=ossf
/// <sha256-hex>  source=registry-yank
/// ```
///
/// The first whitespace-delimited token is the content SHA-256. The remaining
/// `key=value` tokens are order-independent and all optional:
/// * `tags=` a comma list of stable `BehaviorTag` names (see
///   [`BehaviorTag::from_name`]); unknown names are dropped and counted.
/// * `campaign=` a campaign label, interned into the v2 campaign string table.
/// * `source=` `ossf` (default) or `registry-yank` -> [`FileHashProvenance`].
///
/// This feeds [`crate::threatdb::ThreatDbWriter::add_file_sha256`] so the v2
/// `FileHash` + `BehaviorTags` sections go live. It is a SUPERSET-safe pure
/// parser: nothing here reads advisory prose, and a record with no `tags=` is
/// valid (the file hash alone is the indicator; tags are enrichment).
pub fn parse_curated_file_hashes(contents: &str) -> CuratedFileHashes {
    let mut out = CuratedFileHashes::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(sha_token) = fields.next() else {
            continue;
        };
        let Some(sha256) = decode_feed_sha256(sha_token) else {
            out.skipped_bad_sha += 1;
            continue;
        };

        let mut behavior_tags: Vec<BehaviorTag> = Vec::new();
        let mut campaign: Option<String> = None;
        let mut provenance = FileHashProvenance::OssfMalicious;

        for field in fields {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "tags" => {
                    for tag in value.split(',').filter(|t| !t.trim().is_empty()) {
                        match BehaviorTag::from_name(tag) {
                            Some(t) => {
                                if !behavior_tags.contains(&t) {
                                    behavior_tags.push(t);
                                }
                            }
                            None => out.skipped_unknown_tags += 1,
                        }
                    }
                }
                "campaign" => {
                    let label = value.trim();
                    if !label.is_empty() {
                        campaign = Some(label.to_string());
                    }
                }
                "source" => {
                    provenance = match value.trim().to_ascii_lowercase().as_str() {
                        "registry-yank" | "registry_yank" | "yank" => {
                            FileHashProvenance::RegistryYank
                        }
                        _ => FileHashProvenance::OssfMalicious,
                    };
                }
                _ => {}
            }
        }

        out.records.push(CuratedFileHash {
            sha256,
            behavior_tags,
            campaign,
            provenance,
        });
    }
    out
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
    fn exfil_endpoint_list_parses_hostnames() {
        // Fictional template entries only (CLAUDE.md: no real domains).
        let contents = "# curated exfil / webhook-catcher endpoints\nexfil-sink.example\n0.0.0.0 webhook-catcher.invalid\n127.0.0.1 localhost\n";
        let entries = parse_exfil_endpoint_list(contents);
        assert_eq!(
            entries.hostnames,
            vec![
                "exfil-sink.example".to_string(),
                "webhook-catcher.invalid".to_string(),
            ]
        );
        assert!(entries.ips.is_empty());
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

    #[test]
    fn curated_file_hashes_parses_tags_campaign_and_source() {
        let sha = "a".repeat(64);
        let contents = format!(
            "# curated malicious file hashes\n\
             {sha}  tags=process_spawn,network_exfil  campaign=miasma  source=ossf\n"
        );
        let parsed = parse_curated_file_hashes(&contents);
        assert_eq!(parsed.records.len(), 1);
        let rec = &parsed.records[0];
        assert_eq!(rec.sha256, [0xaa; 32]);
        assert!(rec.behavior_tags.contains(&BehaviorTag::ProcessSpawn));
        assert!(rec.behavior_tags.contains(&BehaviorTag::NetworkExfil));
        assert_eq!(rec.campaign.as_deref(), Some("miasma"));
        assert_eq!(rec.provenance, FileHashProvenance::OssfMalicious);
        assert_eq!(parsed.skipped_bad_sha, 0);
        assert_eq!(parsed.skipped_unknown_tags, 0);
    }

    #[test]
    fn curated_file_hashes_record_with_no_tags_is_valid() {
        // A bare file hash is a valid indicator on its own; tags are enrichment.
        let sha = "b".repeat(64);
        let parsed = parse_curated_file_hashes(&format!("{sha}\n"));
        assert_eq!(parsed.records.len(), 1);
        assert!(parsed.records[0].behavior_tags.is_empty());
        assert!(parsed.records[0].campaign.is_none());
    }

    #[test]
    fn curated_file_hashes_registry_yank_source() {
        let sha = "c".repeat(64);
        let parsed = parse_curated_file_hashes(&format!(
            "{sha}  source=registry-yank  campaign=axios-rat\n"
        ));
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(
            parsed.records[0].provenance,
            FileHashProvenance::RegistryYank
        );
        assert_eq!(parsed.records[0].campaign.as_deref(), Some("axios-rat"));
    }

    #[test]
    fn curated_file_hashes_drops_bad_sha_and_unknown_tag() {
        let good = "d".repeat(64);
        let contents = format!(
            "not-a-hash  tags=process_spawn\n\
             {good}  tags=process_spawn,definitely_not_a_tag\n"
        );
        let parsed = parse_curated_file_hashes(&contents);
        // The malformed-digest line is dropped entirely; the good line survives.
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.skipped_bad_sha, 1);
        // The unknown tag token is dropped, the known one is kept.
        assert_eq!(parsed.skipped_unknown_tags, 1);
        assert_eq!(
            parsed.records[0].behavior_tags,
            vec![BehaviorTag::ProcessSpawn]
        );
    }

    #[test]
    fn behavior_tag_name_round_trips() {
        for tag in BehaviorTag::ALL {
            assert_eq!(BehaviorTag::from_name(tag.as_str()), Some(tag));
        }
        assert_eq!(
            BehaviorTag::from_name("PROCESS_SPAWN"),
            Some(BehaviorTag::ProcessSpawn)
        );
        assert_eq!(
            BehaviorTag::from_name("  network_exfil "),
            Some(BehaviorTag::NetworkExfil)
        );
        assert_eq!(BehaviorTag::from_name("nope"), None);
    }
}
