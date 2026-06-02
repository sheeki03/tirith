//! `tirith aliases scan|explain` — thin presenter over [`tirith_core::aliases`]
//! (enumeration + classification live in the library; this module is output).
//!
//! `scan` enumerates aliases + functions (statically; also via no-rc shell-outs
//! with `--include-runtime`) and reports risky ones: exit `1` on any
//! High/Critical finding, else `0`. `explain <name>` shows each matching
//! definition's body (credential-redacted) plus findings; exit 0/2 (2 = unknown
//! name).

use tirith_core::aliases::{self, AliasEntry, AliasFinding, AliasScan};
use tirith_core::redact::redact;
use tirith_core::verdict::Severity;

use super::write_json_stdout;

pub fn scan(include_runtime: bool, json: bool) -> i32 {
    let scan = aliases::scan(include_runtime);
    let any_high = scan.findings.iter().any(AliasFinding::is_high);

    if json {
        let body = scan_json_body(&scan, include_runtime);
        if !write_json_stdout(&body, "tirith aliases scan: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_scan(&scan, include_runtime);
    }

    if any_high {
        1
    } else {
        0
    }
}

/// Exit 0 when found, 2 when the name is unknown (lets a script distinguish
/// "no such alias" from "found, clean").
pub fn explain(name: &str, include_runtime: bool, json: bool) -> i32 {
    let ex = aliases::explain(name, include_runtime);

    if json {
        let body = explain_json_body(name, &ex);
        if !write_json_stdout(&body, "tirith aliases explain: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_explain(name, &ex);
    }

    if ex.matches.is_empty() {
        2
    } else {
        0
    }
}

fn print_human_scan(scan: &AliasScan, include_runtime: bool) {
    let aliases_n = scan
        .entries
        .iter()
        .filter(|e| e.kind == tirith_core::aliases::AliasKind::Alias)
        .count();
    let functions_n = scan.entries.len() - aliases_n;
    eprintln!(
        "tirith aliases: {} definition(s) found ({aliases_n} alias, {functions_n} function).",
        scan.entries.len()
    );
    if include_runtime {
        eprintln!(
            "  (static parse + runtime no-rc introspection; runtime spawns shells with \
             --norc / -f / --no-config so your rc files are NOT sourced.)"
        );
        if !scan.runtime_skipped.is_empty() {
            eprintln!(
                "  runtime-skipped shells (unsupported / not installed): {}",
                scan.runtime_skipped.join(", ")
            );
        }
    } else {
        eprintln!(
            "  (static parse only — pass --include-runtime to also introspect live shells \
             with no-rc flags.)"
        );
    }
    eprintln!();

    for e in &scan.entries {
        let parsed = if e.body_parsed {
            ""
        } else {
            "  [body unparsed — review manually]"
        };
        eprintln!(
            "  {:<9} {:<20} [{}] {}{}",
            e.kind.as_str(),
            e.name,
            e.shell.as_str(),
            aliases::short_location(e),
            parsed,
        );
    }

    if scan.findings.is_empty() {
        eprintln!("\ntirith aliases: no risky aliases / functions detected.");
        return;
    }

    let high = scan.findings.iter().filter(|f| f.is_high()).count();
    eprintln!(
        "\ntirith aliases: {} finding(s) ({high} high).\n",
        scan.findings.len()
    );
    for f in &scan.findings {
        print_one_finding(f);
    }
    eprintln!("Run `tirith aliases explain <name>` to see a definition's body + full analysis.");
}

fn print_human_explain(name: &str, ex: &aliases::AliasExplain) {
    if ex.matches.is_empty() {
        eprintln!("tirith aliases: no alias or function named `{name}` found.");
        eprintln!(
            "  (static parse of your rc/profile files; pass --include-runtime to also check \
             live shells.)"
        );
        return;
    }

    eprintln!(
        "tirith aliases explain `{name}`: {} definition(s).\n",
        ex.matches.len()
    );
    for e in &ex.matches {
        eprintln!(
            "  {} ({}) — {}",
            e.name,
            e.kind.as_str(),
            aliases::short_location(e),
        );
        if e.body.is_empty() {
            eprintln!("    body: (empty / not captured)");
        } else if e.body_parsed {
            // Redact body before display — a function body may inline a secret.
            eprintln!("    body: {}", redact(&e.body));
        } else {
            eprintln!("    body (UNPARSED — review manually): {}", redact(&e.body));
        }
        eprintln!();
    }

    if ex.findings.is_empty() {
        eprintln!("Analysis: no risk rules fired for `{name}`.");
        return;
    }
    eprintln!("Analysis — {} finding(s):", ex.findings.len());
    for f in &ex.findings {
        print_one_finding(f);
    }
}

fn print_one_finding(f: &AliasFinding) {
    eprintln!(
        "  [{}] {}\n      name:     {} ({})\n      location: {}\n      detail:   {}\n",
        severity_label(f.severity),
        f.rule_id,
        f.name,
        f.kind.as_str(),
        f.location,
        f.detail,
    );
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn scan_json_body(scan: &AliasScan, include_runtime: bool) -> serde_json::Value {
    let high = scan.findings.iter().filter(|f| f.is_high()).count();
    serde_json::json!({
        "schema_version": 1,
        "include_runtime": include_runtime,
        "total_definitions": scan.entries.len(),
        "total_findings": scan.findings.len(),
        "high_or_critical": high,
        "runtime_skipped": scan.runtime_skipped,
        "definitions": scan
            .entries
            .iter()
            .map(alias_entry_json)
            .collect::<Vec<_>>(),
        "findings": scan.findings,
    })
}

fn explain_json_body(name: &str, ex: &aliases::AliasExplain) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "name": name,
        "found": !ex.matches.is_empty(),
        "definitions": ex.matches.iter().map(alias_entry_json).collect::<Vec<_>>(),
        "findings": ex.findings,
    })
}

/// Serialize an entry for JSON output with its body credential-redacted (the
/// body can inline a secret; the JSON consumer must not receive it verbatim).
fn alias_entry_json(e: &AliasEntry) -> serde_json::Value {
    serde_json::json!({
        "name": e.name,
        "kind": e.kind.as_str(),
        "shell": e.shell.as_str(),
        "source": e.source.as_str(),
        "source_path": e.source_path.as_ref().map(|p| p.display().to_string()),
        "line": e.line,
        "body_parsed": e.body_parsed,
        "body": redact(&e.body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::aliases::{AliasKind, AliasScan, AliasShell, AliasSource};

    fn sample_entry(name: &str, body: &str) -> AliasEntry {
        AliasEntry {
            name: name.to_string(),
            body: body.to_string(),
            kind: AliasKind::Alias,
            shell: AliasShell::Bash,
            source: AliasSource::StaticFile,
            source_path: Some(std::path::PathBuf::from("/home/u/.bashrc")),
            line: Some(7),
            body_parsed: true,
        }
    }

    #[test]
    fn scan_json_body_redacts_body_and_counts() {
        let scan = AliasScan {
            entries: vec![sample_entry(
                "getkey",
                "cat ~/.aws/credentials AKIAIOSFODNN7EXAMPLE",
            )],
            findings: vec![],
            runtime_skipped: vec![],
        };
        let body = scan_json_body(&scan, false);
        assert_eq!(body["total_definitions"], 1);
        assert_eq!(body["include_runtime"], false);
        // The AWS key in the body must be redacted in the JSON envelope.
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("AKIAIOSFODNN7EXAMPLE"),
            "alias body must be credential-redacted in JSON, got {serialized}"
        );
    }

    #[test]
    fn explain_json_body_marks_found() {
        let ex = aliases::AliasExplain {
            matches: vec![sample_entry("git", "git --no-pager")],
            findings: vec![],
        };
        let body = explain_json_body("git", &ex);
        assert_eq!(body["found"], true);
        assert_eq!(body["name"], "git");

        let empty = aliases::AliasExplain::default();
        let body2 = explain_json_body("nope", &empty);
        assert_eq!(body2["found"], false);
    }
}
