use tirith_core::audit_aggregator::{self, AuditFilter};

/// Run the `tirith audit export` subcommand.
pub fn export(
    format: &str,
    since: Option<&str>,
    until: Option<&str>,
    session: Option<&str>,
    action: Option<&str>,
    rule_ids: &[String],
    entry_type: &str,
) -> i32 {
    if !matches!(
        entry_type,
        "verdict" | "hook_telemetry" | "trust_change" | "all"
    ) {
        eprintln!(
            "tirith: unknown entry type '{entry_type}' (use 'verdict', 'hook_telemetry', 'trust_change', or 'all')"
        );
        eprintln!("  try: tirith audit export --entry-type verdict");
        return 1;
    }

    if format == "csv" && entry_type != "verdict" {
        eprintln!(
            "tirith: CSV export only supports verdict entries; use --format json for {entry_type}"
        );
        return 1;
    }

    let log_path = match tirith_core::policy::data_dir() {
        Some(d) => d.join("log.jsonl"),
        None => {
            eprintln!("tirith: could not determine audit log path");
            return 1;
        }
    };

    if !log_path.exists() {
        eprintln!("tirith: no audit log found at {}", log_path.display());
        return 1;
    }

    let result = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };
    if result.skipped_lines > 0 {
        eprintln!(
            "tirith: warning: {} malformed audit log line(s) skipped",
            result.skipped_lines
        );
    }
    let records = result.records;

    let filter = AuditFilter {
        since: since.map(String::from),
        until: until.map(String::from),
        session_id: session.map(String::from),
        action: action.map(String::from),
        rule_ids: rule_ids.to_vec(),
        entry_type: Some(entry_type.to_string()),
    };

    let filtered = audit_aggregator::filter_records(&records, &filter);

    match format {
        "csv" => print!("{}", audit_aggregator::export_csv(&filtered)),
        _ => println!("{}", audit_aggregator::export_json(&filtered)),
    }

    0
}

/// Run the `tirith audit stats` subcommand.
pub fn stats(session: Option<&str>, json: bool, entry_type: &str) -> i32 {
    match entry_type {
        "verdict" | "hook_telemetry" => {}
        "all" | "trust_change" => {
            eprintln!(
                "tirith: --entry-type {entry_type} is not supported for stats; use verdict or hook_telemetry"
            );
            return 1;
        }
        _ => {
            eprintln!("tirith: unknown --entry-type {entry_type}; use verdict or hook_telemetry");
            return 1;
        }
    }

    let log_path = match tirith_core::policy::data_dir() {
        Some(d) => d.join("log.jsonl"),
        None => {
            eprintln!("tirith: could not determine audit log path");
            return 1;
        }
    };

    if !log_path.exists() {
        eprintln!("tirith: no audit log found at {}", log_path.display());
        return 1;
    }

    let result = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };
    if result.skipped_lines > 0 {
        eprintln!(
            "tirith: warning: {} malformed audit log line(s) skipped",
            result.skipped_lines
        );
    }
    let records = result.records;

    let filtered = if let Some(sid) = session {
        let filter = AuditFilter {
            session_id: Some(sid.to_string()),
            entry_type: Some(entry_type.to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    } else {
        let filter = AuditFilter {
            entry_type: Some(entry_type.to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    };

    if entry_type == "hook_telemetry" {
        let hook_stats = audit_aggregator::compute_hook_stats(&filtered);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&hook_stats).unwrap_or_else(|e| {
                    eprintln!("tirith: audit stats: JSON serialization failed: {e}");
                    "{}".into()
                })
            );
        } else {
            println!("Hook telemetry:");
            // Sort by integration name then event name for stable output.
            let mut integrations: Vec<_> = hook_stats.events_by_integration.keys().collect();
            integrations.sort();
            for integration in integrations {
                let events = &hook_stats.events_by_integration[integration];
                let mut event_list: Vec<_> = events.iter().collect();
                event_list.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                for (event, count) in event_list {
                    println!("  {integration} / {event}: {count:>5}");
                }
            }
            if hook_stats.total_events == 0 {
                println!("  (no events recorded)");
            }
        }
    } else {
        let stats = audit_aggregator::compute_stats(&filtered);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&stats).unwrap_or_else(|e| {
                    eprintln!("tirith: audit stats: JSON serialization failed: {e}");
                    "{}".into()
                })
            );
        } else {
            println!("Commands analyzed: {}", stats.total_commands);
            println!("Total findings:    {}", stats.total_findings);
            println!("Block rate:        {:.1}%", stats.block_rate * 100.0);
            println!("Sessions:          {}", stats.sessions_seen);
            if let Some((ref first, ref last)) = stats.time_range {
                println!("Time range:        {first} to {last}");
            }
            if !stats.top_rules.is_empty() {
                println!("\nTop rules:");
                for (rule, count) in &stats.top_rules {
                    println!("  {rule}: {count}");
                }
            }
        }
    }

    0
}

/// Run the `tirith audit verify` subcommand: check the tamper-evident chain.
pub fn verify(expected_head: Option<&str>, json: bool) -> i32 {
    let Some(path) = tirith_core::audit::audit_log_path() else {
        eprintln!("tirith: no audit log path available");
        return 2;
    };
    if !path.exists() {
        // When the caller anchors verification with --expected-head, a missing
        // log is a FAILURE, not a vacuous pass: the operator asserted a specific
        // tail hash that an absent log cannot satisfy. Reporting success here
        // would let log deletion silently defeat the anchor.
        if expected_head.is_some() {
            if json {
                println!(
                    r#"{{"ok":false,"total_lines":0,"problems":["expected-head supplied but no audit log at {}"]}}"#,
                    path.display()
                );
            } else {
                eprintln!(
                    "tirith audit verify: FAILED — expected-head supplied but no audit log at {}",
                    path.display()
                );
            }
            return 1;
        }
        if json {
            println!(r#"{{"ok":true,"total_lines":0,"note":"no audit log yet"}}"#);
        } else {
            println!("tirith audit verify: no audit log at {}", path.display());
        }
        return 0;
    }
    let report = tirith_core::audit::verify_audit_log(&path, expected_head);
    if json {
        let problems: Vec<serde_json::Value> = report
            .problems
            .iter()
            .map(|p| serde_json::Value::String(p.clone()))
            .collect();
        let obj = serde_json::json!({
            "ok": report.ok,
            "total_lines": report.total_lines,
            "chained_lines": report.chained_lines,
            "legacy_prefix": report.legacy_prefix,
            "head_status": report.head_status,
            "signed_lines": report.signed_lines,
            "signing_expected": report.signing_expected,
            "problems": problems,
        });
        println!("{obj}");
    } else {
        println!(
            "tirith audit verify: {} ({} lines, {} chained, {} legacy)",
            if report.ok { "OK" } else { "FAILED" },
            report.total_lines,
            report.chained_lines,
            report.legacy_prefix
        );
        println!("  {}", report.head_status);
        if report.signing_expected {
            println!(
                "  signing: enabled ({} signed line(s))",
                report.signed_lines
            );
        } else {
            // Honest limitation: for an UNSIGNED log there is no key, so local
            // verification cannot prove signing was never enabled. A fully local
            // attacker could strip signatures and rewrite the head to look
            // unsigned. Detecting that requires an external anchor (a signed log,
            // or an out-of-band --expected-head). See the audit.rs module note.
            println!(
                "  signing: not enabled (local verification cannot prove signing was \
                 never enabled on an unsigned log without an external anchor)"
            );
        }
        for p in &report.problems {
            println!("  problem: {p}");
        }
    }
    if report.ok {
        0
    } else {
        1
    }
}

/// Run the `tirith audit report` subcommand.
pub fn report(format: &str, since: Option<&str>, entry_type: &str) -> i32 {
    if entry_type != "verdict" {
        eprintln!(
            "tirith: --entry-type {entry_type} is not supported for reports; only verdict is supported"
        );
        return 1;
    }

    let log_path = match tirith_core::policy::data_dir() {
        Some(d) => d.join("log.jsonl"),
        None => {
            eprintln!("tirith: could not determine audit log path");
            return 1;
        }
    };

    if !log_path.exists() {
        eprintln!("tirith: no audit log found at {}", log_path.display());
        return 1;
    }

    let result = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };
    if result.skipped_lines > 0 {
        eprintln!(
            "tirith: warning: {} malformed audit log line(s) skipped",
            result.skipped_lines
        );
    }
    let records = result.records;

    let filtered = if let Some(since_date) = since {
        let filter = AuditFilter {
            since: Some(since_date.to_string()),
            entry_type: Some("verdict".to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    } else {
        let filter = AuditFilter {
            entry_type: Some("verdict".to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    };

    let stats = audit_aggregator::compute_stats(&filtered);

    match format {
        "json" => {
            let report_json = serde_json::json!({
                "stats": stats,
                "records": filtered,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&report_json).unwrap_or_else(|e| {
                    eprintln!("tirith: audit report: JSON serialization failed: {e}");
                    "{}".into()
                })
            );
        }
        "html" => {
            print!(
                "{}",
                audit_aggregator::generate_html_report(&filtered, &stats)
            );
        }
        _ => {
            print!(
                "{}",
                audit_aggregator::generate_compliance_report(&filtered, &stats)
            );
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    // Local env lock: `tirith_core::TEST_ENV_LOCK` is pub(crate) and unreachable
    // here, so this module serializes its own env mutation. (tirith bin tests run
    // as a separate process from tirith-core lib tests, so the two locks need not
    // coordinate.)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// F8: `tirith audit verify --expected-head <hash>` must FAIL (non-zero) when
    /// the log is missing — an asserted tail hash cannot be satisfied by an absent
    /// log, so reporting success would let log deletion silently defeat the anchor.
    /// A plain `verify` (no anchor) on a missing log still succeeds (0).
    #[cfg(unix)]
    #[test]
    fn verify_missing_log_with_expected_head_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty_home");
        std::fs::create_dir_all(&empty).unwrap();

        let prev_home = std::env::var("HOME").ok();
        let prev_xdg_data = std::env::var("XDG_DATA_HOME").ok();
        // Point BOTH the XDG data dir (Linux) and HOME (macOS, via etcetera's
        // Apple strategy) at a fresh empty dir, so `audit_log_path()` resolves to a
        // file that does not exist on either platform.
        // SAFETY: serialized via ENV_LOCK above.
        unsafe {
            std::env::set_var("HOME", &empty);
            std::env::set_var("XDG_DATA_HOME", &empty);
        }

        let with_anchor = super::verify(Some("deadbeefcafe"), true);
        let without_anchor = super::verify(None, true);

        // SAFETY: serialized via ENV_LOCK; restore regardless of outcome.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_xdg_data {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }

        assert_eq!(
            with_anchor, 1,
            "verify --expected-head on a missing log must return non-zero"
        );
        assert_eq!(
            without_anchor, 0,
            "verify with no anchor on a missing log stays a vacuous success"
        );
    }
}
