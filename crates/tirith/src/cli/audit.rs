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
    // Validate entry type
    if !matches!(
        entry_type,
        "verdict" | "hook_telemetry" | "trust_change" | "all"
    ) {
        eprintln!(
            "tirith: unknown entry type '{entry_type}' (use 'verdict', 'hook_telemetry', 'trust_change', or 'all')"
        );
        return 1;
    }

    // CSV export only supports verdict entries
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
    // Validate entry_type
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
            // Sort by integration name, then by event name for stable output
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

/// Run the `tirith audit report` subcommand.
pub fn report(format: &str, since: Option<&str>, entry_type: &str) -> i32 {
    // Reports only support verdict entries
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
            // Default: markdown
            print!(
                "{}",
                audit_aggregator::generate_compliance_report(&filtered, &stats)
            );
        }
    }

    0
}
