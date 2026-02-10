use tirith_core::audit_aggregator::{self, AuditFilter};

/// Run the `tirith audit export` subcommand.
pub fn export(
    format: &str,
    since: Option<&str>,
    until: Option<&str>,
    session: Option<&str>,
    action: Option<&str>,
    rule_ids: &[String],
) -> i32 {
    if tirith_core::license::current_tier() < tirith_core::license::Tier::Team {
        eprintln!("tirith: audit export requires a Team license");
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

    let records = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };

    let filter = AuditFilter {
        since: since.map(String::from),
        until: until.map(String::from),
        session_id: session.map(String::from),
        action: action.map(String::from),
        rule_ids: rule_ids.to_vec(),
    };

    let filtered = audit_aggregator::filter_records(&records, &filter);

    match format {
        "csv" => print!("{}", audit_aggregator::export_csv(&filtered)),
        _ => println!("{}", audit_aggregator::export_json(&filtered)),
    }

    0
}

/// Run the `tirith audit stats` subcommand.
pub fn stats(session: Option<&str>, json: bool) -> i32 {
    if tirith_core::license::current_tier() < tirith_core::license::Tier::Team {
        eprintln!("tirith: audit stats requires a Team license");
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

    let records = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };

    let filtered = if let Some(sid) = session {
        let filter = AuditFilter {
            session_id: Some(sid.to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    } else {
        records
    };

    let stats = audit_aggregator::compute_stats(&filtered);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "{}".into())
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

    0
}

/// Run the `tirith audit report` subcommand.
pub fn report(format: &str, since: Option<&str>) -> i32 {
    if tirith_core::license::current_tier() < tirith_core::license::Tier::Team {
        eprintln!("tirith: audit report requires a Team license");
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

    let records = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };

    let filtered = if let Some(since_date) = since {
        let filter = AuditFilter {
            since: Some(since_date.to_string()),
            ..Default::default()
        };
        audit_aggregator::filter_records(&records, &filter)
    } else {
        records
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
                serde_json::to_string_pretty(&report_json).unwrap_or_else(|_| "{}".into())
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
