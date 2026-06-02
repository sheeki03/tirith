use tirith_core::audit;
use tirith_core::audit_aggregator;
use tirith_core::rule_explanations::{self, RuleExplanation};
use tirith_core::verdict::RuleId;

pub fn run(
    rule: Option<&str>,
    list: bool,
    category: Option<&str>,
    finding: Option<&str>,
    fix: bool,
    json: bool,
) -> i32 {
    if list {
        // `--fix` requires `--rule`/`--finding` (clap-enforced), so never reaches here.
        return run_list(category, json);
    }

    // `--finding` resolves to a RuleId via the audit log, then behaves like
    // `--rule <id>`. Resolution failure surfaces here (not as a clap error) so
    // the message can name the audit log path concretely.
    if let Some(id) = finding {
        return match resolve_finding_id(id) {
            Ok(rule_id) => run_single(&rule_id.to_string(), fix, json),
            Err(e) => {
                eprintln!("tirith: {e}");
                1
            }
        };
    }

    match rule {
        Some(id) => run_single(id, fix, json),
        None => {
            eprintln!("tirith: specify --rule <id>, --finding <id>, or --list");
            1
        }
    }
}

/// Resolve a finding ID (`<event_id>:<index>`) to its [`RuleId`] by walking the
/// audit log most-recent-first, capped at [`AUDIT_SCAN_LIMIT`] entries so a busy
/// host's log can't burn unbounded CPU. On a cap miss the error tells the
/// operator to narrow via `tirith audit export --since`.
const AUDIT_SCAN_LIMIT: usize = 10_000;

fn resolve_finding_id(id: &str) -> Result<RuleId, String> {
    let (event_id, index) = audit::parse_finding_id(id).ok_or_else(|| {
        format!(
            "malformed finding ID {id:?} — expected the form `<event_id>:<index>` \
             (try `tirith audit export --format json` to discover one)"
        )
    })?;

    let log_path = audit::audit_log_path().ok_or_else(|| {
        "no audit log path could be resolved (set XDG_DATA_HOME or APPDATA)".to_string()
    })?;

    if !log_path.exists() {
        return Err(format!(
            "no audit log at {} — cannot resolve finding ID {id:?} (run a command first to seed the log)",
            log_path.display()
        ));
    }

    let read = audit_aggregator::read_log(&log_path)
        .map_err(|e| format!("could not read {}: {e}", log_path.display()))?;

    // Walk newest-first (log is append-only, newest at the bottom), bounded by
    // AUDIT_SCAN_LIMIT so the call doesn't quietly miss the entry past the cap.
    let scanned = read.records.len().min(AUDIT_SCAN_LIMIT);
    let entry = read
        .records
        .iter()
        .rev()
        .take(scanned)
        .find(|r| r.event_id.as_deref() == Some(event_id));

    let Some(entry) = entry else {
        if read.records.len() > AUDIT_SCAN_LIMIT {
            return Err(format!(
                "finding ID {id:?} not found in the {scanned} most-recent audit entries (cap is {AUDIT_SCAN_LIMIT}); \
                 narrow via `tirith audit export --since <duration>` and re-run"
            ));
        }
        return Err(format!(
            "finding ID {id:?} not found in {} ({} verdict entr{} scanned)",
            log_path.display(),
            scanned,
            if scanned == 1 { "y" } else { "ies" }
        ));
    };

    let rule_str = entry.rule_ids.get(index).ok_or_else(|| {
        format!(
            "finding ID {id:?} resolves to entry event_id {event_id:?}, but index {index} is \
             out of range (the entry has {} rule id{})",
            entry.rule_ids.len(),
            if entry.rule_ids.len() == 1 { "" } else { "s" },
        )
    })?;

    // serde-roundtrip (mirrors `rule_explanations.rs`): a snake_case RuleId
    // string ("pipe_to_interpreter") parses through the Deserialize impl.
    let parsed: Result<RuleId, _> =
        serde_json::from_value(serde_json::Value::String(rule_str.clone()));
    parsed.map_err(|_| {
        format!(
            "finding ID {id:?} resolves to rule_id {rule_str:?}, which does not match \
             any known RuleId variant (the audit entry may be from a newer tirith release)"
        )
    })
}

/// Compact `--fix` view: just the rule's remediation.
#[derive(serde::Serialize)]
struct FixView<'a> {
    id: &'a str,
    title: &'a str,
    remediation: &'a str,
}

fn run_single(id: &str, fix: bool, json: bool) -> i32 {
    let Some(entry) = rule_explanations::explain(id) else {
        eprintln!("tirith: unknown rule: {id}");
        if let Some(suggestion) = suggest(id) {
            eprintln!("  did you mean: {suggestion}?");
        }
        return 1;
    };

    if fix {
        let view = FixView {
            id: entry.id,
            title: entry.title,
            remediation: entry.remediation,
        };
        if json {
            print_json(&view);
        } else {
            print_human_fix(entry);
        }
        return 0;
    }

    if json {
        print_json(entry);
    } else {
        print_human_single(entry);
    }
    0
}

/// `--fix` human output: the rule's remediation only.
fn print_human_fix(e: &RuleExplanation) {
    println!("{} — {}  [{}]", e.id, e.title, e.category);
    println!();
    println!("Remediation");
    if e.remediation.is_empty() {
        println!("  (no remediation guidance available for this rule)");
    } else {
        println!("  {}", e.remediation);
    }
}

fn run_list(category: Option<&str>, json: bool) -> i32 {
    let entries: Vec<&RuleExplanation> = match category {
        Some(cat) => {
            let list = rule_explanations::list_by_category(cat);
            if list.is_empty() {
                eprintln!("tirith: unknown category: {cat}");
                let cats = rule_explanations::categories();
                eprintln!("  valid categories: {}", cats.join(", "));
                return 1;
            }
            list
        }
        None => rule_explanations::list_all().iter().collect(),
    };

    if json {
        print_json(&entries);
    } else {
        print_human_list(&entries);
    }
    0
}

fn print_human_single(e: &RuleExplanation) {
    println!("{} — {}  [{}]", e.id, e.title, e.category);
    println!("Severity: {}", e.severity_rationale);
    println!();
    println!("Description");
    println!("  {}", e.description);

    if !e.examples_bad.is_empty() {
        println!();
        println!("Examples (flagged)");
        for ex in e.examples_bad {
            println!("  {ex}");
        }
    }

    if !e.examples_good.is_empty() {
        println!();
        println!("Examples (safe)");
        for ex in e.examples_good {
            println!("  {ex}");
        }
    }

    println!();
    println!("False positives");
    println!("  {}", e.false_positive_guidance);

    println!();
    println!("Remediation");
    println!("  {}", e.remediation);

    if let Some(mitre) = e.mitre_id {
        println!();
        println!("MITRE ATT&CK: {mitre}");
    }

    if !e.references.is_empty() {
        println!();
        println!("References");
        for r in e.references {
            println!("  {r}");
        }
    }
}

fn print_human_list(entries: &[&RuleExplanation]) {
    let mut current_category = "";
    for e in entries {
        if e.category != current_category {
            if !current_category.is_empty() {
                println!();
            }
            println!("=== {} ===", e.category.to_uppercase());
            current_category = e.category;
        }
        println!("  {:<40} {}", e.id, e.title);
    }
}

fn print_json(value: &impl serde::Serialize) {
    if let Err(e) = serde_json::to_writer_pretty(std::io::stdout().lock(), value) {
        eprintln!("tirith: failed to write JSON output: {e}");
    }
    println!();
}

fn suggest(query: &str) -> Option<&'static str> {
    let mut best_id = "";
    let mut best_dist = usize::MAX;

    for entry in rule_explanations::list_all() {
        let d = tirith_core::util::levenshtein(query, entry.id);
        if d < best_dist {
            best_dist = d;
            best_id = entry.id;
        }
    }

    if best_dist <= 3 {
        Some(best_id)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_close_typo() {
        let s = suggest("pipe_to_interpeter");
        assert_eq!(s, Some("pipe_to_interpreter"));
    }

    #[test]
    fn test_suggest_no_match() {
        let s = suggest("zzzzzzzzzzzzz");
        assert!(s.is_none());
    }
}
