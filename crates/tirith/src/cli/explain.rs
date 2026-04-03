use tirith_core::rule_explanations::{self, RuleExplanation};

pub fn run(rule: Option<&str>, list: bool, category: Option<&str>, json: bool) -> i32 {
    if list {
        return run_list(category, json);
    }

    match rule {
        Some(id) => run_single(id, json),
        None => {
            eprintln!("tirith: specify --rule <id> or --list");
            1
        }
    }
}

fn run_single(id: &str, json: bool) -> i32 {
    let Some(entry) = rule_explanations::explain(id) else {
        eprintln!("tirith: unknown rule: {id}");
        if let Some(suggestion) = suggest(id) {
            eprintln!("  did you mean: {suggestion}?");
        }
        return 1;
    };

    if json {
        print_json(entry);
    } else {
        print_human_single(entry);
    }
    0
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
