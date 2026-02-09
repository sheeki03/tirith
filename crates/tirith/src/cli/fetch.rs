use tirith_core::license;
use tirith_core::rules::cloaking;

pub fn run(url: &str, json: bool) -> i32 {
    let is_pro = license::current_tier() >= license::Tier::Pro;
    match cloaking::check(url) {
        Ok(mut result) => {
            // Strip diff_text for Free tier (enrichment is Pro-gated per ADR-13)
            if !is_pro {
                for diff in &mut result.diff_pairs {
                    diff.diff_text = None;
                }
            }
            if json {
                print_json(&result, is_pro);
            } else {
                print_human(&result, is_pro);
            }
            if result.cloaking_detected {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("tirith fetch: {e}");
            2
        }
    }
}

fn print_json(result: &cloaking::CloakingResult, is_pro: bool) {
    let json = serde_json::json!({
        "url": result.url,
        "cloaking_detected": result.cloaking_detected,
        "agents": result.agent_responses.iter().map(|a| {
            serde_json::json!({
                "agent": a.agent_name,
                "status_code": a.status_code,
                "content_length": a.content_length,
            })
        }).collect::<Vec<_>>(),
        "diffs": result.diff_pairs.iter().map(|d| {
            let mut entry = serde_json::json!({
                "agent_a": d.agent_a,
                "agent_b": d.agent_b,
                "diff_chars": d.diff_chars,
            });
            if is_pro {
                if let Some(ref text) = d.diff_text {
                    entry.as_object_mut().unwrap().insert("diff_text".into(), serde_json::json!(text));
                }
            }
            entry
        }).collect::<Vec<_>>(),
        "findings": result.findings,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

fn print_human(result: &cloaking::CloakingResult, is_pro: bool) {
    println!("Cloaking check: {}", result.url);
    println!();

    for agent in &result.agent_responses {
        let status = if agent.status_code == 0 {
            "FAILED".to_string()
        } else {
            agent.status_code.to_string()
        };
        println!(
            "  {:<14} status={:<6} length={}",
            agent.agent_name, status, agent.content_length
        );
    }

    println!();

    if result.cloaking_detected {
        println!("\x1b[1;31mCloaking detected!\x1b[0m");
        for diff in &result.diff_pairs {
            println!(
                "  {} vs {}: {} chars different",
                diff.agent_a, diff.agent_b, diff.diff_chars
            );
            if is_pro {
                if let Some(ref text) = diff.diff_text {
                    println!("    {text}");
                }
            }
        }
        if !is_pro {
            println!();
            println!("  \x1b[90m(Pro license unlocks detailed diff text)\x1b[0m");
        }
    } else {
        println!("\x1b[32mNo cloaking detected.\x1b[0m");
    }
}
