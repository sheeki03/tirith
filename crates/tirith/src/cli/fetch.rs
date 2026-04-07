use tirith_core::rules::cloaking;

pub fn run(url: &str, json: bool) -> i32 {
    match cloaking::check(url) {
        Ok(result) => {
            if json {
                print_json(&result);
            } else {
                print_human(&result);
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

fn print_json(result: &cloaking::CloakingResult) {
    let json = result.to_json(true);
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|e| {
            eprintln!("tirith: fetch: JSON serialization failed: {e}");
            "{}".to_string()
        })
    );
}

fn print_human(result: &cloaking::CloakingResult) {
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
        println!(
            "{}",
            tirith_core::style::bold_red("Cloaking detected!", tirith_core::style::Stream::Stdout)
        );
        for diff in &result.diff_pairs {
            println!(
                "  {} vs {}: {} chars different",
                diff.agent_a, diff.agent_b, diff.diff_chars
            );
            if let Some(ref text) = diff.diff_text {
                println!("    {text}");
            }
        }
    } else {
        println!(
            "{}",
            tirith_core::style::green("No cloaking detected.", tirith_core::style::Stream::Stdout)
        );
    }
}
