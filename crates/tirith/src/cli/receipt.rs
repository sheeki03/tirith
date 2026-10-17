use super::receipt_display as display;
use tirith_core::receipt::Receipt;

fn failure(error: &str) -> i32 {
    eprintln!("tirith receipt: {error}");
    1
}

fn saved() -> Result<Vec<Receipt>, &'static str> {
    let mut receipts = display::list_download()?;
    receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(receipts)
}

pub fn last(json: bool) -> i32 {
    let compiled = display::output_dlp();
    match saved() {
        Ok(receipts) => match receipts.first() {
            Some(receipt) => {
                let value = display::download(receipt, &compiled);
                if let Err(error) = display::bounded(&value) { return failure(error); }
                if json { i32::from(!display::write(&value)) }
                else { print_receipt(&value); 0 }
            }
            None => failure("No download receipts found. `tirith run` records download receipts; shell execution receipts use a separate store."),
        },
        Err(error) => failure(error),
    }
}

pub fn list(json: bool) -> i32 {
    let compiled = display::output_dlp();
    match saved() {
        Ok(receipts) => {
            let values: Vec<_> = receipts
                .iter()
                .map(|receipt| display::download(receipt, &compiled))
                .collect();
            let value = serde_json::Value::Array(values);
            if let Err(error) = display::bounded(&value) {
                return failure(error);
            }
            if json {
                return i32::from(!display::write(&value));
            }
            if receipts.is_empty() {
                eprintln!("tirith: no download receipts found");
            }
            for row in value.as_array().expect("receipt list") {
                eprintln!(
                    "  {} {} ({} bytes) {}",
                    tirith_core::receipt::short_hash(&display::text(row, "sha256")),
                    display::text(row, "url"),
                    row["size"],
                    display::text(row, "timestamp")
                );
            }
            0
        }
        Err(error) => failure(error),
    }
}

pub fn verify(sha256: &str, json: bool) -> i32 {
    let compiled = display::output_dlp();
    let receipt = match display::load_download(sha256) {
        Ok(receipt) => receipt,
        Err(error) => return failure(error),
    };
    // Verification reads the original receipt, never its presentation clone.
    match display::verify_download(&receipt) {
        Ok(valid) => {
            if json {
                let projected = display::download(&receipt, &compiled);
                let value =
                    serde_json::json!({"sha256":sha256,"valid":valid,"url":projected["url"]});
                if !display::write(&value) {
                    return 1;
                }
            } else {
                eprintln!(
                    "tirith: receipt {} {}",
                    tirith_core::receipt::short_hash(sha256),
                    if valid {
                        "verified OK"
                    } else {
                        "FAILED verification"
                    }
                );
            }
            i32::from(!valid)
        }
        Err(error) => failure(&tirith_core::output::sanitize_human_field_with_compiled(
            error, &compiled,
        )),
    }
}

fn print_receipt(receipt: &serde_json::Value) {
    eprintln!("tirith: receipt");
    for (label, key) in [
        ("url", "url"),
        ("final_url", "final_url"),
        ("sha256", "sha256"),
        ("analyzed", "analysis_method"),
        ("privilege", "privilege"),
        ("when", "timestamp"),
    ] {
        if !receipt[key].is_null() {
            eprintln!("  {label}: {}", display::text(receipt, key));
        }
    }
    eprintln!("  size: {} bytes", receipt["size"]);
    if let Some(domains) = receipt["domains_referenced"].as_array() {
        let domains: Vec<_> = domains.iter().filter_map(|value| value.as_str()).collect();
        if !domains.is_empty() {
            eprintln!(
                "  domains: {}",
                super::sanitize_for_human_output(&domains.join(", "), false)
            );
        }
    }
}
