use tirith_core::receipt::Receipt;

pub fn last(json: bool) -> i32 {
    match Receipt::list() {
        Ok(receipts) => {
            if let Some(r) = receipts.first() {
                if json {
                    let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), r);
                    println!();
                } else {
                    print_receipt(r);
                }
                0
            } else {
                eprintln!("tirith: no receipts found");
                1
            }
        }
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

pub fn list(json: bool) -> i32 {
    match Receipt::list() {
        Ok(receipts) => {
            if json {
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &receipts);
                println!();
            } else if receipts.is_empty() {
                eprintln!("tirith: no receipts found");
            } else {
                for r in &receipts {
                    eprintln!(
                        "  {} {} ({} bytes) {}",
                        tirith_core::receipt::short_hash(&r.sha256),
                        r.url,
                        r.size,
                        r.timestamp
                    );
                }
            }
            0
        }
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

pub fn verify(sha256: &str, json: bool) -> i32 {
    match Receipt::load(sha256) {
        Ok(r) => match r.verify() {
            Ok(valid) => {
                if json {
                    let out = serde_json::json!({
                        "sha256": sha256,
                        "valid": valid,
                        "url": r.url,
                    });
                    let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
                    println!();
                } else if valid {
                    eprintln!(
                        "tirith: receipt {} verified OK",
                        tirith_core::receipt::short_hash(sha256)
                    );
                } else {
                    eprintln!(
                        "tirith: receipt {} FAILED verification",
                        tirith_core::receipt::short_hash(sha256)
                    );
                }
                if valid {
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                eprintln!("tirith: verify failed: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

fn print_receipt(r: &Receipt) {
    eprintln!("tirith: receipt");
    eprintln!("  url:       {}", r.url);
    if let Some(ref fu) = r.final_url {
        eprintln!("  final_url: {fu}");
    }
    eprintln!("  sha256:    {}", r.sha256);
    eprintln!("  size:      {} bytes", r.size);
    eprintln!("  analyzed:  {}", r.analysis_method);
    eprintln!("  privilege: {}", r.privilege);
    eprintln!("  when:      {}", r.timestamp);
    if !r.domains_referenced.is_empty() {
        eprintln!("  domains:   {}", r.domains_referenced.join(", "));
    }
}
