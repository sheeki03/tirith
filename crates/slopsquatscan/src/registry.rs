use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::Value;

const NPM_WEEKLY_THRESHOLD: u64 = 100;
const PYPI_WEEKLY_THRESHOLD: u64 = 100;
const DAYS_NEW_THRESHOLD: i64 = 30;
const AUR_VOTES_THRESHOLD: u64 = 5;

pub const fn npm_threshold() -> u64 { NPM_WEEKLY_THRESHOLD }
pub const fn pypi_threshold() -> u64 { PYPI_WEEKLY_THRESHOLD }
pub const fn days_threshold() -> i64 { DAYS_NEW_THRESHOLD }

#[derive(Debug, Clone)]
pub enum PackageStatus {
    Clean { detail: String },
    Warning { reason: String },
    Suspicious { reason: String },
}

#[derive(Debug, Clone)]
pub struct PackageResult {
    pub registry: &'static str,
    pub name: String,
    pub status: PackageStatus,
}

fn days_since_iso(date_str: &str) -> Option<i64> {
    // Try RFC 3339 first (npm uses this), then naive datetime (PyPI's upload_time has no tz)
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
        return Some((Utc::now() - dt.with_timezone(&Utc)).num_days());
    }
    let ndt = chrono::NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S").ok()?;
    Some((Utc::now() - ndt.and_utc()).num_days())
}

fn days_since_epoch(epoch: i64) -> i64 {
    (Utc::now().timestamp() - epoch) / 86400
}

pub fn scan_npm(client: &Client) -> Vec<PackageResult> {
    let mut results = Vec::new();

    let output = std::process::Command::new("npm")
        .args(["list", "-g", "--depth=0", "--json"])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return results,
    };

    let json: Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => return results,
    };

    let deps = match json.get("dependencies").and_then(|d| d.as_object()) {
        Some(d) => d,
        None => return results,
    };

    for pkg in deps.keys() {
        if pkg == "npm" { continue; }

        let resp = client
            .get(format!("https://registry.npmjs.org/{pkg}"))
            .timeout(std::time::Duration::from_secs(10))
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(_) => {
                results.push(PackageResult {
                    registry: "npm",
                    name: pkg.clone(),
                    status: PackageStatus::Suspicious { reason: "registry unreachable".into() },
                });
                continue;
            }
        };

        let body: Value = match resp.json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        if body.get("error").is_some() {
            results.push(PackageResult {
                registry: "npm",
                name: pkg.clone(),
                status: PackageStatus::Suspicious { reason: "NOT FOUND on npm registry".into() },
            });
            continue;
        }

        // Check age
        if let Some(created) = body.pointer("/time/created").and_then(|v| v.as_str()) {
            if let Some(age) = days_since_iso(created) {
                if age < DAYS_NEW_THRESHOLD {
                    results.push(PackageResult {
                        registry: "npm",
                        name: pkg.clone(),
                        status: PackageStatus::Warning { reason: format!("created {age}d ago") },
                    });
                    continue;
                }
            }
        }

        // Check weekly downloads
        let weekly = client
            .get(format!("https://api.npmjs.org/downloads/point/last-week/{pkg}"))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .ok()
            .and_then(|r| r.json::<Value>().ok())
            .and_then(|v| v.get("downloads")?.as_u64())
            .unwrap_or(0);

        if weekly < NPM_WEEKLY_THRESHOLD {
            results.push(PackageResult {
                registry: "npm",
                name: pkg.clone(),
                status: PackageStatus::Warning { reason: format!("only {weekly} downloads/week") },
            });
            continue;
        }

        results.push(PackageResult {
            registry: "npm",
            name: pkg.clone(),
            status: PackageStatus::Clean { detail: format!("{weekly} dl/week") },
        });
    }

    results
}

pub fn scan_pip(client: &Client) -> Vec<PackageResult> {
    let mut results = Vec::new();

    let pip_cmd = if which("pip3") { "pip3" } else if which("pip") { "pip" } else { return results };

    let output = std::process::Command::new(pip_cmd)
        .args(["list", "--format=json"])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return results,
    };

    let pkgs: Vec<Value> = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => return results,
    };

    for entry in &pkgs {
        let pkg = match entry.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };

        let resp = client
            .get(format!("https://pypi.org/pypi/{pkg}/json"))
            .timeout(std::time::Duration::from_secs(10))
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(_) => {
                results.push(PackageResult {
                    registry: "pip",
                    name: pkg.to_string(),
                    status: PackageStatus::Suspicious { reason: "registry unreachable".into() },
                });
                continue;
            }
        };

        if resp.status() == 404 {
            results.push(PackageResult {
                registry: "pip",
                name: pkg.to_string(),
                status: PackageStatus::Suspicious { reason: "NOT FOUND on PyPI".into() },
            });
            continue;
        }

        let body: Value = match resp.json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check age — find earliest upload_time across all releases
        if let Some(releases) = body.get("releases").and_then(|r| r.as_object()) {
            let earliest = releases.values()
                .filter_map(|files| files.as_array())
                .flatten()
                .filter_map(|f| f.get("upload_time").and_then(|t| t.as_str()))
                .min();
            if let Some(upload) = earliest {
                if let Some(age) = days_since_iso(upload) {
                    if age < DAYS_NEW_THRESHOLD {
                        results.push(PackageResult {
                            registry: "pip",
                            name: pkg.to_string(),
                            status: PackageStatus::Warning { reason: format!("first upload {age}d ago") },
                        });
                        continue;
                    }
                }
            }
        }

        // Check weekly downloads via pypistats
        let weekly = client
            .get(format!("https://pypistats.org/api/packages/{pkg}/recent"))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .ok()
            .and_then(|r| r.json::<Value>().ok())
            .and_then(|v| v.pointer("/data/last_week")?.as_u64())
            .unwrap_or(0);

        if weekly < PYPI_WEEKLY_THRESHOLD {
            results.push(PackageResult {
                registry: "pip",
                name: pkg.to_string(),
                status: PackageStatus::Warning { reason: format!("only {weekly} downloads/week") },
            });
            continue;
        }

        results.push(PackageResult {
            registry: "pip",
            name: pkg.to_string(),
            status: PackageStatus::Clean { detail: format!("{weekly} dl/week") },
        });
    }

    results
}

pub fn scan_aur(client: &Client) -> Vec<PackageResult> {
    let mut results = Vec::new();

    let output = std::process::Command::new("pacman")
        .args(["-Qm"])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return results,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkgs: Vec<&str> = stdout.lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    for pkg in pkgs {
        let resp = client
            .get(format!("https://aur.archlinux.org/rpc/v5/info?arg[]={pkg}"))
            .timeout(std::time::Duration::from_secs(10))
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(_) => {
                results.push(PackageResult {
                    registry: "aur",
                    name: pkg.to_string(),
                    status: PackageStatus::Suspicious { reason: "AUR unreachable".into() },
                });
                continue;
            }
        };

        let body: Value = match resp.json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let count = body.get("resultcount").and_then(|v| v.as_u64()).unwrap_or(0);
        if count == 0 {
            results.push(PackageResult {
                registry: "aur",
                name: pkg.to_string(),
                status: PackageStatus::Suspicious { reason: "NOT FOUND on AUR".into() },
            });
            continue;
        }

        let votes = body.pointer("/results/0/NumVotes")
            .and_then(|v| v.as_u64()).unwrap_or(0);
        let first_submitted = body.pointer("/results/0/FirstSubmitted")
            .and_then(|v| v.as_i64()).unwrap_or(0);

        if first_submitted > 0 {
            let age = days_since_epoch(first_submitted);
            if age < DAYS_NEW_THRESHOLD {
                results.push(PackageResult {
                    registry: "aur",
                    name: pkg.to_string(),
                    status: PackageStatus::Warning { reason: format!("submitted {age}d ago, {votes} votes") },
                });
                continue;
            }
        }

        if votes < AUR_VOTES_THRESHOLD {
            results.push(PackageResult {
                registry: "aur",
                name: pkg.to_string(),
                status: PackageStatus::Warning { reason: format!("only {votes} AUR votes") },
            });
            continue;
        }

        results.push(PackageResult {
            registry: "aur",
            name: pkg.to_string(),
            status: PackageStatus::Clean { detail: format!("{votes} votes") },
        });
    }

    results
}

fn which(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
