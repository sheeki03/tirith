mod output;
mod registry;

use clap::Parser;
use registry::{PackageResult, PackageStatus};
use reqwest::blocking::Client;

#[derive(Parser)]
#[command(
    name = "slopsquatscan",
    version,
    about = "Scan installed packages for potential slopsquatting"
)]
struct Cli {
    /// Scan pip packages only
    #[arg(long)]
    pip: bool,

    /// Scan npm global packages only
    #[arg(long)]
    npm: bool,

    /// Scan AUR packages only
    #[arg(long)]
    aur: bool,

    /// Scan everything (default if no flags)
    #[arg(long)]
    all: bool,

    /// Show clean packages too
    #[arg(long)]
    verbose: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();

    let scan_all = cli.all || (!cli.pip && !cli.npm && !cli.aur);
    let scan_npm = scan_all || cli.npm;
    let scan_pip = scan_all || cli.pip;
    let scan_aur = scan_all || cli.aur;

    if !cli.json {
        output::banner();
        eprintln!();
        output::thresholds(
            registry::npm_threshold(),
            registry::pypi_threshold(),
            registry::days_threshold(),
        );
    }

    let client = Client::new();
    let mut all_results: Vec<PackageResult> = Vec::new();

    if scan_npm {
        if !cli.json { eprintln!("\n{}npm (global){}", output::BOLD, output::RST); }
        let results = registry::scan_npm(&client);
        if !cli.json { print_results(&results, cli.verbose); }
        all_results.extend(results);
    }

    if scan_pip {
        if !cli.json { eprintln!("\n{}pip{}", output::BOLD, output::RST); }
        let results = registry::scan_pip(&client);
        if !cli.json { print_results(&results, cli.verbose); }
        all_results.extend(results);
    }

    if scan_aur {
        if !cli.json { eprintln!("\n{}AUR (foreign packages){}", output::BOLD, output::RST); }
        let results = registry::scan_aur(&client);
        if !cli.json { print_results(&results, cli.verbose); }
        all_results.extend(results);
    }

    let clean = all_results.iter().filter(|r| matches!(r.status, PackageStatus::Clean { .. })).count();
    let warnings = all_results.iter().filter(|r| matches!(r.status, PackageStatus::Warning { .. })).count();
    let suspicious: Vec<_> = all_results.iter().filter(|r| matches!(r.status, PackageStatus::Suspicious { .. })).collect();

    if cli.json {
        print_json(&all_results, clean, warnings, suspicious.len());
    } else {
        eprintln!("\n{}Summary{}", output::BOLD, output::RST);
        eprintln!("  {}Clean:{}      {clean}", output::GRN, output::RST);
        eprintln!("  {}Warnings:{}   {warnings}", output::YLW, output::RST);
        eprintln!("  {}Suspicious:{} {}", output::RED, output::RST, suspicious.len());

        if !suspicious.is_empty() {
            eprintln!();
            eprintln!("{}{}Action required:{} these packages were NOT FOUND on their registry:", output::RED, output::BOLD, output::RST);
            for s in &suspicious {
                eprintln!("  {}→{} {}:{}", output::RED, output::RST, s.registry, s.name);
            }
            eprintln!();
            eprintln!("This could mean: typosquatted name, removed package, or private package.");
            eprintln!("Investigate before continuing to use them.");
        } else if warnings > 0 {
            eprintln!();
            eprintln!("{}Some packages have low popularity or are very new — worth a quick check.{}", output::YLW, output::RST);
        } else {
            eprintln!("\n{}All clear.{}", output::GRN, output::RST);
        }
    }

    if !suspicious.is_empty() {
        std::process::exit(1);
    }
}

fn print_results(results: &[PackageResult], verbose: bool) {
    if results.is_empty() {
        eprintln!("  {}no packages found{}", output::DIM, output::RST);
        return;
    }
    for r in results {
        match &r.status {
            PackageStatus::Suspicious { reason } => output::log_sus(&r.name, reason),
            PackageStatus::Warning { reason } => output::log_warn(&r.name, reason),
            PackageStatus::Clean { detail } => output::log_ok(&r.name, detail, verbose),
        }
    }
}

fn print_json(results: &[PackageResult], clean: usize, warnings: usize, suspicious: usize) {
    #[derive(serde::Serialize)]
    struct JsonOutput {
        summary: JsonSummary,
        packages: Vec<JsonPackage>,
    }
    #[derive(serde::Serialize)]
    struct JsonSummary {
        clean: usize,
        warnings: usize,
        suspicious: usize,
    }
    #[derive(serde::Serialize)]
    struct JsonPackage {
        registry: String,
        name: String,
        status: String,
        detail: String,
    }

    let packages: Vec<JsonPackage> = results.iter().map(|r| {
        let (status, detail) = match &r.status {
            PackageStatus::Clean { detail } => ("clean", detail.clone()),
            PackageStatus::Warning { reason } => ("warning", reason.clone()),
            PackageStatus::Suspicious { reason } => ("suspicious", reason.clone()),
        };
        JsonPackage {
            registry: r.registry.to_string(),
            name: r.name.clone(),
            status: status.to_string(),
            detail,
        }
    }).collect();

    let out = JsonOutput {
        summary: JsonSummary { clean, warnings, suspicious },
        packages,
    };

    let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
    println!();
}
