mod output;
mod registry;

use clap::Parser;

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

    println!("slopsquatscan: npm={scan_npm} pip={scan_pip} aur={scan_aur} verbose={} json={}", cli.verbose, cli.json);
}
