pub const RED: &str = "\x1b[0;31m";
pub const YLW: &str = "\x1b[0;33m";
pub const GRN: &str = "\x1b[0;32m";
pub const DIM: &str = "\x1b[0;90m";
pub const RST: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";

pub fn log_sus(name: &str, reason: &str) {
    eprintln!("  {RED}\u{2717}{RST} {name:<30} {RED}{reason}{RST}");
}

pub fn log_warn(name: &str, reason: &str) {
    eprintln!("  {YLW}!{RST} {name:<30} {YLW}{reason}{RST}");
}

pub fn log_ok(name: &str, detail: &str, verbose: bool) {
    if verbose {
        eprintln!("  {GRN}\u{2713}{RST} {name:<30} {DIM}{detail}{RST}");
    }
}

pub fn banner() {
    eprintln!(
        "{RED}\
 _____ _             _____                   _   _____
/  ___| |           /  ___|                 | | /  ___|
\\ `--.| | ___  _ __ \\ `--.  __ _ _   _  __ _| |_\\ `--.  ___ __ _ _ __
 `--. \\ |/ _ \\| '_ \\ `--. \\/ _` | | | |/ _` | __|`--. \\/ __/ _` | '_ \\
/\\__/ / | (_) | |_) /\\__/ / (_| | |_| | (_| | |_/\\__/ / (_| (_| | | | |
\\____/|_|\\___/| .__/\\____/ \\__, |\\__,_|\\__,_|\\__\\____/ \\___\\__,_|_| |_|
              | |             | |
              |_|             |_|{RST}"
    );
}

pub fn thresholds(npm_weekly: u64, pypi_weekly: u64, days_new: i64) {
    eprintln!("{DIM}thresholds: <{npm_weekly} dl/week (npm), <{pypi_weekly} dl/week (pypi), <{days_new}d old = warning{RST}");
}
