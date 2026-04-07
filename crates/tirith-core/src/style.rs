use crate::verdict::Severity;
use owo_colors::OwoColorize;

/// Which output stream color decisions should be based on.
/// Commands route human output to different streams (e.g., check uses stderr,
/// warnings uses stdout), so color must be evaluated per-stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Check if color should be used for a given output stream.
/// Respects the `NO_COLOR` env var (https://no-color.org/) and TTY detection.
///
/// Per the NO_COLOR spec, the presence of the variable is sufficient to disable
/// color, regardless of its value (including empty string).
pub fn use_color_for(stream: Stream) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match stream {
        Stream::Stderr => is_terminal::is_terminal(std::io::stderr()),
        Stream::Stdout => is_terminal::is_terminal(std::io::stdout()),
    }
}

/// Format a severity label with color appropriate for the given stream.
/// Returns a bracketed severity label like `[CRITICAL]` with ANSI color when
/// color is supported, or plain text otherwise.
pub fn severity_label(severity: &Severity, stream: Stream) -> String {
    let label = format!("[{}]", severity);
    if !use_color_for(stream) {
        return label;
    }
    match severity {
        Severity::Critical => label.bright_red().to_string(),
        Severity::High => label.red().to_string(),
        Severity::Medium => label.yellow().to_string(),
        Severity::Low => label.cyan().to_string(),
        Severity::Info => label.dimmed().to_string(),
    }
}

/// Format text as bold if color is enabled for the stream.
pub fn bold(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.bold().to_string()
    } else {
        text.to_string()
    }
}

/// Format text as bold + red if color is enabled. Falls back to plain text.
pub fn bold_red(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.bold().red().to_string()
    } else {
        text.to_string()
    }
}

/// Format text as green if color is enabled.
pub fn green(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.green().to_string()
    } else {
        text.to_string()
    }
}

/// Format text as red if color is enabled.
pub fn red(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.red().to_string()
    } else {
        text.to_string()
    }
}

/// Format text as yellow if color is enabled.
pub fn yellow(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.yellow().to_string()
    } else {
        text.to_string()
    }
}

/// Format text as dimmed if color is enabled for the stream.
pub fn dim(text: &str, stream: Stream) -> String {
    if use_color_for(stream) {
        text.dimmed().to_string()
    } else {
        text.to_string()
    }
}

/// Format a pass/success marker (green checkmark or `[ok]`).
pub fn pass_mark(stream: Stream) -> String {
    if use_color_for(stream) {
        "\u{2713}".green().to_string()
    } else {
        "[ok]".to_string()
    }
}

/// Format a fail marker (red X or `[!!]`).
pub fn fail_mark(stream: Stream) -> String {
    if use_color_for(stream) {
        "\u{2717}".red().to_string()
    } else {
        "[!!]".to_string()
    }
}
