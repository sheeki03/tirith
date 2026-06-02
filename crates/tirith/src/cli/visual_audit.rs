//! M12 ch2 — `tirith visual-audit`.
//!
//! Renders pairs of visually-confusable glyphs and asks the operator whether they
//! can tell them apart in their own terminal + font — measuring the half of the
//! homograph problem tirith's heuristic detection can't (does THIS terminal render
//! a Cyrillic `а` like a Latin `a`?).
//!
//! The result is inherently LOCAL: it depends on the emulator + font + rendering
//! stack, so it is NOT portable, and both the human summary and JSON say so. We
//! ship only the raw operator answers, never a "your terminal is safe" verdict.
//!
//! `--non-interactive` skips prompting, records every pair as `skipped`, never reads
//! stdin (CI-deterministic). Interactive mode gates the stdin read on
//! `is_terminal(stdin)` so a non-TTY prints a message instead of blocking forever.

use std::io::Write;

use super::write_json_stdout;

/// One confusable pair shown to the operator. `name` is a short human label,
/// `ascii` is the benign ASCII glyph, `confusable` is the look-alike, and
/// `codepoints` is the human-readable `U+XXXX` description used in both the
/// prompt and the recorded result.
#[derive(Debug, Clone, Copy)]
pub struct ConfusablePair {
    /// Short label, e.g. `"latin-i-vs-cyrillic-i"`.
    pub name: &'static str,
    /// The benign ASCII reference glyph rendered in the prompt.
    pub ascii: &'static str,
    /// The confusable look-alike glyph rendered in the prompt.
    pub confusable: &'static str,
    /// Human-readable codepoint description, e.g. `"U+0069 vs U+0456"`.
    pub codepoints: &'static str,
    /// `true` for the high-value pairs included under `--pairs critical`. The
    /// `all` set is every pair regardless of this flag.
    pub critical: bool,
}

/// The full audit pair table: Cyrillic / Greek look-alikes, fullwidth forms,
/// math-alphanumeric letters, plus a zero-width space and an RTL override. The
/// `critical` subset is the handful most likely in a real homograph / typosquat attack.
///
/// NOTE: the zero-width and bidi entries embed the invisible character INSIDE
/// `confusable` so the operator judges exactly what the terminal renders.
pub const PAIRS: &[ConfusablePair] = &[
    ConfusablePair {
        name: "latin-i-vs-cyrillic-i",
        ascii: "i",
        confusable: "\u{0456}", // і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        codepoints: "U+0069 vs U+0456",
        critical: true,
    },
    ConfusablePair {
        name: "latin-a-vs-cyrillic-a",
        ascii: "a",
        confusable: "\u{0430}", // а CYRILLIC SMALL LETTER A
        codepoints: "U+0061 vs U+0430",
        critical: true,
    },
    ConfusablePair {
        name: "latin-e-vs-cyrillic-e",
        ascii: "e",
        confusable: "\u{0435}", // е CYRILLIC SMALL LETTER IE
        codepoints: "U+0065 vs U+0435",
        critical: true,
    },
    ConfusablePair {
        name: "latin-o-vs-cyrillic-o",
        ascii: "o",
        confusable: "\u{043E}", // о CYRILLIC SMALL LETTER O
        codepoints: "U+006F vs U+043E",
        critical: true,
    },
    ConfusablePair {
        name: "latin-p-vs-cyrillic-er",
        ascii: "p",
        confusable: "\u{0440}", // р CYRILLIC SMALL LETTER ER
        codepoints: "U+0070 vs U+0440",
        critical: true,
    },
    ConfusablePair {
        name: "latin-c-vs-cyrillic-es",
        ascii: "c",
        confusable: "\u{0441}", // с CYRILLIC SMALL LETTER ES
        codepoints: "U+0063 vs U+0441",
        critical: true,
    },
    ConfusablePair {
        name: "latin-x-vs-cyrillic-ha",
        ascii: "x",
        confusable: "\u{0445}", // х CYRILLIC SMALL LETTER HA
        codepoints: "U+0078 vs U+0445",
        critical: false,
    },
    ConfusablePair {
        name: "latin-y-vs-cyrillic-u",
        ascii: "y",
        confusable: "\u{0443}", // у CYRILLIC SMALL LETTER U
        codepoints: "U+0079 vs U+0443",
        critical: false,
    },
    ConfusablePair {
        name: "latin-o-vs-greek-omicron",
        ascii: "o",
        confusable: "\u{03BF}", // ο GREEK SMALL LETTER OMICRON
        codepoints: "U+006F vs U+03BF",
        critical: true,
    },
    ConfusablePair {
        name: "latin-v-vs-greek-nu",
        ascii: "v",
        confusable: "\u{03BD}", // ν GREEK SMALL LETTER NU
        codepoints: "U+0076 vs U+03BD",
        critical: false,
    },
    ConfusablePair {
        name: "latin-a-vs-greek-alpha",
        ascii: "a",
        confusable: "\u{03B1}", // α GREEK SMALL LETTER ALPHA
        codepoints: "U+0061 vs U+03B1",
        critical: false,
    },
    ConfusablePair {
        name: "latin-cap-b-vs-greek-beta",
        ascii: "B",
        confusable: "\u{0392}", // Β GREEK CAPITAL LETTER BETA
        codepoints: "U+0042 vs U+0392",
        critical: false,
    },
    ConfusablePair {
        name: "latin-a-vs-fullwidth-a",
        ascii: "a",
        confusable: "\u{FF41}", // ａ FULLWIDTH LATIN SMALL LETTER A
        codepoints: "U+0061 vs U+FF41",
        critical: true,
    },
    ConfusablePair {
        name: "latin-cap-g-vs-fullwidth-g",
        ascii: "G",
        confusable: "\u{FF27}", // Ｇ FULLWIDTH LATIN CAPITAL LETTER G
        codepoints: "U+0047 vs U+FF27",
        critical: false,
    },
    ConfusablePair {
        name: "latin-cap-o-vs-math-script-o",
        ascii: "O",
        confusable: "\u{1D4AA}", // 𝒪 MATHEMATICAL SCRIPT CAPITAL O
        codepoints: "U+004F vs U+1D4AA",
        critical: true,
    },
    ConfusablePair {
        name: "latin-cap-a-vs-math-bold-a",
        ascii: "A",
        confusable: "\u{1D400}", // 𝐀 MATHEMATICAL BOLD CAPITAL A
        codepoints: "U+0041 vs U+1D400",
        critical: false,
    },
    ConfusablePair {
        name: "latin-cap-s-vs-math-fraktur-s",
        ascii: "S",
        confusable: "\u{1D516}", // 𝔖 MATHEMATICAL FRAKTUR CAPITAL S
        codepoints: "U+0053 vs U+1D516",
        critical: false,
    },
    ConfusablePair {
        name: "latin-a-vs-latin-a-ring",
        ascii: "a",
        confusable: "\u{00E5}", // å LATIN SMALL LETTER A WITH RING ABOVE
        codepoints: "U+0061 vs U+00E5",
        critical: false,
    },
    // Invisible/hidden-char entries: the confusable embeds the invisible char inline.
    ConfusablePair {
        name: "zero-width-space-between-letters",
        ascii: "ab",
        // Embeds U+200B ZERO WIDTH SPACE between `a` and `b`.
        confusable: "a\u{200B}b",
        codepoints: "ab vs a<U+200B>b (zero-width space)",
        critical: true,
    },
    ConfusablePair {
        name: "bidi-rtl-override-demo",
        ascii: "abc.txt",
        // U+202E RTL override flips display order (the classic filename-spoofing trick).
        confusable: "abc\u{202E}txt.exe",
        codepoints: "U+202E RIGHT-TO-LEFT OVERRIDE",
        critical: true,
    },
];

/// JSON / record shape written to `config_dir()/visual-audit-result.json` and
/// (optionally) emitted under `--json`. Local-by-nature: `terminal` records the
/// `$TERM` value so a reader knows which rendering stack produced these answers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VisualAuditResult {
    /// RFC-3339 timestamp the audit ran.
    pub audited_at: String,
    /// The `$TERM` value at audit time (empty string if unset). The result is
    /// only meaningful for this terminal + font.
    pub terminal: String,
    /// How many pairs were presented (the selected subset size).
    pub pairs_total: usize,
    /// Pairs the operator marked visually DISTINGUISHABLE.
    pub distinguishable: usize,
    /// Pairs the operator marked INDISTINGUISHABLE (a local rendering risk).
    pub indistinguishable: usize,
    /// Pairs skipped (operator chose skip, or `--non-interactive`).
    pub skipped: usize,
    /// Per-pair verdicts in presentation order.
    pub results: Vec<PairResult>,
}

/// One operator answer for one pair.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairResult {
    /// The pair's `name`.
    pub name: String,
    /// The pair's human-readable codepoint description.
    pub codepoints: String,
    /// The operator's answer for this pair.
    pub verdict: Verdict,
}

/// One operator answer, as a closed set (not a free `String`) so the
/// `distinguishable + indistinguishable + skipped == pairs_total` partition that
/// `tally` / `doctor --compat` rely on is total at the type level. `snake_case`
/// serde keeps the on-disk JSON tokens byte-for-byte backward/forward compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The operator could tell the two glyphs apart.
    Distinguishable,
    /// The two glyphs looked identical — a local rendering risk.
    Indistinguishable,
    /// No judgment given (operator chose skip, EOF, or `--non-interactive`).
    Skipped,
}

/// Resolve the `--pairs` selector into the slice of pairs to present. Unknown
/// values fall back to `critical` (and the caller prints a note). `None` (flag
/// omitted) defaults to `critical` — the short, high-signal set.
pub fn select_pairs(selector: Option<&str>) -> (Vec<&'static ConfusablePair>, bool) {
    match selector
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("all") => (PAIRS.iter().collect(), true),
        // `critical`, omitted, or anything unrecognized → the critical subset.
        // The bool reports whether the selector was recognized.
        Some("critical") | None => (PAIRS.iter().filter(|p| p.critical).collect(), true),
        Some(_) => (PAIRS.iter().filter(|p| p.critical).collect(), false),
    }
}

/// `tirith visual-audit` entry point. `non_interactive` records every pair as
/// `skipped` without reading stdin; `pairs` is `critical` (default) or `all`; `json`
/// also emits [`VisualAuditResult`]. Returns the exit code: 0 on the happy path, 1 on
/// a JSON write failure or a requested-but-failed persist (never report a non-recorded
/// audit as recorded).
pub fn run(non_interactive: bool, pairs: Option<String>, json: bool) -> i32 {
    let (selected, recognized) = select_pairs(pairs.as_deref());
    if !recognized {
        eprintln!(
            "tirith visual-audit: unknown --pairs value '{}'; using 'critical' (valid: critical, all)",
            pairs.as_deref().unwrap_or("")
        );
    }

    let term = std::env::var("TERM").unwrap_or_default();

    // Explicit `--non-interactive` is deliberate, so we DO persist the all-skipped
    // result (an honest trace `doctor --compat` can surface). The non-TTY degrade
    // path below does NOT persist — there was no deliberate run and no judgment.
    if non_interactive {
        let result = build_skipped_result(&term, &selected);
        return finish(result, json, /*persist=*/ true);
    }

    // Interactive read needs a TTY: don't block on a stdin read that never gets input.
    // Mirrors the `command-card create` gate.
    if !is_terminal::is_terminal(std::io::stdin()) {
        eprintln!(
            "tirith visual-audit: stdin is not a TTY — cannot prompt interactively.\n  \
             Run this in a real terminal, or pass --non-interactive for a headless (all-skipped) run."
        );
        // Not a failure (a CI lane that forgot the flag shouldn't turn red): exit 0
        // with an all-skipped result, NOT persisted (no operator judgment).
        let result = build_skipped_result(&term, &selected);
        return finish(result, json, /*persist=*/ false);
    }

    eprintln!(
        "tirith visual-audit: rendering {} confusable pair(s).",
        selected.len()
    );
    eprintln!(
        "  IMPORTANT: this measures YOUR terminal + font only. The result is local\n  \
         and not portable to another machine, emulator, or font."
    );
    eprintln!(
        "  For each pair, answer whether the two glyphs look DIFFERENT: [y]es / [n]o / [s]kip."
    );
    eprintln!();

    let results = collect_verdicts(&selected, |idx, pair| {
        eprintln!(
            "  ({}/{}) {} — {}",
            idx + 1,
            selected.len(),
            pair.name,
            pair.codepoints
        );
        eprintln!("      reference (ASCII):  [{}]", pair.ascii);
        eprintln!("      candidate:          [{}]", pair.confusable);
        prompt_verdict("      distinguishable? [y/n/skip]")
    });

    let result = tally(&term, results);
    finish(result, json, /*persist=*/ true)
}

/// Build an all-`skipped` result for `selected` (used by the non-interactive and
/// non-TTY paths). Counts land entirely in `skipped`.
fn build_skipped_result(term: &str, selected: &[&'static ConfusablePair]) -> VisualAuditResult {
    let results = selected
        .iter()
        .map(|p| PairResult {
            name: p.name.to_string(),
            codepoints: p.codepoints.to_string(),
            verdict: Verdict::Skipped,
        })
        .collect();
    tally(term, results)
}

/// Tally per-pair verdicts into a [`VisualAuditResult`] with a fresh timestamp.
fn tally(term: &str, results: Vec<PairResult>) -> VisualAuditResult {
    let distinguishable = results
        .iter()
        .filter(|r| r.verdict == Verdict::Distinguishable)
        .count();
    let indistinguishable = results
        .iter()
        .filter(|r| r.verdict == Verdict::Indistinguishable)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.verdict == Verdict::Skipped)
        .count();
    VisualAuditResult {
        audited_at: chrono::Utc::now().to_rfc3339(),
        terminal: term.to_string(),
        pairs_total: results.len(),
        distinguishable,
        indistinguishable,
        skipped,
        results,
    }
}

/// Persist (when `persist`), then print the human summary and/or JSON. Exit code: 1 on
/// a requested-but-failed persist or a JSON write failure, else 0. Output is still emitted
/// on a persist failure so a caller sees the (unsaved) result.
fn finish(result: VisualAuditResult, json: bool, persist: bool) -> i32 {
    let mut persist_failed = false;
    if persist {
        match persist_result(&result) {
            Ok(path) => eprintln!("tirith visual-audit: recorded result to {}", path.display()),
            Err(e) => {
                eprintln!("tirith visual-audit: error — could not save result: {e}");
                persist_failed = true;
            }
        }
    }

    if json {
        if !write_json_stdout(&result, "tirith visual-audit: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_summary(&result);
    }
    if persist_failed {
        1
    } else {
        0
    }
}

/// Write the result to `config_dir()/visual-audit-result.json` atomically,
/// returning the path on success. Uses `write_file_atomic` (overwrite) so a
/// re-run replaces the prior result cleanly.
fn persist_result(result: &VisualAuditResult) -> Result<std::path::PathBuf, String> {
    let config = tirith_core::policy::config_dir()
        .ok_or_else(|| "could not resolve the tirith config directory".to_string())?;
    std::fs::create_dir_all(&config).map_err(|e| format!("create {}: {e}", config.display()))?;
    let path = config.join("visual-audit-result.json");
    let bytes = serde_json::to_vec_pretty(result).map_err(|e| format!("serialize: {e}"))?;
    super::write_file_atomic(&path, &bytes, true)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// Print the human-readable summary to stderr. Reiterates the local-only caveat.
fn print_human_summary(result: &VisualAuditResult) {
    eprintln!();
    eprintln!("tirith visual-audit summary (this terminal + font only):");
    let term = if result.terminal.is_empty() {
        "(unset)"
    } else {
        result.terminal.as_str()
    };
    eprintln!("  TERM:               {term}");
    eprintln!("  pairs presented:    {}", result.pairs_total);
    eprintln!("  distinguishable:    {}", result.distinguishable);
    eprintln!("  indistinguishable:  {}", result.indistinguishable);
    eprintln!("  skipped:            {}", result.skipped);
    if result.indistinguishable > 0 {
        eprintln!();
        eprintln!(
            "  NOTE: {} pair(s) were indistinguishable in THIS terminal. That is a local\n  \
             rendering risk — a homograph attack using those glyphs could look identical\n  \
             to legitimate text here. tirith's detection still flags them regardless.",
            result.indistinguishable
        );
    }
    eprintln!();
    eprintln!("  This result describes only this machine and is not portable.");
}

/// Drive the per-pair prompt loop. `prompt(idx, pair)` returns the operator's verdict,
/// or `None` on EOF / unreadable stdin. After the first `None` we record every remaining
/// pair as skipped WITHOUT re-prompting (a closed stdin stays closed). Factored to take
/// the prompt as a closure so a mid-audit EOF is unit-testable without real stdin.
fn collect_verdicts<F>(selected: &[&'static ConfusablePair], mut prompt: F) -> Vec<PairResult>
where
    F: FnMut(usize, &ConfusablePair) -> Option<Verdict>,
{
    let mut results: Vec<PairResult> = Vec::with_capacity(selected.len());
    let mut input_closed = false;
    for (idx, pair) in selected.iter().enumerate() {
        let verdict = if input_closed {
            Verdict::Skipped
        } else {
            match prompt(idx, pair) {
                Some(v) => v,
                None => {
                    // EOF mid-loop: stop prompting; record the rest as skipped.
                    input_closed = true;
                    eprintln!(
                        "tirith visual-audit: input closed; recording remaining pairs as skipped."
                    );
                    Verdict::Skipped
                }
            }
        };
        results.push(PairResult {
            name: pair.name.to_string(),
            codepoints: pair.codepoints.to_string(),
            verdict,
        });
    }
    results
}

/// Prompt on stderr, read one stdin line, map to a verdict. Returns `None` on EOF /
/// read error so the caller can stop the loop cleanly.
fn prompt_verdict(label: &str) -> Option<Verdict> {
    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(verdict_from_answer(&line)),
    }
}

/// Map a raw answer line to a [`Verdict`]. Case-insensitive, trimmed.
fn verdict_from_answer(answer: &str) -> Verdict {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Verdict::Distinguishable,
        "n" | "no" => Verdict::Indistinguishable,
        // `s`, `skip`, empty, anything else → skipped (never infer an unguessed judgment).
        _ => Verdict::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair table is a FIXED set. Pin the exact count (CodeRabbit R4) so a
    /// dropped class is caught, not silently tolerated by a `>=` floor.
    #[test]
    fn pair_table_has_expected_breadth() {
        assert_eq!(
            PAIRS.len(),
            20,
            "the visual-audit pair set is fixed at 20; got {}",
            PAIRS.len()
        );
        // Names are unique (so per-pair results never collide).
        let mut names: Vec<&str> = PAIRS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "pair names must be unique");
    }

    /// Spot-check the exact codepoints the task calls out are present and carry
    /// the right glyph, so a copy-paste error in the table is caught.
    #[test]
    fn pair_table_carries_required_codepoints() {
        let by_name = |n: &str| PAIRS.iter().find(|p| p.name == n).expect("pair present");

        // Cyrillic і U+0456 vs Latin i.
        assert_eq!(by_name("latin-i-vs-cyrillic-i").confusable, "\u{0456}");
        // Greek ο U+03BF vs Latin o.
        assert_eq!(by_name("latin-o-vs-greek-omicron").confusable, "\u{03BF}");
        // Fullwidth ａ U+FF41 vs a.
        assert_eq!(by_name("latin-a-vs-fullwidth-a").confusable, "\u{FF41}");
        // Math-script 𝒪 U+1D4AA vs O.
        assert_eq!(
            by_name("latin-cap-o-vs-math-script-o").confusable,
            "\u{1D4AA}"
        );
        // Zero-width space embedded between two letters.
        let zw = by_name("zero-width-space-between-letters");
        assert!(zw.confusable.contains('\u{200B}'), "must embed U+200B");
        assert_eq!(zw.confusable.chars().count(), 3, "a + ZWSP + b = 3 chars");
        // Bidi RTL override demo embeds U+202E.
        assert!(
            by_name("bidi-rtl-override-demo")
                .confusable
                .contains('\u{202E}'),
            "bidi demo must embed U+202E"
        );

        // The Cyrillic а/е/р/о and Greek ν/α look-alikes the task lists are all
        // present.
        for n in [
            "latin-a-vs-cyrillic-a",
            "latin-e-vs-cyrillic-e",
            "latin-p-vs-cyrillic-er",
            "latin-o-vs-cyrillic-o",
            "latin-v-vs-greek-nu",
            "latin-a-vs-greek-alpha",
        ] {
            let _ = by_name(n);
        }
    }

    /// `--pairs critical` is a non-empty subset of `all`; an unknown value falls
    /// back to critical and reports `recognized == false`.
    #[test]
    fn select_pairs_subset_and_fallback() {
        let (all, ok_all) = select_pairs(Some("all"));
        assert!(ok_all);
        assert_eq!(all.len(), PAIRS.len());

        let (crit, ok_crit) = select_pairs(Some("critical"));
        assert!(ok_crit);
        assert!(!crit.is_empty(), "critical subset must be non-empty");
        assert!(crit.len() < all.len(), "critical must be a strict subset");

        // None (flag omitted) defaults to critical.
        let (def, ok_def) = select_pairs(None);
        assert!(ok_def);
        assert_eq!(def.len(), crit.len());

        // Unknown value → critical subset, recognized == false.
        let (fallback, ok_fallback) = select_pairs(Some("bogus"));
        assert!(!ok_fallback);
        assert_eq!(fallback.len(), crit.len());
    }

    /// The non-interactive path is deterministic and reads NO stdin: every
    /// selected pair is recorded as skipped, and the counts add up.
    #[test]
    fn non_interactive_records_all_skipped() {
        let (selected, _) = select_pairs(Some("critical"));
        let result = build_skipped_result("xterm-256color", &selected);
        assert_eq!(result.pairs_total, selected.len());
        assert_eq!(result.skipped, selected.len());
        assert_eq!(result.distinguishable, 0);
        assert_eq!(result.indistinguishable, 0);
        assert_eq!(result.terminal, "xterm-256color");
        // Counts partition the total.
        assert_eq!(
            result.distinguishable + result.indistinguishable + result.skipped,
            result.pairs_total
        );
    }

    /// Mid-audit EOF: after the closure returns `None`, no further prompts are issued
    /// and the tail is all skipped. Regression guard against re-prompting after EOF.
    #[test]
    fn collect_verdicts_stops_prompting_after_eof() {
        let (selected, _) = select_pairs(Some("all"));
        assert!(
            selected.len() >= 3,
            "need several pairs to exercise the tail"
        );

        let mut calls = 0usize;
        let results = collect_verdicts(&selected, |idx, _pair| {
            calls += 1;
            match idx {
                0 => Some(Verdict::Distinguishable),
                1 => Some(Verdict::Indistinguishable),
                // From the third pair on, stdin is "closed": return None. The
                // loop must NOT call us again after this.
                _ => None,
            }
        });

        // The closure was called for pairs 0, 1, and once more (which returned
        // None) — and NEVER again, even though more pairs remain.
        assert_eq!(
            calls, 3,
            "prompt must be called exactly 3 times (2 answers + 1 EOF), not once per remaining pair"
        );
        // The result is well-formed: one entry per selected pair, in order.
        assert_eq!(results.len(), selected.len());
        assert_eq!(results[0].verdict, Verdict::Distinguishable);
        assert_eq!(results[1].verdict, Verdict::Indistinguishable);
        for r in &results[2..] {
            assert_eq!(
                r.verdict,
                Verdict::Skipped,
                "every pair after EOF must be skipped"
            );
        }

        // And the tally partitions cleanly.
        let tallied = tally("xterm-256color", results);
        assert_eq!(tallied.distinguishable, 1);
        assert_eq!(tallied.indistinguishable, 1);
        assert_eq!(tallied.skipped, selected.len() - 2);
        assert_eq!(tallied.pairs_total, selected.len());
    }

    /// The all-answers path (no EOF): the closure is called once per pair and
    /// each answer is recorded — the complement of the EOF test above.
    #[test]
    fn collect_verdicts_records_every_answer_when_stdin_stays_open() {
        let (selected, _) = select_pairs(Some("critical"));
        let mut calls = 0usize;
        let results = collect_verdicts(&selected, |_idx, _pair| {
            calls += 1;
            Some(Verdict::Distinguishable)
        });
        assert_eq!(calls, selected.len(), "every pair must be prompted");
        assert!(results
            .iter()
            .all(|r| r.verdict == Verdict::Distinguishable));
    }

    /// The answer→verdict mapping is the parser the interactive loop relies on.
    #[test]
    fn verdict_from_answer_maps_yes_no_skip() {
        assert_eq!(verdict_from_answer("y"), Verdict::Distinguishable);
        assert_eq!(verdict_from_answer("YES\n"), Verdict::Distinguishable);
        assert_eq!(verdict_from_answer(" n "), Verdict::Indistinguishable);
        assert_eq!(verdict_from_answer("No"), Verdict::Indistinguishable);
        assert_eq!(verdict_from_answer("s"), Verdict::Skipped);
        assert_eq!(verdict_from_answer("skip"), Verdict::Skipped);
        assert_eq!(verdict_from_answer(""), Verdict::Skipped);
        assert_eq!(verdict_from_answer("garbage"), Verdict::Skipped);
    }

    /// `tally` partitions verdicts into the three counts correctly.
    #[test]
    fn tally_counts_each_verdict() {
        let results = vec![
            PairResult {
                name: "a".into(),
                codepoints: "x".into(),
                verdict: Verdict::Distinguishable,
            },
            PairResult {
                name: "b".into(),
                codepoints: "y".into(),
                verdict: Verdict::Indistinguishable,
            },
            PairResult {
                name: "c".into(),
                codepoints: "z".into(),
                verdict: Verdict::Skipped,
            },
            PairResult {
                name: "d".into(),
                codepoints: "w".into(),
                verdict: Verdict::Indistinguishable,
            },
        ];
        let r = tally("dumb", results);
        assert_eq!(r.distinguishable, 1);
        assert_eq!(r.indistinguishable, 2);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.pairs_total, 4);
    }

    /// The result round-trips through JSON (the on-disk + `--json` contract).
    #[test]
    fn result_roundtrips_json() {
        let (selected, _) = select_pairs(Some("all"));
        let r = build_skipped_result("screen", &selected);
        let json = serde_json::to_string(&r).unwrap();
        let back: VisualAuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pairs_total, r.pairs_total);
        assert_eq!(back.skipped, r.skipped);
        assert_eq!(back.terminal, "screen");
        assert_eq!(back.results.len(), selected.len());
        assert!(back.results.iter().all(|p| p.verdict == Verdict::Skipped));
    }

    /// [`Verdict`] serializes to EXACTLY the three legacy JSON tokens, keeping the
    /// on-disk file and `doctor --compat` byte-for-byte compatible after the String→enum
    /// migration. Asserts both wire directions, not just a Rust round-trip.
    #[test]
    fn verdict_serializes_to_legacy_tokens() {
        assert_eq!(
            serde_json::to_string(&Verdict::Distinguishable).unwrap(),
            r#""distinguishable""#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Indistinguishable).unwrap(),
            r#""indistinguishable""#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Skipped).unwrap(),
            r#""skipped""#
        );
        // Forward-compat direction `doctor --compat` exercises: token → enum.
        assert_eq!(
            serde_json::from_str::<Verdict>(r#""indistinguishable""#).unwrap(),
            Verdict::Indistinguishable
        );

        // A whole record in the legacy wire shape (bare-string verdict) parses identically.
        let legacy = r#"{"name":"latin-a-vs-cyrillic-a","codepoints":"U+0061 vs U+0430","verdict":"indistinguishable"}"#;
        let pr: PairResult = serde_json::from_str(legacy).unwrap();
        assert_eq!(pr.verdict, Verdict::Indistinguishable);
    }
}
