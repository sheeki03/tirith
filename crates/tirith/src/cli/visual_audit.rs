//! M12 ch2 — `tirith visual-audit`.
//!
//! An interactive audit that renders pairs of visually-confusable glyphs and
//! asks the operator whether they can tell them apart **in their terminal and
//! font**. tirith's homograph / confusable detection is heuristic and
//! conservative; this command lets an operator measure the OTHER half of the
//! problem — whether their own terminal renders, say, a Cyrillic `а` (U+0430)
//! indistinguishably from a Latin `a`.
//!
//! ## The result is inherently LOCAL
//!
//! The whole point is that the answer depends on the operator's terminal
//! emulator + font + rendering stack. A pair that is obviously distinct in one
//! font may be pixel-identical in another. So the recorded result is NOT
//! portable: it describes THIS machine's rendering, and the human summary and
//! the JSON envelope both say so. We deliberately do not ship a "your terminal
//! is safe" verdict — only the raw operator answers.
//!
//! ## Headless / CI
//!
//! `--non-interactive` skips all prompting and records every selected pair as
//! `skipped`, exiting 0. It NEVER reads stdin, so a headless CI lane can run
//! `tirith visual-audit --non-interactive --pairs critical` deterministically.
//! In interactive mode without `--non-interactive`, we gate the stdin read on
//! `is_terminal(stdin)` (the same gate `command-card create` uses): a non-TTY
//! stdin prints a clear message and exits rather than blocking on a read that
//! will never receive input.

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

/// The full audit pair table. Spans the confusable classes tirith's detection
/// cares about: Cyrillic / Greek look-alikes, fullwidth forms, math-alphanumeric
/// styled letters, plus the two "is something hidden here?" cases (a zero-width
/// space embedded between two letters, and a right-to-left override). The
/// `critical` subset is the handful most likely to appear in a real homograph
/// domain / typosquat attack.
///
/// NOTE: the zero-width and bidi entries deliberately embed the invisible
/// character INSIDE `confusable` so the operator is judging exactly what the
/// terminal renders — there is no separate "control" glyph for those two.
pub const PAIRS: &[ConfusablePair] = &[
    // ---- Cyrillic look-alikes (the classic homograph alphabet) -------------
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
    // ---- Greek look-alikes -------------------------------------------------
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
    // ---- Fullwidth forms (common in pasted CJK-locale text) ----------------
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
    // ---- Math-alphanumeric styled letters (U+1D400–U+1D7FF) ----------------
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
    // ---- Latin diacritic look-alike ----------------------------------------
    ConfusablePair {
        name: "latin-a-vs-latin-a-ring",
        ascii: "a",
        confusable: "\u{00E5}", // å LATIN SMALL LETTER A WITH RING ABOVE
        codepoints: "U+0061 vs U+00E5",
        critical: false,
    },
    // ---- Invisible / hidden characters (judge what the terminal renders) ---
    ConfusablePair {
        name: "zero-width-space-between-letters",
        // The benign reference is the two letters with NOTHING between them.
        ascii: "ab",
        // The confusable embeds U+200B ZERO WIDTH SPACE between `a` and `b`:
        // "is there a hidden character here?"
        confusable: "a\u{200B}b",
        codepoints: "ab vs a<U+200B>b (zero-width space)",
        critical: true,
    },
    ConfusablePair {
        name: "bidi-rtl-override-demo",
        // Benign: the plain word.
        ascii: "abc.txt",
        // Confusable: a right-to-left override (U+202E) flips display order —
        // the classic `report\u{202e}txt.exe` filename-spoofing trick, here
        // shown inline so the operator sees how their terminal handles it.
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
    /// `"distinguishable"`, `"indistinguishable"`, or `"skipped"`.
    pub verdict: String,
}

/// Verdict tokens. Kept as constants so the prompt parser, the recorder, and the
/// tests cannot drift.
const VERDICT_DISTINGUISHABLE: &str = "distinguishable";
const VERDICT_INDISTINGUISHABLE: &str = "indistinguishable";
const VERDICT_SKIPPED: &str = "skipped";

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

/// `tirith visual-audit` entry point.
///
/// * `non_interactive` — never read stdin; record every selected pair as
///   `skipped` and exit 0 (CI-safe).
/// * `pairs` — `critical` (default) or `all`.
/// * `json` — also emit the [`VisualAuditResult`] as JSON on stdout.
///
/// Returns the process exit code. Always 0 on the happy path (including the
/// non-interactive and non-TTY-degrade paths); 1 only on a stdout JSON write
/// failure (broken pipe).
pub fn run(non_interactive: bool, pairs: Option<String>, json: bool) -> i32 {
    let (selected, recognized) = select_pairs(pairs.as_deref());
    if !recognized {
        eprintln!(
            "tirith visual-audit: unknown --pairs value '{}'; using 'critical' (valid: critical, all)",
            pairs.as_deref().unwrap_or("")
        );
    }

    let term = std::env::var("TERM").unwrap_or_default();

    // ---- non-interactive (CI): no prompting, all pairs recorded as skipped --
    // An EXPLICIT `--non-interactive` is a deliberate choice, so we DO persist
    // the all-skipped result — it leaves an honest trace ("an audit ran but was
    // skipped") that `tirith doctor --compat` can then surface. (The non-TTY
    // DEGRADE path below — where the operator forgot the flag — does NOT
    // persist, because there was no deliberate run and no judgment.) Records no
    // operator judgment either way; every pair is `skipped`.
    if non_interactive {
        let result = build_skipped_result(&term, &selected);
        return finish(result, json, /*persist=*/ true);
    }

    // ---- interactive read requires a TTY on stdin --------------------------
    // `prompt_verdict` reads a line from stdin; if stdin is NOT a terminal we
    // must not block on a read that will never get input. Mirrors the
    // `command-card create` gate (is_terminal on the actual stream we read).
    if !is_terminal::is_terminal(std::io::stdin()) {
        eprintln!(
            "tirith visual-audit: stdin is not a TTY — cannot prompt interactively.\n  \
             Run this in a real terminal, or pass --non-interactive for a headless (all-skipped) run."
        );
        // Not a failure: a CI lane that forgot --non-interactive should not
        // turn red. Record an all-skipped result (NOT persisted — there was no
        // operator judgment) and exit 0.
        let result = build_skipped_result(&term, &selected);
        return finish(result, json, /*persist=*/ false);
    }

    // ---- interactive prompt loop -------------------------------------------
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
            verdict: VERDICT_SKIPPED.to_string(),
        })
        .collect();
    tally(term, results)
}

/// Tally per-pair verdicts into a [`VisualAuditResult`] with a fresh timestamp.
fn tally(term: &str, results: Vec<PairResult>) -> VisualAuditResult {
    let distinguishable = results
        .iter()
        .filter(|r| r.verdict == VERDICT_DISTINGUISHABLE)
        .count();
    let indistinguishable = results
        .iter()
        .filter(|r| r.verdict == VERDICT_INDISTINGUISHABLE)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.verdict == VERDICT_SKIPPED)
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

/// Persist (when `persist`), then print the human summary and/or JSON. Returns
/// the exit code (0 on success, 1 only on a JSON write failure).
fn finish(result: VisualAuditResult, json: bool, persist: bool) -> i32 {
    if persist {
        match persist_result(&result) {
            Ok(path) => eprintln!("tirith visual-audit: recorded result to {}", path.display()),
            Err(e) => eprintln!("tirith visual-audit: warning — could not save result: {e}"),
        }
    }

    if json {
        if !write_json_stdout(&result, "tirith visual-audit: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_summary(&result);
    }
    0
}

/// Write the result to `config_dir()/visual-audit-result.json` atomically,
/// returning the path on success. Uses `write_file_atomic` (overwrite) so a
/// re-run replaces the prior result cleanly.
fn persist_result(result: &VisualAuditResult) -> Result<std::path::PathBuf, String> {
    let config = tirith_core::policy::config_dir()
        .ok_or_else(|| "no config directory ($HOME / $XDG_CONFIG_HOME unset)".to_string())?;
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

/// Drive the per-pair prompt loop. `prompt(idx, pair)` returns the operator's
/// verdict for one pair, or `None` on EOF / unreadable stdin.
///
/// Once `prompt` returns `None` we set an `input_closed` flag and record EVERY
/// remaining pair as skipped WITHOUT calling `prompt` again — a closed stdin
/// stays closed, so re-prompting would just spin returning `None` (and, for a
/// real terminal, spam the same prompt for each remaining pair). The result is
/// always well-formed: one [`PairResult`] per selected pair, in order.
///
/// Factored out (taking the prompt as a closure) so a mid-audit EOF can be
/// exercised in a unit test without driving real stdin.
fn collect_verdicts<F>(selected: &[&'static ConfusablePair], mut prompt: F) -> Vec<PairResult>
where
    F: FnMut(usize, &ConfusablePair) -> Option<String>,
{
    let mut results: Vec<PairResult> = Vec::with_capacity(selected.len());
    let mut input_closed = false;
    for (idx, pair) in selected.iter().enumerate() {
        let verdict = if input_closed {
            // stdin already closed earlier this run — do not prompt again.
            VERDICT_SKIPPED.to_string()
        } else {
            match prompt(idx, pair) {
                Some(v) => v,
                None => {
                    // EOF / unreadable stdin mid-loop: stop prompting for the
                    // rest of this run; record everything remaining as skipped so
                    // the result stays well-formed.
                    input_closed = true;
                    eprintln!(
                        "tirith visual-audit: input closed; recording remaining pairs as skipped."
                    );
                    VERDICT_SKIPPED.to_string()
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

/// Prompt on stderr, read one line from stdin, and map the answer to a verdict
/// token. `y`/`yes` → distinguishable, `n`/`no` → indistinguishable, anything
/// else (`s`, `skip`, blank) → skipped. Returns `None` on EOF / read error so
/// the caller can stop the loop cleanly.
fn prompt_verdict(label: &str) -> Option<String> {
    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(verdict_from_answer(&line)),
    }
}

/// Map a raw answer line to a verdict token. Factored out so the mapping is
/// unit-testable without stdin. Case-insensitive, trimmed.
fn verdict_from_answer(answer: &str) -> String {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => VERDICT_DISTINGUISHABLE.to_string(),
        "n" | "no" => VERDICT_INDISTINGUISHABLE.to_string(),
        // `s`, `skip`, empty, or anything else → skipped (the safe default —
        // we never infer a judgment the operator did not give).
        _ => VERDICT_SKIPPED.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair table must cover the classes the task specifies and be at least
    /// ~20 pairs. A regression that drops a class would silently narrow the audit.
    #[test]
    fn pair_table_has_expected_breadth() {
        assert!(
            PAIRS.len() >= 20,
            "expected at least 20 confusable pairs, got {}",
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

    /// Mid-audit EOF: once the prompt closure returns `None`, NO further prompts
    /// are issued and every remaining pair is recorded as skipped. We answer the
    /// first two pairs, then "close" stdin — the closure must not be called for
    /// pair index ≥ 2, and the tail is all skipped. Guards the regression where
    /// the loop kept calling `prompt_verdict` after EOF.
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
                0 => Some(VERDICT_DISTINGUISHABLE.to_string()),
                1 => Some(VERDICT_INDISTINGUISHABLE.to_string()),
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
        assert_eq!(results[0].verdict, VERDICT_DISTINGUISHABLE);
        assert_eq!(results[1].verdict, VERDICT_INDISTINGUISHABLE);
        for r in &results[2..] {
            assert_eq!(
                r.verdict, VERDICT_SKIPPED,
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
            Some(VERDICT_DISTINGUISHABLE.to_string())
        });
        assert_eq!(calls, selected.len(), "every pair must be prompted");
        assert!(results.iter().all(|r| r.verdict == VERDICT_DISTINGUISHABLE));
    }

    /// The answer→verdict mapping is the parser the interactive loop relies on.
    #[test]
    fn verdict_from_answer_maps_yes_no_skip() {
        assert_eq!(verdict_from_answer("y"), VERDICT_DISTINGUISHABLE);
        assert_eq!(verdict_from_answer("YES\n"), VERDICT_DISTINGUISHABLE);
        assert_eq!(verdict_from_answer(" n "), VERDICT_INDISTINGUISHABLE);
        assert_eq!(verdict_from_answer("No"), VERDICT_INDISTINGUISHABLE);
        assert_eq!(verdict_from_answer("s"), VERDICT_SKIPPED);
        assert_eq!(verdict_from_answer("skip"), VERDICT_SKIPPED);
        assert_eq!(verdict_from_answer(""), VERDICT_SKIPPED);
        assert_eq!(verdict_from_answer("garbage"), VERDICT_SKIPPED);
    }

    /// `tally` partitions verdicts into the three counts correctly.
    #[test]
    fn tally_counts_each_verdict() {
        let results = vec![
            PairResult {
                name: "a".into(),
                codepoints: "x".into(),
                verdict: VERDICT_DISTINGUISHABLE.into(),
            },
            PairResult {
                name: "b".into(),
                codepoints: "y".into(),
                verdict: VERDICT_INDISTINGUISHABLE.into(),
            },
            PairResult {
                name: "c".into(),
                codepoints: "z".into(),
                verdict: VERDICT_SKIPPED.into(),
            },
            PairResult {
                name: "d".into(),
                codepoints: "w".into(),
                verdict: VERDICT_INDISTINGUISHABLE.into(),
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
    }
}
