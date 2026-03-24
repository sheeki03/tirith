//! Credential leak detection.
//!
//! Two-layer approach:
//! 1. Known patterns: provider-specific regex (AWS, GitHub, Stripe, etc.)
//! 2. Generic detection: keyword context + p_random() entropy scoring
//!
//! Entropy detection algorithm ported from ripsecrets
//! (MIT, Copyright 2021 ripsecrets contributors).
//! https://github.com/sirwart/ripsecrets
//!
//! Provider patterns sourced from gitleaks (MIT, Copyright 2019 Zachary Rice).
//! https://github.com/gitleaks/gitleaks

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

use crate::extract::ScanContext;
use crate::rules::shared::SENSITIVE_KEY_VARS;
use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PatternFile {
    #[serde(default)]
    pattern: Vec<PatternDef>,
    #[serde(default)]
    private_key_pattern: Vec<PrivateKeyDef>,
}

#[derive(Deserialize)]
struct PatternDef {
    #[allow(dead_code)]
    id: String,
    name: String,
    regex: String,
    #[allow(dead_code)]
    tier1_fragment: String,
    #[allow(dead_code)]
    redact_prefix_len: Option<usize>,
    #[allow(dead_code)]
    severity: String,
}

#[derive(Deserialize)]
struct PrivateKeyDef {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    regex: String,
    #[allow(dead_code)]
    tier1_fragment: String,
    #[allow(dead_code)]
    severity: String,
}

// ---------------------------------------------------------------------------
// Compiled patterns (loaded once)
// ---------------------------------------------------------------------------

struct CompiledPattern {
    name: String,
    regex: Regex,
}

static KNOWN_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    let toml_src = include_str!("../../assets/data/credential_patterns.toml");
    let file: PatternFile = toml::from_str(toml_src).expect("credential_patterns.toml parse error");
    file.pattern
        .into_iter()
        .map(|p| CompiledPattern {
            name: p.name,
            regex: Regex::new(&p.regex).unwrap_or_else(|e| {
                panic!("bad regex in credential_patterns.toml ({}): {e}", p.id)
            }),
        })
        .collect()
});

static PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    let toml_src = include_str!("../../assets/data/credential_patterns.toml");
    let file: PatternFile = toml::from_str(toml_src).expect("credential_patterns.toml parse error");
    let pat = &file
        .private_key_pattern
        .first()
        .expect("credential_patterns.toml must contain at least one [[private_key_pattern]]")
        .regex;
    Regex::new(pat).expect("bad private key regex")
});

// Generic secret regex: keyword context + assignment + value capture.
// Ported from ripsecrets RANDOM_STRING_REGEX.
static GENERIC_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i:key|token|secret|password)\w*["']?\]?\s*(?:[:=]|:=|=>|<-|>)\s*[\t "'`]?([\w+./=~\\\-`^]{15,90})(?:[\t\n "'`]|</|$)"#,
    )
    .expect("GENERIC_SECRET_RE compile")
});

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Check text for credential leaks. Exec + paste only (not file-scan).
pub fn check(input: &str, _shell: ShellType, context: ScanContext) -> Vec<Finding> {
    if matches!(context, ScanContext::FileScan) {
        return Vec::new();
    }

    let mut findings = Vec::new();

    findings.extend(check_known_patterns(input));
    findings.extend(check_private_keys(input));

    if matches!(context, ScanContext::Paste) {
        findings.extend(check_generic_secrets(input));
    }

    findings
}

// ---------------------------------------------------------------------------
// Layer 1: Known provider patterns
// ---------------------------------------------------------------------------

fn check_known_patterns(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pat in KNOWN_PATTERNS.iter() {
        for m in pat.regex.find_iter(input) {
            if is_covered_by_env_export(input, m.start()) {
                continue;
            }
            findings.push(Finding {
                rule_id: RuleId::CredentialInText,
                severity: Severity::High,
                title: format!("{} detected", pat.name),
                description:
                    "A credential matching a known provider pattern was found in the input. \
                              Credentials should not appear in commands or pasted text."
                        .to_string(),
                evidence: vec![Evidence::Text {
                    detail: format!("Matched {} pattern", pat.name),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Layer 2: Private key blocks
// ---------------------------------------------------------------------------

fn check_private_keys(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for _ in PRIVATE_KEY_RE.find_iter(input) {
        findings.push(Finding {
            rule_id: RuleId::PrivateKeyExposed,
            severity: Severity::Critical,
            title: "Private key block detected".to_string(),
            description: "A PEM-encoded private key header was found in the input. \
                          Private keys should never be pasted into a terminal or used inline."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "Matched BEGIN PRIVATE KEY block".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Layer 3: Generic entropy-based secrets (paste only)
// ---------------------------------------------------------------------------

fn check_generic_secrets(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for caps in GENERIC_SECRET_RE.captures_iter(input) {
        let value = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        if !is_random(value.as_bytes()) {
            continue;
        }
        findings.push(Finding {
            rule_id: RuleId::HighEntropySecret,
            severity: Severity::Medium,
            title: "High-entropy secret value detected".to_string(),
            description:
                "A value assigned to a secret/key/token/password variable appears to contain \
                          a random credential. Avoid pasting secrets into terminals."
                    .to_string(),
            evidence: vec![Evidence::Text {
                detail: "High-entropy value in secret assignment context".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Dedup helper: suppress if the match is part of `export VAR=`, `env VAR=`,
// or fish `set ... VAR` where VAR is in SENSITIVE_KEY_VARS.
// ---------------------------------------------------------------------------

fn is_covered_by_env_export(input: &str, match_start: usize) -> bool {
    let prefix = &input[..match_start];
    let trimmed = prefix.trim_end();

    // Case 1: POSIX-style `VAR=value` — check for export/env/set before VAR=
    let posix_match = SENSITIVE_KEY_VARS.iter().any(|var| {
        let suffix_eq = format!("{var}=");
        let suffix_eq_sq = format!("{var}='");
        let suffix_eq_dq = format!("{var}=\"");
        let has_eq = trimmed.ends_with(&suffix_eq)
            || trimmed.ends_with(&suffix_eq_sq)
            || trimmed.ends_with(&suffix_eq_dq);
        if !has_eq {
            return false;
        }
        if let Some(var_pos) = trimmed.rfind(&suffix_eq) {
            let before_var = trimmed[..var_pos].trim_end();
            before_var.ends_with("export")
                || has_command_prefix(before_var, "env")
                || has_command_prefix(before_var, "set")
        } else {
            false
        }
    });

    if posix_match {
        return true;
    }

    // Case 2: Fish-style `set [-gx] VAR value` — VAR is followed by space, not =
    // The matched secret starts at match_start. In fish, the prefix looks like
    // `set -gx AWS_ACCESS_KEY_ID ` (space before the value, no =).
    // Use the raw prefix (not trimmed) to preserve trailing space.
    let raw_prefix = prefix;
    SENSITIVE_KEY_VARS.iter().any(|var| {
        let suffix_space = format!("{var} ");
        // Check raw prefix (not trimmed) so trailing space is preserved
        if !raw_prefix.ends_with(&suffix_space) {
            return false;
        }
        if let Some(var_pos) = raw_prefix.rfind(var) {
            let before_var = raw_prefix[..var_pos].trim_end();
            has_command_prefix(before_var, "set")
        } else {
            false
        }
    })
}

/// Check if `before` ends with a chain starting from `cmd`.
/// Handles intervening flags like `env -S VAR=` or `set -gx VAR`.
fn has_command_prefix(before: &str, cmd: &str) -> bool {
    // Split on whitespace and check if cmd appears as any word
    let words: Vec<&str> = before.split_whitespace().collect();
    // Find the last occurrence of cmd in the words
    for (i, w) in words.iter().enumerate().rev() {
        if *w == cmd {
            // Everything after cmd should be flags or VAR=val pairs
            let rest = &words[i + 1..];
            return rest.iter().all(|w| w.starts_with('-') || w.contains('='));
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Entropy scoring — ported from ripsecrets (MIT)
// ---------------------------------------------------------------------------

/// Probability that `s` is a random string (higher = more likely random).
fn p_random(s: &[u8]) -> f64 {
    let base = if is_hex_string(s) {
        16.0
    } else if is_cap_and_numbers(s) {
        36.0
    } else {
        64.0
    };
    let mut p = p_random_distinct_values(s, base) * p_random_char_class(s, base);
    if base == 64.0 {
        // bigrams are only calibrated for base64
        p *= p_random_bigrams(s);
    }
    p
}

fn is_hex_string(s: &[u8]) -> bool {
    s.len() >= 16 && s.iter().all(|b| b.is_ascii_hexdigit())
}

fn is_cap_and_numbers(s: &[u8]) -> bool {
    s.len() >= 16
        && s.iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Determine if `s` looks random enough to flag as a secret.
fn is_random(s: &[u8]) -> bool {
    let p = p_random(s);
    if p < 1.0 / 1e5 {
        return false;
    }
    let contains_num = s.iter().any(|b| b.is_ascii_digit());
    if !contains_num && p < 1.0 / 1e4 {
        return false;
    }
    true
}

// ---- Bigrams (from ripsecrets) ----

static BIGRAMS: Lazy<HashSet<&'static [u8]>> = Lazy::new(|| {
    let bigrams_bytes: &[u8] = b"er,te,an,en,ma,ke,10,at,/m,on,09,ti,al,io,.h,./,..,ra,ht,es,or,tm,pe,ml,re,in,3/,n3,0F,ok,ey,00,80,08,ss,07,15,81,F3,st,52,KE,To,01,it,2B,2C,/E,P_,EY,B7,se,73,de,VP,EV,to,od,B0,0E,nt,et,_P,A0,60,90,0A,ri,30,ar,C0,op,03,ec,ns,as,FF,F7,po,PK,la,.p,AE,62,me,F4,71,8E,yp,pa,50,qu,D7,7D,rs,ea,Y_,t_,ha,3B,c/,D2,ls,DE,pr,am,E0,oc,06,li,do,id,05,51,40,ED,_p,70,ed,04,02,t.,rd,mp,20,d_,co,ro,ex,11,ua,nd,0C,0D,D0,Eq,le,EF,wo,e_,e.,ct,0B,_c,Li,45,rT,pt,14,61,Th,56,sT,E6,DF,nT,16,85,em,BF,9E,ne,_s,25,91,78,57,BE,ta,ng,cl,_t,E1,1F,y_,xp,cr,4F,si,s_,E5,pl,AB,ge,7E,F8,35,E2,s.,CF,58,32,2F,E7,1B,ve,B1,3D,nc,Gr,EB,C6,77,64,sl,8A,6A,_k,79,C8,88,ce,Ex,5C,28,EA,A6,2A,Ke,A7,th,CA,ry,F0,B6,7/,D9,6B,4D,DA,3C,ue,n7,9C,.c,7B,72,ac,98,22,/o,va,2D,n.,_m,B8,A3,8D,n_,12,nE,ca,3A,is,AD,rt,r_,l-,_C,n1,_v,y.,yw,1/,ov,_n,_d,ut,no,ul,sa,CT,_K,SS,_e,F1,ty,ou,nG,tr,s/,il,na,iv,L_,AA,da,Ty,EC,ur,TX,xt,lu,No,r.,SL,Re,sw,_1,om,e/,Pa,xc,_g,_a,X_,/e,vi,ds,ai,==,ts,ni,mg,ic,o/,mt,gm,pk,d.,ch,/p,tu,sp,17,/c,ym,ot,ki,Te,FE,ub,nL,eL,.k,if,he,34,e-,23,ze,rE,iz,St,EE,-p,be,In,ER,67,13,yn,ig,ib,_f,.o,el,55,Un,21,fi,54,mo,mb,gi,_r,Qu,FD,-o,ie,fo,As,7F,48,41,/i,eS,ab,FB,1E,h_,ef,rr,rc,di,b.,ol,im,eg,ap,_l,Se,19,oS,ew,bs,Su,F5,Co,BC,ud,C1,r-,ia,_o,65,.r,sk,o_,ck,CD,Am,9F,un,fa,F6,5F,nk,lo,ev,/f,.t,sE,nO,a_,EN,E4,Di,AC,95,74,1_,1A,us,ly,ll,_b,SA,FC,69,5E,43,um,tT,OS,CE,87,7A,59,44,t-,bl,ad,Or,D5,A_,31,24,t/,ph,mm,f.,ag,RS,Of,It,FA,De,1D,/d,-k,lf,hr,gu,fy,D6,89,6F,4E,/k,w_,cu,br,TE,ST,R_,E8,/O";
    bigrams_bytes.split(|b| *b == b',').collect()
});

fn p_random_bigrams(s: &[u8]) -> f64 {
    let mut num_bigrams = 0;
    for i in 0..s.len().saturating_sub(1) {
        let bigram = &s[i..=i + 1];
        if BIGRAMS.contains(bigram) {
            num_bigrams += 1;
        }
    }
    p_binomial(s.len(), num_bigrams, (BIGRAMS.len() as f64) / (64.0 * 64.0))
}

// ---- Char class probabilities ----

fn p_random_char_class(s: &[u8], base: f64) -> f64 {
    if base == 16.0 {
        return p_random_char_class_aux(s, b'0', b'9', 16.0);
    }
    let char_classes_36: &[(u8, u8)] = &[(b'0', b'9'), (b'A', b'Z')];
    let char_classes_64: &[(u8, u8)] = &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')];
    let classes = if base == 36.0 {
        char_classes_36
    } else {
        char_classes_64
    };
    classes
        .iter()
        .map(|(lo, hi)| p_random_char_class_aux(s, *lo, *hi, base))
        .fold(f64::INFINITY, f64::min)
}

fn p_random_char_class_aux(s: &[u8], min: u8, max: u8, base: f64) -> f64 {
    // Note: upper bound is exclusive to match ripsecrets scoring behaviour.
    let count = s.iter().filter(|b| **b >= min && **b < max).count();
    let num_chars = (max - min + 1) as f64;
    p_binomial(s.len(), count, num_chars / base)
}

// ---- Distinct values ----

fn p_random_distinct_values(s: &[u8], base: f64) -> f64 {
    let total_possible: f64 = base.powi(s.len() as i32);
    let num_distinct = count_distinct(s);
    let mut sum: f64 = 0.0;
    for i in 1..=num_distinct {
        sum += num_possible_outcomes(s.len(), i, base as usize);
    }
    sum / total_possible
}

fn count_distinct(s: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0;
    for &b in s {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
        }
    }
    count
}

fn num_possible_outcomes(num_values: usize, num_distinct: usize, base: usize) -> f64 {
    let mut res = base as f64;
    for i in 1..num_distinct {
        res *= (base - i) as f64;
    }
    res * num_distinct_configurations(num_values, num_distinct)
}

fn num_distinct_configurations(num_values: usize, num_distinct: usize) -> f64 {
    if num_distinct == 1 || num_distinct == num_values {
        return 1.0;
    }
    num_distinct_configurations_aux(num_distinct, 0, num_values - num_distinct)
}

fn num_distinct_configurations_aux(num_positions: usize, position: usize, remaining: usize) -> f64 {
    if remaining == 0 {
        return 1.0;
    }
    let mut configs = 0.0;
    if position + 1 < num_positions {
        configs += num_distinct_configurations_aux(num_positions, position + 1, remaining);
    }
    configs
        + (position + 1) as f64
            * num_distinct_configurations_aux(num_positions, position, remaining - 1)
}

// ---- Binomial probability ----

fn p_binomial(n: usize, x: usize, p: f64) -> f64 {
    let left_tail = (x as f64) < n as f64 * p;
    let min = if left_tail { 0 } else { x };
    let max = if left_tail { x } else { n };

    let mut total = 0.0;
    for i in min..=max {
        total += factorial(n) / (factorial(n - i) * factorial(i))
            * p.powi(i as i32)
            * (1.0 - p).powi((n - i) as i32);
    }
    total
}

fn factorial(n: usize) -> f64 {
    let mut res = 1.0;
    for i in 2..=n {
        res *= i as f64;
    }
    res
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_aws_key_suppressed() {
        let input = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "export VAR= should be suppressed (handled by SensitiveEnvExport rule): {findings:?}"
        );
    }

    #[test]
    fn test_env_aws_key_suppressed() {
        let input = "env AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE ./run.sh";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "env VAR= should be suppressed: {findings:?}"
        );
    }

    #[test]
    fn test_bare_aws_key_assignment_fires() {
        // Bare VAR= without export/env/set is NOT suppressed
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings.is_empty(),
            "bare VAR= should still fire credential detection"
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::CredentialInText));
    }

    #[test]
    fn test_aws_key_in_curl_header_fires() {
        let input = "curl -H 'Authorization: AKIAIOSFODNN7EXAMPLE' https://api.example.com";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(!findings.is_empty(), "AWS key in curl header should fire");
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::CredentialInText));
        // Title must NOT contain the secret value
        for f in &findings {
            assert!(
                !f.title.contains("AKIAIOSFODNN7EXAMPLE"),
                "title must not contain the raw secret"
            );
        }
    }

    #[test]
    fn test_a3t_variant_detected() {
        let input = "A3T1IOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Posix, ScanContext::Paste);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "A3T-prefixed AWS key variant should be detected"
        );
    }

    #[test]
    fn test_slack_token_detected() {
        let input = concat!(
            "xoxb-",
            "123456789012-",
            "123456789012-",
            "AbCdEfGhIjKlMnOpQrStUvWx"
        );
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "valid Slack token should be detected"
        );
    }

    #[test]
    fn test_slack_token_does_not_match_word_suffix() {
        let input = concat!(
            "xoxb-",
            "123456789012-",
            "123456789012-",
            "AbCdEfGhIjKlMnOpQrStUvWx",
            "_suffix"
        );
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != RuleId::CredentialInText),
            "Slack token regex should not match when a word suffix extends the token"
        );
    }

    #[test]
    fn test_private_key_detected() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/yGaV...\n-----END RSA PRIVATE KEY-----";
        let findings = check(input, ShellType::Posix, ScanContext::Paste);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivateKeyExposed),
            "private key block should be detected: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .filter(|f| f.rule_id == RuleId::PrivateKeyExposed)
                .all(|f| f.severity == Severity::Critical),
            "private key should be Critical severity"
        );
    }

    #[test]
    fn test_generic_entropy_detected() {
        // A keyword-assignment with a random-looking value in paste context
        let input = r#"secret_key = "xK9mP2vL7nR4wQ8jF3hB6dT1yC5uA0eG""#;
        let findings = check(input, ShellType::Posix, ScanContext::Paste);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HighEntropySecret),
            "high-entropy secret should be detected in paste context: {findings:?}"
        );
    }

    #[test]
    fn test_generic_entropy_skipped_in_exec() {
        // Same input but in exec context — generic detection should NOT run
        let input = r#"secret_key = "xK9mP2vL7nR4wQ8jF3hB6dT1yC5uA0eG""#;
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HighEntropySecret),
            "generic entropy should be skipped in exec context"
        );
    }

    #[test]
    fn test_readable_password_not_flagged() {
        // A readable, non-random password should NOT be flagged by entropy check
        let input = r#"password = "hello_world""#;
        let findings = check(input, ShellType::Posix, ScanContext::Paste);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HighEntropySecret),
            "readable password should not be flagged as high-entropy: {findings:?}"
        );
    }

    #[test]
    fn test_p_random_ported_correctly() {
        // Verify the ported p_random gives same results as ripsecrets
        assert!(p_random(b"hello_world") < 1.0 / 1e6);
        assert!(p_random(b"xK9mP2vL7nR4wQ8jF3hB6dT1yC5uA0eG") > 1.0 / 1e4);
        assert!(p_random(b"rT8vN1kL5qW3mC7xH2jP9sD4fB6yZ0uA") > 1.0 / 1e4);
    }

    #[test]
    fn test_is_random_basic() {
        assert!(!is_random(b"hello_world"));
        assert!(is_random(b"xK9mP2vL7nR4wQ8jF3hB6dT1yC5uA0eG"));
    }

    #[test]
    fn test_file_scan_skipped() {
        let input = "AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Posix, ScanContext::FileScan);
        assert!(
            findings.is_empty(),
            "file scan context should produce no findings"
        );
    }

    #[test]
    fn test_fish_set_eq_suppressed() {
        // POSIX-style VAR= after set (some fish versions)
        let input = "set -gx AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Fish, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "fish set -gx VAR= should be suppressed: {findings:?}"
        );
    }

    #[test]
    fn test_fish_set_space_suppressed() {
        // Canonical fish form: set -gx VAR value (space-separated)
        let input = "set -gx AWS_ACCESS_KEY_ID AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Fish, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "fish set -gx VAR value should be suppressed: {findings:?}"
        );
    }
}
