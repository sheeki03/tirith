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

fn check_known_patterns(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pat in KNOWN_PATTERNS.iter() {
        for m in pat.regex.find_iter(input) {
            if is_covered_by_env_export(input, m.start()) {
                continue;
            }
            // AWS access keys legitimately appear in SigV4 pre-signed URLs /
            // Authorization headers; the signature is the secret, not the key ID
            // (issue #101).
            if pat.name == "AWS Access Key" && is_covered_by_aws_sigv4(input, &m) {
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

/// Suppress a credential match already covered by `SensitiveEnvExport` — i.e.
/// behind `export VAR=` / `env VAR=` / fish `set ... VAR` where `VAR` is in
/// `SENSITIVE_KEY_VARS`. Avoids double-reporting.
fn is_covered_by_env_export(input: &str, match_start: usize) -> bool {
    let prefix = &input[..match_start];
    let trimmed = prefix.trim_end();

    // POSIX form: `... export VAR=value` / `... env VAR=value` / `... set VAR=value`.
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

    // Fish form: `set [-gx] VAR value` (space, not `=`). Anchor on the trailing
    // space, so use the raw (un-trimmed) prefix.
    let raw_prefix = prefix;
    SENSITIVE_KEY_VARS.iter().any(|var| {
        let suffix_space = format!("{var} ");
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

/// Suppress an `AWS Access Key` match inside a SigV4 signed URL or Authorization
/// header — the key ID is public; the secret is the X-Amz-Signature (issue #101).
fn is_covered_by_aws_sigv4(input: &str, m: &regex::Match) -> bool {
    covered_by_url_sigv4(input, m) || covered_by_header_sigv4(input, m)
}

/// True if `m` is inside the `X-Amz-Credential` value of a URL that also has
/// `X-Amz-Algorithm=AWS4-HMAC-SHA256` and a non-empty `X-Amz-Signature`.
fn covered_by_url_sigv4(input: &str, m: &regex::Match) -> bool {
    let Some((url_str, url_offset)) = extract_url_token(input, m.start()) else {
        return false;
    };
    let Ok(url) = url::Url::parse(url_str) else {
        return false;
    };

    let mut credential_value: Option<String> = None;
    let mut has_correct_algorithm = false;
    let mut has_signature = false;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "X-Amz-Credential" => credential_value = Some(v.into_owned()),
            "X-Amz-Algorithm" if v == "AWS4-HMAC-SHA256" => {
                has_correct_algorithm = true;
            }
            "X-Amz-Signature" if !v.is_empty() => {
                has_signature = true;
            }
            _ => {}
        }
    }

    let Some(credential_value) = credential_value else {
        return false;
    };
    if !has_correct_algorithm || !has_signature {
        return false;
    }

    // Anchor to the credential parameter's byte span, not "any AKIA in this URL".
    let match_in_url_start = match m.start().checked_sub(url_offset) {
        Some(off) => off,
        None => return false,
    };
    let match_in_url_end = match_in_url_start + m.as_str().len();
    let Some((cred_start, cred_end)) =
        find_query_value_span(url_str, "X-Amz-Credential", &credential_value)
    else {
        return false;
    };
    match_in_url_start >= cred_start && match_in_url_end <= cred_end
}

/// Byte span (within `url_str`) of the value of query param `name`. Scans the
/// RAW query and accepts any encoded form whose decoded value matches
/// `decoded_value` (which may be percent-decoded by `url::Url`).
fn find_query_value_span(url_str: &str, name: &str, decoded_value: &str) -> Option<(usize, usize)> {
    let q_start = url_str.find('?')? + 1;
    let query = &url_str[q_start..];
    let query = query.split('#').next()?; // strip fragment
    let mut cursor = 0usize;
    while cursor <= query.len() {
        let segment_end = query[cursor..]
            .find('&')
            .map(|i| cursor + i)
            .unwrap_or(query.len());
        let segment = &query[cursor..segment_end];
        if let Some(eq_idx) = segment.find('=') {
            let raw_name = &segment[..eq_idx];
            let raw_value = &segment[eq_idx + 1..];
            // Case-sensitive (AWS uses exact `X-Amz-Credential`).
            if raw_name == name {
                // `form_urlencoded::parse` on a bare value returns it as the key.
                let dec: String = url::form_urlencoded::parse(raw_value.as_bytes())
                    .next()
                    .map(|(k, _)| k.into_owned())
                    .unwrap_or_default();
                if dec == decoded_value {
                    let value_start = q_start + cursor + eq_idx + 1;
                    let value_end = q_start + segment_end;
                    return Some((value_start, value_end));
                }
            }
        }
        if segment_end >= query.len() {
            break;
        }
        cursor = segment_end + 1;
    }
    None
}

/// Find the URL token containing byte offset `match_pos`, extending to
/// whitespace/quote/control boundaries. Returns the slice + its byte offset.
fn extract_url_token(input: &str, match_pos: usize) -> Option<(&str, usize)> {
    if match_pos > input.len() {
        return None;
    }
    let bytes = input.as_bytes();
    let is_boundary = |b: u8| {
        matches!(
            b,
            b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'`' | b'<' | b'>'
        )
    };

    // Walk left/right to a boundary (boundary chars are ASCII).
    let mut start = match_pos;
    while start > 0 {
        let prev = start - 1;
        if is_boundary(bytes[prev]) {
            break;
        }
        start = prev;
    }
    let mut end = match_pos;
    while end < bytes.len() && !is_boundary(bytes[end]) {
        end += 1;
    }
    // Defensive char-boundary alignment.
    while start < input.len() && !input.is_char_boundary(start) {
        start += 1;
    }
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let token = input.get(start..end)?;
    // Must start with a scheme.
    if !token.starts_with("http://") && !token.starts_with("https://") {
        return None;
    }
    Some((token, start))
}

/// True if `m` is inside the `Credential=` field of an Authorization header that
/// also has `AWS4-HMAC-SHA256` and a non-empty `Signature=` (header name
/// ASCII-case-insensitive).
///
/// Anchored to absolute byte spans: the match must fall entirely inside both the
/// header value's span AND the `Credential=` value's span, so a second
/// occurrence of the same key elsewhere is NOT suppressed.
fn covered_by_header_sigv4(input: &str, m: &regex::Match) -> bool {
    // Nearest preceding `authorization:` (case-insensitive); LAST occurrence so
    // repeated headers anchor on the rightmost.
    let prefix = &input[..m.start()];
    let auth_pos = match find_last_ascii_ignore_case(prefix, "authorization:") {
        Some(i) => i,
        None => return false,
    };
    let header_value_start = auth_pos + "authorization:".len();

    // Bound the header value at the first newline / quote at-or-after the start
    // (curl wraps in `'...'`/`"..."`; wire format ends at LF/CR).
    let bytes = input.as_bytes();
    let mut header_value_end = header_value_start;
    while header_value_end < bytes.len() {
        let b = bytes[header_value_end];
        if b == b'\n' || b == b'\r' || b == b'"' || b == b'\'' {
            break;
        }
        header_value_end += 1;
    }
    while header_value_end > header_value_start && !input.is_char_boundary(header_value_end) {
        header_value_end -= 1;
    }

    // Match must fall ENTIRELY inside the header value range (a second AKIA
    // after the closing quote must not be suppressed).
    if m.start() < header_value_start || m.end() > header_value_end {
        return false;
    }

    let header_value = &input[header_value_start..header_value_end];

    if !header_value.contains("AWS4-HMAC-SHA256") {
        return false;
    }

    // Locate the `Credential=` field's absolute span. A well-formed SigV4 header
    // is comma-separated and `Credential=` is never last, so it must be followed
    // by a comma; without one the header is malformed and we refuse to suppress
    // (else the span could swallow a later unrelated AKIA).
    let cred_idx_in_value = match header_value.find("Credential=") {
        Some(i) => i,
        None => return false,
    };
    let cred_search_offset = cred_idx_in_value + "Credential=".len();
    let cred_end_in_value = match header_value[cred_search_offset..].find(',') {
        Some(i) => cred_search_offset + i,
        None => return false, // malformed: Credential= has no closing comma
    };
    let cred_value_start_abs = header_value_start + cred_search_offset;
    let cred_value_end_abs = header_value_start + cred_end_in_value;

    // Match must fall ENTIRELY inside the Credential= value's span (string
    // containment alone would wrongly suppress a second occurrence elsewhere).
    if m.start() < cred_value_start_abs || m.end() > cred_value_end_abs {
        return false;
    }

    // Require a non-empty `Signature=` in the header value.
    let sig_idx = match header_value.find("Signature=") {
        Some(i) => i,
        None => return false,
    };
    let sig_value_start = sig_idx + "Signature=".len();
    let sig_value_end = header_value[sig_value_start..]
        .find(',')
        .map(|i| sig_value_start + i)
        .unwrap_or(header_value.len());
    let sig_value = header_value[sig_value_start..sig_value_end].trim();
    if sig_value.is_empty() {
        return false;
    }

    true
}

/// Last byte position in `haystack` where `needle` occurs, ASCII-case-insensitive.
fn find_last_ascii_ignore_case(haystack: &str, needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    if n.is_empty() || haystack.len() < n.len() {
        return None;
    }
    let h = haystack.as_bytes();
    let mut last: Option<usize> = None;
    'outer: for i in 0..=(h.len() - n.len()) {
        for j in 0..n.len() {
            if !h[i + j].eq_ignore_ascii_case(&n[j]) {
                continue 'outer;
            }
        }
        last = Some(i);
    }
    last
}

/// True if `before` ends with `cmd` plus only flags / VAR=val pairs (e.g.
/// `env -S VAR=`, `set -gx VAR`).
fn has_command_prefix(before: &str, cmd: &str) -> bool {
    let words: Vec<&str> = before.split_whitespace().collect();
    for (i, w) in words.iter().enumerate().rev() {
        if *w == cmd {
            let rest = &words[i + 1..];
            return rest.iter().all(|w| w.starts_with('-') || w.contains('='));
        }
    }
    false
}

// Entropy scoring — ported from ripsecrets (MIT). See module-level docs for source.

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
        // bigrams calibrated for base64 only
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
        // Bare VAR= (no export/env/set) must NOT be suppressed.
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
        // Title must NOT contain the secret value.
        for f in &findings {
            assert!(
                !f.title.contains("AKIAIOSFODNN7EXAMPLE"),
                "title must not contain the raw secret"
            );
        }
    }

    // AWS SigV4 carve-out tests (issue #101).

    #[test]
    fn test_bare_aws_key_still_fires() {
        let input = "AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Posix, ScanContext::Paste);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::CredentialInText));
    }

    #[test]
    fn test_aws_key_in_url_without_signature_fires() {
        // X-Amz-Credential present, X-Amz-Signature missing → still leaks.
        let input = "wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260504/us-east-1/s3/aws4_request'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "URL with credential but no signature should still fire"
        );
    }

    #[test]
    fn test_aws_key_in_url_without_algorithm_fires() {
        // X-Amz-Credential and X-Amz-Signature, but no AWS4-HMAC-SHA256.
        let input = "wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260504/us-east-1/s3/aws4_request&X-Amz-Signature=abc123'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "URL without AWS4-HMAC-SHA256 algorithm should still fire"
        );
    }

    #[test]
    fn test_aws_key_in_authorization_header_without_sigv4_fires() {
        let input = "curl -H 'Authorization: Bearer AKIAIOSFODNN7EXAMPLE' https://api.example.com";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "Bearer-style header without SigV4 markers should still fire"
        );
    }

    #[test]
    fn test_second_aws_key_in_url_path_still_fires() {
        // A stray AKIA in the PATH outside X-Amz-Credential: only the
        // credential-anchored one is suppressed.
        let input = "wcurl 'https://bucket.s3.amazonaws.com/AKIAIOSFODNN7EXAMPLE/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request&X-Amz-Signature=abc'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "stray AKIA in URL path must still fire even when SigV4 markers are present"
        );
    }

    #[test]
    fn test_s3_presigned_url_suppressed() {
        let input = "wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request&X-Amz-Date=20260504T034020Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=68e7c9aa09da959dc65bbbaa92b228251ccdda14e4d0dc5842e5e1037c76123e'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "fully-formed SigV4 pre-signed URL must not flag credential_in_text; got {findings:?}"
        );
    }

    #[test]
    fn test_s3_presigned_url_url_encoded_credential_value_suppressed() {
        // %2F-encoded X-Amz-Credential value (issue #101); url::Url decodes it so
        // AKIA still matches.
        let input = "wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20260504%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260504T034020Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=68e7c9aa09da959dc65bbbaa92b228251ccdda14e4d0dc5842e5e1037c76123e'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "URL-encoded credential scope must still be suppressed; got {findings:?}"
        );
    }

    #[test]
    fn test_aws_sigv4_authorization_header_suppressed() {
        let input = "curl -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=68e7c9aa09da959dc65bbbaa92b228251ccdda14e4d0dc5842e5e1037c76123e' https://s3.amazonaws.com/bucket/file";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "SigV4 Authorization header must not flag credential_in_text; got {findings:?}"
        );
    }

    #[test]
    fn test_aws_sigv4_authorization_header_lowercased_suppressed() {
        // Lowercase header name — ASCII-case-insensitive match must work.
        let input = "curl -H 'authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc' https://s3.amazonaws.com/bucket/file";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "lowercase authorization header must still be suppressed; got {findings:?}"
        );
    }

    #[test]
    fn test_second_aws_key_after_sigv4_header_still_fires() {
        // Span anchoring regression: the same AKIA in the URL after the closing
        // quote must still fire (only the in-Credential= one is suppressed).
        let input = "curl -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc' https://example.com/AKIAVCODYLSA53PQK4ZA";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "second AKIA after a SigV4 Authorization header must still fire; got {findings:?}"
        );
    }

    #[test]
    fn test_same_aws_key_in_other_header_after_sigv4_still_fires() {
        // The same key in a separate non-SigV4 header must still flag.
        let input = "curl -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc' -H 'X-Custom-Key: AKIAVCODYLSA53PQK4ZA' https://example.com/";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "AKIA in a separate non-SigV4 header after a SigV4 header must still fire; got {findings:?}"
        );
    }

    #[test]
    fn test_same_aws_key_in_body_after_sigv4_still_fires() {
        // SigV4 header followed by the same key string in a POST body.
        let input = "curl -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc' -d 'leaked=AKIAVCODYLSA53PQK4ZA' https://example.com/";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "AKIA in body data after a SigV4 header must still fire; got {findings:?}"
        );
    }

    #[test]
    fn test_malformed_unquoted_authorization_header_does_not_suppress() {
        // No comma after `Credential=` → not valid SigV4; suppression must reject
        // it, else the value span swallows the next AKIA.
        let input = "Authorization: AWS4-HMAC-SHA256 Credential=AKIAVCODYLSA53PQK4ZA Signature=abc https://example.com/AKIAVCODYLSA53PQK4ZA";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "malformed unquoted SigV4 header must NOT suppress; got {findings:?}"
        );
    }

    #[test]
    fn test_reordered_query_params_suppressed() {
        // Same SigV4 markers, different param order (query_pairs is order-agnostic).
        let input = "wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Signature=abc&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request&X-Amz-Algorithm=AWS4-HMAC-SHA256'";
        let findings = check(input, ShellType::Posix, ScanContext::Exec);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::CredentialInText),
            "reordered SigV4 query params must still be suppressed; got {findings:?}"
        );
    }

    #[test]
    fn test_non_ascii_prefix_does_not_panic() {
        // Multi-byte UTF-8 before the URL: byte-window scanning must respect
        // char boundaries. Passes if there's no panic.
        let input = "echo «attempt» wcurl 'https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA/20260504/us-east-1/s3/aws4_request&X-Amz-Signature=abc'";
        let _ = check(input, ShellType::Posix, ScanContext::Exec);
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
        // Exec scan context: generic detection should NOT run.
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
        // Anchors against ripsecrets behaviour.
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
        // Some fish versions accept POSIX-style VAR= after `set`.
        let input = "set -gx AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Fish, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "fish set -gx VAR= should be suppressed: {findings:?}"
        );
    }

    #[test]
    fn test_fish_set_space_suppressed() {
        // Canonical fish form: `set -gx VAR value` (space, no `=`).
        let input = "set -gx AWS_ACCESS_KEY_ID AKIAIOSFODNN7EXAMPLE";
        let findings = check(input, ShellType::Fish, ScanContext::Exec);
        assert!(
            findings.is_empty(),
            "fish set -gx VAR value should be suppressed: {findings:?}"
        );
    }
}
