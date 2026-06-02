//! M11 ch4 — secret-rotation ASSISTANT (guidance only).
//!
//! A presenter over existing audit data plus a static provider table: it tells
//! the user where and how to rotate a leaked credential but does NOT rotate or
//! revoke anything, and makes ZERO network calls — the "URLs" here are inert
//! string literals for the human to open. This honesty contract is stated in
//! `--help` and the command output (see [`HONESTY_BANNER`]).
//!
//! No new RuleIds: `tirith secret triage` reads existing credential-type
//! findings from the audit log (see [`CREDENTIAL_RULE_IDS`]) and matches each
//! against a provider in [`PROVIDERS`]. Each [`Provider`] carries a
//! [`Provider::last_verified`] date so a stale entry is visible.

/// The date every [`PROVIDERS`] entry was last hand-verified (surfaced under
/// `--verbose`). Bump this and re-check each URL whenever the table is revised.
pub const LAST_VERIFIED: &str = "2026-05-28";

/// The honesty banner: tirith shows where and how, the user does the rotation.
/// Printed by every `tirith secret` subcommand and echoed in `--help`.
pub const HONESTY_BANNER: &str =
    "tirith does NOT perform rotation or revocation; it shows you where and how. You do the rotation.";

/// The credential-EXPOSURE audit rule IDs `tirith secret triage` scans for, as
/// their `snake_case` serialized forms.
///
/// SCOPE: only rules signalling an ACTUAL leaked secret (for which "rotate this
/// credential" is correct) — the three direct credential rules plus
/// `canary_token_touched`. Deliberately EXCLUDES the `threat_*package*`
/// reputation rules, which fire on a package name, not a leaked credential.
pub const CREDENTIAL_RULE_IDS: &[&str] = &[
    "credential_in_text",
    "high_entropy_secret",
    "private_key_exposed",
    CANARY_RULE_ID,
];

/// `true` when `rule_id` is one of the credential-type rules the
/// `tirith secret triage` command acts on.
pub fn is_credential_rule(rule_id: &str) -> bool {
    CREDENTIAL_RULE_IDS.contains(&rule_id)
}

/// The audit `rule_id` for a touched canary (tirith's own honeytoken). A named
/// constant so the triage suppression and [`TriageItem::next_step`] advice stay
/// in lockstep.
pub const CANARY_RULE_ID: &str = "canary_token_touched";

/// `true` when `rule_id` is the canary-touched rule. A canary is tirith's OWN
/// bait token, so triage must not attribute it to a provider.
pub fn is_canary_rule(rule_id: &str) -> bool {
    rule_id == CANARY_RULE_ID
}

/// A single provider's rotation guidance. Pure data — no behavior, no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The canonical CLI token (`aws`, `github`, …). Lowercase, no spaces.
    pub provider: &'static str,
    /// The page where the user revokes the credential. Printed, never fetched.
    pub revocation_url: &'static str,
    /// The provider's authoritative rotation / key-management documentation.
    pub doc_url: &'static str,
    /// Manual checklist the user performs; tirith only prints these.
    pub manual_checklist: &'static [&'static str],
    /// VALUE-shape fragments of the credential (`AKIA…`, `sk-ant-api…`) used by
    /// `triage` to attribute a finding. TIER-1 in [`match_provider`]: a value
    /// shape always beats an [`Provider::env_name_markers`] match (CodeRabbit
    /// R15 #2), so a real `sk-ant-api` outranks the longer `OPENAI_API_KEY`.
    pub key_prefix_shapes: &'static [&'static str],
    /// Env-var / config-key NAME markers, matched only as a TIER-2 FALLBACK when
    /// no value shape matched (a redacted record masks the value but keeps the
    /// var name). A separate tier so a long name can't outrank a real value shape.
    pub env_name_markers: &'static [&'static str],
    /// The date this entry was last hand-verified (see [`LAST_VERIFIED`]).
    pub last_verified: &'static str,
}

/// The 11-provider rotation table, in canonical display order.
pub static PROVIDERS: &[Provider] = &[
    Provider {
        provider: "aws",
        revocation_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
        doc_url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
        manual_checklist: &[
            "Sign in to the IAM console and locate the leaked access key by its AKIA… ID.",
            "Create a SECOND access key (so live workloads keep working during rollover).",
            "Deploy the new key to every consumer (CI secrets, env files, deploy configs).",
            "Set the OLD key to Inactive and confirm nothing breaks.",
            "DELETE the old key once traffic has fully moved off it.",
            "Review CloudTrail for unauthorized use of the leaked key.",
        ],
        key_prefix_shapes: &["AKIA", "ASIA"],
        // `~/.aws/credentials` INI keys: TIER-2 fallback, so a redacted record
        // still routes to aws when no `AKIA…` value survives.
        env_name_markers: &["aws_access_key_id", "aws_secret_access_key"],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "github",
        revocation_url: "https://github.com/settings/tokens",
        doc_url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        manual_checklist: &[
            "Open Settings → Developer settings → Personal access tokens.",
            "Find the leaked token and click Delete / Revoke immediately.",
            "Generate a replacement with the MINIMUM scopes the consumer needs.",
            "Update CI secrets, git credential helpers, and any .netrc / env files.",
            "Check Settings → Security log for use of the leaked token.",
            "If it was an OAuth app or fine-grained token, rotate that credential too.",
        ],
        key_prefix_shapes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "npm",
        revocation_url: "https://www.npmjs.com/settings/~/tokens",
        doc_url: "https://docs.npmjs.com/about-access-tokens",
        manual_checklist: &[
            "Open npmjs.com → Account → Access Tokens.",
            "Delete the leaked token.",
            "Run `npm token create` (or the website) for a replacement.",
            "Update ~/.npmrc, CI publish secrets, and any automation.",
            "Audit recently published package versions for unexpected releases.",
        ],
        // `npm_` is a real value prefix (tier 1); the `.npmrc` `:_authToken=`
        // line is a config-KEY name → tier 2 (CodeRabbit R13b), so it can't
        // out-rank another provider's real prefix.
        key_prefix_shapes: &["npm_"],
        env_name_markers: &["//registry.npmjs.org/:_authToken"],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "pypi",
        revocation_url: "https://pypi.org/manage/account/token/",
        doc_url: "https://pypi.org/help/#apitoken",
        manual_checklist: &[
            "Open pypi.org → Account settings → API tokens.",
            "Remove the leaked token.",
            "Create a replacement scoped to a single project where possible.",
            "Update ~/.pypirc, CI publish secrets, and any twine automation.",
            "Review your projects' release history for unexpected uploads.",
        ],
        key_prefix_shapes: &["pypi-"],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "cargo",
        revocation_url: "https://crates.io/settings/tokens",
        doc_url: "https://doc.rust-lang.org/cargo/reference/publishing.html",
        manual_checklist: &[
            "Open crates.io → Account Settings → API Tokens.",
            "Revoke the leaked token.",
            "Run `cargo login` with a freshly generated token.",
            "Update CI publish secrets and ~/.cargo/credentials.toml.",
            "Check your crates' version history for unexpected publishes.",
        ],
        // crates.io tokens are `cio…`, but the bare "cio" substring false-matches
        // common words, so there is no value shape. cargo is matched only via the
        // `cargo-registry-token` config KEY (NAME marker, tier 2 — CodeRabbit R13b).
        key_prefix_shapes: &[],
        env_name_markers: &["cargo-registry-token"],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "stripe",
        revocation_url: "https://dashboard.stripe.com/apikeys",
        doc_url: "https://stripe.com/docs/keys#rolling-keys",
        manual_checklist: &[
            "Open the Stripe Dashboard → Developers → API keys.",
            "Click Roll key on the leaked secret key (Stripe issues a new one).",
            "Optionally set an expiry on the old key to keep traffic alive briefly.",
            "Deploy the new key to every service, then expire the old immediately.",
            "Review the Dashboard's events / logs for unauthorized API calls.",
            "If a restricted or webhook signing secret leaked, rotate that too.",
        ],
        key_prefix_shapes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "slack",
        revocation_url: "https://api.slack.com/apps",
        doc_url: "https://api.slack.com/authentication/token-types",
        manual_checklist: &[
            "Open api.slack.com/apps and select the affected app.",
            "Under OAuth & Permissions, reinstall the app to rotate its tokens.",
            "For a bot/user token, revoke via `auth.revoke` then reissue.",
            "Rotate the app's Signing Secret under Basic Information if exposed.",
            "Update every service holding the old token, then confirm revocation.",
        ],
        key_prefix_shapes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xapp-"],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "openai",
        revocation_url: "https://platform.openai.com/api-keys",
        doc_url: "https://platform.openai.com/docs/api-reference/authentication",
        manual_checklist: &[
            "Open platform.openai.com → API keys.",
            "Revoke the leaked key.",
            "Create a replacement and restrict it to a project where possible.",
            "Update env files, CI secrets, and any SDK configuration.",
            "Review usage in the dashboard for unexpected spend.",
        ],
        key_prefix_shapes: &["sk-proj-", "sk-svcacct-", "sk-"],
        // TIER-2 NAME marker (CodeRabbit R9 #I, R15 #2): once the `sk-…` value is
        // masked the var name still attributes. NOT a value shape — at 14 bytes it
        // would longest-match over anthropic's `sk-ant-api` and steal a real key.
        env_name_markers: &["OPENAI_API_KEY"],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "anthropic",
        revocation_url: "https://console.anthropic.com/settings/keys",
        doc_url: "https://docs.anthropic.com/en/api/getting-started",
        manual_checklist: &[
            "Open console.anthropic.com → Settings → API Keys.",
            "Delete the leaked key.",
            "Create a replacement and scope it to a workspace where possible.",
            "Update env files, CI secrets, and any SDK configuration.",
            "Review usage for unexpected activity.",
        ],
        key_prefix_shapes: &["sk-ant-api", "sk-ant-"],
        // TIER-2 NAME marker (CodeRabbit R9 #I): same rationale as openai. The two
        // var-name markers share no substring, so neither cross-attributes.
        env_name_markers: &["ANTHROPIC_API_KEY"],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "gcp",
        revocation_url: "https://console.cloud.google.com/apis/credentials",
        doc_url: "https://cloud.google.com/iam/docs/keys-create-delete",
        manual_checklist: &[
            "Open the Cloud Console → APIs & Services → Credentials.",
            "For a service-account key, create a NEW key, then delete the leaked one.",
            "For an API key, regenerate or delete it and tighten its restrictions.",
            "Roll the new credential out to every workload before deleting the old.",
            "Review Cloud Audit Logs for use of the leaked credential.",
        ],
        // The generic PEM private-key header is NOT listed — it is not
        // GCP-specific and would misroute every bare private key here. Only
        // GCP-distinctive shapes: the `AIza` prefix and the service-account JSON
        // `type` field. BOTH spaced and MINIFIED `type` forms are listed
        // (CodeRabbit R11 #8) since the substring scan is literal on spacing, in
        // their real lowercase form (tier-1 is case-sensitive — CodeRabbit R13d).
        key_prefix_shapes: &[
            "AIza",
            "\"type\": \"service_account\"",
            "\"type\":\"service_account\"",
        ],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
    Provider {
        provider: "azure",
        revocation_url: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        doc_url: "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal",
        manual_checklist: &[
            "Open portal.azure.com → Microsoft Entra ID → App registrations.",
            "Select the affected app → Certificates & secrets.",
            "Create a NEW client secret, then delete the leaked one.",
            "Deploy the new secret to every consumer before removing the old.",
            "Review the sign-in / audit logs for unauthorized use.",
        ],
        key_prefix_shapes: &["AccountKey=", "SharedAccessKey=", "DefaultEndpointsProtocol="],
        env_name_markers: &[],
        last_verified: LAST_VERIFIED,
    },
];

/// Look up a provider by canonical token (case-insensitive, trimmed); `None`
/// for an unknown provider.
pub fn lookup(provider: &str) -> Option<&'static Provider> {
    let needle = provider.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.provider == needle)
}

/// The valid provider tokens, in display order (for the unknown-provider error).
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.provider).collect()
}

/// Attribute a leaked-secret `finding_text` to a provider by substring-matching
/// its shapes. Returns the provider owning the LONGEST matching shape (ties
/// broken by [`PROVIDERS`] order); `None` when nothing matches.
///
/// Two tiers (CodeRabbit R15 #2): a real value shape always beats an env-var
/// NAME marker. TIER-1 is [`Provider::key_prefix_shapes`]; TIER-2 is
/// [`Provider::env_name_markers`], tried only when no tier-1 shape matched.
/// Without the split, the 14-byte `OPENAI_API_KEY` would longest-match over a
/// real 10-byte `sk-ant-api` and mis-route. Longest-match (not first) also lets
/// the specific `sk-ant-api` win over the shared `sk-` family prefix.
///
/// A cheap substring scan, not a parser: redacted text usually keeps a leading
/// prefix (`AKIA…`, `ghp_…`), enough to route.
pub fn match_provider(finding_text: &str) -> Option<&'static Provider> {
    let lower = finding_text.to_ascii_lowercase();
    // TIER-1: value shapes, case-sensitive against the original text — wins
    // outright over any marker.
    match_longest(finding_text, |p| p.key_prefix_shapes, true)
        // TIER-2: NAME markers, case-insensitive, only when no value shape hit.
        .or_else(|| match_longest(&lower, |p| p.env_name_markers, false))
}

/// Longest-match (table-order tie-break) of `haystack` against `shapes_of(p)`
/// per provider. Shared by both tiers of [`match_provider`].
///
/// `case_sensitive` (CodeRabbit R13d): TIER-1 value shapes pass `true` so a
/// fixed-case prefix can't be matched by an ordinary word in the wrong case
/// (e.g. "asia" → `ASIA`). TIER-2 markers pass `false` (and a pre-lowered
/// haystack) so an env-var name in any case still attributes.
fn match_longest(
    haystack: &str,
    shapes_of: impl Fn(&'static Provider) -> &'static [&'static str],
    case_sensitive: bool,
) -> Option<&'static Provider> {
    PROVIDERS
        .iter()
        .filter_map(|p| {
            shapes_of(p)
                .iter()
                .copied()
                .filter(|shape| {
                    if case_sensitive {
                        haystack.contains(*shape)
                    } else {
                        haystack.contains(&shape.to_ascii_lowercase())
                    }
                })
                .map(|shape| shape.len())
                .max()
                .map(|best| (p, best))
        })
        // `max_by_key` returns the LAST maximal element; reverse so a tie
        // resolves to the FIRST provider in table order.
        .rev()
        .max_by_key(|(_, len)| *len)
        .map(|(p, _)| p)
}

/// One triage line: a credential finding with its optional attributed provider
/// and the redacted text that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageItem {
    /// The audit `rule_id` that fired (e.g. `credential_in_text`).
    pub rule_id: String,
    /// The record's RFC-3339 timestamp, for ordering / display.
    pub timestamp: String,
    /// The redacted command text (the engine redacts at write time).
    pub redacted: String,
    /// The provider this finding was attributed to, if any shape matched.
    pub provider: Option<&'static Provider>,
}

impl TriageItem {
    /// The one-line next-step shown by `tirith secret triage`. A touched canary
    /// gets its own investigate-the-bait advice, never provider rotation
    /// (CodeRabbit R12 #E); otherwise point at the attributed revocation URL, or
    /// generic guidance when none matched.
    pub fn next_step(&self) -> String {
        if is_canary_rule(&self.rule_id) {
            return format!(
                "{} ({}) → a tirith canary (bait) token was READ — this is NOT a \
                 third-party credential to rotate. Investigate WHO/WHAT touched it: \
                 `tirith canary status`, then consider `tirith incident start`.",
                self.rule_id, self.timestamp
            );
        }
        match self.provider {
            Some(p) => format!(
                "{} ({}) → rotate the {} credential at {}",
                self.rule_id, self.timestamp, p.provider, p.revocation_url
            ),
            None => format!(
                "{} ({}) → credential detected; run `tirith secret rotate <provider>` \
                 (one of: {})",
                self.rule_id,
                self.timestamp,
                provider_names().join(", ")
            ),
        }
    }
}

/// Build the triage list from already-loaded audit records. Pure and I/O-free
/// (the CLI reads the audit log and hands records here).
///
/// Keeps only `verdict` entries whose `rule_ids` include a credential-type rule
/// (see [`CREDENTIAL_RULE_IDS`]), emitting one [`TriageItem`] per matching
/// `(record, rule)` pair. `recent` caps to the most recent N (input order; `0`
/// means no cap).
pub fn triage_records(
    records: &[crate::audit_aggregator::AuditRecord],
    recent: usize,
) -> Vec<TriageItem> {
    let mut items: Vec<TriageItem> = Vec::new();
    for r in records {
        // Only verdict entries carry credential rule_ids (empty = legacy verdict).
        if !(r.entry_type.is_empty() || r.entry_type == "verdict") {
            continue;
        }
        for rid in &r.rule_ids {
            if is_credential_rule(rid) {
                // Suppress provider attribution for a canary explicitly
                // (CodeRabbit R12 #E): the redacted text can coincidentally carry
                // a provider key-shape, so we don't rely on `match_provider`
                // returning `None`.
                let provider = if is_canary_rule(rid) {
                    None
                } else {
                    match_provider(&r.command_redacted)
                };
                items.push(TriageItem {
                    rule_id: rid.clone(),
                    timestamp: r.timestamp.clone(),
                    redacted: r.command_redacted.clone(),
                    provider,
                });
            }
        }
    }
    if recent > 0 && items.len() > recent {
        // Keep the tail (most recent) when input is oldest-first.
        items.drain(0..items.len() - recent);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_aggregator::AuditRecord;

    fn verdict(ts: &str, rules: &[&str], redacted: &str) -> AuditRecord {
        AuditRecord {
            timestamp: ts.to_string(),
            session_id: "s1".to_string(),
            action: "Warn".to_string(),
            rule_ids: rules.iter().map(|s| s.to_string()).collect(),
            command_redacted: redacted.to_string(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: true,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
            entry_type: "verdict".to_string(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        }
    }

    #[test]
    fn table_has_exactly_eleven_providers() {
        assert_eq!(PROVIDERS.len(), 11, "spec pins 11 providers");
        let names = provider_names();
        for expected in [
            "aws",
            "github",
            "npm",
            "pypi",
            "cargo",
            "stripe",
            "slack",
            "openai",
            "anthropic",
            "gcp",
            "azure",
        ] {
            assert!(names.contains(&expected), "missing provider {expected}");
        }
    }

    #[test]
    fn every_entry_is_well_formed_and_dated() {
        for p in PROVIDERS {
            assert!(
                p.revocation_url.starts_with("https://"),
                "{}: revocation_url must be https",
                p.provider
            );
            assert!(
                p.doc_url.starts_with("https://"),
                "{}: doc_url must be https",
                p.provider
            );
            assert!(
                !p.manual_checklist.is_empty(),
                "{}: checklist must be non-empty",
                p.provider
            );
            assert!(
                !p.key_prefix_shapes.is_empty() || !p.env_name_markers.is_empty(),
                "{}: needs at least one triage shape (value shape or env-name marker)",
                p.provider
            );
            assert_eq!(
                p.last_verified, LAST_VERIFIED,
                "{}: last_verified must match the table constant",
                p.provider
            );
            assert_eq!(p.last_verified, "2026-05-28", "staleness date pinned");
        }
    }

    #[test]
    fn lookup_is_case_insensitive_and_rejects_unknown() {
        assert_eq!(lookup("GitHub").map(|p| p.provider), Some("github"));
        assert_eq!(lookup("  aws ").map(|p| p.provider), Some("aws"));
        assert!(lookup("bogus-provider").is_none());
    }

    #[test]
    fn match_provider_routes_by_shape() {
        assert_eq!(
            match_provider("export AWS_KEY=AKIAEXAMPLE0000abcd").map(|p| p.provider),
            Some("aws")
        );
        assert_eq!(
            match_provider("token=ghp_xxxxxxxxxxxxxxxxxxxx").map(|p| p.provider),
            Some("github")
        );
        assert_eq!(
            match_provider("STRIPE=sk_live_redacted").map(|p| p.provider),
            Some("stripe")
        );
        // anthropic's sk-ant- must not be mis-attributed to openai's sk-.
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=sk-ant-api03-redacted").map(|p| p.provider),
            Some("anthropic")
        );
        assert!(match_provider("nothing credential-shaped here").is_none());
    }

    #[test]
    fn redacted_env_var_names_still_attribute_openai_and_anthropic() {
        // CodeRabbit R9 #I: triage matches the POST-mask text — the value shape
        // is gone but the env-var NAME survives and must still attribute.
        assert_eq!(
            match_provider("OPENAI_API_KEY=[REDACTED]").map(|p| p.provider),
            Some("openai"),
            "a masked OPENAI_API_KEY record must still route to openai"
        );
        assert_eq!(
            match_provider("OPENAI_API_KEY=[REDACTED:OpenAI API Key]").map(|p| p.provider),
            Some("openai"),
            "the builtin-redactor label form must also route to openai"
        );
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=[REDACTED]").map(|p| p.provider),
            Some("anthropic"),
            "a masked ANTHROPIC_API_KEY record must still route to anthropic"
        );
        // Case-insensitive: an upper/lower-cased var name still attributes.
        assert_eq!(
            match_provider("export openai_api_key=[REDACTED]").map(|p| p.provider),
            Some("openai")
        );
        // The two var names must not cross-attribute (no shared substring).
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=[REDACTED:Anthropic API Key]").map(|p| p.provider),
            Some("anthropic"),
            "ANTHROPIC_API_KEY must not be mis-routed to openai"
        );
    }

    #[test]
    fn real_prefix_outranks_env_var_name_marker() {
        // CodeRabbit R15 #2 — pin both two-tier properties.
        // (1) With BOTH a NAME marker and a real prefix, the real prefix wins
        // even though the 14-byte marker is longer than the 10-byte `sk-ant-api`.
        assert_eq!(
            match_provider("OPENAI_API_KEY=[REDACTED] sk-ant-api03-xxxx").map(|p| p.provider),
            Some("anthropic"),
            "a real sk-ant-api prefix must outrank the longer OPENAI_API_KEY marker"
        );
        // Order-independent: marker after the real prefix routes the same way.
        assert_eq!(
            match_provider("sk-ant-api03-xxxx leaked; was in OPENAI_API_KEY").map(|p| p.provider),
            Some("anthropic"),
            "tier-1 value shape wins regardless of textual order"
        );
        // The same precedence holds for the AWS config-key markers vs another
        // provider's real value shape (marker must not steal a real github key).
        assert_eq!(
            match_provider("aws_secret_access_key was next to ghp_xxxxxxxxxxxxxxxxxxxx")
                .map(|p| p.provider),
            Some("github"),
            "a real ghp_ value shape must outrank the aws_secret_access_key marker"
        );

        // (2) A LONE env-var-name marker still attributes via the tier-2 fallback.
        assert_eq!(
            match_provider("OPENAI_API_KEY=[REDACTED]").map(|p| p.provider),
            Some("openai"),
            "a lone OPENAI_API_KEY marker must still attribute to openai (tier-2 fallback)"
        );
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=[REDACTED]").map(|p| p.provider),
            Some("anthropic"),
            "a lone ANTHROPIC_API_KEY marker must still attribute to anthropic (tier-2 fallback)"
        );
        assert_eq!(
            match_provider("aws_secret_access_key=[REDACTED]").map(|p| p.provider),
            Some("aws"),
            "a lone aws_secret_access_key marker must still attribute to aws (tier-2 fallback)"
        );
    }

    #[test]
    fn triage_attributes_masked_openai_env_record() {
        // End-to-end: a masked `OPENAI_API_KEY=…` verdict triages to openai.
        let rec = verdict(
            "2026-05-01T00:00:00Z",
            &["credential_in_text"],
            "export OPENAI_API_KEY=[REDACTED:OpenAI API Key]",
        );
        let items = triage_records(&[rec], 0);
        assert_eq!(items.len(), 1, "one credential rule → one triage item");
        assert_eq!(
            items[0].provider.map(|p| p.provider),
            Some("openai"),
            "the masked OPENAI_API_KEY record must triage to openai"
        );
    }

    #[test]
    fn bare_pem_header_does_not_attribute_to_gcp() {
        // F4: the generic PEM private-key header must not misroute to gcp.
        // CodeRabbit R7 #8: assemble the header from fragments at runtime so no
        // contiguous private-key literal is committed (it trips secret scanners).
        let dashes = "-".repeat(5);
        let pem_header = format!("{dashes}BEGIN PRIVATE KEY{dashes}");
        assert!(
            match_provider(&pem_header).is_none(),
            "a bare PEM private-key header must not attribute to gcp"
        );
        let pem_block = format!("cat key.pem\n{pem_header}\nMIIE...");
        assert!(
            match_provider(&pem_block).map(|p| p.provider) != Some("gcp"),
            "a generic PEM block must not route to gcp"
        );
        // GCP-distinctive shapes still attribute correctly.
        assert_eq!(
            match_provider("export KEY=AIzaSyExampleExampleExample").map(|p| p.provider),
            Some("gcp")
        );
        assert_eq!(
            match_provider("{\"type\": \"service_account\", \"project_id\": \"x\"}")
                .map(|p| p.provider),
            Some("gcp")
        );
    }

    #[test]
    fn minified_service_account_json_attributes_to_gcp() {
        // CodeRabbit R11 #8: a MINIFIED service-account record must attribute to
        // gcp (the substr scan is literal on spacing, so list the minified shape).
        assert_eq!(
            match_provider("{\"type\":\"service_account\",\"project_id\":\"x\"}")
                .map(|p| p.provider),
            Some("gcp"),
            "a minified service-account JSON must attribute to gcp"
        );
        // Tier-1 is case-sensitive (CodeRabbit R13d), so an UPPERCASED variant
        // (never a real key) does not attribute — gcp has no marker, so None.
        assert_eq!(
            match_provider("{\"TYPE\":\"SERVICE_ACCOUNT\"}").map(|p| p.provider),
            None
        );
    }

    #[test]
    fn env_name_markers_are_case_insensitive() {
        // F5: an UPPERCASE env-var name (no value shape) still attributes via the
        // case-insensitive tier-2 marker.
        assert_eq!(
            match_provider("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIexample").map(|p| p.provider),
            Some("aws"),
            "uppercase AWS_SECRET_ACCESS_KEY must route to aws via the tier-2 name marker"
        );
        // A real lowercase value prefix still matches tier-1 (case-sensitive).
        assert_eq!(
            match_provider("NPM_TOKEN env: npm_AbCdEf").map(|p| p.provider),
            Some("npm")
        );
        // An uppercased value misses tier-1, but the `ANTHROPIC_API_KEY` name
        // marker (tier-2) still routes it to anthropic.
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=SK-ANT-API03-REDACTED").map(|p| p.provider),
            Some("anthropic"),
            "the ANTHROPIC_API_KEY name marker routes an uppercased value to anthropic"
        );
    }

    #[test]
    fn tier1_value_shapes_are_case_sensitive_no_word_false_match() {
        // CodeRabbit R13d: case-sensitive tier-1 means the word "asia" must not
        // match AWS's `ASIA` prefix, while a real uppercase `ASIA…` does.
        assert!(
            match_provider("deploy the service to the asia-pacific region").is_none(),
            "the word 'asia' must not match AWS's `ASIA` value prefix"
        );
        assert!(
            match_provider("the username nakia logged in").is_none(),
            "the 'akia' inside 'nakia' must not match AWS's `AKIA` value prefix"
        );
        // A genuine uppercase AWS prefix still attributes.
        assert_eq!(
            match_provider("ASIAEXAMPLE0000TEMPCRED").map(|p| p.provider),
            Some("aws"),
            "a real uppercase ASIA… STS prefix must still route to aws"
        );
    }

    #[test]
    fn match_provider_equal_length_tie_breaks_to_earlier_table_entry() {
        // Pin an equal-length tie: aws's `AKIA` and github's `ghp_` are both 4
        // bytes and aws precedes github, so an input matching both routes to aws.
        assert_eq!("AKIA".len(), "ghp_".len(), "shapes must be equal length");
        let aws_idx = PROVIDERS.iter().position(|p| p.provider == "aws").unwrap();
        let github_idx = PROVIDERS
            .iter()
            .position(|p| p.provider == "github")
            .unwrap();
        assert!(
            aws_idx < github_idx,
            "test assumes aws precedes github in PROVIDERS"
        );

        // Both 4-byte shapes match and neither has a longer one — a genuine tie.
        let both = "AKIA0000example ghp_0000example";
        assert_eq!(
            match_provider(both).map(|p| p.provider),
            Some("aws"),
            "equal-length tie must resolve to the earlier table entry (aws)"
        );
        // Order in the INPUT text must not change the outcome — only table order.
        let reversed = "ghp_0000example AKIA0000example";
        assert_eq!(
            match_provider(reversed).map(|p| p.provider),
            Some("aws"),
            "tie-break is by table order, not input order"
        );
    }

    #[test]
    fn cargo_cio_substring_does_not_false_match() {
        // Regression (code-reviewer #1): a benign command containing "suspicious"
        // / "precious" must NOT route to cargo via a "cio" substring.
        assert!(
            match_provider("npm install suspicious-pkg").is_none(),
            "'suspicious' must not route to cargo via a 'cio' substring"
        );
        assert!(match_provider("echo precious metals").is_none());
        // The explicit cargo config key still routes correctly.
        assert_eq!(
            match_provider("cargo-registry-token = redacted").map(|p| p.provider),
            Some("cargo")
        );
    }

    #[test]
    fn real_value_prefix_outranks_npm_cargo_config_markers() {
        // CodeRabbit R13b: the npm/cargo config-KEY markers are now tier 2, so in
        // a mixed command another provider's real value prefix (tier 1) wins.
        assert_eq!(
            match_provider("npmrc //registry.npmjs.org/:_authToken=x and ghp_realleakedtoken")
                .map(|p| p.provider),
            Some("github"),
            "a real ghp_ prefix (tier 1) must beat npm's tier-2 config-key marker"
        );
        assert_eq!(
            match_provider("cargo-registry-token = x ; also AKIAEXAMPLEREALKEY")
                .map(|p| p.provider),
            Some("aws"),
            "a real AKIA prefix (tier 1) must beat cargo's tier-2 config-key marker"
        );
        // And with NO competing real prefix, the tier-2 markers still attribute.
        assert_eq!(
            match_provider("//registry.npmjs.org/:_authToken=redacted").map(|p| p.provider),
            Some("npm")
        );
    }

    #[test]
    fn benign_non_credential_command_yields_no_provider() {
        // pr-test-analyzer #9: a credential-shaped WORD (not a real token) must
        // not attribute a provider.
        assert!(match_provider("echo sk_live is my variable name").is_none());
        assert!(match_provider("git commit -m 'add aws docs'").is_none());
    }

    #[test]
    fn triage_emits_one_item_per_credential_rule() {
        let records = vec![
            verdict("2026-05-28T10:00:00Z", &["credential_in_text"], "AKIA…leak"),
            // A non-credential finding is ignored.
            verdict("2026-05-28T10:01:00Z", &["shortened_url"], "curl bit.ly/x"),
            // Two credential rules on one command → two items.
            verdict(
                "2026-05-28T10:02:00Z",
                &["high_entropy_secret", "private_key_exposed"],
                "ghp_redacted and a key",
            ),
        ];
        let items = triage_records(&records, 0);
        assert_eq!(items.len(), 3, "3 credential findings across 2 records");
        assert_eq!(items[0].rule_id, "credential_in_text");
        assert_eq!(items[0].provider.map(|p| p.provider), Some("aws"));
        assert_eq!(items[2].provider.map(|p| p.provider), Some("github"));
    }

    #[test]
    fn triage_skips_non_verdict_entries() {
        let mut tele = verdict("2026-05-28T10:00:00Z", &["credential_in_text"], "AKIA…");
        tele.entry_type = "hook_telemetry".to_string();
        assert!(triage_records(&[tele], 0).is_empty());
    }

    #[test]
    fn triage_recent_cap_keeps_the_tail() {
        let records: Vec<AuditRecord> = (0..5)
            .map(|i| {
                verdict(
                    &format!("2026-05-28T10:0{i}:00Z"),
                    &["credential_in_text"],
                    "AKIA…",
                )
            })
            .collect();
        let items = triage_records(&records, 2);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].timestamp, "2026-05-28T10:03:00Z");
        assert_eq!(items[1].timestamp, "2026-05-28T10:04:00Z");
    }

    #[test]
    fn canary_touch_is_a_credential_signal() {
        assert!(is_credential_rule("canary_token_touched"));
        let items = triage_records(
            &[verdict(
                "2026-05-28T10:00:00Z",
                &["canary_token_touched"],
                "cat decoy",
            )],
            0,
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].rule_id, "canary_token_touched");
    }

    #[test]
    fn canary_touch_is_not_attributed_to_a_third_party_provider() {
        // CodeRabbit R12 #E: even when the redacted text carries real provider
        // key-shapes, a touched canary must NOT attribute to a provider and its
        // next-step must point at canary investigation.
        let items = triage_records(
            &[verdict(
                "2026-05-28T10:00:00Z",
                &["canary_token_touched"],
                // Laden with provider shapes match_provider would otherwise hit.
                "cat ~/.aws/credentials # AKIA... ghp_xxx",
            )],
            0,
        );
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.rule_id, "canary_token_touched");
        assert!(
            item.provider.is_none(),
            "a canary touch must NOT be attributed to a provider, got {:?}",
            item.provider.map(|p| p.provider)
        );
        let step = item.next_step();
        assert!(
            step.contains("canary") && step.contains("bait"),
            "canary next-step must describe the bait investigation, got: {step}"
        );
        assert!(
            !step.to_ascii_lowercase().contains("rotate the aws")
                && !step.contains("rotate your")
                && !step.contains("secret rotate <provider>"),
            "canary next-step must NOT offer third-party-provider rotation, got: {step}"
        );

        // Contrast: a REAL credential rule with the same AWS shape IS attributed
        // to aws (the suppression is canary-specific, not a blanket disable).
        let real = triage_records(
            &[verdict(
                "2026-05-28T10:01:00Z",
                &["credential_in_text"],
                "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            )],
            0,
        );
        assert_eq!(real.len(), 1);
        assert_eq!(
            real[0].provider.map(|p| p.provider),
            Some("aws"),
            "a real credential finding with an AKIA shape must still attribute to aws"
        );
    }

    #[test]
    fn package_risk_findings_are_not_credential_exposure() {
        // CodeRabbit R5 #2: the `threat_*package*` reputation rules fire on a
        // package name, not a leaked credential, so they're out of triage scope.
        for rid in [
            "threat_malicious_package",
            "threat_package_typosquat",
            "threat_package_similar_name",
            "threat_suspicious_package",
        ] {
            assert!(
                !is_credential_rule(rid),
                "{rid} is a package-risk rule and must not be a credential-exposure signal"
            );
        }
        // A verdict carrying ONLY a package-risk rule yields NO triage item.
        let pkg = triage_records(
            &[verdict(
                "2026-05-28T10:00:00Z",
                &["threat_package_typosquat"],
                "npm install reqeusts",
            )],
            0,
        );
        assert!(
            pkg.is_empty(),
            "a package-risk finding must produce no rotation item, got {pkg:?}"
        );
        // A real credential finding in the SAME batch still produces one.
        let mixed = triage_records(
            &[
                verdict(
                    "2026-05-28T10:00:00Z",
                    &["threat_package_typosquat"],
                    "npm install reqeusts",
                ),
                verdict(
                    "2026-05-28T10:01:00Z",
                    &["credential_in_text"],
                    "export AWS_ACCESS_KEY_ID=AKIA…",
                ),
            ],
            0,
        );
        assert_eq!(
            mixed.len(),
            1,
            "only the real credential finding is triaged, got {mixed:?}"
        );
        assert_eq!(mixed[0].rule_id, "credential_in_text");
    }

    #[test]
    fn next_step_points_at_revocation_url_or_generic() {
        let with = TriageItem {
            rule_id: "credential_in_text".to_string(),
            timestamp: "t".to_string(),
            redacted: "AKIA…".to_string(),
            provider: lookup("aws"),
        };
        assert!(with.next_step().contains("console.aws.amazon.com"));

        let without = TriageItem {
            rule_id: "high_entropy_secret".to_string(),
            timestamp: "t".to_string(),
            redacted: "????".to_string(),
            provider: None,
        };
        let s = without.next_step();
        assert!(s.contains("tirith secret rotate <provider>"));
        assert!(s.contains("anthropic"));
    }
}
