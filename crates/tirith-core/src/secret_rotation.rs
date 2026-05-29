//! M11 ch4 — secret-rotation ASSISTANT (guidance only).
//!
//! This module is a **presenter over existing audit data plus a static provider
//! table**. It tells the user *where* and *how* to rotate a leaked credential —
//! it does NOT rotate or revoke anything, and it makes **zero network calls**.
//! There is no HTTP client constructed anywhere in this module or in
//! [`crate::cli::secret`] (the CLI front-end); the only "URLs" here are inert
//! string literals printed for the human to open in their own browser.
//!
//! # Honesty contract
//!
//! tirith does NOT perform rotation or revocation. It shows you the provider's
//! revocation page and a manual checklist; **you** do the rotation. This is
//! stated loudly in `--help` and in the command output (see
//! [`HONESTY_BANNER`]).
//!
//! # No new RuleIds
//!
//! `tirith secret triage` reads RECENT credential-type findings already recorded
//! in the local audit log (written by the engine's existing rules — see
//! [`CREDENTIAL_RULE_IDS`]) and, for each, matches the finding against a
//! provider in [`PROVIDERS`] to print a one-line next-step. No detection logic,
//! no new [`crate::verdict::RuleId`] — the rules that produced those findings
//! already exist.
//!
//! # Guidance staleness
//!
//! Provider revocation URLs and checklists drift over time. Every [`Provider`]
//! entry carries a [`Provider::last_verified`] date (surfaced under `--verbose`)
//! so a stale entry is visible rather than silently trusted.

/// The date every provider entry in [`PROVIDERS`] was last hand-verified.
/// Surfaced under `tirith secret rotate <p> --verbose`. Bump this (and
/// re-check each URL) whenever the table is revised.
pub const LAST_VERIFIED: &str = "2026-05-28";

/// The loud honesty banner. tirith is an assistant, not an actor: it never
/// rotates or revokes a credential — it shows the user where and how, and the
/// user does the rotation. Printed by every `tirith secret` subcommand and
/// echoed in `--help`.
pub const HONESTY_BANNER: &str =
    "tirith does NOT perform rotation or revocation; it shows you where and how. You do the rotation.";

/// The credential-EXPOSURE audit rule IDs `tirith secret triage` scans for, as
/// the `snake_case` strings they serialize to in the audit log's `rule_ids`
/// array (serde `rename_all = "snake_case"` on [`crate::verdict::RuleId`]).
///
/// SCOPE: only rules that signal an ACTUAL leaked / exposed secret — for which
/// "rotate this credential" is the correct playbook. That is the three direct
/// credential rules (`credential_in_text`, `high_entropy_secret`,
/// `private_key_exposed`) plus the M11 ch3 `canary_token_touched` rule (a touched
/// bait token IS a planted secret being read — a strong "rotate now" signal).
///
/// Deliberately EXCLUDES the `threat_*package*` reputation rules (malicious /
/// typosquat / similar-name / suspicious package). Those fire on a package's
/// NAME / reputation, not on a leaked credential — emitting a "rotate this
/// credential" next-step for them would be the wrong playbook (there is no secret
/// to rotate).
pub const CREDENTIAL_RULE_IDS: &[&str] = &[
    "credential_in_text",
    "high_entropy_secret",
    "private_key_exposed",
    "canary_token_touched",
];

/// `true` when `rule_id` is one of the credential-type rules
/// [`tirith secret triage`](crate::cli) acts on.
pub fn is_credential_rule(rule_id: &str) -> bool {
    CREDENTIAL_RULE_IDS.contains(&rule_id)
}

/// A single provider's rotation guidance. Pure data — no behavior, no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The canonical CLI token (`aws`, `github`, …). Lowercase, no spaces.
    pub provider: &'static str,
    /// The page where the user revokes / regenerates the credential. Printed
    /// for the user to open themselves — tirith never fetches it.
    pub revocation_url: &'static str,
    /// The provider's authoritative rotation / key-management documentation.
    pub doc_url: &'static str,
    /// Step-by-step manual checklist the user performs. tirith performs NONE of
    /// these — it only prints them.
    pub manual_checklist: &'static [&'static str],
    /// Literal key-prefix / shape fragments used by `triage` to attribute a
    /// leaked-secret finding to this provider (substring match against the
    /// redacted finding text). Best-effort: a redacted finding may not retain
    /// enough of the prefix to match, in which case triage falls back to
    /// generic guidance.
    pub key_prefix_shapes: &'static [&'static str],
    /// The date this entry was last hand-verified (see [`LAST_VERIFIED`]).
    pub last_verified: &'static str,
}

/// The 11-provider rotation table. Order is the canonical display order used by
/// `tirith secret rotate <bogus>` when listing valid providers.
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
        key_prefix_shapes: &["AKIA", "ASIA", "aws_access_key_id", "aws_secret_access_key"],
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
        key_prefix_shapes: &["npm_", "//registry.npmjs.org/:_authToken"],
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
        // NB: crates.io tokens are `cio…`, but the bare 3-char substring "cio"
        // false-matches common words ("suspicious", "precious", …) and would
        // mis-route an unrelated leak to crates.io. Match cargo only via the
        // explicit `cargo-registry-token` config key — no short-prefix shape.
        key_prefix_shapes: &["cargo-registry-token"],
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
        // Env-var NAME marker (CodeRabbit R9 #I): a redacted audit record masks the
        // `sk-…` value (`OPENAI_API_KEY=[REDACTED]` / `[REDACTED:OpenAI API Key]`),
        // so the `sk-` shape is gone post-mask — but the var name survives and is
        // enough to attribute. Mirrors aws's `aws_secret_access_key` marker.
        key_prefix_shapes: &["sk-proj-", "sk-svcacct-", "sk-", "OPENAI_API_KEY"],
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
        // Env-var NAME marker (CodeRabbit R9 #I): same rationale as openai — the
        // masked record keeps `ANTHROPIC_API_KEY` even after the `sk-ant-…` value
        // is redacted. `ANTHROPIC_API_KEY` (17 bytes) is longer than openai's
        // `OPENAI_API_KEY` (14) and shares no substring, so the longest-match
        // tie-break still routes each var name to the right provider.
        key_prefix_shapes: &["sk-ant-api", "sk-ant-", "ANTHROPIC_API_KEY"],
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
        // NOTE: the generic `-----BEGIN PRIVATE KEY-----` PEM header is
        // deliberately NOT listed here. It is not GCP-specific (any RSA/EC
        // service key, SSH key, or unrelated PEM uses it) and would misroute
        // every bare private key to GCP. We keep only GCP-distinctive shapes:
        // the `AIza` API-key prefix and the service-account JSON `type` field.
        //
        // BOTH the spaced and MINIFIED `type` shapes are listed (CodeRabbit R11
        // #8): a service-account key file is commonly stored minified (no spaces
        // after the colon), and the substring scan is literal on spacing — without
        // the minified form a `{"type":"service_account",...}` record would not
        // attribute. (Case is already handled — `match_provider` lowercases both
        // sides.) The minified shape is longer, so when both match it wins the
        // longest-match tie-break, still routing to gcp.
        key_prefix_shapes: &[
            "AIza",
            "\"type\": \"service_account\"",
            "\"type\":\"service_account\"",
        ],
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
        last_verified: LAST_VERIFIED,
    },
];

/// Look up a provider by its canonical token (case-insensitive, trimmed).
/// Returns `None` for an unknown provider so the CLI can print the valid list.
pub fn lookup(provider: &str) -> Option<&'static Provider> {
    let needle = provider.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.provider == needle)
}

/// The canonical list of valid provider tokens, in display order. Used by the
/// CLI's "unknown provider" error and `--help`.
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.provider).collect()
}

/// Attribute a leaked-secret `finding_text` (typically the redacted command
/// from an audit record) to a provider by substring-matching the provider's
/// [`Provider::key_prefix_shapes`]. Returns the provider owning the LONGEST
/// matching shape; ties (same shape length) are broken by [`PROVIDERS`] order.
/// `None` when no shape matches (the caller then prints generic guidance).
///
/// **Longest-match, not first-match.** Several providers share an `sk-` family
/// prefix (OpenAI `sk-`, Anthropic `sk-ant-…`, Stripe `sk_live_…`). A naive
/// first-provider scan would mis-route an Anthropic `sk-ant-api03-…` key to
/// OpenAI because `sk-` matches first. Preferring the longest shape means the
/// more specific `sk-ant-api` wins, so a key is routed to the right provider.
///
/// This is intentionally a cheap substring scan, not a parser: redacted audit
/// text often keeps a credential's leading prefix (`AKIA…`, `ghp_…`) even after
/// the body is masked, which is enough to route the user to the right provider.
pub fn match_provider(finding_text: &str) -> Option<&'static Provider> {
    // Case-insensitive: redacted audit text may upper/lower-case an env-var name
    // (`AWS_SECRET_ACCESS_KEY=` vs the table's `aws_secret_access_key`), so we
    // lowercase BOTH the haystack and each shape before comparing. The
    // longest-match (then table-order) tie-break is preserved — lengths are
    // unchanged by ASCII-lowercasing, so `sk-ant-api` still beats `sk-`.
    let haystack = finding_text.to_ascii_lowercase();
    PROVIDERS
        .iter()
        .filter_map(|p| {
            p.key_prefix_shapes
                .iter()
                .filter(|shape| haystack.contains(&shape.to_ascii_lowercase()))
                .map(|shape| shape.len())
                .max()
                .map(|best| (p, best))
        })
        // `max_by_key` returns the LAST maximal element; iterating in reverse
        // makes that the FIRST provider in table order among equal-length ties.
        .rev()
        .max_by_key(|(_, len)| *len)
        .map(|(p, _)| p)
}

/// One triage line: a credential finding paired with its (optional) attributed
/// provider and the redacted text that produced it. Pure value — the CLI turns
/// this into a one-line next-step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageItem {
    /// The audit `rule_id` that fired (e.g. `credential_in_text`).
    pub rule_id: String,
    /// The record's RFC-3339 timestamp, for ordering / display.
    pub timestamp: String,
    /// The redacted command text from the audit record (already redacted by the
    /// engine at write time — triage never sees raw secrets).
    pub redacted: String,
    /// The provider this finding was attributed to, if any shape matched.
    pub provider: Option<&'static Provider>,
}

impl TriageItem {
    /// The one-line next-step shown by `tirith secret triage`. When a provider
    /// was attributed, points at its revocation URL; otherwise gives generic
    /// guidance (the user names the provider for `tirith secret rotate <p>`).
    pub fn next_step(&self) -> String {
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

/// Build the triage list from already-loaded audit records.
///
/// Pure and I/O-free so it is unit-testable without touching the filesystem:
/// the CLI is responsible for reading the audit log (via
/// [`crate::audit::audit_log_path`] + [`crate::audit_aggregator::read_log`])
/// and handing the records here.
///
/// * Keeps only `verdict` entries whose `rule_ids` include at least one
///   credential-type rule (see [`CREDENTIAL_RULE_IDS`]).
/// * Emits one [`TriageItem`] per matching `(record, credential-rule)` pair, so
///   a single command that tripped two credential rules yields two lines.
/// * `recent` caps the result to the most recent N items (by input order —
///   callers pass records newest-last or sort beforehand). `0` means no cap.
pub fn triage_records(
    records: &[crate::audit_aggregator::AuditRecord],
    recent: usize,
) -> Vec<TriageItem> {
    let mut items: Vec<TriageItem> = Vec::new();
    for r in records {
        // Only verdict entries carry credential rule_ids; telemetry / trust
        // entries are skipped (empty entry_type is a legacy "verdict").
        if !(r.entry_type.is_empty() || r.entry_type == "verdict") {
            continue;
        }
        for rid in &r.rule_ids {
            if is_credential_rule(rid) {
                items.push(TriageItem {
                    rule_id: rid.clone(),
                    timestamp: r.timestamp.clone(),
                    redacted: r.command_redacted.clone(),
                    provider: match_provider(&r.command_redacted),
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
                !p.key_prefix_shapes.is_empty(),
                "{}: needs at least one triage shape",
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
        // CodeRabbit R9 #I: triage matches the POST-mask `command_redacted`. Once
        // the engine masks the value, the `sk-…` shape is gone — but the env-var
        // NAME survives and must still attribute. (Mirrors aws's
        // `aws_secret_access_key` marker.)
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
    fn triage_attributes_masked_openai_env_record() {
        // End-to-end through `triage_records`: a verdict record whose
        // `command_redacted` is a MASKED `OPENAI_API_KEY=…` assignment triages to
        // openai (the rotation next-step points at OpenAI's revocation URL).
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
        // F4 (Minor): the generic PEM private-key header is not GCP-specific and
        // must NOT misroute an unrelated private key to gcp.
        //
        // CodeRabbit R7 #8: assemble the `-----BEGIN ... PRIVATE KEY-----` header
        // from fragments at runtime so a contiguous private-key header LITERAL is
        // not committed (it trips private-key scanners). The reconstructed string
        // is byte-identical to the header `match_provider` sees in real input.
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
        // CodeRabbit R11 #8: a MINIFIED service-account record (no spaces after
        // the colon — the common on-disk shape) must attribute to gcp. The substr
        // scan is literal on spacing, so the minified shape has to be listed too.
        assert_eq!(
            match_provider("{\"type\":\"service_account\",\"project_id\":\"x\"}")
                .map(|p| p.provider),
            Some("gcp"),
            "a minified service-account JSON must attribute to gcp"
        );
        // Case-insensitive too (redacted text may alter case).
        assert_eq!(
            match_provider("{\"TYPE\":\"SERVICE_ACCOUNT\"}").map(|p| p.provider),
            Some("gcp")
        );
    }

    #[test]
    fn match_provider_is_case_insensitive() {
        // F5 (Minor): redacted audit text may upper-case an env-var name. An
        // UPPERCASE `AWS_SECRET_ACCESS_KEY=` must still attribute to aws.
        assert_eq!(
            match_provider("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIexample").map(|p| p.provider),
            Some("aws"),
            "uppercase AWS_SECRET_ACCESS_KEY must route to aws"
        );
        // Mixed case of a shorter shape also matches.
        assert_eq!(
            match_provider("NPM_TOKEN env: npm_AbCdEf").map(|p| p.provider),
            Some("npm")
        );
        // Case-insensitivity must NOT broaden the longest-match tie-break: an
        // uppercase Anthropic key still beats OpenAI's `sk-`.
        assert_eq!(
            match_provider("ANTHROPIC_API_KEY=SK-ANT-API03-REDACTED").map(|p| p.provider),
            Some("anthropic"),
            "uppercased sk-ant-api must still win over sk-"
        );
    }

    #[test]
    fn match_provider_equal_length_tie_breaks_to_earlier_table_entry() {
        // The longest-match rule documents that an EQUAL-byte-length shape tie
        // resolves to the FIRST provider in PROVIDERS order. Pin an actual tie:
        // aws's `AKIA` and github's `ghp_` are BOTH 4 bytes, and aws precedes
        // github in the table, so an input matching both must route to aws.
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

        // Input contains both 4-byte shapes; neither provider has a LONGER shape
        // matching here, so the best length is 4 for both — a genuine tie.
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
        // Regression (code-reviewer #1): the dropped 3-char "cio" shape matched
        // inside common words. A benign command containing "suspicious" /
        // "precious" must NOT route to cargo (crates.io).
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
    fn benign_non_credential_command_yields_no_provider() {
        // pr-test-analyzer #9: a benign command that merely mentions a
        // credential-shaped WORD (not an actual token) must not attribute a
        // provider — no false triage routing.
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
    fn package_risk_findings_are_not_credential_exposure() {
        // CodeRabbit R5 #2: the `threat_*package*` reputation rules fire on a
        // package NAME / reputation, NOT on a leaked credential. They must be
        // OUT of the triage (credential-rotation) scope — "rotate this
        // credential" is the wrong playbook when there is no secret to rotate.
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
