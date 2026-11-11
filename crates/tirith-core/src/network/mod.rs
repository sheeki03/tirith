pub mod dns;
pub mod shorturl;

pub use dns::{
    check_dns_blocklist, check_dns_blocklist_with, DnsRequestBudget, DnsResolver, SystemDnsResolver,
};
pub use shorturl::resolve_shortened_url;

/// `true` when `TIRITH_OFFLINE` is set truthy (`1`/`true`/`yes`/`on`,
/// case-insensitive, trimmed). The one reading of the variable: the CLI's
/// offline switch and the audit-upload drain both route through it, so they
/// cannot disagree about what counts as offline.
pub fn offline_env_active() -> bool {
    std::env::var("TIRITH_OFFLINE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
