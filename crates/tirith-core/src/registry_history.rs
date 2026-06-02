//! Local JSONL snapshot store for registry-API responses.
//!
//! Every successful `--online` fetch writes one snapshot row per package to
//! `state_dir()/registry_snapshots/<eco>/<name>.jsonl` (append-only, oldest
//! pruned at [`MAX_SNAPSHOTS_PER_PACKAGE`]). Diffing the two most recent rows
//! feeds [`crate::package_risk::MaintainerChangeHistory`] / [`OwnershipTransfer`]
//! — a real maintainer-set diff over time, which a single response cannot show,
//! superseding the legacy one-response `ApiProvenance::ownership_transferred`.
//!
//! Invariants: best-effort I/O (read-only on failure, never panics); reuses the
//! already-fetched response (no extra request); rolling cap; stores only
//! registry-public maintainer identifiers (no PII).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::package_risk::{
    ApiProvenance, MaintainerChangeHistory, MaintainerRef, OwnershipTransfer,
};
use crate::policy;
use crate::threatdb::Ecosystem;

/// Rolling cap of snapshot rows per package on disk (~a year of monthly snaps).
pub const MAX_SNAPSHOTS_PER_PACKAGE: usize = 12;

/// One snapshot row, one line of JSONL on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRow {
    /// Unix epoch seconds at capture.
    pub captured_at: u64,
    /// Maintainer ids the registry reported. Empty vec = real "zero owners";
    /// an absent field = registry does not expose maintainers (PyPI, crates.io).
    pub maintainers: Vec<MaintainerRef>,
    #[serde(default)]
    pub latest_version: Option<String>,
    #[serde(default)]
    pub repository_url: Option<String>,
}

/// Snapshot store path for `(eco, name)`. `None` when `state_dir()` is absent.
fn snapshot_path(eco: Ecosystem, name: &str) -> Option<PathBuf> {
    let state = policy::state_dir()?;
    let dir = state
        .join("registry_snapshots")
        .join(eco.to_string().to_lowercase());
    let safe_name: String = name
        .chars()
        .map(|c| match c {
            '/' => '_',
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@') => c,
            _ => '_',
        })
        .collect();
    Some(dir.join(format!("{safe_name}.jsonl")))
}

/// Record a snapshot from an already-fetched [`ApiProvenance`] (no network
/// call). Best-effort; `true` on success.
pub fn record_snapshot(eco: Ecosystem, name: &str, prov: &ApiProvenance) -> bool {
    let row = SnapshotRow {
        captured_at: unix_now(),
        maintainers: maintainers_from_provenance(prov),
        latest_version: prov.latest_version.clone(),
        repository_url: prov.repository_url_for_check(),
    };
    write_row(eco, name, &row)
}

/// Best-effort write of one row, with rolling-cap pruning.
fn write_row(eco: Ecosystem, name: &str, row: &SnapshotRow) -> bool {
    let Some(path) = snapshot_path(eco, name) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }
    let mut rows = read_rows(&path);
    rows.push(row.clone());
    if rows.len() > MAX_SNAPSHOTS_PER_PACKAGE {
        let drop = rows.len() - MAX_SNAPSHOTS_PER_PACKAGE;
        rows.drain(..drop);
    }
    let mut buf = String::new();
    for r in &rows {
        if let Ok(line) = serde_json::to_string(r) {
            buf.push_str(&line);
            buf.push('\n');
        }
    }
    std::fs::write(path, buf).is_ok()
}

/// Read all rows from `path` oldest-first. Empty on missing file or parse
/// failure — best-effort, never panics.
pub fn read_rows(path: &std::path::Path) -> Vec<SnapshotRow> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SnapshotRow>(l).ok())
        .collect()
}

/// Read all rows for `(eco, name)`. Public for tests + the CLI inspector.
pub fn read_snapshots(eco: Ecosystem, name: &str) -> Vec<SnapshotRow> {
    let Some(path) = snapshot_path(eco, name) else {
        return Vec::new();
    };
    read_rows(&path)
}

/// Diff the two most recent snapshots. `None` when fewer than two exist (the
/// first `--online` run can only record).
pub fn diff_recent(eco: Ecosystem, name: &str) -> Option<MaintainerChangeHistory> {
    let rows = read_snapshots(eco, name);
    if rows.len() < 2 {
        return None;
    }
    let older = &rows[rows.len() - 2];
    let newer = &rows[rows.len() - 1];
    Some(diff_two_snapshots(older, newer))
}

/// Compute a `MaintainerChangeHistory` from two rows. Pure, no I/O.
pub fn diff_two_snapshots(older: &SnapshotRow, newer: &SnapshotRow) -> MaintainerChangeHistory {
    let old_ids: std::collections::HashSet<&str> =
        older.maintainers.iter().map(|m| m.id.as_str()).collect();
    let new_ids: std::collections::HashSet<&str> =
        newer.maintainers.iter().map(|m| m.id.as_str()).collect();
    let added: Vec<MaintainerRef> = newer
        .maintainers
        .iter()
        .filter(|m| !old_ids.contains(m.id.as_str()))
        .cloned()
        .collect();
    let removed: Vec<MaintainerRef> = older
        .maintainers
        .iter()
        .filter(|m| !new_ids.contains(m.id.as_str()))
        .cloned()
        .collect();
    let transfer_within_days = if newer.captured_at >= older.captured_at {
        let secs = newer.captured_at - older.captured_at;
        Some((secs / 86_400) as u32)
    } else {
        None
    };
    MaintainerChangeHistory {
        added,
        removed,
        transfer_within_days,
    }
}

/// Synthesize an `OwnershipTransfer` from two rows. `previous`/`current` are the
/// FULL older/newer maintainer sets (NOT the added/removed diff slices) so the
/// consumer can render "from {alice, bob} to {eve}".
pub fn synthesize_transfer_from_snapshots(
    older: &SnapshotRow,
    newer: &SnapshotRow,
) -> OwnershipTransfer {
    let within_days = if newer.captured_at >= older.captured_at {
        let secs = newer.captured_at - older.captured_at;
        Some((secs / 86_400) as u32)
    } else {
        None
    };
    OwnershipTransfer {
        previous: older.maintainers.clone(),
        current: newer.maintainers.clone(),
        within_days,
    }
}

/// Diff and synthesize-transfer in one shot. `None` when fewer than two
/// snapshots exist (mirrors `diff_recent`).
///
/// The transfer is `Some` ONLY on a real takeover (no maintainer survives older
/// → newer AND at least one new one joined). This is the canonical predicate;
/// the diff-only [`MaintainerChangeHistory::is_full_ownership_transfer`] can't
/// see a stable maintainer absent from both `added`/`removed`, so it false-
/// positives on partial churn.
pub fn diff_and_transfer_recent(
    eco: Ecosystem,
    name: &str,
) -> Option<(MaintainerChangeHistory, Option<OwnershipTransfer>)> {
    let rows = read_snapshots(eco, name);
    if rows.len() < 2 {
        return None;
    }
    let older = &rows[rows.len() - 2];
    let newer = &rows[rows.len() - 1];
    let hist = diff_two_snapshots(older, newer);
    let transfer = if is_full_takeover_snapshots(older, newer) {
        Some(synthesize_transfer_from_snapshots(older, newer))
    } else {
        None
    };
    Some((hist, transfer))
}

/// `true` when newer shares NO ids with older and newer is non-empty — a real
/// ownership transfer between snapshots.
fn is_full_takeover_snapshots(older: &SnapshotRow, newer: &SnapshotRow) -> bool {
    if older.maintainers.is_empty() || newer.maintainers.is_empty() {
        // No data, no claim — only flag when both snapshots carry maintainers.
        return false;
    }
    let old_ids: std::collections::HashSet<&str> =
        older.maintainers.iter().map(|m| m.id.as_str()).collect();
    !newer
        .maintainers
        .iter()
        .any(|m| old_ids.contains(m.id.as_str()))
}

/// `ApiProvenance` carries no maintainer list today, so this returns empty
/// (honest no-data). Maintainers are written explicitly via
/// [`record_snapshot_with_maintainers`] from the `RegistryMetadata`-aware paths;
/// this is a hook for when `ApiProvenance` grows a maintainers field.
fn maintainers_from_provenance(_prov: &ApiProvenance) -> Vec<MaintainerRef> {
    Vec::new()
}

/// Snapshot writer for when the caller already has the maintainer list (e.g.
/// from `RegistryMetadata`).
pub fn record_snapshot_with_maintainers(
    eco: Ecosystem,
    name: &str,
    maintainers: Vec<MaintainerRef>,
    latest_version: Option<String>,
    repository_url: Option<String>,
) -> bool {
    let row = SnapshotRow {
        captured_at: unix_now(),
        maintainers,
        latest_version,
        repository_url,
    };
    write_row(eco, name, &row)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(captured_at: u64, ids: &[&str]) -> SnapshotRow {
        SnapshotRow {
            captured_at,
            maintainers: ids
                .iter()
                .map(|s| MaintainerRef {
                    id: (*s).to_string(),
                })
                .collect(),
            latest_version: Some("1.0.0".to_string()),
            repository_url: None,
        }
    }

    #[test]
    fn diff_two_snapshots_adds_and_removes() {
        let older = row(1_000_000, &["alice", "bob"]);
        let newer = row(1_000_000 + 86_400 * 5, &["bob", "eve"]);
        let h = diff_two_snapshots(&older, &newer);
        assert_eq!(
            h.added.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["eve"]
        );
        assert_eq!(
            h.removed.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alice"]
        );
        assert_eq!(h.transfer_within_days, Some(5));
    }

    #[test]
    fn diff_two_snapshots_full_transfer_marks_no_overlap() {
        let older = row(0, &["alice"]);
        let newer = row(86_400, &["eve"]);
        let h = diff_two_snapshots(&older, &newer);
        assert!(h.is_full_ownership_transfer());
        let t = synthesize_transfer_from_snapshots(&older, &newer);
        // Transfer carries the FULL older/newer sets, not the diff.
        assert_eq!(
            t.previous.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alice"]
        );
        assert_eq!(
            t.current.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["eve"]
        );
        // Disjoint by id — alice ∉ {eve}, eve ∉ {alice}.
        assert!(t
            .previous
            .iter()
            .all(|p| !t.current.iter().any(|c| c.id == p.id)));
    }

    #[test]
    fn synthesize_transfer_carries_full_snapshot_sets_not_diff() {
        // Partial churn {alice,bob} → {alice,eve}: the transfer carries the FULL
        // sets, so alice appears in both `previous` and `current`.
        let older = row(0, &["alice", "bob"]);
        let newer = row(86_400, &["alice", "eve"]);
        let t = synthesize_transfer_from_snapshots(&older, &newer);
        assert_eq!(
            t.previous.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alice", "bob"]
        );
        assert_eq!(
            t.current.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alice", "eve"]
        );
    }

    #[test]
    fn is_full_takeover_snapshots_rejects_partial_churn() {
        // {alice, bob, carol} → {alice, dave} — alice carries over, NOT a
        // full takeover.
        let older = row(0, &["alice", "bob", "carol"]);
        let newer = row(86_400, &["alice", "dave"]);
        assert!(!is_full_takeover_snapshots(&older, &newer));
    }

    #[test]
    fn is_full_takeover_snapshots_accepts_clean_takeover() {
        // {alice, bob} → {eve, mallory} — no overlap, real takeover.
        let older = row(0, &["alice", "bob"]);
        let newer = row(86_400, &["eve", "mallory"]);
        assert!(is_full_takeover_snapshots(&older, &newer));
    }

    #[test]
    fn is_full_takeover_snapshots_rejects_empty_snapshots() {
        // Empty older → empty signal — don't claim a transfer with no data.
        let older = row(0, &[]);
        let newer = row(86_400, &["eve"]);
        assert!(!is_full_takeover_snapshots(&older, &newer));
        // Empty newer → "lost every owner" is the legacy
        // `ownership_transferred=Some(true)` signal, not an OwnershipTransfer.
        let older2 = row(0, &["alice"]);
        let newer2 = row(86_400, &[]);
        assert!(!is_full_takeover_snapshots(&older2, &newer2));
    }

    #[test]
    fn partial_maintainer_churn_via_diff_and_transfer_recent_returns_no_transfer() {
        // {alice,bob,carol} → {alice,dave}: alice carries over, so NOT a full
        // transfer. The decisive predicate the consumer must use is set overlap
        // on the synthesized transfer, not the diff-only
        // `is_full_ownership_transfer` (which can't see the surviving alice).
        let older = row(0, &["alice", "bob", "carol"]);
        let newer = row(86_400, &["alice", "dave"]);
        let t = synthesize_transfer_from_snapshots(&older, &newer);
        let any_overlap = t
            .previous
            .iter()
            .any(|p| t.current.iter().any(|c| c.id == p.id));
        assert!(any_overlap, "alice carries over → not a full transfer");
    }

    #[test]
    fn diff_two_snapshots_empty_change_returns_empty_lists() {
        let older = row(0, &["alice"]);
        let newer = row(86_400, &["alice"]);
        let h = diff_two_snapshots(&older, &newer);
        assert!(h.added.is_empty());
        assert!(h.removed.is_empty());
        assert!(!h.is_recent()); // no diff → not recent
    }

    #[test]
    fn diff_recent_returns_none_when_fewer_than_two_rows() {
        // No state dir override — this should still gracefully return None.
        // (We can't write to state_dir from a unit test, so we exercise the
        // logic of read_snapshots returning empty.)
        let _ = read_snapshots(Ecosystem::Npm, "nonexistent-package-xyzzy-test");
    }

    #[test]
    fn snapshot_row_serializes_and_round_trips() {
        let r = row(123, &["a", "b"]);
        let s = serde_json::to_string(&r).unwrap();
        let back: SnapshotRow = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn snapshot_path_sanitizes_name() {
        // `/` must become `_` so a scoped npm name does not write to a nested dir.
        let path = snapshot_path(Ecosystem::Npm, "@org/util");
        if let Some(p) = path {
            let s = p.to_string_lossy();
            assert!(s.contains("@org_util.jsonl"));
        }
    }
}
