use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;

/// Whether we have already logged a poison recovery (log once, not every call).
static POISON_LOGGED: AtomicBool = AtomicBool::new(false);

/// Acquire the DB mutex and recover from poison (prior panic) to keep serving requests.
fn acquire_db(lock: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            if !POISON_LOGGED.swap(true, Ordering::Relaxed) {
                tracing::error!("DB mutex poisoned by prior panic; recovering with inner state");
            }
            poisoned.into_inner()
        }
    }
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id     TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    processed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id             TEXT PRIMARY KEY,
    customer_id    TEXT NOT NULL DEFAULT 'unknown',
    email          TEXT NOT NULL DEFAULT 'unknown',
    tier           TEXT NOT NULL DEFAULT 'unknown',
    status         TEXT NOT NULL DEFAULT 'active',
    product_id     TEXT NOT NULL DEFAULT 'unknown',
    last_event_at  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
    token           TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash        TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL UNIQUE REFERENCES subscriptions(id),
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_receipts (
    receipt_secret  TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
    api_key_enc     BLOB NOT NULL,
    api_key_nonce   BLOB NOT NULL,
    token           TEXT,
    checkout_id     TEXT NOT NULL UNIQUE,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dead_letter (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    subscription_id TEXT,
    event_type      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    occurred_at     TEXT,
    payload         TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_receipts_checkout ON pending_receipts(checkout_id);
CREATE INDEX IF NOT EXISTS idx_receipts_expires ON pending_receipts(expires_at);
CREATE INDEX IF NOT EXISTS idx_sub_customer ON subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS idx_tokens_sub ON tokens(subscription_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_sub ON api_keys(subscription_id);
"#;

/// repo-0445: `last_event_at` participates in SQLite `MAX()` over TEXT, which
/// only matches chronological order when every value shares one fixed-width
/// UTC encoding. Normalize RFC3339 inputs (any offset/fraction) to
/// `...T..:..:.. .mmmZ`; unparseable values pass through unchanged (the stale
/// guards treat them conservatively).
fn normalize_event_ts(raw: Option<&str>) -> Option<String> {
    raw.map(|value| {
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|ts| {
                ts.to_utc()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            })
            .unwrap_or_else(|_| value.to_string())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventTimestampError {
    Missing,
    InvalidIncoming,
    InvalidStored,
    Stale,
}

/// Validate an event timestamp and compare it to the row version observed in
/// the same transaction. A missing or unparseable timestamp is never allowed to
/// carry a lifecycle side effect, and an unparseable legacy row fails closed
/// until it is repaired deliberately.
fn ordered_event_timestamp(
    incoming: Option<&str>,
    previous: Option<&str>,
) -> Result<String, EventTimestampError> {
    let incoming = incoming.ok_or(EventTimestampError::Missing)?;
    let incoming = chrono::DateTime::parse_from_rfc3339(incoming)
        .map_err(|_| EventTimestampError::InvalidIncoming)?;
    if let Some(previous) = previous {
        let previous = chrono::DateTime::parse_from_rfc3339(previous)
            .map_err(|_| EventTimestampError::InvalidStored)?;
        if incoming < previous {
            return Err(EventTimestampError::Stale);
        }
    }
    Ok(incoming
        .to_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

impl Db {
    pub fn open(path: &str) -> Result<Self, AppError> {
        let conn =
            Connection::open(path).map_err(|e| AppError::Internal(format!("db open: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| AppError::Internal(format!("db schema: {e}")))?;
        Self::migrate(&conn)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run schema migrations. Safe to call repeatedly — each migration is
    /// guarded by column-existence checks.
    fn migrate(conn: &Connection) -> Result<(), AppError> {
        // Rename the legacy `price_id` column to `product_id` when the old
        // column exists but the new one does not.
        let has_price_id = conn
            .prepare("SELECT price_id FROM subscriptions LIMIT 0")
            .is_ok();
        let has_product_id = conn
            .prepare("SELECT product_id FROM subscriptions LIMIT 0")
            .is_ok();

        if has_price_id && !has_product_id {
            conn.execute_batch("ALTER TABLE subscriptions RENAME COLUMN price_id TO product_id")
                .map_err(|e| AppError::Internal(format!("migration price_id→product_id: {e}")))?;
        }

        Ok(())
    }

    pub fn open_readonly(path: &str) -> Result<Connection, AppError> {
        Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| AppError::Internal(format!("db open readonly: {e}")))
    }

    pub async fn event_exists(&self, event_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let eid = event_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM webhook_events WHERE event_id=?1",
                    params![eid],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db idempotency check: {e}")))?
                .unwrap_or(false);
            Ok(exists)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// First-time provision path (triggered by `order.paid` or the first
    /// `subscription.active`).
    pub async fn process_subscription_created(
        &self,
        data: CreatedData,
    ) -> Result<CreatedOutcome, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM webhook_events WHERE event_id=?1",
                    params![data.event_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db idem: {e}")))?
                .unwrap_or(false);
            if exists {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(CreatedOutcome::Duplicate);
            }

            // Reconcile status to 'active' unless the row is already
            // terminal ('revoked'). The CASE preserves 'revoked' so the
            // guard below can detect it.
            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, product_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   -- repo-0444: a reordered `created` must not flip a
                   -- payment-failed ('past_due') or terminal ('revoked') row
                   -- back to 'active'; a user-canceled row still reconciles.
                   status=CASE WHEN subscriptions.status IN ('revoked','past_due') THEN subscriptions.status ELSE 'active' END,
                   email=excluded.email, product_id=excluded.product_id, tier=excluded.tier,
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), excluded.last_event_at),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id,
                    data.email,
                    data.tier,
                    data.product_id,
                    normalize_event_ts(data.occurred_at.as_deref()),
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert sub: {e}")))?;

            // Re-read status — may still be 'revoked' if the row pre-existed.
            let status: String = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("db read status: {e}")))?;

            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                params![data.event_id, data.event_type],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            // 'revoked' is absorbing — never provision on top of it.
            if status == "revoked" {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(CreatedOutcome::SkippedRevoked);
            }

            let key_exists: bool = tx
                .query_row(
                    "SELECT 1 FROM api_keys WHERE subscription_id=?1",
                    params![data.subscription_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db key check: {e}")))?
                .unwrap_or(false);

            if key_exists {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(CreatedOutcome::AlreadyProvisioned);
            }

            // past_due starts with the key flagged as revoked — partial
            // provision.
            let revoked = if status == "past_due" { 1 } else { 0 };

            tx.execute(
                "INSERT INTO api_keys (key_hash, subscription_id, revoked) VALUES (?1, ?2, ?3)",
                params![data.key_hash, data.subscription_id, revoked],
            )
            .map_err(|e| AppError::Internal(format!("db insert key: {e}")))?;

            // Tokens are only issued on full (non-past_due) provisioning.
            if revoked == 0 {
                if let Some(ref token) = data.token {
                    tx.execute(
                        "INSERT INTO tokens (subscription_id, token, expires_at) VALUES (?1, ?2, ?3)",
                        params![data.subscription_id, token, data.token_expires_at],
                    )
                    .map_err(|e| AppError::Internal(format!("db insert token: {e}")))?;
                }
            }

            // A pending_receipts row is the one-time browser-delivery vehicle,
            // looked up by checkout_id at /receipt/lookup. Only create it when
            // we have a real checkout_id. For checkout-less subscriptions
            // (checkout_id is None) there is no browser checkout redirect to
            // deliver through, and a row keyed by a guessable placeholder (the
            // old "unknown" value) would be raceable via
            // /receipt/lookup?checkout=unknown. The key/token/subscription are
            // still provisioned above; out-of-band subscribers use the API key
            // with `tirith license refresh`.
            if let Some(ref checkout_id) = data.checkout_id {
                tx.execute(
                    "INSERT INTO pending_receipts (receipt_secret, subscription_id, api_key_enc, api_key_nonce, token, checkout_id, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now', '+1 hour'))",
                    params![
                        data.receipt_secret,
                        data.subscription_id,
                        data.api_key_enc,
                        data.api_key_nonce,
                        if revoked == 0 { data.token.as_deref() } else { None },
                        checkout_id,
                    ],
                )
                .map_err(|e| AppError::Internal(format!("db insert receipt: {e}")))?;
            }

            tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
            if revoked == 1 {
                Ok(CreatedOutcome::PartialProvisioned)
            } else {
                Ok(CreatedOutcome::Provisioned)
            }
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// `subscription.canceled`: benefits continue until period end; the API
    /// key is NOT revoked.
    pub async fn process_subscription_canceled(
        &self,
        data: CanceledData,
    ) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM webhook_events WHERE event_id=?1",
                    params![data.event_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db idem: {e}")))?
                .unwrap_or(false);
            if exists {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(false);
            }

            // 'revoked' absorbs canceled.
            let prev_status: Option<String> = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read prev: {e}")))?;

            if prev_status.as_deref() == Some("revoked") {
                tx.execute(
                    "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.canceled')",
                    params![data.event_id],
                )
                .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(false);
            }

            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, product_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'canceled', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   status='canceled',
                   customer_id=COALESCE(NULLIF(excluded.customer_id,'unknown'), subscriptions.customer_id),
                   email=COALESCE(NULLIF(excluded.email,'unknown'), subscriptions.email),
                   tier=COALESCE(NULLIF(excluded.tier,'unknown'), subscriptions.tier),
                   product_id=COALESCE(NULLIF(excluded.product_id,'unknown'), subscriptions.product_id),
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), COALESCE(excluded.last_event_at,'')),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id.as_deref().unwrap_or("unknown"),
                    data.email.as_deref().unwrap_or("unknown"),
                    data.tier.as_deref().unwrap_or("unknown"),
                    data.product_id.as_deref().unwrap_or("unknown"),
                    normalize_event_ts(data.occurred_at.as_deref()),
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert canceled: {e}")))?;

            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.canceled')",
                params![data.event_id],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
            Ok(true)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// `subscription.revoked`: terminal state, revokes the API key.
    pub async fn process_subscription_revoked(&self, data: RevokedData) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM webhook_events WHERE event_id=?1",
                    params![data.event_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db idem: {e}")))?
                .unwrap_or(false);
            if exists {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(false);
            }

            let previous_event_at: Option<String> = tx
                .query_row(
                    "SELECT last_event_at FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read revoked order: {e}")))?
                .flatten();
            let occurred_at = match ordered_event_timestamp(
                data.occurred_at.as_deref(),
                previous_event_at.as_deref(),
            ) {
                Ok(occurred_at) => occurred_at,
                Err(reason) => {
                    tracing::warn!(
                        event_id = %data.event_id,
                        ?reason,
                        "subscription.revoked did not carry a provably newer timestamp; state unchanged"
                    );
                    // `Stale` is an ordinary non-advance: the stored state is
                    // already at or past this event, so declining it is right.
                    // The other variants mean the event could not be ordered at
                    // all, and marking it processed below is what makes that
                    // terminal — the handler answers 200, Polar never
                    // redelivers, and the subscription stays active with its API
                    // key unrevoked. Revocation is the one action where silently
                    // declining keeps paid access open, so record those for the
                    // dead-letter retry tooling instead of only warning.
                    if !matches!(reason, EventTimestampError::Stale) {
                        tx.execute(
                            "INSERT OR IGNORE INTO dead_letter \
                             (event_id, subscription_id, event_type, reason, occurred_at, payload) \
                             VALUES (?1, ?2, 'subscription.revoked', ?3, ?4, ?5)",
                            params![
                                data.event_id,
                                data.subscription_id,
                                format!("unorderable revoked timestamp: {reason:?}"),
                                data.occurred_at,
                                serde_json::json!({
                                    "subscription_id": data.subscription_id,
                                    "customer_id": data.customer_id,
                                    "email": data.email,
                                    "tier": data.tier,
                                    "product_id": data.product_id,
                                    "occurred_at": data.occurred_at,
                                })
                                .to_string(),
                            ],
                        )
                        .map_err(|e| {
                            AppError::Internal(format!("db dead-letter revoked: {e}"))
                        })?;
                    }
                    tx.execute(
                        "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.revoked')",
                        params![data.event_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db mark rejected revoked: {e}")))?;
                    tx.commit()
                        .map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                    return Ok(false);
                }
            };

            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, product_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'revoked', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   status='revoked',
                   customer_id=COALESCE(NULLIF(excluded.customer_id,'unknown'), subscriptions.customer_id),
                   email=COALESCE(NULLIF(excluded.email,'unknown'), subscriptions.email),
                   tier=COALESCE(NULLIF(excluded.tier,'unknown'), subscriptions.tier),
                   product_id=COALESCE(NULLIF(excluded.product_id,'unknown'), subscriptions.product_id),
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), COALESCE(excluded.last_event_at,'')),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id.as_deref().unwrap_or("unknown"),
                    data.email.as_deref().unwrap_or("unknown"),
                    data.tier.as_deref().unwrap_or("unknown"),
                    data.product_id.as_deref().unwrap_or("unknown"),
                    occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert revoked: {e}")))?;

            tx.execute(
                "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                params![data.subscription_id],
            )
            .map_err(|e| AppError::Internal(format!("db revoke key: {e}")))?;

            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.revoked')",
                params![data.event_id],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
            Ok(true)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn has_api_key(&self, subscription_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let sid = subscription_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM api_keys WHERE subscription_id=?1",
                    params![sid],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db key exists check: {e}")))?
                .unwrap_or(false);
            Ok(exists)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// `subscription.updated`: status transitions with a terminal guard so
    /// a prior `revoked` row absorbs later state changes.
    pub async fn process_subscription_updated(
        &self,
        data: UpdatedData,
    ) -> Result<UpdatedOutcome, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM webhook_events WHERE event_id=?1",
                    params![data.event_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db idem: {e}")))?
                .unwrap_or(false);
            if exists {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(UpdatedOutcome::Duplicate);
            }

            // Read previous status AND last_event_at BEFORE any writes so the
            // terminal and ordering guards below can compare against the real
            // prior state.
            let prev_row: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT status, last_event_at FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read prev: {e}")))?;
            let prev_status = prev_row.as_ref().map(|(s, _)| s.as_str());
            let prev_last_event_at = prev_row.as_ref().and_then(|(_, t)| t.as_deref());

            // Missing, malformed, and stale timestamps are all non-advances.
            // This check runs before the terminal-state branch so every update
            // has one ordering contract, including events targeting a revoked
            // row and `revoked` updates routed through this generic seam.
            let occurred_at = match ordered_event_timestamp(
                data.occurred_at.as_deref(),
                prev_last_event_at,
            ) {
                Ok(occurred_at) => occurred_at,
                Err(reason) => {
                    tracing::warn!(
                        event_id = %data.event_id,
                        ?reason,
                        "subscription update did not carry a provably newer timestamp; state unchanged"
                    );
                    tx.execute(
                        "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                        params![data.event_id, data.event_type],
                    )
                    .map_err(|e| AppError::Internal(format!("db mark rejected update: {e}")))?;
                    tx.commit()
                        .map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                    return Ok(UpdatedOutcome::StaleIgnored);
                }
            };

            // revoked absorbs every non-revoked transition.
            if prev_status == Some("revoked") && data.new_status != "revoked" {
                tx.execute(
                    "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                    params![data.event_id, data.event_type],
                )
                .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(UpdatedOutcome::TerminalIgnored);
            }

            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, product_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                   status=excluded.status,
                   customer_id=COALESCE(NULLIF(excluded.customer_id,'unknown'), subscriptions.customer_id),
                   email=COALESCE(NULLIF(excluded.email,'unknown'), subscriptions.email),
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), COALESCE(excluded.last_event_at,'')),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id.as_deref().unwrap_or("unknown"),
                    data.email.as_deref().unwrap_or("unknown"),
                    data.tier.as_deref().unwrap_or("unknown"),
                    data.new_status,
                    data.product_id.as_deref().unwrap_or("unknown"),
                    occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert updated: {e}")))?;

            if let Some(ref tier) = data.resolved_tier {
                if let Some(ref product_id) = data.product_id {
                    tx.execute(
                        "UPDATE subscriptions SET tier=?1, product_id=?2 WHERE id=?3",
                        params![tier, product_id, data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db update tier: {e}")))?;
                }
            } else if data.tier_unknown {
                tx.execute(
                    "UPDATE subscriptions SET tier='unknown' WHERE id=?1",
                    params![data.subscription_id],
                )
                .map_err(|e| AppError::Internal(format!("db set unknown tier: {e}")))?;
            }

            // Side effects by status. The earlier terminal guard means
            // `prev_status == revoked` never reaches this match, so any
            // remaining prev_status (past_due / canceled / active / None)
            // is safe to un-revoke when transitioning to active.
            let outcome = match data.new_status.as_str() {
                "active" => {
                    let rows = tx
                        .execute(
                            "UPDATE api_keys SET revoked=0 WHERE subscription_id=?1",
                            params![data.subscription_id],
                        )
                        .map_err(|e| AppError::Internal(format!("db unrevoke: {e}")))?;
                    if rows == 0 {
                        UpdatedOutcome::ActiveNoKey
                    } else {
                        UpdatedOutcome::Unrevoked
                    }
                }
                "canceled" => {
                    // Benefits continue until period end, so the key is
                    // left as-is.
                    UpdatedOutcome::StatusUpdated
                }
                "past_due" => {
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke: {e}")))?;
                    UpdatedOutcome::Revoked
                }
                "revoked" => {
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke: {e}")))?;
                    UpdatedOutcome::Revoked
                }
                _ => {
                    // Unknown status → revoke defensively.
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke unknown: {e}")))?;
                    UpdatedOutcome::UnknownStatusRevoked
                }
            };

            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                params![data.event_id, data.event_type],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
            Ok(outcome)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn receipt_lookup(&self, checkout_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.clone();
        let cid = checkout_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let secret: Option<String> = conn
                .query_row(
                    "SELECT receipt_secret FROM pending_receipts WHERE checkout_id=?1 AND expires_at > datetime('now')",
                    params![cid],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db receipt lookup: {e}")))?;
            Ok(secret)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// Non-destructive availability check for confirmation pages. This avoids
    /// loading encrypted credentials for safe GET/HEAD requests.
    pub async fn receipt_available(&self, receipt_secret: &str) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let secret = receipt_secret.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let exists: i64 = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_receipts WHERE receipt_secret=?1 AND expires_at > datetime('now'))",
                    params![secret],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("db receipt availability: {e}")))?;
            Ok(exists != 0)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// repo-0237: non-destructive read of a pending receipt. `receipt_consume`
    /// peeks, decrypts/validates, and only then calls the atomic consume below
    /// — a decryption/validation failure must not destroy the only recoverable
    /// encrypted API key.
    pub async fn receipt_peek(&self, receipt_secret: &str) -> Result<Option<ReceiptRow>, AppError> {
        let conn = self.conn.clone();
        let secret = receipt_secret.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let row: Option<ReceiptRow> = conn
                .query_row(
                    "SELECT subscription_id, api_key_enc, api_key_nonce, token, checkout_id FROM pending_receipts WHERE receipt_secret=?1 AND expires_at > datetime('now')",
                    params![secret],
                    |row| {
                        Ok(ReceiptRow {
                            subscription_id: row.get(0)?,
                            api_key_enc: row.get(1)?,
                            api_key_nonce: row.get(2)?,
                            token: row.get(3)?,
                            checkout_id: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db receipt peek: {e}")))?;
            Ok(row)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// Atomic consume — DELETE … RETURNING ensures exactly one request
    /// receives the row.
    pub async fn receipt_consume(
        &self,
        receipt_secret: &str,
    ) -> Result<Option<ReceiptRow>, AppError> {
        let conn = self.conn.clone();
        let secret = receipt_secret.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let row: Option<ReceiptRow> = conn
                .query_row(
                    "DELETE FROM pending_receipts WHERE receipt_secret=?1 AND expires_at > datetime('now') RETURNING subscription_id, api_key_enc, api_key_nonce, token, checkout_id",
                    params![secret],
                    |row| {
                        Ok(ReceiptRow {
                            subscription_id: row.get(0)?,
                            api_key_enc: row.get(1)?,
                            api_key_nonce: row.get(2)?,
                            token: row.get(3)?,
                            checkout_id: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db receipt consume: {e}")))?;
            Ok(row)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn lookup_api_key(&self, key_hash: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.clone();
        let kh = key_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let sub_id: Option<String> = conn
                .query_row(
                    "SELECT subscription_id FROM api_keys WHERE key_hash=?1 AND revoked=0",
                    params![kh],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db key lookup: {e}")))?;
            Ok(sub_id)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn get_subscription(&self, sub_id: &str) -> Result<Option<SubRow>, AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let row: Option<SubRow> = conn
                .query_row(
                    "SELECT id, status, tier FROM subscriptions WHERE id=?1",
                    params![sid],
                    |row| {
                        Ok(SubRow {
                            id: row.get(0)?,
                            status: row.get(1)?,
                            tier: row.get(2)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db get sub: {e}")))?;
            Ok(row)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// Atomically publish a refresh token only when this subscription has not
    /// received one inside `min_interval_secs`. The decision and INSERT share
    /// one SQLite statement while the connection mutex is held, so parallel
    /// refresh requests cannot all observe an old token and then all win.
    pub async fn insert_refresh_token_if_due(
        &self,
        sub_id: &str,
        token: &str,
        expires_at: i64,
        min_interval_secs: i64,
    ) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        let tok = token.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let inserted = conn
                .execute(
                    "INSERT INTO tokens (subscription_id, token, expires_at)
                     SELECT ?1, ?2, ?3
                     WHERE NOT EXISTS (
                       SELECT 1 FROM tokens
                       WHERE subscription_id=?1
                         AND CAST(strftime('%s', created_at) AS INTEGER)
                             > unixepoch('now') - ?4
                     )",
                    params![sid, tok, expires_at, min_interval_secs],
                )
                .map_err(|e| AppError::Internal(format!("db insert refresh token: {e}")))?;
            Ok(inserted == 1)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    #[cfg(test)]
    fn count_tokens_for_subscription(&self, sub_id: &str) -> i64 {
        let conn = acquire_db(&self.conn);
        conn.query_row(
            "SELECT COUNT(*) FROM tokens WHERE subscription_id=?1",
            params![sub_id],
            |row| row.get(0),
        )
        .expect("count tokens")
    }

    #[cfg(test)]
    fn delete_tokens_for_subscription(&self, sub_id: &str) {
        let conn = acquire_db(&self.conn);
        conn.execute(
            "DELETE FROM tokens WHERE subscription_id=?1",
            params![sub_id],
        )
        .expect("delete tokens");
    }

    pub async fn insert_dead_letter(&self, dl: DeadLetterData) -> Result<(), AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            conn.execute(
                "INSERT OR IGNORE INTO dead_letter (event_id, subscription_id, event_type, reason, occurred_at, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![dl.event_id, dl.subscription_id, dl.event_type, dl.reason, dl.occurred_at, dl.payload],
            )
            .map_err(|e| AppError::Internal(format!("db dead letter: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn cleanup(&self) -> Result<(), AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            conn.execute_batch(
                "DELETE FROM pending_receipts WHERE expires_at < datetime('now');
                 DELETE FROM dead_letter WHERE created_at < datetime('now', '-90 days');
                 DELETE FROM tokens WHERE expires_at < (unixepoch('now') - 90*86400);",
            )
            .map_err(|e| AppError::Internal(format!("db cleanup: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    /// Returns only subscription-type dead letters — filtered in SQL.
    pub async fn get_retryable_dead_letters(&self) -> Result<Vec<RetryableDeadLetter>, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            let mut stmt = conn
                .prepare(
                    "SELECT dl.id, dl.event_id, dl.subscription_id, dl.event_type, dl.occurred_at, s.tier, s.last_event_at
                     FROM dead_letter dl
                     LEFT JOIN subscriptions s ON dl.subscription_id = s.id
                     WHERE dl.reason='unresolvable_product'
                       AND dl.event_type LIKE 'subscription.%'
                       AND dl.created_at > datetime('now', '-1 hour')
                       AND dl.subscription_id IS NOT NULL",
                )
                .map_err(|e| AppError::Internal(format!("db prepare retry: {e}")))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(RetryableDeadLetter {
                        id: row.get(0)?,
                        event_id: row.get(1)?,
                        subscription_id: row.get(2)?,
                        event_type: row.get(3)?,
                        occurred_at: row.get(4)?,
                        current_tier: row.get(5)?,
                        last_event_at: row.get(6)?,
                    })
                })
                .map_err(|e| AppError::Internal(format!("db query retry: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::Internal(format!("db collect retry: {e}")))?;
            Ok(rows)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn apply_retry_tier_fix(
        &self,
        dead_letter_id: i64,
        sub_id: &str,
        new_tier: &str,
        new_product_id: &str,
        expected_last_event_at: Option<String>,
    ) -> Result<(), AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        let tier = new_tier.to_string();
        let pid = new_product_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            // repo-0448: compare-and-swap on the version observed when the
            // Polar request STARTED. A plan transition landing mid-flight must
            // not be overwritten by the stale response.
            conn.execute(
                "UPDATE subscriptions SET tier=?1, product_id=?2, updated_at=datetime('now') WHERE id=?3 AND tier='unknown' AND last_event_at IS ?4",
                params![tier, pid, sid, expected_last_event_at],
            )
            .map_err(|e| AppError::Internal(format!("db retry tier fix: {e}")))?;
            conn.execute(
                "DELETE FROM dead_letter WHERE id=?1",
                params![dead_letter_id],
            )
            .map_err(|e| AppError::Internal(format!("db delete dl: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    pub async fn delete_dead_letter(&self, dead_letter_id: i64) -> Result<(), AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = acquire_db(&conn);
            conn.execute(
                "DELETE FROM dead_letter WHERE id=?1",
                params![dead_letter_id],
            )
            .map_err(|e| AppError::Internal(format!("db delete dl: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }
}

pub struct CreatedData {
    pub event_id: String,
    pub event_type: String,
    pub subscription_id: String,
    pub customer_id: String,
    pub email: String,
    pub tier: String,
    pub product_id: String,
    pub occurred_at: Option<String>,
    /// Polar checkout id, used as the browser-receipt lookup key. `None` for
    /// checkout-less subscriptions (e.g. admin/API-created), in which case no
    /// `pending_receipts` row is created — there is no browser checkout flow to
    /// deliver one, and a row keyed by a guessable placeholder would let an
    /// attacker race the one-time receipt via `/receipt/lookup`.
    pub checkout_id: Option<String>,
    pub key_hash: String,
    pub token: Option<String>,
    pub token_expires_at: i64,
    pub receipt_secret: String,
    pub api_key_enc: Vec<u8>,
    pub api_key_nonce: Vec<u8>,
}

#[derive(Debug)]
pub enum CreatedOutcome {
    Provisioned,
    PartialProvisioned,
    SkippedRevoked,
    AlreadyProvisioned,
    Duplicate,
}

pub struct CanceledData {
    pub event_id: String,
    pub subscription_id: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub product_id: Option<String>,
    pub occurred_at: Option<String>,
}

pub struct RevokedData {
    pub event_id: String,
    pub subscription_id: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub product_id: Option<String>,
    pub occurred_at: Option<String>,
}

pub struct UpdatedData {
    pub event_id: String,
    pub event_type: String,
    pub subscription_id: String,
    pub new_status: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub product_id: Option<String>,
    pub occurred_at: Option<String>,
    pub resolved_tier: Option<String>,
    pub tier_unknown: bool,
}

#[derive(Debug, PartialEq)]
pub enum UpdatedOutcome {
    Duplicate,
    Unrevoked,
    Revoked,
    ActiveNoKey,
    StatusUpdated,
    TerminalIgnored,
    /// A genuine event arrived out of order (its `occurred_at` is older than
    /// the row's `last_event_at`). Recorded for idempotency but applied no
    /// status overwrite or `revoked` side-effect, so a stale `active` can
    /// never re-enable a key revoked by a newer `past_due`/`revoked`.
    StaleIgnored,
    UnknownStatusRevoked,
}

#[allow(dead_code)]
pub struct ReceiptRow {
    pub subscription_id: String,
    pub api_key_enc: Vec<u8>,
    pub api_key_nonce: Vec<u8>,
    pub token: Option<String>,
    pub checkout_id: String,
}

pub struct SubRow {
    pub id: String,
    pub status: String,
    pub tier: String,
}

pub struct DeadLetterData {
    pub event_id: String,
    pub subscription_id: Option<String>,
    pub event_type: String,
    pub reason: String,
    pub occurred_at: Option<String>,
    pub payload: String,
}

#[allow(dead_code)]
pub struct RetryableDeadLetter {
    pub id: i64,
    pub event_id: String,
    pub subscription_id: Option<String>,
    pub event_type: String,
    pub occurred_at: Option<String>,
    pub current_tier: Option<String>,
    pub last_event_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::open(":memory:").expect("open in-memory db")
    }

    fn make_created(event_id: &str, sub_id: &str, tier: &str) -> CreatedData {
        CreatedData {
            event_id: event_id.to_string(),
            event_type: "subscription.active".to_string(),
            subscription_id: sub_id.to_string(),
            customer_id: "cust_1".to_string(),
            email: "test@example.com".to_string(),
            tier: tier.to_string(),
            product_id: "prod_1".to_string(),
            occurred_at: Some("2024-01-01T00:00:00Z".to_string()),
            checkout_id: Some(format!("checkout_{event_id}")),
            key_hash: format!("keyhash_{sub_id}"),
            token: Some("token_1".to_string()),
            token_expires_at: 9999999999,
            receipt_secret: format!("receipt_{event_id}"),
            api_key_enc: vec![1, 2, 3],
            api_key_nonce: vec![4, 5, 6],
        }
    }

    fn make_canceled(event_id: &str, sub_id: &str) -> CanceledData {
        CanceledData {
            event_id: event_id.to_string(),
            subscription_id: sub_id.to_string(),
            customer_id: Some("cust_1".to_string()),
            email: Some("test@example.com".to_string()),
            tier: Some("team".to_string()),
            product_id: Some("prod_1".to_string()),
            occurred_at: Some("2024-01-02T00:00:00Z".to_string()),
        }
    }

    fn make_revoked(event_id: &str, sub_id: &str) -> RevokedData {
        RevokedData {
            event_id: event_id.to_string(),
            subscription_id: sub_id.to_string(),
            customer_id: Some("cust_1".to_string()),
            email: Some("test@example.com".to_string()),
            tier: Some("team".to_string()),
            product_id: Some("prod_1".to_string()),
            occurred_at: Some("2024-01-03T00:00:00Z".to_string()),
        }
    }

    fn make_updated(event_id: &str, sub_id: &str, status: &str) -> UpdatedData {
        UpdatedData {
            event_id: event_id.to_string(),
            event_type: format!("subscription.{status}"),
            subscription_id: sub_id.to_string(),
            new_status: status.to_string(),
            customer_id: Some("cust_1".to_string()),
            email: Some("test@example.com".to_string()),
            tier: Some("team".to_string()),
            product_id: Some("prod_1".to_string()),
            occurred_at: Some("2024-01-04T00:00:00Z".to_string()),
            resolved_tier: Some("team".to_string()),
            tier_unknown: false,
        }
    }

    /// Helper to read status and key revoked state from DB.
    fn read_state(db: &Db, sub_id: &str) -> (String, Option<bool>) {
        let conn = db.conn.lock().unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM subscriptions WHERE id=?1",
                params![sub_id],
                |row| row.get(0),
            )
            .unwrap();
        let revoked: Option<bool> = conn
            .query_row(
                "SELECT revoked FROM api_keys WHERE subscription_id=?1",
                params![sub_id],
                |row| row.get::<_, i32>(0).map(|v| v != 0),
            )
            .optional()
            .unwrap();
        (status, revoked)
    }

    #[tokio::test]
    async fn test_provision_creates_key_and_token() {
        let db = test_db();
        let data = make_created("evt_1", "sub_1", "team");
        let outcome = db.process_subscription_created(data).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::Provisioned));

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn parallel_refreshes_have_exactly_one_atomic_winner() {
        let db = test_db();
        db.process_subscription_created(make_created("evt_1", "sub_1", "team"))
            .await
            .unwrap();
        db.delete_tokens_for_subscription("sub_1");

        let contestants = 16;
        let barrier = Arc::new(tokio::sync::Barrier::new(contestants));
        let mut tasks = Vec::new();
        for index in 0..contestants {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                db.insert_refresh_token_if_due(
                    "sub_1",
                    &format!("refresh-token-{index}"),
                    9_999_999_999,
                    60,
                )
                .await
                .unwrap()
            }));
        }

        let mut winners = 0;
        for task in tasks {
            winners += usize::from(task.await.unwrap());
        }
        assert_eq!(winners, 1, "parallel refreshes must have one winner");
        assert_eq!(db.count_tokens_for_subscription("sub_1"), 1);
    }

    #[tokio::test]
    async fn test_provision_duplicate_event() {
        let db = test_db();
        let data1 = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(data1).await.unwrap();

        let data2 = make_created("evt_1", "sub_1", "team");
        let outcome = db.process_subscription_created(data2).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::Duplicate));
    }

    #[tokio::test]
    async fn test_provision_already_has_key() {
        let db = test_db();
        let data1 = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(data1).await.unwrap();

        let mut data2 = make_created("evt_2", "sub_1", "team");
        data2.checkout_id = Some("checkout_2".to_string());
        data2.receipt_secret = "receipt_2".to_string();
        let outcome = db.process_subscription_created(data2).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::AlreadyProvisioned));
    }

    /// Count pending_receipts rows for a subscription (test helper).
    fn count_receipts(db: &Db, sub_id: &str) -> i64 {
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM pending_receipts WHERE subscription_id=?1",
            params![sub_id],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// F5 regression: a checkout-less subscription (`checkout_id = None`) must
    /// NOT create a `pending_receipts` row keyed by a guessable id, so an
    /// attacker cannot grab the one-time receipt via
    /// `/receipt/lookup?checkout=unknown`. The API key is still provisioned.
    #[tokio::test]
    async fn test_checkout_less_provision_creates_no_lookupable_receipt() {
        let db = test_db();
        let mut data = make_created("evt_1", "sub_1", "team");
        data.checkout_id = None;
        let outcome = db.process_subscription_created(data).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::Provisioned));

        // The key/token/subscription were still provisioned.
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));

        // But NO pending_receipts row exists, so nothing is lookup-able.
        assert_eq!(count_receipts(&db, "sub_1"), 0);

        // The old "unknown" placeholder — and any guess — cannot match.
        assert_eq!(db.receipt_lookup("unknown").await.unwrap(), None);
    }

    /// Happy path stays intact: a real checkout_id yields a lookup-able receipt.
    #[tokio::test]
    async fn test_checkout_provision_receipt_is_lookupable() {
        let db = test_db();
        let mut data = make_created("evt_1", "sub_1", "team");
        data.checkout_id = Some("checkout_real".to_string());
        db.process_subscription_created(data).await.unwrap();

        assert_eq!(count_receipts(&db, "sub_1"), 1);
        let secret = db.receipt_lookup("checkout_real").await.unwrap();
        assert_eq!(secret, Some("receipt_evt_1".to_string()));
        // A different/guessed checkout still does not match.
        assert_eq!(db.receipt_lookup("unknown").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_receipt_availability_is_non_consuming_until_atomic_consume() {
        let db = test_db();
        let mut data = make_created("evt_1", "sub_1", "team");
        data.checkout_id = Some("checkout_real".to_string());
        db.process_subscription_created(data).await.unwrap();

        assert!(db.receipt_available("receipt_evt_1").await.unwrap());
        assert!(db.receipt_available("receipt_evt_1").await.unwrap());
        assert!(db.receipt_consume("receipt_evt_1").await.unwrap().is_some());
        assert!(!db.receipt_available("receipt_evt_1").await.unwrap());
        assert!(db.receipt_consume("receipt_evt_1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_provision_skipped_if_revoked() {
        let db = test_db();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO subscriptions (id, status, tier) VALUES ('sub_1', 'revoked', 'team')",
                [],
            )
            .unwrap();
        }
        let data = make_created("evt_1", "sub_1", "team");
        let outcome = db.process_subscription_created(data).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::SkippedRevoked));
    }

    #[tokio::test]
    async fn test_canceled_does_not_revoke_key() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let canceled = make_canceled("evt_2", "sub_1");
        let processed = db.process_subscription_canceled(canceled).await.unwrap();
        assert!(processed);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "canceled");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn test_canceled_absorbed_by_revoked() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let revoked = make_revoked("evt_2", "sub_1");
        db.process_subscription_revoked(revoked).await.unwrap();

        let canceled = make_canceled("evt_3", "sub_1");
        let processed = db.process_subscription_canceled(canceled).await.unwrap();
        assert!(!processed);

        let (status, _) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
    }

    #[tokio::test]
    async fn test_revoked_revokes_key() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let revoked = make_revoked("evt_2", "sub_1");
        let processed = db.process_subscription_revoked(revoked).await.unwrap();
        assert!(processed);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn stale_revoked_event_cannot_override_newer_active_state() {
        let db = test_db();
        db.process_subscription_created(make_created("evt_1", "sub_1", "team"))
            .await
            .unwrap();

        let mut newer_active = make_updated("evt_2", "sub_1", "active");
        newer_active.occurred_at = Some("2024-03-01T00:00:00Z".to_string());
        assert_eq!(
            db.process_subscription_updated(newer_active).await.unwrap(),
            UpdatedOutcome::Unrevoked
        );

        let mut stale_revoked = make_revoked("evt_3", "sub_1");
        stale_revoked.occurred_at = Some("2024-02-01T00:00:00Z".to_string());
        assert!(!db
            .process_subscription_revoked(stale_revoked)
            .await
            .unwrap());
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));

        let mut newer_revoked = make_revoked("evt_4", "sub_1");
        newer_revoked.occurred_at = Some("2024-04-01T00:00:00Z".to_string());
        assert!(db
            .process_subscription_revoked(newer_revoked)
            .await
            .unwrap());
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn missing_update_timestamp_cannot_reenable_key() {
        let db = test_db();
        db.process_subscription_created(make_created("evt_1", "sub_1", "team"))
            .await
            .unwrap();

        let mut past_due = make_updated("evt_2", "sub_1", "past_due");
        past_due.occurred_at = Some("2024-03-01T00:00:00Z".to_string());
        assert_eq!(
            db.process_subscription_updated(past_due).await.unwrap(),
            UpdatedOutcome::Revoked
        );

        let mut missing_timestamp = make_updated("evt_3", "sub_1", "active");
        missing_timestamp.occurred_at = None;
        assert_eq!(
            db.process_subscription_updated(missing_timestamp)
                .await
                .unwrap(),
            UpdatedOutcome::StaleIgnored
        );
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn missing_revoked_timestamp_cannot_change_state() {
        let db = test_db();
        db.process_subscription_created(make_created("evt_1", "sub_1", "team"))
            .await
            .unwrap();

        let mut revoked_event = make_revoked("evt_2", "sub_1");
        revoked_event.occurred_at = None;
        assert!(!db
            .process_subscription_revoked(revoked_event)
            .await
            .unwrap());
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn test_active_after_past_due_unrevokes() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let past_due = make_updated("evt_2", "sub_1", "past_due");
        let outcome = db.process_subscription_updated(past_due).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Revoked);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));

        let active = make_updated("evt_3", "sub_1", "active");
        let outcome = db.process_subscription_updated(active).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Unrevoked);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));
    }

    /// F21 regression: a stale/out-of-order `active` (older occurred_at than the
    /// `past_due` that revoked the key) must NOT re-enable the key. It is
    /// recorded for idempotency but applies no status overwrite or unrevoke.
    #[tokio::test]
    async fn test_stale_active_after_past_due_is_ignored() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        // past_due arrives with a NEWER occurred_at — revokes the key and
        // advances last_event_at to 2024-03-01.
        let mut past_due = make_updated("evt_2", "sub_1", "past_due");
        past_due.occurred_at = Some("2024-03-01T00:00:00Z".to_string());
        let outcome = db.process_subscription_updated(past_due).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Revoked);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));

        // A genuine `active` that was emitted BEFORE the past_due but delivered
        // after it (occurred_at 2024-02-01 < last_event_at 2024-03-01). It must
        // be ignored as stale, leaving the key revoked and status unchanged.
        let mut stale_active = make_updated("evt_3", "sub_1", "active");
        stale_active.occurred_at = Some("2024-02-01T00:00:00Z".to_string());
        let outcome = db.process_subscription_updated(stale_active).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::StaleIgnored);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));

        // The stale event is still recorded so a re-delivery is a no-op
        // duplicate (idempotency preserved).
        let mut redelivered = make_updated("evt_3", "sub_1", "active");
        redelivered.occurred_at = Some("2024-02-01T00:00:00Z".to_string());
        let outcome = db.process_subscription_updated(redelivered).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Duplicate);
    }

    /// F21 regression: the stale guard must compare timestamps as instants,
    /// not raw RFC3339 strings. An `active` whose occurred_at is chronologically
    /// OLDER than the stored last_event_at but encoded with a non-`Z` UTC offset
    /// sorts LATER lexicographically (`...T13:30:00+02:00` > `...T12:00:00Z` as
    /// bytes, even though 13:30+02:00 == 11:30Z < 12:00Z). A raw string compare
    /// would treat it as newer and re-enable the revoked key; the instant
    /// compare correctly flags it as stale.
    #[tokio::test]
    async fn test_stale_active_with_offset_encoding_is_ignored() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        // past_due revokes the key and advances last_event_at to a Z-encoded
        // instant of 2024-03-01T12:00:00Z.
        let mut past_due = make_updated("evt_2", "sub_1", "past_due");
        past_due.occurred_at = Some("2024-03-01T12:00:00Z".to_string());
        let outcome = db.process_subscription_updated(past_due).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Revoked);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));

        // A genuine but stale `active`: 13:30:00+02:00 == 11:30:00Z, which is
        // 30 minutes BEFORE the stored 12:00:00Z. Lexicographically its string
        // sorts after the stored value (the '13' hour), so the old raw-string
        // compare would let it through and un-revoke the key.
        let mut stale_active = make_updated("evt_3", "sub_1", "active");
        stale_active.occurred_at = Some("2024-03-01T13:30:00+02:00".to_string());
        let outcome = db.process_subscription_updated(stale_active).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::StaleIgnored);

        // Status and key state are untouched — the key stays revoked.
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "past_due");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn test_active_after_revoked_is_absorbed() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let revoked = make_revoked("evt_2", "sub_1");
        db.process_subscription_revoked(revoked).await.unwrap();

        let active = make_updated("evt_3", "sub_1", "active");
        let outcome = db.process_subscription_updated(active).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::TerminalIgnored);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn test_past_due_after_revoked_is_absorbed() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let revoked = make_revoked("evt_2", "sub_1");
        db.process_subscription_revoked(revoked).await.unwrap();

        let past_due = make_updated("evt_3", "sub_1", "past_due");
        let outcome = db.process_subscription_updated(past_due).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::TerminalIgnored);

        let (status, _) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
    }

    #[tokio::test]
    async fn test_canceled_status_update_no_key_change() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let canceled = make_updated("evt_2", "sub_1", "canceled");
        let outcome = db.process_subscription_updated(canceled).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::StatusUpdated);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "canceled");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn test_uncanceled_back_to_active() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let canceled = make_updated("evt_2", "sub_1", "canceled");
        db.process_subscription_updated(canceled).await.unwrap();

        let active = make_updated("evt_3", "sub_1", "active");
        let outcome = db.process_subscription_updated(active).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Unrevoked);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn test_duplicate_updated_event() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let updated = make_updated("evt_2", "sub_1", "past_due");
        db.process_subscription_updated(updated).await.unwrap();

        let updated_dup = make_updated("evt_2", "sub_1", "past_due");
        let outcome = db.process_subscription_updated(updated_dup).await.unwrap();
        assert_eq!(outcome, UpdatedOutcome::Duplicate);
    }

    #[tokio::test]
    async fn test_provision_after_canceled_reconciles_to_active() {
        let db = test_db();
        // canceled arrives first (creates row with status=canceled) and
        // subscription.active provision arrives second.
        let canceled = make_canceled("evt_1", "sub_1");
        db.process_subscription_canceled(canceled).await.unwrap();

        let (status, _) = read_state(&db, "sub_1");
        assert_eq!(status, "canceled");

        let created = make_created("evt_2", "sub_1", "team");
        let outcome = db.process_subscription_created(created).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::Provisioned));

        // Status should be reconciled to active, not stuck at canceled.
        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "active");
        assert_eq!(revoked, Some(false));
    }

    #[tokio::test]
    async fn test_revoked_after_revoked_is_idempotent() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let revoked1 = make_revoked("evt_2", "sub_1");
        db.process_subscription_revoked(revoked1).await.unwrap();

        let mut revoked2 = make_revoked("evt_3", "sub_1");
        revoked2.occurred_at = Some("2024-01-04T00:00:00Z".to_string());
        let processed = db.process_subscription_revoked(revoked2).await.unwrap();
        // Distinct event_id so not a duplicate; re-revoke is idempotent.
        assert!(processed);

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
        assert_eq!(revoked, Some(true));
    }

    #[tokio::test]
    async fn test_migration_renames_price_id_to_product_id() {
        // Seed a DB carrying the legacy `price_id` column.
        let conn = Connection::open(":memory:").unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS subscriptions (
                 id TEXT PRIMARY KEY,
                 customer_id TEXT NOT NULL DEFAULT 'unknown',
                 email TEXT NOT NULL DEFAULT 'unknown',
                 tier TEXT NOT NULL DEFAULT 'unknown',
                 status TEXT NOT NULL DEFAULT 'active',
                 price_id TEXT NOT NULL DEFAULT 'unknown',
                 last_event_at TEXT,
                 created_at TEXT NOT NULL DEFAULT (datetime('now')),
                 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO subscriptions (id, tier, status, price_id) VALUES ('sub_old', 'pro', 'active', 'pri_abc');",
        )
        .unwrap();

        Db::migrate(&conn).unwrap();

        let product_id: String = conn
            .query_row(
                "SELECT product_id FROM subscriptions WHERE id='sub_old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(product_id, "pri_abc");

        assert!(conn
            .prepare("SELECT price_id FROM subscriptions LIMIT 0")
            .is_err());
    }
}
