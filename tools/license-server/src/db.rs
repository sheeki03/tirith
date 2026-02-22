use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;

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
    price_id       TEXT NOT NULL DEFAULT 'unknown',
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

impl Db {
    pub fn open(path: &str) -> Result<Self, AppError> {
        let conn =
            Connection::open(path).map_err(|e| AppError::Internal(format!("db open: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| AppError::Internal(format!("db schema: {e}")))?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_readonly(path: &str) -> Result<Connection, AppError> {
        Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| AppError::Internal(format!("db open readonly: {e}")))
    }

    // ─── Idempotency ────────────────────────────────────────────────

    pub async fn event_exists(&self, event_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let eid = event_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── subscription.created ───────────────────────────────────────

    pub async fn process_subscription_created(
        &self,
        data: CreatedData,
    ) -> Result<CreatedOutcome, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            // Idempotency check
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

            // UPSERT subscription — metadata-only update on existing rows
            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, price_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   email=excluded.email, price_id=excluded.price_id, tier=excluded.tier,
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), excluded.last_event_at),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id,
                    data.email,
                    data.tier,
                    data.price_id,
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert sub: {e}")))?;

            // Read current status
            let status: String = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("db read status: {e}")))?;

            // Mark event
            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.created')",
                params![data.event_id],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            if status == "canceled" {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(CreatedOutcome::SkippedCanceled);
            }

            // Check if api_key already exists
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

            // Determine if this is partial provisioning (past_due/paused)
            let revoked = if status == "past_due" || status == "paused" { 1 } else { 0 };

            // Insert api_key
            tx.execute(
                "INSERT INTO api_keys (key_hash, subscription_id, revoked) VALUES (?1, ?2, ?3)",
                params![data.key_hash, data.subscription_id, revoked],
            )
            .map_err(|e| AppError::Internal(format!("db insert key: {e}")))?;

            // Insert token (only for full provisioning)
            if revoked == 0 {
                if let Some(ref token) = data.token {
                    tx.execute(
                        "INSERT INTO tokens (subscription_id, token, expires_at) VALUES (?1, ?2, ?3)",
                        params![data.subscription_id, token, data.token_expires_at],
                    )
                    .map_err(|e| AppError::Internal(format!("db insert token: {e}")))?;
                }
            }

            // Insert pending receipt
            tx.execute(
                "INSERT INTO pending_receipts (receipt_secret, subscription_id, api_key_enc, api_key_nonce, token, checkout_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now', '+1 hour'))",
                params![
                    data.receipt_secret,
                    data.subscription_id,
                    data.api_key_enc,
                    data.api_key_nonce,
                    if revoked == 0 { data.token.as_deref() } else { None },
                    data.checkout_id,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db insert receipt: {e}")))?;

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

    // ─── subscription.canceled ──────────────────────────────────────

    pub async fn process_subscription_canceled(
        &self,
        data: CanceledData,
    ) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            // Idempotency
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
                return Ok(false); // duplicate
            }

            // UPSERT with canceled status — COALESCE preserves existing values
            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, price_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'canceled', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   status='canceled',
                   customer_id=COALESCE(NULLIF(excluded.customer_id,'unknown'), subscriptions.customer_id),
                   email=COALESCE(NULLIF(excluded.email,'unknown'), subscriptions.email),
                   tier=COALESCE(NULLIF(excluded.tier,'unknown'), subscriptions.tier),
                   price_id=COALESCE(NULLIF(excluded.price_id,'unknown'), subscriptions.price_id),
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), COALESCE(excluded.last_event_at,'')),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id.as_deref().unwrap_or("unknown"),
                    data.email.as_deref().unwrap_or("unknown"),
                    data.tier.as_deref().unwrap_or("unknown"),
                    data.price_id.as_deref().unwrap_or("unknown"),
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert canceled: {e}")))?;

            // Revoke api key (always execute)
            tx.execute(
                "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                params![data.subscription_id],
            )
            .map_err(|e| AppError::Internal(format!("db revoke key: {e}")))?;

            // Mark event
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

    // ─── subscription.updated ───────────────────────────────────────

    pub async fn process_subscription_updated(
        &self,
        data: UpdatedData,
    ) -> Result<UpdatedOutcome, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let tx = conn.unchecked_transaction()
                .map_err(|e| AppError::Internal(format!("db tx: {e}")))?;

            // Idempotency
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

            // Step 1: Read previous status
            let prev_status: Option<String> = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read prev: {e}")))?;

            // Step 2: UPSERT subscription
            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, price_id, last_event_at)
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
                    data.price_id.as_deref().unwrap_or("unknown"),
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert updated: {e}")))?;

            // Step 2b: Apply tier if resolved
            if let Some(ref tier) = data.resolved_tier {
                if let Some(ref price_id) = data.price_id {
                    tx.execute(
                        "UPDATE subscriptions SET tier=?1, price_id=?2 WHERE id=?3",
                        params![tier, price_id, data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db update tier: {e}")))?;
                }
            } else if data.tier_unknown {
                // Fail-closed: set tier to unknown
                tx.execute(
                    "UPDATE subscriptions SET tier='unknown' WHERE id=?1",
                    params![data.subscription_id],
                )
                .map_err(|e| AppError::Internal(format!("db set unknown tier: {e}")))?;
            }

            // Step 3: Conditional side effects
            let outcome = match data.new_status.as_str() {
                "active" => {
                    // Guard: only un-revoke from past_due/paused, NOT from canceled
                    let can_unrevoke = match prev_status.as_deref() {
                        Some("canceled") => false,
                        _ => true, // past_due, paused, active, or new row (None)
                    };
                    if can_unrevoke {
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
                    } else {
                        UpdatedOutcome::StaleActiveIgnored
                    }
                }
                "past_due" | "paused" => {
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke: {e}")))?;
                    UpdatedOutcome::Revoked
                }
                "canceled" => {
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke: {e}")))?;
                    UpdatedOutcome::Revoked
                }
                _ => {
                    // Unknown status → treat as inactive
                    tx.execute(
                        "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                        params![data.subscription_id],
                    )
                    .map_err(|e| AppError::Internal(format!("db revoke unknown: {e}")))?;
                    UpdatedOutcome::UnknownStatusRevoked
                }
            };

            // Mark event
            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.updated')",
                params![data.event_id],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
            Ok(outcome)
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    // ─── Receipt lookup ─────────────────────────────────────────────

    pub async fn receipt_lookup(&self, checkout_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.clone();
        let cid = checkout_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── Receipt consume (atomic) ───────────────────────────────────

    pub async fn receipt_consume(
        &self,
        receipt_secret: &str,
    ) -> Result<Option<ReceiptRow>, AppError> {
        let conn = self.conn.clone();
        let secret = receipt_secret.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── Refresh (auth + token signing) ─────────────────────────────

    pub async fn lookup_api_key(&self, key_hash: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.clone();
        let kh = key_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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
            let conn = conn.lock().unwrap();
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

    pub async fn insert_token(
        &self,
        sub_id: &str,
        token: &str,
        expires_at: i64,
    ) -> Result<(), AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        let tok = token.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO tokens (subscription_id, token, expires_at) VALUES (?1, ?2, ?3)",
                params![sid, tok, expires_at],
            )
            .map_err(|e| AppError::Internal(format!("db insert token: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
    }

    // ─── Dead letter ────────────────────────────────────────────────

    pub async fn insert_dead_letter(&self, dl: DeadLetterData) -> Result<(), AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── Cleanup ────────────────────────────────────────────────────

    pub async fn cleanup(&self) -> Result<(), AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── Dead-letter auto-retry query ───────────────────────────────

    pub async fn get_retryable_dead_letters(&self) -> Result<Vec<RetryableDeadLetter>, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT dl.id, dl.event_id, dl.subscription_id, dl.occurred_at, s.tier, s.last_event_at
                     FROM dead_letter dl
                     LEFT JOIN subscriptions s ON dl.subscription_id = s.id
                     WHERE dl.reason='unresolvable_price'
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
                        occurred_at: row.get(3)?,
                        current_tier: row.get(4)?,
                        last_event_at: row.get(5)?,
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
        new_price_id: &str,
    ) -> Result<(), AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        let tier = new_tier.to_string();
        let pid = new_price_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE subscriptions SET tier=?1, price_id=?2, updated_at=datetime('now') WHERE id=?3 AND tier='unknown'",
                params![tier, pid, sid],
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
            let conn = conn.lock().unwrap();
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

// ─── Data types ─────────────────────────────────────────────────────

pub struct CreatedData {
    pub event_id: String,
    pub subscription_id: String,
    pub customer_id: String,
    pub email: String,
    pub tier: String,
    pub price_id: String,
    pub occurred_at: Option<String>,
    pub checkout_id: String,
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
    SkippedCanceled,
    AlreadyProvisioned,
    Duplicate,
}

pub struct CanceledData {
    pub event_id: String,
    pub subscription_id: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub price_id: Option<String>,
    pub occurred_at: Option<String>,
}

pub struct UpdatedData {
    pub event_id: String,
    pub subscription_id: String,
    pub new_status: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub price_id: Option<String>,
    pub occurred_at: Option<String>,
    pub resolved_tier: Option<String>,
    pub tier_unknown: bool,
}

#[derive(Debug)]
pub enum UpdatedOutcome {
    Duplicate,
    Unrevoked,
    Revoked,
    ActiveNoKey,
    StaleActiveIgnored,
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
    pub occurred_at: Option<String>,
    pub current_tier: Option<String>,
    pub last_event_at: Option<String>,
}
