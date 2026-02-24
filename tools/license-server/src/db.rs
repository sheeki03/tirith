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

    /// Run schema migrations for Paddle → Polar transition.
    /// Safe to call repeatedly — each migration is guarded by column-existence checks.
    fn migrate(conn: &Connection) -> Result<(), AppError> {
        // Migration 1: Rename price_id → product_id in subscriptions table.
        // If the table has price_id but not product_id, rename it.
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

    // ─── Provision (order.paid or subscription.active first event) ──

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

            // UPSERT subscription — reconcile status to 'active' unless terminal (revoked).
            // The CASE preserves 'revoked' so the terminal guard below can detect it.
            tx.execute(
                "INSERT INTO subscriptions (id, customer_id, email, tier, status, product_id, last_event_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   status=CASE WHEN subscriptions.status='revoked' THEN 'revoked' ELSE 'active' END,
                   email=excluded.email, product_id=excluded.product_id, tier=excluded.tier,
                   last_event_at=MAX(COALESCE(subscriptions.last_event_at,''), excluded.last_event_at),
                   updated_at=datetime('now')",
                params![
                    data.subscription_id,
                    data.customer_id,
                    data.email,
                    data.tier,
                    data.product_id,
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert sub: {e}")))?;

            // Read current status (may differ from 'active' if row already existed)
            let status: String = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("db read status: {e}")))?;

            // Mark event
            tx.execute(
                "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                params![data.event_id, data.event_type],
            )
            .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;

            // Terminal guard: revoked is absorbing — do not provision
            if status == "revoked" {
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(CreatedOutcome::SkippedRevoked);
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

            // Determine if this is partial provisioning (past_due)
            let revoked = if status == "past_due" { 1 } else { 0 };

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

    // ─── subscription.canceled (benefits continue until period end) ──

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

            // Terminal guard: if already revoked, absorb
            let prev_status: Option<String> = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read prev: {e}")))?;

            if prev_status.as_deref() == Some("revoked") {
                // Mark event, absorb transition
                tx.execute(
                    "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, 'subscription.canceled')",
                    params![data.event_id],
                )
                .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(false); // absorbed by terminal state
            }

            // UPSERT with canceled status — key NOT revoked (benefits continue)
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
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert canceled: {e}")))?;

            // NO key revocation — Polar canceled means benefits continue until period end

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

    // ─── subscription.revoked (terminal — revoke key) ────────────────

    pub async fn process_subscription_revoked(&self, data: RevokedData) -> Result<bool, AppError> {
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

            // UPSERT with revoked status
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
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert revoked: {e}")))?;

            // Revoke API key
            tx.execute(
                "UPDATE api_keys SET revoked=1 WHERE subscription_id=?1",
                params![data.subscription_id],
            )
            .map_err(|e| AppError::Internal(format!("db revoke key: {e}")))?;

            // Mark event
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

    // ─── API key existence check (for webhook routing) ────────────────

    pub async fn has_api_key(&self, subscription_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.clone();
        let sid = subscription_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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

    // ─── subscription.updated (status transitions with terminal guard) ─

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

            // Step 1: Read previous status BEFORE any writes
            let prev_status: Option<String> = tx
                .query_row(
                    "SELECT status FROM subscriptions WHERE id=?1",
                    params![data.subscription_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| AppError::Internal(format!("db read prev: {e}")))?;

            // Step 2: Terminal absorption — revoked absorbs ALL non-revoked transitions
            if prev_status.as_deref() == Some("revoked") && data.new_status != "revoked" {
                // Mark event + commit, but do NOT change status
                tx.execute(
                    "INSERT INTO webhook_events (event_id, event_type) VALUES (?1, ?2)",
                    params![data.event_id, data.event_type],
                )
                .map_err(|e| AppError::Internal(format!("db mark event: {e}")))?;
                tx.commit().map_err(|e| AppError::Internal(format!("db commit: {e}")))?;
                return Ok(UpdatedOutcome::TerminalIgnored);
            }

            // Step 3: UPSERT with validated status (safe — revoked can't be overwritten)
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
                    data.occurred_at,
                ],
            )
            .map_err(|e| AppError::Internal(format!("db upsert updated: {e}")))?;

            // Step 3b: Apply tier if resolved
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

            // Step 4: Side effects based on status
            // Since revoked was already absorbed in step 2, all remaining prev_statuses
            // (past_due, canceled, active, None) are valid for un-revoke on active.
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
                    // No key change — benefits continue until period end
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
                    // Idempotent re-revoke (prev was also revoked or first time)
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

    // ─── Dead-letter auto-retry query (subscription events only) ────

    pub async fn get_retryable_dead_letters(&self) -> Result<Vec<RetryableDeadLetter>, AppError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
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
    ) -> Result<(), AppError> {
        let conn = self.conn.clone();
        let sid = sub_id.to_string();
        let tier = new_tier.to_string();
        let pid = new_product_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE subscriptions SET tier=?1, product_id=?2, updated_at=datetime('now') WHERE id=?3 AND tier='unknown'",
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
    pub event_type: String,
    pub subscription_id: String,
    pub customer_id: String,
    pub email: String,
    pub tier: String,
    pub product_id: String,
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
            checkout_id: format!("checkout_{event_id}"),
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

    // ─── Provision tests ─────────────────────────────────────────────

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
        data2.checkout_id = "checkout_2".to_string();
        data2.receipt_secret = "receipt_2".to_string();
        let outcome = db.process_subscription_created(data2).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::AlreadyProvisioned));
    }

    #[tokio::test]
    async fn test_provision_skipped_if_revoked() {
        let db = test_db();
        // Manually create a revoked subscription with no key
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

    // ─── Canceled tests (benefits continue) ──────────────────────────

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
        assert_eq!(revoked, Some(false)); // key NOT revoked
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
        assert!(!processed); // absorbed

        let (status, _) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked"); // still revoked
    }

    // ─── Revoked tests (terminal) ────────────────────────────────────

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
        assert_eq!(revoked, Some(true)); // key IS revoked
    }

    // ─── Updated tests (terminal absorption) ─────────────────────────

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
        assert_eq!(status, "revoked"); // still revoked
        assert_eq!(revoked, Some(true)); // still revoked
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
        assert_eq!(revoked, Some(false)); // key NOT revoked
    }

    #[tokio::test]
    async fn test_uncanceled_back_to_active() {
        let db = test_db();
        let created = make_created("evt_1", "sub_1", "team");
        db.process_subscription_created(created).await.unwrap();

        let canceled = make_updated("evt_2", "sub_1", "canceled");
        db.process_subscription_updated(canceled).await.unwrap();

        // Uncanceled → active
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

    // ─── Out-of-order event tests ────────────────────────────────────

    #[tokio::test]
    async fn test_provision_after_canceled_reconciles_to_active() {
        let db = test_db();
        // canceled arrives first (creates row with status=canceled)
        let canceled = make_canceled("evt_1", "sub_1");
        db.process_subscription_canceled(canceled).await.unwrap();

        let (status, _) = read_state(&db, "sub_1");
        assert_eq!(status, "canceled");

        // subscription.active provision arrives second
        let created = make_created("evt_2", "sub_1", "team");
        let outcome = db.process_subscription_created(created).await.unwrap();
        assert!(matches!(outcome, CreatedOutcome::Provisioned));

        // Status should be reconciled to active, not stuck at canceled
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
        assert!(processed); // not a duplicate event, but idempotent

        let (status, revoked) = read_state(&db, "sub_1");
        assert_eq!(status, "revoked");
        assert_eq!(revoked, Some(true));
    }

    // ─── Migration test ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_migration_renames_price_id_to_product_id() {
        // Create a DB with old schema (price_id)
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

        // Run migration
        Db::migrate(&conn).unwrap();

        // Verify product_id column exists and has the old data
        let product_id: String = conn
            .query_row(
                "SELECT product_id FROM subscriptions WHERE id='sub_old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(product_id, "pri_abc");

        // Verify price_id no longer exists
        assert!(conn
            .prepare("SELECT price_id FROM subscriptions LIMIT 0")
            .is_err());
    }
}
