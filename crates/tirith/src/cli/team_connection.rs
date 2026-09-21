//! Explicit local selection only. Enrollment/fetch/report are separate services.
use super::setup::{self, fs_helpers::FileUpdate, TransactionOutcome};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use tirith_core::policy_team::{Id, SCHEMA_VERSION};
use tirith_core::policy_team_client::{AuthorityBinding, EndpointOptions};
use tirith_core::policy_team_connection::{
    ConnectionStatus, PreparedConnection, SelectedConnection,
};

#[derive(clap::Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    #[arg(long)]
    pub server_url: String,
    #[arg(long)]
    pub authority_id: String,
    #[arg(long)]
    pub policy_id: String,
    #[arg(long)]
    pub credential_file: PathBuf,
    #[arg(long)]
    pub private_ca_file: Option<PathBuf>,
    #[arg(long = "address")]
    #[serde(default)]
    pub pinned_addresses: Vec<IpAddr>,
    /// Exact currently selected connection ID. Required for a real replacement.
    #[arg(long)]
    pub expected_connection_id: Option<String>,
}
#[derive(clap::Subcommand)]
pub enum Action {
    /// Explicitly activate, synchronize, withdraw, or report optional team Runtime
    Enrollment {
        #[command(subcommand)]
        action: super::team_enrollment::Action,
    },
    /// Review, publish and roll back policies on the selected team authority
    Rollout {
        #[command(subcommand)]
        action: super::team_rollout::Action,
    },
    /// Authenticate and save an optional team connection; does not enroll Runtime
    Connect {
        #[command(flatten)]
        options: ConnectRequest,
        #[arg(long)]
        json: bool,
    },
    /// Inspect local selection; --refresh explicitly contacts the selected authority
    Status {
        #[arg(long)]
        refresh: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove the exact selected connection; separate enrollment is left unchanged
    Disconnect {
        #[arg(long)]
        expected_connection_id: String,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Serialize)]
pub struct ConnectionView {
    pub connection: ConnectionStatus,
    pub storage: StorageOutcome,
    pub notice: &'static str,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageOutcome {
    Observed,
    Unchanged,
    Saved,
    Disconnected,
    SavedWithRecovery,
}
const NOTICE:&str="A saved connection does not enable team policy, enroll this device, or prove policy adoption. Personal protection does not require a team connection. Separate enrollment is unchanged.";
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn network_allowed() -> Result<(), String> {
    if super::offline_env_active() {
        Err("team authority contact is disabled by offline mode".into())
    } else {
        Ok(())
    }
}
fn id(value: &str) -> Result<Id, String> {
    Id::parse(value).map_err(|_| "a canonical non-nil connection UUID is required".into())
}
fn replacement_allowed(
    current: Option<&Id>,
    expected: Option<&Id>,
    same: bool,
) -> Result<(), String> {
    match (current,expected) {
  (None,None)=>Ok(()),(Some(a),Some(b)) if a==b=>Ok(()),(Some(_),None) if same=>Ok(()),
  _=>Err("selected connection changed or replacement was not explicitly selected; inspect status and use its exact connection ID".into())
 }
}
pub struct ConnectionService;
impl ConnectionService {
    pub fn current(refresh: bool) -> Result<ConnectionView, String> {
        if refresh {
            network_allowed()?
        }
        let selection = SelectedConnection::capture_current().map_err(error)?;
        Ok(ConnectionView {
            connection: selection.status(refresh).map_err(error)?,
            storage: StorageOutcome::Observed,
            notice: NOTICE,
        })
    }
    pub fn connect(request: ConnectRequest) -> Result<ConnectionView, String> {
        network_allowed()?;
        if request.server_url.len() > 2048
            || request.pinned_addresses.len() > 8
            || request.credential_file.as_os_str().len() > 8192
            || request
                .private_ca_file
                .as_ref()
                .is_some_and(|p| p.as_os_str().len() > 8192)
        {
            return Err("team connection input exceeds its fixed bound".into());
        }
        let expected = request
            .expected_connection_id
            .as_deref()
            .map(id)
            .transpose()?;
        let original = SelectedConnection::capture_current().map_err(error)?;
        // Wrong explicit IDs refuse before reading the selected credential or network.
        if let Some(expected) = &expected {
            replacement_allowed(original.connection_id(), Some(expected), false)?
        }
        let proposed = PreparedConnection::discover(
            AuthorityBinding {
                schema_version: SCHEMA_VERSION,
                base_url: request.server_url,
                authority_id: id(&request.authority_id)?,
                policy_id: id(&request.policy_id)?,
                transport: EndpointOptions {
                    pinned_addresses: request.pinned_addresses,
                    additional_ca_pem: None,
                },
            },
            &request.credential_file,
            request.private_ca_file.as_deref(),
        )
        .map_err(error)?;
        let same = proposed.same_selection(&original);
        replacement_allowed(original.connection_id(), expected.as_ref(), same)?;
        original.revalidate().map_err(error)?;
        proposed.revalidate().map_err(error)?;
        if same {
            return Ok(ConnectionView {
                connection: proposed
                    .authenticated_existing_status(&original)
                    .map_err(error)?,
                storage: StorageOutcome::Unchanged,
                notice: NOTICE,
            });
        }
        let bytes = proposed.private_bytes().map_err(error)?;
        let outcome = setup::update_private_team_connection(
            original.private_path(),
            original.private_scope(),
            |snapshot| {
                if !original.matches_private_bytes(snapshot.bytes()) {
                    return Err("selected connection changed before save".into());
                }
                let content = std::str::from_utf8(bytes.as_bytes())
                    .map_err(|_| "invalid private connection encoding")?
                    .to_owned();
                Ok(FileUpdate::write_text(content, 0o600)
                    .with_exact_mode()
                    .with_backup(false))
            },
            || {
                original.revalidate().map_err(error)?;
                proposed.revalidate().map_err(error)
            },
        )
        // Native error details can contain private paths. Do not project them.
        .map_err(|_| {
            "connection save was not confirmed; inspect local status before retrying".to_string()
        })?;
        drop(original);
        let saved = SelectedConnection::capture_current().map_err(|_| {
            "connection was written but its current private state could not be confirmed"
                .to_string()
        })?;
        if !saved.matches_private_bytes(Some(bytes.as_bytes())) {
            return Err("connection changed after save; inspect local status".into());
        }
        saved.revalidate().map_err(error)?;
        proposed.revalidate().map_err(error)?;
        Ok(ConnectionView {
            connection: proposed.status(),
            storage: match outcome {
                TransactionOutcome::Written => StorageOutcome::Saved,
                TransactionOutcome::WrittenWithRecovery => StorageOutcome::SavedWithRecovery,
                _ => return Err("unexpected connection publication result".into()),
            },
            notice: NOTICE,
        })
    }
    pub fn disconnect(expected_connection_id: &str) -> Result<ConnectionView, String> {
        let expected = id(expected_connection_id)?;
        let original = SelectedConnection::capture_current().map_err(error)?;
        if !original.configured() {
            return Ok(ConnectionView {
                connection: original.status(false).map_err(error)?,
                storage: StorageOutcome::Unchanged,
                notice: NOTICE,
            });
        }
        replacement_allowed(original.connection_id(), Some(&expected), false)?;
        setup::delete_private_team_connection(
            original.private_path(),
            original.private_scope(),
            |bytes| original.matches_private_bytes(bytes),
            || original.revalidate().map_err(error),
        )
        .map_err(|_| {
            "disconnect was not confirmed; inspect local status before retrying".to_string()
        })?;
        // Windows delete-pending becomes absence only after our read witness closes.
        drop(original);
        let current = SelectedConnection::capture_current().map_err(|_| {
            "disconnect was requested but absence is not yet confirmed; inspect local status"
                .to_string()
        })?;
        if current.configured() {
            return Err("a connection appeared after disconnect; inspect local status".into());
        }
        Ok(ConnectionView {
            connection: current.status(false).map_err(error)?,
            storage: StorageOutcome::Disconnected,
            notice: NOTICE,
        })
    }
}
pub fn run(action: Action) -> i32 {
    let (result, json) = match action {
        Action::Rollout { action } => return super::team_rollout::run(action),
        Action::Enrollment { action } => return super::team_enrollment::run(action),
        Action::Connect { options, json } => (ConnectionService::connect(options), json),
        Action::Status { refresh, json } => (ConnectionService::current(refresh), json),
        Action::Disconnect {
            expected_connection_id,
            json,
        } => (ConnectionService::disconnect(&expected_connection_id), json),
    };
    match result {
        Ok(view) => {
            if json {
                if super::write_json_stdout(&view, "cannot write team connection status") {
                    0
                } else {
                    1
                }
            } else {
                let c = &view.connection;
                println!(
                    "Team connection: {}",
                    if c.configured {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
                if let Some(id) = &c.connection_id {
                    println!("Connection ID: {}", id.as_str())
                }
                if let Some(role) = c.role {
                    println!("Authenticated role: {role:?}")
                }
                println!("{}", view.notice);
                0
            }
        }
        Err(message) => {
            if json {
                super::write_json_stdout(
                    &serde_json::json!({"schema_version":1,"error":message,"execution_permitted":false}),
                    "cannot write team connection error",
                );
            } else {
                eprintln!("tirith: {message}");
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_create_and_exact_idempotence_are_distinct_from_replacement() {
        let a = Id::new();
        let b = Id::new();
        assert!(replacement_allowed(None, None, false).is_ok());
        assert!(replacement_allowed(Some(&a), None, true).is_ok());
        assert!(replacement_allowed(Some(&a), None, false).is_err());
        assert!(replacement_allowed(Some(&a), Some(&b), true).is_err());
        assert!(replacement_allowed(None, Some(&a), false).is_err());
        assert!(replacement_allowed(Some(&a), Some(&a), false).is_ok());
    }
    #[test]
    fn browser_input_does_not_accept_token_or_runtime_enablement() {
        let base = serde_json::json!({"server_url":"https://example.com","authority_id":Id::new(),"policy_id":Id::new(),"credential_file":"/private/selected"});
        for field in ["token", "credential", "runtime_enabled", "enrolled"] {
            let mut v = base.clone();
            v[field] = serde_json::json!("secret");
            assert!(serde_json::from_value::<ConnectRequest>(v).is_err());
        }
    }
    #[test]
    fn nil_and_noncanonical_expected_ids_refuse() {
        assert!(id("00000000-0000-0000-0000-000000000000").is_err());
        assert!(id("E029DFA0-7008-401A-87E7-BF93F4715D47").is_err());
    }
}
