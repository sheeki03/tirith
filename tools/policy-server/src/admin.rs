use clap::{Parser, Subcommand, ValueEnum};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tirith_core::policy_team::{ErrorCode, Id, Role, MAX_POLICY_BYTES};
use tirith_policy_server::{http, private_fs, store::Store};
#[derive(Parser)]
#[command(
    name = "tirith-policy-server",
    version,
    about = "Explicit, optional self-hosted team policy authority"
)]
struct Args {
    /// Existing private absolute directory; init creates only this final directory.
    #[arg(long)]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        policy: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8778")]
        listen: SocketAddr,
    },
    Identity,
    Credentials {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
    },
    Import {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
        #[arg(long,value_parser=parse_id)]
        expected_revision: Id,
        #[arg(long)]
        policy: PathBuf,
    },
    IssueCredential {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
        #[arg(long, value_enum)]
        role: CredentialRole,
        #[arg(long,value_parser=parse_id)]
        principal: Id,
        #[arg(long,value_parser=parse_id)]
        client: Option<Id>,
        #[arg(long)]
        expires_unix_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    RevokeCredential {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
        #[arg(long,value_parser=parse_id)]
        credential: Id,
    },
    RegisterClient {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
        #[arg(long,value_parser=parse_id)]
        expected_roster: Id,
    },
    DeactivateClient {
        #[arg(long,value_parser=parse_id)]
        authority: Id,
        #[arg(long,value_parser=parse_id)]
        expected_roster: Id,
        #[arg(long,value_parser=parse_id)]
        client: Id,
    },
}
#[derive(Clone, ValueEnum)]
enum CredentialRole {
    Publisher,
    Observer,
    Client,
}
impl From<CredentialRole> for Role {
    fn from(value: CredentialRole) -> Self {
        match value {
            CredentialRole::Publisher => Self::Publisher,
            CredentialRole::Observer => Self::Observer,
            CredentialRole::Client => Self::Client,
        }
    }
}
fn parse_id(value: &str) -> Result<Id, String> {
    Id::parse(value).map_err(|_| "canonical nonzero UUID required".into())
}
fn policy(path: &std::path::Path) -> Result<String, ErrorCode> {
    let bytes =
        private_fs::read_input(path, MAX_POLICY_BYTES).map_err(|_| ErrorCode::InvalidPolicy)?;
    String::from_utf8(bytes).map_err(|_| ErrorCode::InvalidPolicy)
}
pub fn run() -> Result<(), ErrorCode> {
    let args = Args::parse();
    private_fs::ordinary_owner().map_err(|_| ErrorCode::Forbidden)?;
    if let Command::Init { policy: input } = &args.command {
        let store = Store::initialize(&args.data_dir, &policy(input)?)?;
        return print_identity(&store);
    }
    // Read the selected input before opening SQLite. Even an accidental input
    // alias of the database must never create/drop a foreign descriptor while
    // this process has a live SQLite connection.
    let import_input = if let Command::Import { policy: input, .. } = &args.command {
        Some(policy(input)?)
    } else {
        None
    };
    let store = Store::open(&args.data_dir)?;
    match args.command {
        Command::Init { .. } => Err(ErrorCode::InvalidRequest),
        Command::Identity => print_identity(&store),
        Command::Credentials { authority } => {
            let rows = store.credentials(&authority)?;
            println!(
                "{}",
                serde_json::to_string(&rows).map_err(|_| ErrorCode::StorageUnavailable)?
            );
            Ok(())
        }
        Command::Serve { listen } => {
            if !listen.ip().is_loopback() {
                return Err(ErrorCode::InvalidRequest);
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(32)
                .enable_all()
                .build()
                .map_err(|_| ErrorCode::StorageUnavailable)?;
            runtime.block_on(http::serve(Arc::new(store), listen))
        }
        Command::Import {
            authority,
            expected_revision,
            policy: _,
        } => {
            let revision = store.import(
                &authority,
                &expected_revision,
                import_input.as_deref().ok_or(ErrorCode::InvalidRequest)?,
            )?;
            println!("revision={}", revision.as_str());
            Ok(())
        }
        Command::IssueCredential {
            authority,
            role,
            principal,
            client,
            expires_unix_ms,
            output,
        } => {
            let credential = store.issue_credential(
                &authority,
                role.into(),
                &principal,
                client.as_ref(),
                expires_unix_ms,
                &output,
            )?;
            println!("credential_id={}", credential.as_str());
            println!("credential_file={}", output.display());
            Ok(())
        }
        Command::RevokeCredential {
            authority,
            credential,
        } => store.revoke(&authority, &credential),
        Command::RegisterClient {
            authority,
            expected_roster,
        } => {
            let client = store.register_client(&authority, &expected_roster)?;
            println!("client_id={}", client.as_str());
            print_identity(&store)
        }
        Command::DeactivateClient {
            authority,
            expected_roster,
            client,
        } => {
            store.deactivate_client(&authority, &expected_roster, &client)?;
            print_identity(&store)
        }
    }
}
fn print_identity(store: &Store) -> Result<(), ErrorCode> {
    let value = store.identity()?;
    println!(
        "authority_id={}\npolicy_id={}\nrevision={}\nroster_revision={}",
        value.authority_id.as_str(),
        value.policy_id.as_str(),
        value.current_revision.as_str(),
        value.roster_revision.as_str()
    );
    Ok(())
}
