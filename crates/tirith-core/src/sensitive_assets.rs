//! Central sensitive-asset registry.
//!
//! This module is deliberately the only place that knows the complete set of
//! credential environment names, wallet paths, structural Web3 secret formats,
//! and Web3/RPC redaction aliases. Observations carry classification metadata
//! only: raw values, prefixes, and stable hashes are never retained.

use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::ops::Range;
use unicode_normalization::UnicodeNormalization as _;

/// The upstream snapshot used for the vendored BIP-39 English wordlist.
pub const BIP39_ENGLISH_SOURCE_REVISION: &str =
    "bitcoin/bips@ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e";
pub const BIP39_ENGLISH_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveEnvKind {
    Credential,
    EvmPrivateKey,
    Mnemonic,
    SolanaKeypair,
    Password,
    RpcEndpoint,
}

impl SensitiveEnvKind {
    /// Public RPC endpoint locations are configuration, not credentials. Their
    /// URL values still pass through the RPC canonicalizer, but the variable
    /// name itself must not trigger credential-export or capsule stripping.
    pub const fn is_secret(self) -> bool {
        !matches!(self, Self::RpcEndpoint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveEnvDefinition {
    pub name: &'static str,
    pub kind: SensitiveEnvKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveEnvPrefixDefinition {
    pub prefix: &'static str,
    pub kind: SensitiveEnvKind,
}

macro_rules! sensitive_env_catalog {
    ($($name:literal => $kind:ident),+; rpc { $($rpc_name:literal),+ $(,)? }) => {
        /// Typed sensitive environment registry. Every detector and redactor
        /// derives its exact and prefix behavior from these entries.
        pub const SENSITIVE_ENV_DEFINITIONS: &[SensitiveEnvDefinition] = &[
            $(SensitiveEnvDefinition { name: $name, kind: SensitiveEnvKind::$kind },)+
            $(SensitiveEnvDefinition { name: $rpc_name, kind: SensitiveEnvKind::RpcEndpoint },)+
        ];

        /// Exact secret-bearing names, emitted by the same catalog declaration
        /// as the typed definitions for compatibility consumers.
        pub const SECRET_ENV_NAMES: &[&str] = &[$($name,)+];
    };
}

sensitive_env_catalog! {
    "AWS_ACCESS_KEY_ID" => Credential,
    "AWS_SECRET_ACCESS_KEY" => Credential,
    "AWS_SESSION_TOKEN" => Credential,
    "AWS_SECURITY_TOKEN" => Credential,
    "AWS_WEB_IDENTITY_TOKEN_FILE" => Credential,
    "AWS_CONTAINER_AUTHORIZATION_TOKEN" => Credential,
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => Credential,
    "AWS_CONTAINER_CREDENTIALS_FULL_URI" => Credential,
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => Credential,
    "AZURE_CLIENT_SECRET" => Credential,
    "GOOGLE_APPLICATION_CREDENTIALS" => Credential,
    "GOOGLE_API_KEY" => Credential,
    "GOOGLE_OAUTH_ACCESS_TOKEN" => Credential,
    "GITHUB_TOKEN" => Credential,
    "GH_TOKEN" => Credential,
    "NPM_TOKEN" => Credential,
    "NODE_AUTH_TOKEN" => Credential,
    "PYPI_TOKEN" => Credential,
    "OPENAI_API_KEY" => Credential,
    "ANTHROPIC_API_KEY" => Credential,
    "STRIPE_API_KEY" => Credential,
    "DOCKER_PASSWORD" => Password,
    "DOCKER_CONFIG" => Credential,
    "DOCKER_AUTH_CONFIG" => Credential,
    "KUBECONFIG" => Credential,
    "SLACK_TOKEN" => Credential,
    "SSH_AUTH_SOCK" => Credential,
    "GPG_AGENT_INFO" => Credential,
    "PRIVATE_KEY" => EvmPrivateKey,
    "DEPLOYER_PRIVATE_KEY" => EvmPrivateKey,
    "WALLET_PRIVATE_KEY" => EvmPrivateKey,
    "ETH_PRIVATE_KEY" => EvmPrivateKey,
    "EVM_PRIVATE_KEY" => EvmPrivateKey,
    "FOUNDRY_PRIVATE_KEY" => EvmPrivateKey,
    "MNEMONIC" => Mnemonic,
    "SEED_PHRASE" => Mnemonic,
    "WALLET_MNEMONIC" => Mnemonic,
    "SOLANA_KEYPAIR" => SolanaKeypair,
    "SOLANA_KEYPAIR_PATH" => SolanaKeypair,
    "ANCHOR_WALLET" => SolanaKeypair,
    "KEYSTORE_PASSWORD" => Password,
    "WALLET_PASSWORD" => Password,
    "UV_INDEX_URL" => Credential,
    "PIP_INDEX_URL" => Credential,
    "PIP_EXTRA_INDEX_URL" => Credential,
    "TWINE_PASSWORD" => Password,
    "TWINE_TOKEN" => Credential,
    "RPC_API_KEY" => Credential,
    "JWT_SECRET" => Credential;
    rpc {
        "RPC_URL",
        "ETH_RPC_URL",
        "SOLANA_RPC_URL",
    }
}

/// Typed prefix families. Every consumer goes through [`sensitive_env_kind`]
/// instead of maintaining an exact-only list that silently misses new members.
macro_rules! sensitive_env_prefix_catalog {
    ($($prefix:literal => $kind:ident),+ $(,)?) => {
        pub const SENSITIVE_ENV_PREFIX_DEFINITIONS: &[SensitiveEnvPrefixDefinition] = &[
            $(SensitiveEnvPrefixDefinition {
                prefix: $prefix,
                kind: SensitiveEnvKind::$kind,
            },)+
        ];
        pub const SECRET_ENV_PREFIXES: &[&str] = &[$($prefix,)+];
    };
}

sensitive_env_prefix_catalog! {
    "AWS_SECRET_" => Credential,
    "AWS_SESSION_TOKEN_" => Credential,
    "AWS_SECURITY_TOKEN_" => Credential,
    "AZURE_CLIENT_SECRET_" => Credential,
    "GOOGLE_API_KEY_" => Credential,
    "GOOGLE_OAUTH_ACCESS_TOKEN_" => Credential,
    "TWINE_PASSWORD_" => Password,
    "TWINE_TOKEN_" => Credential,
}

/// Stable compatibility view of exact secret-bearing environment names.
/// RPC endpoint names are deliberately absent because sensitivity is
/// determined from their value.
pub fn secret_env_names() -> &'static [&'static str] {
    SECRET_ENV_NAMES
}

/// Capsule-only compatibility families. Runtime containment historically denied
/// provider credential *and credential-control* variables more broadly than the
/// command detector: a hostile child must not inherit an alternate AWS metadata
/// endpoint, shared-credentials path, profile selector, or registry credential
/// control merely because its value is not itself a token. Keep that stronger
/// boundary in the central registry without teaching ordinary prose/assignment
/// detection that every `AWS_*` or `TWINE_*` spelling is a secret alias.
pub const CAPSULE_SENSITIVE_ENV_EXACT: &[&str] = &[
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DOCKER_CONFIG",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_ENDPOINT_URL",
    "AWS_CA_BUNDLE",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_RETRY_MODE",
    "AWS_MAX_ATTEMPTS",
    "AWS_USE_FIPS_ENDPOINT",
    "AWS_USE_DUALSTACK_ENDPOINT",
    "AWS_ACCOUNT_ID",
    "AWS_ACCOUNT_ID_ENDPOINT_MODE",
    "AWS_IMDS_USE_IPV6",
    "AWS_EC2_METADATA_V1_DISABLED",
    "AWS_METADATA_SERVICE_TIMEOUT",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
    "AZURE_CONFIG_DIR",
    "AZURE_AUTH_LOCATION",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GOOGLE_CLOUD_UNIVERSE_DOMAIN",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_DEFAULT_INDEX",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_CONFIG_FILE",
    "PIP_TRUSTED_HOST",
    "PIP_CERT",
    "PIP_CLIENT_CERT",
    "TWINE_USERNAME",
    "TWINE_PASSWORD",
    "TWINE_REPOSITORY",
    "TWINE_REPOSITORY_URL",
    "TWINE_CERT",
    "TWINE_CLIENT_CERT",
    "TWINE_NON_INTERACTIVE",
];

/// Capsule-only family prefixes preserved from the pre-registry containment
/// contract. These are intentionally broader than ordinary secret aliases: a
/// hostile child must not inherit provider selector/control variables merely
/// because a particular spelling is not itself a credential value.
pub const CAPSULE_SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "UV_INDEX",
    "PIP_INDEX",
    "TWINE_",
];

/// Capsule name classification is deliberately canonical environment syntax,
/// not the human-friendly alias grammar used for config keys. This preserves the
/// historical all-family containment deny while preventing aliases such as
/// `AWS_SECRETARY` from becoming Web3/credential findings in normal analysis.
pub fn is_capsule_sensitive_env_name(name: &str) -> bool {
    let name = name.trim().to_ascii_uppercase();
    CAPSULE_SENSITIVE_ENV_EXACT
        .iter()
        .any(|exact| name == *exact)
        || CAPSULE_SENSITIVE_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || is_sensitive_env_name(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivePathMatchMode {
    ComponentRoot,
    AbsoluteRoot,
    BasenameExact,
    BasenameSuffix,
    BrowserExtensionId,
    BrowserStorageRoot,
    BrowserSourceRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivePathKind {
    Credential,
    EncryptedKeystore,
    SolanaKeypair,
    WalletDatabase,
    DesktopWalletData,
    BrowserWalletStorage,
    PrivilegedSystem,
}

/// One reviewed path definition drives command/exfil classification, container
/// bind protection, and capsule deny-root generation. `bind_root` may be a
/// parent of `match_root` when mounting the parent exposes the sensitive child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitivePathDefinition {
    pub match_mode: SensitivePathMatchMode,
    pub match_root: &'static str,
    pub bind_root: Option<&'static str>,
    pub capsule_relative: Option<&'static str>,
    pub kind: SensitivePathKind,
}

macro_rules! home_path {
    ($root:literal, $bind:literal, $kind:ident) => {
        SensitivePathDefinition {
            match_mode: SensitivePathMatchMode::ComponentRoot,
            match_root: $root,
            bind_root: Some($bind),
            capsule_relative: Some($root),
            kind: SensitivePathKind::$kind,
        }
    };
}

macro_rules! absolute_path {
    ($root:literal, $bind:expr, $kind:ident) => {
        SensitivePathDefinition {
            match_mode: SensitivePathMatchMode::AbsoluteRoot,
            match_root: $root,
            bind_root: $bind,
            capsule_relative: None,
            kind: SensitivePathKind::$kind,
        }
    };
}

macro_rules! classified_path {
    ($mode:ident, $root:literal, $kind:ident) => {
        SensitivePathDefinition {
            match_mode: SensitivePathMatchMode::$mode,
            match_root: $root,
            bind_root: None,
            capsule_relative: None,
            kind: SensitivePathKind::$kind,
        }
    };
    ($mode:ident, $root:literal, $capsule:literal, $kind:ident) => {
        SensitivePathDefinition {
            match_mode: SensitivePathMatchMode::$mode,
            match_root: $root,
            bind_root: None,
            capsule_relative: Some($capsule),
            kind: SensitivePathKind::$kind,
        }
    };
}

pub const SENSITIVE_PATH_DEFINITIONS: &[SensitivePathDefinition] = &[
    home_path!(".ssh", ".ssh", Credential),
    home_path!(".aws", ".aws", Credential),
    home_path!(".azure", ".azure", Credential),
    home_path!(".config/gcloud", ".config/gcloud", Credential),
    home_path!(".gnupg", ".gnupg", Credential),
    home_path!(".kube", ".kube", Credential),
    home_path!(".docker/config.json", ".docker", Credential),
    home_path!(".netrc", ".netrc", Credential),
    home_path!(".npmrc", ".npmrc", Credential),
    home_path!(".pypirc", ".pypirc", Credential),
    home_path!(".git-credentials", ".git-credentials", Credential),
    home_path!(".config/gh", ".config/gh", Credential),
    home_path!(".cargo/credentials.toml", ".cargo", Credential),
    home_path!(".ethereum/keystore", ".ethereum", EncryptedKeystore),
    home_path!(
        "Library/Ethereum/keystore",
        "Library/Ethereum",
        EncryptedKeystore
    ),
    home_path!(
        "AppData/Roaming/Ethereum/keystore",
        "AppData/Roaming/Ethereum",
        EncryptedKeystore
    ),
    home_path!(".config/solana", ".config/solana", SolanaKeypair),
    home_path!(".electrum/wallets", ".electrum", WalletDatabase),
    home_path!(
        "Library/Application Support/Electrum/wallets",
        "Library/Application Support/Electrum",
        WalletDatabase
    ),
    home_path!(
        "AppData/Roaming/Electrum/wallets",
        "AppData/Roaming/Electrum",
        WalletDatabase
    ),
    home_path!("wallet.dat", "wallet.dat", WalletDatabase),
    home_path!(".bitcoin/wallet.dat", ".bitcoin", WalletDatabase),
    home_path!(
        "Library/Application Support/Bitcoin/wallet.dat",
        "Library/Application Support/Bitcoin",
        WalletDatabase
    ),
    home_path!(
        "AppData/Roaming/Bitcoin/wallet.dat",
        "AppData/Roaming/Bitcoin",
        WalletDatabase
    ),
    home_path!(
        ".config/Exodus/exodus.wallet",
        ".config/Exodus",
        DesktopWalletData
    ),
    home_path!(
        "Library/Application Support/Exodus/exodus.wallet",
        "Library/Application Support/Exodus",
        DesktopWalletData
    ),
    home_path!(
        "AppData/Roaming/Exodus/exodus.wallet",
        "AppData/Roaming/Exodus",
        DesktopWalletData
    ),
    home_path!(".config/atomic", ".config/atomic", DesktopWalletData),
    home_path!(
        "Library/Application Support/atomic",
        "Library/Application Support/atomic",
        DesktopWalletData
    ),
    home_path!(
        "AppData/Roaming/atomic",
        "AppData/Roaming/atomic",
        DesktopWalletData
    ),
    home_path!(
        ".config/Ledger Live",
        ".config/Ledger Live",
        DesktopWalletData
    ),
    home_path!(
        "Library/Application Support/Ledger Live",
        "Library/Application Support/Ledger Live",
        DesktopWalletData
    ),
    home_path!(
        "AppData/Roaming/Ledger Live",
        "AppData/Roaming/Ledger Live",
        DesktopWalletData
    ),
    absolute_path!("/etc", Some("/etc"), PrivilegedSystem),
    absolute_path!(
        "/var/run/docker.sock",
        Some("/var/run/docker.sock"),
        PrivilegedSystem
    ),
    absolute_path!(
        "/run/docker.sock",
        Some("/run/docker.sock"),
        PrivilegedSystem
    ),
    absolute_path!(
        "/var/run/podman/podman.sock",
        Some("/var/run/podman/podman.sock"),
        PrivilegedSystem
    ),
    classified_path!(
        BasenameExact,
        "solana-keypair.json",
        "solana-keypair.json",
        SolanaKeypair
    ),
    // A basename suffix cannot be represented by recursive OS deny-root APIs.
    // Deny the conventional keypair parent used by Solana deployment tooling;
    // `.config/solana` is independently covered above.
    classified_path!(BasenameSuffix, "-keypair.json", "keys", SolanaKeypair),
    classified_path!(
        BrowserExtensionId,
        "nkbihfbeogaeaoehlefnkodbefgpgknn",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserExtensionId,
        "bfnaelmomeimhlpmgjnjophhpkkoljpa",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserExtensionId,
        "acmacodkjbdgmoleebolmdjonilkdbch",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserExtensionId,
        "dmkamcknogkgcdfhhbddcghachkejeap",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserExtensionId,
        "hnfanknocfeofbddgcijnmhnfnkdnaad",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserStorageRoot,
        "Local Extension Settings",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserStorageRoot,
        "Sync Extension Settings",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserStorageRoot,
        "IndexedDB/chrome-extension_",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserStorageRoot,
        "IndexedDB/moz-extension_",
        BrowserWalletStorage
    ),
    classified_path!(
        BrowserStorageRoot,
        "Local Storage/leveldb",
        BrowserWalletStorage
    ),
    classified_path!(BrowserSourceRoot, "Extensions", BrowserWalletStorage),
];

/// Browser stores are profile-shaped (`Default`, `Profile 1`, arbitrary Firefox
/// profile IDs), while capsule backends enforce concrete recursive roots rather
/// than globs. Denying the reviewed browser user-data parents is the smallest
/// enforceable representation that covers every wallet extension/storage entry
/// without pretending a basename or extension-ID glob reached the OS boundary.
pub const CAPSULE_BROWSER_DATA_ROOTS: &[&str] = &[
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".mozilla/firefox",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Firefox/Profiles",
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Chromium/User Data",
    "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "AppData/Roaming/Mozilla/Firefox/Profiles",
];

/// Non-path terms that cheaply admit output-side read-and-send directives.
/// Reviewed paths themselves come only from [`SENSITIVE_PATH_DEFINITIONS`].
pub const OUTPUT_SENSITIVE_TERMS: &[&str] = &[".env", "id_rsa", "credentials", "secret"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveAssetKind {
    ProviderCredential,
    PrivateKeyBlock,
    EvmPrivateKey,
    Bip39Mnemonic,
    SolanaKeypair,
    EncryptedKeystore,
    WalletDatabase,
    BrowserWalletStorage,
    DesktopWalletData,
    WalletEnvironmentReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveLocationClass {
    EnvironmentName,
    InlineValue,
    FilePath,
    ApplicationData,
    BrowserExtensionData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveSourceClass {
    Literal,
    SymbolicReference,
    LocalFile,
    ApplicationStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMethod {
    EnvironmentRegistry,
    Secp256k1Scalar,
    Bip39EnglishChecksum,
    Ed25519PublicHalf,
    JsonKeystoreShape,
    ReviewedPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Medium,
    High,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionClass {
    SecretValue,
    SensitiveReference,
    PrivatePath,
    CanonicalRpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionContext {
    Exec,
    Paste,
    FileScan,
    Exfiltration,
    Redaction,
    Capsule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcProvider {
    Infura,
    Alchemy,
    Moralis,
    Chainstack,
    GetBlock,
    QuickNode,
    Ankr,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcPathClass {
    Root,
    Rpc,
    JsonRpc,
    Versioned,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcCredentialClass {
    Public,
    UserInfo,
    Query,
    Fragment,
    HostToken,
    PathToken,
    Multiple,
}

/// Private wire projection used to validate deserialization and revalidate
/// every Debug/Serialize boundary after callers have had mutable field access.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEndpointProjection {
    scheme: String,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    provider: RpcProvider,
    path_class: RpcPathClass,
    credential_class: RpcCredentialClass,
}

/// Secret-free RPC projection suitable for findings, Debug, and JSON.
///
/// A private seal prevents direct construction outside this module. Public
/// fields preserve the existing read API; mandatory custom Debug/Serialize
/// implementations revalidate them so post-construction mutation fails closed
/// instead of emitting attacker-controlled material.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcEndpointSummary {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub provider: RpcProvider,
    pub path_class: RpcPathClass,
    pub credential_class: RpcCredentialClass,
    _validated: ValidatedRpcEndpoint,
}

#[derive(Clone, PartialEq, Eq)]
struct ValidatedRpcEndpoint;

impl std::fmt::Debug for RpcEndpointSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let projection = self.projection();
        if !validate_rpc_endpoint_projection(&projection) {
            return formatter.write_str("RpcEndpointSummary(INVALID)");
        }
        formatter
            .debug_struct("RpcEndpointSummary")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("provider", &self.provider)
            .field("path_class", &self.path_class)
            .field("credential_class", &self.credential_class)
            .finish()
    }
}

impl serde::Serialize for RpcEndpointSummary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let projection = self.projection();
        if !validate_rpc_endpoint_projection(&projection) {
            return Err(<S::Error as serde::ser::Error>::custom(
                "invalid public RPC endpoint projection",
            ));
        }
        serde::Serialize::serialize(&projection, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RpcEndpointSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let projection = <RpcEndpointProjection as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_projection(projection).ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("invalid public RPC endpoint projection")
        })
    }
}

impl RpcEndpointSummary {
    fn from_projection(projection: RpcEndpointProjection) -> Option<Self> {
        validate_rpc_endpoint_projection(&projection).then_some(Self {
            scheme: projection.scheme,
            host: projection.host,
            port: projection.port,
            provider: projection.provider,
            path_class: projection.path_class,
            credential_class: projection.credential_class,
            _validated: ValidatedRpcEndpoint,
        })
    }

    fn projection(&self) -> RpcEndpointProjection {
        RpcEndpointProjection {
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            port: self.port,
            provider: self.provider,
            path_class: self.path_class,
            credential_class: self.credential_class,
        }
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    pub const fn provider(&self) -> RpcProvider {
        self.provider
    }

    pub const fn path_class(&self) -> RpcPathClass {
        self.path_class
    }

    pub const fn credential_class(&self) -> RpcCredentialClass {
        self.credential_class
    }
}

/// Safe classification metadata. Intentionally does not implement Serialize and
/// contains no value, prefix, path, digest, or other stable secret identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveAssetObservation {
    pub kind: SensitiveAssetKind,
    pub confidence: Confidence,
    pub validation: ValidationMethod,
    pub source_class: SensitiveSourceClass,
    pub location_class: SensitiveLocationClass,
    pub redaction_class: RedactionClass,
}

#[derive(Debug, Clone)]
pub(crate) struct SensitiveSpan {
    pub kind: SensitiveAssetKind,
    pub range: Range<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct SensitiveValueRedactionSpan {
    pub range: Range<usize>,
    pub replacement: String,
    pub priority: u16,
}

/// Namespace type making the ownership boundary explicit at call sites.
#[derive(Debug, Clone, Copy, Default)]
pub struct SensitiveAssetRegistry;

impl SensitiveAssetRegistry {
    pub fn observe(input: &str, context: DetectionContext) -> Vec<SensitiveAssetObservation> {
        observations(input, context)
    }

    pub fn classify_path(path: &str) -> Option<SensitiveAssetObservation> {
        classify_path(path)
    }

    pub fn is_sensitive_env_name(name: &str) -> bool {
        is_sensitive_env_name(name)
    }

    pub fn redact(input: &str) -> String {
        redact_sensitive_values(input)
    }
}

static BIP39_ENGLISH: Lazy<Vec<&'static str>> = Lazy::new(|| {
    let words: Vec<_> = include_str!("../assets/data/bip39_english.txt")
        .lines()
        .collect();
    assert_eq!(
        words.len(),
        2048,
        "vendored BIP-39 wordlist must have 2048 words"
    );
    assert!(
        words.windows(2).all(|pair| pair[0] < pair[1]),
        "BIP-39 wordlist must stay sorted"
    );
    words
});

fn alias_spellings(name: &str) -> Vec<String> {
    let words = name
        .trim_matches('_')
        .split('_')
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let capitalize = |word: &str| {
        let mut characters = word.chars();
        characters.next().map_or_else(String::new, |first| {
            first.to_ascii_uppercase().to_string() + characters.as_str()
        })
    };
    let camel = words.first().cloned().unwrap_or_default()
        + &words
            .iter()
            .skip(1)
            .map(|word| capitalize(word))
            .collect::<String>();
    let pascal = words
        .iter()
        .map(|word| capitalize(word))
        .collect::<String>();
    let mut variants = vec![
        words.join("_"),
        words.join("-"),
        words.join(""),
        camel,
        pascal,
    ];
    variants.sort();
    variants.dedup();
    variants
}

fn alias_variants(name: &str) -> Vec<String> {
    alias_spellings(name)
        .into_iter()
        .map(|alias| regex::escape(&alias))
        .collect()
}

fn prefix_alias_variants(prefix: &str) -> Vec<String> {
    let words = prefix
        .trim_matches('_')
        .split('_')
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if words.is_empty() {
        return Vec::new();
    }
    // Prefix families require a literal separator before the extension. Exact
    // names still accept snake/kebab/compact/camel/Pascal spellings through
    // `alias_variants`; families do not, because a compact starts-with grammar
    // makes unrelated identifiers such as AWS_SECRETARY and TWINE_TOKENIZER
    // indistinguishable from an intended family member.
    vec![
        format!(r"{}_[a-z0-9][a-z0-9_-]*", regex::escape(&words.join("_"))),
        format!(r"{}-[a-z0-9][a-z0-9_-]*", regex::escape(&words.join("-"))),
    ]
}

fn alias_alternation(kinds: &[SensitiveEnvKind], extras: &[&str]) -> String {
    let mut aliases = Vec::new();
    for definition in SENSITIVE_ENV_DEFINITIONS
        .iter()
        .filter(|definition| kinds.contains(&definition.kind))
    {
        aliases.extend(alias_variants(definition.name));
    }
    for definition in SENSITIVE_ENV_PREFIX_DEFINITIONS
        .iter()
        .filter(|definition| kinds.contains(&definition.kind))
    {
        aliases.extend(prefix_alias_variants(definition.prefix));
    }
    aliases.extend(extras.iter().map(|alias| (*alias).to_string()));
    aliases.sort();
    aliases.dedup();
    aliases.join("|")
}

static EVM_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    let aliases = alias_alternation(&[SensitiveEnvKind::EvmPrivateKey], &["private[-_]?key"]);
    RegexBuilder::new(&format!(
        r#"(?:\"?\b(?:{aliases})\b\"?[\t \r\n]*[:=][\t \r\n]*|--?(?:{aliases})(?:[\t ]*=[\t ]*|[\t ]+)|\bset(?:[\t ]+--?[a-z-]+)*[\t ]+(?:{aliases})[\t ]+)(?:\\\r?\n[\t ]*)?[\"']?(?P<value>(?:0x)?[0-9a-f]{{64}})\b"#
    ))
    .case_insensitive(true)
    .build()
    .expect("EVM context regex")
});

static MNEMONIC_CONTEXT_START_RE: Lazy<Regex> = Lazy::new(|| {
    let aliases = alias_alternation(
        &[SensitiveEnvKind::Mnemonic],
        &["mnemonic", "seed[-_]?phrase"],
    );
    RegexBuilder::new(&format!(
        r#"(?:\"?\b(?:{aliases})\b\"?[\t \r\n]*[:=][\t \r\n]*|--?(?:{aliases})(?:[\t ]*=[\t ]*|[\t ]+)|\bset(?:[\t ]+--?[a-z-]+)*[\t ]+(?:{aliases})[\t ]+)(?:\\\r?\n[\t ]*)?[\"']?"#
    ))
    .case_insensitive(true)
    .build()
    .expect("mnemonic context start regex")
});

static SOLANA_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(?:\s*[0-9]{1,3}\s*,){63}\s*[0-9]{1,3}\s*\]").expect("Solana keypair regex")
});

static WORD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\p{L}+").expect("Unicode word regex"));

// BIP-39 scanning is deliberately independent of the surrounding FileScan/MCP
// transport limits. Keeping an explicit local budget prevents a future caller
// from accidentally feeding an unbounded value into checksum recognition.
pub(crate) const MAX_BIP39_SCAN_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_BIP39_WORD_TOKENS: usize = 32_768;
pub(crate) const MAX_BIP39_CHECKSUM_CANDIDATES: usize = 16_384;
pub(crate) const MAX_BIP39_MATCHES: usize = 1_024;
const MAX_BIP39_WORDS_PER_PHRASE: usize = 24;
const MAX_BIP39_NORMALIZED_WORD_BYTES: usize = 16;

#[derive(Debug, Clone)]
struct Bip39WordRecord {
    range: Range<usize>,
    index: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Bip39ScanStats {
    bip39_word_tokens: usize,
    checksum_candidates: usize,
    confirmed_matches: usize,
    max_rolling_words: usize,
}

#[derive(Debug, Default)]
struct Bip39ScanResult {
    spans: Vec<SensitiveSpan>,
    incomplete: bool,
    stats: Bip39ScanStats,
}

#[derive(Debug, Default)]
struct StructuredSecretScan {
    spans: Vec<SensitiveSpan>,
    incomplete: bool,
}

#[derive(Debug, Default)]
pub(crate) struct SensitiveAssetScan {
    pub observations: Vec<SensitiveAssetObservation>,
    pub incomplete: bool,
}

fn bip39_word_index(word: &str) -> Option<u16> {
    // The pinned English list is lowercase ASCII. This is the overwhelmingly
    // common path and performs no allocation. The compatibility path also uses
    // a fixed stack buffer, so hostile non-ASCII prose cannot force one owned
    // String allocation per word while NFKD/full-width compatibility remains.
    let index = if word.is_ascii() {
        BIP39_ENGLISH.binary_search(&word).ok()?
    } else {
        let mut bytes = [0u8; MAX_BIP39_NORMALIZED_WORD_BYTES];
        let mut length = 0usize;
        for character in word.nfkd() {
            if !character.is_ascii() || length == bytes.len() {
                return None;
            }
            bytes[length] = character as u8;
            length += 1;
        }
        let normalized = std::str::from_utf8(&bytes[..length]).ok()?;
        BIP39_ENGLISH.binary_search(&normalized).ok()?
    };
    Some(index as u16)
}

static TIER1_ENV_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
    let aliases = alias_alternation(
        &[
            SensitiveEnvKind::Credential,
            SensitiveEnvKind::EvmPrivateKey,
            SensitiveEnvKind::Mnemonic,
            SensitiveEnvKind::SolanaKeypair,
            SensitiveEnvKind::Password,
            SensitiveEnvKind::RpcEndpoint,
        ],
        &[],
    );
    RegexBuilder::new(&format!(
        r#"(?:\"?\b(?:{aliases})\b\"?[\t \r\n]*[:=]|--?(?:{aliases})(?:[ \t]*=[ \t]*|[ \t]+)|\bset(?:[ \t]+--?[a-z-]+)*[ \t]+(?:{aliases})(?:[ \t]|$))"#
    ))
    .case_insensitive(true)
    .build()
    .expect("tier-1 sensitive env alias regex")
});

static TIER1_EVM_HEX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[^0-9a-f])(?:0x)?[0-9a-f]{64}(?:$|[^0-9a-f])")
        .expect("tier-1 EVM scalar shape")
});

fn has_bip39_word_run_candidate(input: &str) -> bool {
    // This predicate runs before Tier 3. Enforce the same byte budget before
    // constructing the regex iterator so an oversized Paste/FileScan is routed
    // to the fail-closed scanner without first tokenizing the entire value.
    if input.len() > MAX_BIP39_SCAN_INPUT_BYTES {
        return true;
    }
    let mut run = 0usize;
    let mut word_tokens = 0usize;
    let mut cursor = 0usize;
    for matched in WORD_RE.find_iter(input) {
        if !input[cursor..matched.start()]
            .chars()
            .all(char::is_whitespace)
        {
            run = 0;
        }
        cursor = matched.end();
        if bip39_word_index(matched.as_str()).is_some() {
            if word_tokens == MAX_BIP39_WORD_TOKENS {
                // Tier 3 will turn the exhausted token budget into an explicit
                // AnalysisIncomplete result. The gate must never fast-Allow it.
                return true;
            }
            word_tokens += 1;
            run += 1;
            if run >= 12 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_registry_path_candidate(input: &str) -> bool {
    has_registry_path_candidate_for_platform(input, target_path_flavor())
}

fn has_registry_path_candidate_for_platform(
    input: &str,
    target_flavor: SensitivePathFlavor,
) -> bool {
    // Tier 1 receives whole commands/prose, not an isolated path. Normalize
    // separators and platform casing without applying basename/ADS or `..`
    // semantics to the surrounding command text. On macOS, case-folding the
    // whole Tier-1 value is a safe superset; Tier 3 re-applies path-specific
    // flavor semantics before producing a finding.
    let flavor = if contains_windows_path_syntax(input) {
        SensitivePathFlavor::Windows
    } else if contains_macos_path_syntax(input) {
        SensitivePathFlavor::MacOs
    } else {
        target_flavor
    };
    let mut normalized = input.replace('\\', "/");
    // PowerShell frequently quotes only the environment-variable segment
    // (`"$env:APPDATA"\\Exodus`). Tier 1 is a cheap superset gate, so discard
    // shell quote delimiters before alias expansion rather than letting the
    // closing quote split a reviewed registry root.
    normalized.retain(|character| !matches!(character, '\'' | '"'));
    if flavor.is_case_insensitive() {
        normalized.make_ascii_lowercase();
    }
    if flavor == SensitivePathFlavor::Windows {
        expand_windows_path_aliases(&mut normalized);
    }
    SENSITIVE_PATH_DEFINITIONS.iter().any(|definition| {
        let root = normalize_definition_root(definition.match_root, flavor);
        match definition.match_mode {
            SensitivePathMatchMode::AbsoluteRoot => normalized.contains(&root),
            SensitivePathMatchMode::BasenameSuffix => normalized.contains(&root),
            _ => normalized.contains(&root),
        }
    })
}

/// Cheap, registry-derived Tier-1 superset for all sensitive-asset consumers.
/// It intentionally accepts false positives; Tier 3 performs checksum, scalar,
/// keypair, URL, and path-boundary validation. Every scan must consult this gate
/// before the normal fast exit so a new registry entry cannot become unreachable.
pub(crate) fn tier1_sensitive_asset_candidate(input: &str) -> bool {
    TIER1_ENV_ALIAS_RE.is_match(input)
        || contains_symbolic_env_reference(input)
        || has_registry_path_candidate(input)
        || TIER1_EVM_HEX_RE.is_match(input)
        || SOLANA_ARRAY_RE.is_match(input)
}

/// Deep/file/paste scans admit checksum validation of an otherwise unlabelled
/// BIP-39 word run. The Exec hot path uses [`tier1_sensitive_asset_candidate`]
/// and therefore pays no global wordlist scan for ordinary prose; an explicit
/// mnemonic/seed assignment still enters through `TIER1_ENV_ALIAS_RE`.
pub(crate) fn tier1_sensitive_asset_candidate_deep(input: &str) -> bool {
    if input.len() > MAX_BIP39_SCAN_INPUT_BYTES {
        return true;
    }
    tier1_sensitive_asset_candidate(input) || has_bip39_word_run_candidate(input)
}

static SYMBOLIC_ENV_RE: Lazy<Regex> = Lazy::new(|| {
    let names = alias_alternation(
        &[
            SensitiveEnvKind::Credential,
            SensitiveEnvKind::EvmPrivateKey,
            SensitiveEnvKind::Mnemonic,
            SensitiveEnvKind::SolanaKeypair,
            SensitiveEnvKind::Password,
        ],
        &[],
    );
    RegexBuilder::new(&format!(
        r"(?:\$(?:{names})\b|\$\{{(?:{names})\}}|%(?:{names})%|\$env:(?:{names})\b)"
    ))
    .case_insensitive(true)
    .build()
    .expect("symbolic sensitive env regex")
});

static SENSITIVE_VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    let aliases = alias_alternation(
        &[
            SensitiveEnvKind::Credential,
            SensitiveEnvKind::EvmPrivateKey,
            SensitiveEnvKind::Mnemonic,
            SensitiveEnvKind::SolanaKeypair,
            SensitiveEnvKind::Password,
        ],
        &[
            "private[-_]?key",
            "mnemonic",
            "seed[-_]?phrase",
            "passphrase",
            "password",
            "access[-_]?key",
            "jwt[-_]?secret",
            "secret[-_]?key",
            "keystore[-_]?password",
        ],
    );
    RegexBuilder::new(&format!(
        r#"(?P<prefix>(?:\"?\b(?:{aliases})\"?[\t \r\n]*(?:[:=]|[ \t])[\t \r\n]*(?:\\\r?\n[\t ]*)?|--?(?:{aliases})(?:[ \t]*=[\t ]*|[ \t]+)(?:\\\r?\n[\t ]*)?|\bset(?:[ \t]+--?[a-z-]+)*[ \t]+(?:{aliases})[ \t]+(?:\\\r?\n[\t ]*)?))(?P<value>\"(?:\\\r?\n|[^\"])*\"|'[^']*'|\[REDACTED(?::[^\]\r\n]{{1,64}})?\][^\s,;|&}}]*|(?:\\\r?\n|[^\s,;|&}}])+)"#
    ))
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .expect("sensitive value regex")
});

static RPC_VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    let aliases = alias_alternation(
        &[SensitiveEnvKind::RpcEndpoint],
        &["rpc[-_]?url", "fork[-_]?url", "provider[-_]?url"],
    );
    RegexBuilder::new(&format!(
        r#"(?P<prefix>(?:\"?\b(?:{aliases})\"?[\t \r\n]*(?:[:=]|[ \t])[\t \r\n]*(?:\\\r?\n[\t ]*)?|--?(?:{aliases})(?:[ \t]*=[\t ]*|[ \t]+)(?:\\\r?\n[\t ]*)?|\bset(?:[ \t]+--?[a-z-]+)*[ \t]+(?:{aliases})[ \t]+(?:\\\r?\n[\t ]*)?))(?P<value>\"(?:\\\r?\n|[^\"])*\"|'[^']*'|(?:\\\r?\n|[^\s,;|])+)"#
    ))
    .case_insensitive(true)
    .build()
    .expect("RPC value regex")
});

static BARE_RPC_URL_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"\b(?:https?|wss?)://[^\s<>\"'`,;|]+"#)
        .case_insensitive(true)
        .build()
        .expect("bare RPC URL regex")
});

const CANONICAL_REDACTION_LABELS: &[&str] = &[
    "web3_secret",
    "rpc",
    "evm_private_key",
    "bip39_mnemonic",
    "solana_keypair",
    "sensitive_asset",
    "OpenAI API Key",
    "AWS Access Key",
    "GitHub PAT",
    "GitHub Server Token",
    "Anthropic API Key",
    "Slack Token",
    "Email Address",
    "Bearer Token",
    "custom",
    "customer_id",
    "incomplete",
    "private_ipv4",
    "internal_hostname",
    "home_path",
];

fn is_canonical_redaction_marker(value: &str) -> bool {
    let value = value.trim();
    let unquoted = if value.len() >= 2
        && ((value.starts_with('\"') && value.ends_with('\"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if unquoted == "[REDACTED]" {
        return true;
    }
    unquoted
        .strip_prefix("[REDACTED:")
        .and_then(|label| label.strip_suffix(']'))
        .is_some_and(|label| CANONICAL_REDACTION_LABELS.contains(&label))
}

fn compact_env_alias(name: &str) -> String {
    name.trim()
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn strip_unquoted_rc_comment(value: &str) -> String {
    let mut quote = None;
    let mut escaped = false;
    let mut previous_whitespace = true;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            previous_whitespace = character.is_whitespace();
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            previous_whitespace = false;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            previous_whitespace = false;
            continue;
        }
        if character == '#' && quote.is_none() && previous_whitespace {
            return value[..index].trim_end().to_string();
        }
        previous_whitespace = character.is_whitespace();
    }
    value.trim().to_string()
}

fn prefix_alias_matches(name: &str, prefix: &str) -> bool {
    let trimmed_prefix = prefix.trim_end_matches('_');
    let lower = name.trim().to_ascii_lowercase();
    let snake = format!("{}_", trimmed_prefix.to_ascii_lowercase());
    let kebab = format!("{}-", trimmed_prefix.to_ascii_lowercase().replace('_', "-"));
    lower
        .strip_prefix(&snake)
        .or_else(|| lower.strip_prefix(&kebab))
        .is_some_and(|suffix| {
            let mut bytes = suffix.bytes();
            bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

pub fn sensitive_env_kind(name: &str) -> Option<SensitiveEnvKind> {
    let compact = compact_env_alias(name);
    SENSITIVE_ENV_DEFINITIONS
        .iter()
        .find(|definition| compact_env_alias(definition.name) == compact)
        .map(|definition| definition.kind)
        .or_else(|| {
            SENSITIVE_ENV_PREFIX_DEFINITIONS
                .iter()
                .find(|definition| prefix_alias_matches(name, definition.prefix))
                .map(|definition| definition.kind)
        })
}

pub fn is_registered_env_name(name: &str) -> bool {
    sensitive_env_kind(name).is_some()
}

/// Whether an environment name represents secret-bearing material. Public RPC
/// endpoint variables deliberately return false.
pub fn is_sensitive_env_name(name: &str) -> bool {
    sensitive_env_kind(name).is_some_and(SensitiveEnvKind::is_secret)
}

/// Closed alias grammar for structured key/value DLP. These generic labels are
/// accepted as complete keys only; prefix/starts-with matching is forbidden so
/// ordinary fields such as `password_policy` or `secretary` stay benign.
pub fn is_sensitive_value_alias(name: &str) -> bool {
    if is_sensitive_env_name(name) {
        return true;
    }
    matches!(
        compact_env_alias(name).as_str(),
        "privatekey"
            | "mnemonic"
            | "seedphrase"
            | "passphrase"
            | "password"
            | "accesskey"
            | "jwtsecret"
            | "secretkey"
            | "keystorepassword"
    )
}

pub fn secret_env_definitions() -> impl Iterator<Item = &'static SensitiveEnvDefinition> {
    SENSITIVE_ENV_DEFINITIONS
        .iter()
        .filter(|definition| definition.kind.is_secret())
}

pub(crate) fn secret_env_regex_fragment() -> String {
    alias_alternation(
        &[
            SensitiveEnvKind::Credential,
            SensitiveEnvKind::EvmPrivateKey,
            SensitiveEnvKind::Mnemonic,
            SensitiveEnvKind::SolanaKeypair,
            SensitiveEnvKind::Password,
        ],
        &[],
    )
}

pub fn contains_symbolic_env_reference(input: &str) -> bool {
    SYMBOLIC_ENV_RE.is_match(input)
}

fn looks_like_windows_path(path: &str) -> bool {
    let trimmed = path.trim().trim_matches(|ch| matches!(ch, '\'' | '\"'));
    let bytes = trimmed.as_bytes();
    trimmed.contains('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || trimmed.to_ascii_lowercase().contains("%appdata%")
        || trimmed.to_ascii_lowercase().contains("$env:appdata")
        || trimmed.to_ascii_lowercase().contains("$env:localappdata")
        || trimmed.to_ascii_lowercase().contains("${env:appdata}")
        || trimmed.to_ascii_lowercase().contains("${env:localappdata}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SensitivePathFlavor {
    Posix,
    MacOs,
    Windows,
}

impl SensitivePathFlavor {
    const fn is_case_insensitive(self) -> bool {
        matches!(self, Self::MacOs | Self::Windows)
    }
}

const fn target_path_flavor() -> SensitivePathFlavor {
    if cfg!(windows) {
        SensitivePathFlavor::Windows
    } else if cfg!(target_os = "macos") {
        SensitivePathFlavor::MacOs
    } else {
        SensitivePathFlavor::Posix
    }
}

/// Recognize reviewed macOS home/application-data spellings without treating
/// arbitrary Linux POSIX paths as case-insensitive. `/Users` and the macOS
/// home-relative `Library` forms are explicit lexical flavor signals.
fn contains_macos_path_syntax(path: &str) -> bool {
    let lower = path
        .trim()
        .trim_matches(|character| matches!(character, '\'' | '"'))
        .replace(['\'', '"'], "")
        .to_ascii_lowercase();
    let at_token_boundary = |index: usize| {
        index == 0
            || lower.as_bytes().get(index - 1).is_some_and(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(byte, b'=' | b'(' | b'[' | b'{' | b';' | b'|' | b'&' | b',')
            })
    };
    let contains_token = |needle: &str| {
        lower
            .match_indices(needle)
            .any(|(index, _)| at_token_boundary(index))
    };
    contains_token("/users/")
        || contains_token("/system/volumes/data/users/")
        || contains_token("~/library/")
        || contains_token("$home/library/")
        || contains_token("${home}/library/")
}

fn path_flavor_for_platform(path: &str, target_flavor: SensitivePathFlavor) -> SensitivePathFlavor {
    if looks_like_windows_path(path) {
        SensitivePathFlavor::Windows
    } else if contains_macos_path_syntax(path) {
        SensitivePathFlavor::MacOs
    } else {
        // All local non-Windows paths inherit the actual target semantics.
        // Callers analyzing a foreign filesystem can bypass inference through
        // `classify_path_for_flavor(..., SensitivePathFlavor::Posix)`.
        target_flavor
    }
}

fn path_flavor(path: &str) -> SensitivePathFlavor {
    path_flavor_for_platform(path, target_path_flavor())
}

/// Tier 1 sees a whole command, so a drive-relative Windows path may begin
/// after a shell token boundary (`type C:WALLET.DAT`). Keep that broader scan
/// out of isolated-path flavor detection: a foreign POSIX filename such as
/// `/tmp/a:WALLET.DAT` is legal and remains case-sensitive under the explicit
/// POSIX override.
fn contains_windows_path_syntax(input: &str) -> bool {
    if looks_like_windows_path(input) {
        return true;
    }
    let bytes = input.as_bytes();
    let embedded_drive = bytes.iter().enumerate().any(|(index, byte)| {
        let token_boundary = index == 0
            || bytes[index - 1].is_ascii_whitespace()
            || matches!(
                bytes[index - 1],
                b'\'' | b'"' | b'=' | b'(' | b'[' | b'{' | b';' | b'|' | b'&' | b','
            );
        byte.is_ascii_alphabetic() && bytes.get(index + 1) == Some(&b':') && token_boundary
    });
    embedded_drive
}

fn expand_windows_path_aliases(raw: &mut String) {
    for (alias, replacement) in [
        ("%localappdata%", "appdata/local"),
        ("${env:localappdata}", "appdata/local"),
        ("$env:localappdata", "appdata/local"),
        ("%appdata%", "appdata/roaming"),
        ("${env:appdata}", "appdata/roaming"),
        ("$env:appdata", "appdata/roaming"),
    ] {
        if raw.contains(alias) {
            *raw = raw.replace(alias, replacement);
        }
    }
    while raw.contains("//") {
        *raw = raw.replace("//", "/");
    }
}

fn normalize_definition_root(root: &str, flavor: SensitivePathFlavor) -> String {
    normalize_path_for_explicit_flavor(root, flavor)
}

/// `/`-separated path form used only for classification. Windows and local
/// macOS spellings are case-folded; Linux and explicit POSIX spellings retain
/// case.
pub fn normalize_path_for_match(path: &str) -> String {
    normalize_path_with_flavor(path).0
}

fn normalize_path_with_flavor(path: &str) -> (String, SensitivePathFlavor) {
    let flavor = path_flavor(path);
    (normalize_path_for_explicit_flavor(path, flavor), flavor)
}

/// Normalize using the caller-selected lexical flavor. Registry roots must use
/// the flavor of the path being matched, rather than re-detecting their own
/// relative spelling (which would accidentally case-fold POSIX roots on a
/// Windows build).
fn normalize_path_for_explicit_flavor(path: &str, flavor: SensitivePathFlavor) -> String {
    let mut raw = path
        .trim()
        .trim_matches(|ch| matches!(ch, '\'' | '\"'))
        .to_string();
    // PowerShell commonly quotes the environment expression separately from the
    // remaining path (`"$env:APPDATA"\\Exodus`). Quotes are shell syntax, not
    // path components, so remove them before the classification-only fold.
    raw.retain(|ch| !matches!(ch, '\'' | '\"'));
    raw = raw.replace('\\', "/");
    if flavor.is_case_insensitive() {
        raw.make_ascii_lowercase();
    }
    if flavor == SensitivePathFlavor::Windows {
        expand_windows_path_aliases(&mut raw);
        let bytes = raw.as_bytes();
        if bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] != b'/'
        {
            // `C:wallet.dat` is drive-relative, but `wallet.dat` remains a real
            // path component and must reach basename rules.
            raw.insert(2, '/');
        }
        // Alternate data streams decorate the final filename; they do not
        // change the basename of the underlying sensitive file.
        let component_start = raw.rfind('/').map_or(0, |index| index + 1);
        if let Some(stream_offset) = raw[component_start..].find(':') {
            raw.truncate(component_start + stream_offset);
        }
    }
    let absolute = raw.starts_with('/');
    let mut components: Vec<&str> = Vec::new();
    for component in raw.split('/') {
        match component {
            "" | "." => {}
            // Lexically cancelling a parent can cross a symlink trust boundary
            // (`link/..`). Preserve it so earlier sensitive roots remain
            // visible and classification fails conservatively.
            ".." => components.push(component),
            _ => components.push(component),
        }
    }
    let joined = components.join("/");
    let normalized = if absolute {
        format!("/{joined}")
    } else {
        joined
    };
    normalized
}

fn padded_path(path: &str) -> String {
    format!("/{}/", path.trim_matches('/'))
}

fn path_definition_matches(
    path: &str,
    basename: &str,
    definition: &SensitivePathDefinition,
    flavor: SensitivePathFlavor,
) -> bool {
    let root = normalize_definition_root(definition.match_root, flavor);
    match definition.match_mode {
        SensitivePathMatchMode::AbsoluteRoot => path == root || path.starts_with(&(root + "/")),
        SensitivePathMatchMode::ComponentRoot | SensitivePathMatchMode::BrowserSourceRoot => {
            padded_path(path).contains(&padded_path(&root))
        }
        SensitivePathMatchMode::BasenameExact => basename == root,
        SensitivePathMatchMode::BasenameSuffix => basename.ends_with(&root),
        SensitivePathMatchMode::BrowserExtensionId => path.contains(&root),
        SensitivePathMatchMode::BrowserStorageRoot => {
            padded_path(path).contains(&format!("/{root}"))
        }
    }
}

fn bind_root_matches(
    path: &str,
    definition: &SensitivePathDefinition,
    root: &str,
    flavor: SensitivePathFlavor,
) -> bool {
    let root = normalize_definition_root(root, flavor);
    match definition.match_mode {
        SensitivePathMatchMode::AbsoluteRoot => path == root || path.starts_with(&(root + "/")),
        _ => padded_path(path).contains(&padded_path(&root)),
    }
}

fn path_kind_observation(kind: SensitivePathKind) -> SensitiveAssetObservation {
    match kind {
        SensitivePathKind::Credential | SensitivePathKind::PrivilegedSystem => path_observation(
            SensitiveAssetKind::ProviderCredential,
            SensitiveLocationClass::FilePath,
        ),
        SensitivePathKind::EncryptedKeystore => path_observation(
            SensitiveAssetKind::EncryptedKeystore,
            SensitiveLocationClass::FilePath,
        ),
        SensitivePathKind::SolanaKeypair => path_observation(
            SensitiveAssetKind::SolanaKeypair,
            SensitiveLocationClass::FilePath,
        ),
        SensitivePathKind::WalletDatabase => path_observation(
            SensitiveAssetKind::WalletDatabase,
            SensitiveLocationClass::FilePath,
        ),
        SensitivePathKind::DesktopWalletData => path_observation(
            SensitiveAssetKind::DesktopWalletData,
            SensitiveLocationClass::ApplicationData,
        ),
        SensitivePathKind::BrowserWalletStorage => path_observation(
            SensitiveAssetKind::BrowserWalletStorage,
            SensitiveLocationClass::BrowserExtensionData,
        ),
    }
}

/// Central bind-source classifier used by container/config consumers.
pub fn is_sensitive_bind_path(path: &str) -> bool {
    let (normalized, flavor) = normalize_path_with_flavor(path);
    classify_path(path).is_some()
        || SENSITIVE_PATH_DEFINITIONS.iter().any(|definition| {
            definition
                .bind_root
                .is_some_and(|root| bind_root_matches(&normalized, definition, root, flavor))
        })
}

/// Relative authenticated-home roots used by capsule deny policies.
pub fn capsule_deny_relative_paths() -> impl Iterator<Item = &'static str> {
    SENSITIVE_PATH_DEFINITIONS
        .iter()
        .filter_map(|definition| definition.capsule_relative)
        .chain(CAPSULE_BROWSER_DATA_ROOTS.iter().copied())
}

/// Regex alternation for output-side read-and-send detection. Reviewed path
/// roots and non-path terms are combined at the call site without a second path
/// catalog.
pub fn output_sensitive_regex_fragment() -> String {
    let path_regex = |path: &str| regex::escape(path).replace('/', r"[/\\]");
    let leading = r#"(?:^|[/\\\s\"'`=:@(\[])"#;
    let trailing = r#"(?:$|[/\\\s\"'`,;:)\]])"#;
    let mut fragments = SENSITIVE_PATH_DEFINITIONS
        .iter()
        .filter(|definition| {
            !matches!(
                definition.match_mode,
                SensitivePathMatchMode::BrowserExtensionId
                    | SensitivePathMatchMode::BrowserStorageRoot
                    | SensitivePathMatchMode::BrowserSourceRoot
            )
        })
        .map(|definition| match definition.match_mode {
            SensitivePathMatchMode::BasenameExact => {
                format!("{leading}{}{trailing}", path_regex(definition.match_root))
            }
            SensitivePathMatchMode::BasenameSuffix => {
                format!(
                    r"{leading}[^/\\\s]*{}{trailing}",
                    path_regex(definition.match_root)
                )
            }
            _ => format!("{leading}{}{trailing}", path_regex(definition.match_root)),
        })
        .chain(OUTPUT_SENSITIVE_TERMS.iter().map(|term| match *term {
            ".env" => format!(
                r"{leading}\.env(?:\.(?:local|production|development|staging|test))?{trailing}"
            ),
            "credentials" => format!(r"{leading}credentials(?:\.(?:json|ya?ml|toml))?{trailing}"),
            "secret" => format!(r"{leading}secret(?:\.(?:txt|json|ya?ml|toml|env))?{trailing}"),
            _ => format!("{leading}{}{trailing}", path_regex(term)),
        }))
        .collect::<Vec<_>>();
    let grouped_paths = |mode| {
        let mut alternatives = SENSITIVE_PATH_DEFINITIONS
            .iter()
            .filter(|definition| definition.match_mode == mode)
            .map(|definition| path_regex(definition.match_root))
            .collect::<Vec<_>>();
        alternatives.sort();
        alternatives.dedup();
        alternatives.join("|")
    };
    let extension_ids = grouped_paths(SensitivePathMatchMode::BrowserExtensionId);
    let storage_roots = grouped_paths(SensitivePathMatchMode::BrowserStorageRoot);
    if !extension_ids.is_empty() && !storage_roots.is_empty() {
        // Keep the catalog's storage-root × wallet-extension relationship,
        // but factor each alternation once. Expanding every pair duplicated
        // both large case-insensitive programs and exceeded regex's bounded
        // compiler size. BrowserSourceRoot remains excluded above: an unpacked
        // extension source tree is not wallet storage merely because its path
        // contains a reviewed extension ID.
        let indexeddb_suffix = r"(?:_[0-9]{1,10}\.indexeddb\.leveldb)?";
        fragments.push(format!(
            r"{leading}(?:{storage_roots}).{{0,256}}(?:{extension_ids}){indexeddb_suffix}{trailing}"
        ));
        fragments.push(format!(
            r"{leading}(?:{extension_ids}){indexeddb_suffix}.{{0,256}}(?:{storage_roots}){trailing}"
        ));
    }
    fragments.join("|")
}

/// Byte ranges of reviewed PRIVATE file paths inside free-form command text.
///
/// This is the path counterpart to [`sensitive_value_redaction_spans`], which
/// only covers secret *values*. A wallet or credential path is not a secret
/// byte string, so no value pattern matches it, yet echoing
/// `~/.config/Exodus/exodus.wallet` still tells a reader exactly which wallet a
/// user holds and where it lives. Rules that quote raw command text on a
/// bounded-analysis path (container/sudo work-budget gaps) would otherwise
/// carry that path into CLI output and the persistent audit log.
///
/// Deliberately excludes [`SensitivePathKind::PrivilegedSystem`]. `/etc`,
/// container sockets, and the unresolved-`..` catch-all are ordinary system
/// locations, not private user data; redacting them would blank routine
/// evidence without protecting anyone. [`OUTPUT_SENSITIVE_TERMS`] is excluded
/// for the same reason: bare words like `secret` and `credentials` appear in
/// ordinary prose.
///
/// Each match consumes the reviewed root plus its remaining path segments so a
/// keystore filename (which embeds an account address) cannot survive the root
/// being blanked. Shell metacharacters terminate a match, keeping a following
/// sink command visible in the evidence.
pub(crate) fn private_path_redaction_spans(input: &str) -> Vec<std::ops::Range<usize>> {
    static PRIVATE_PATH_RE: Lazy<Regex> = Lazy::new(|| {
        // A literal space survives `regex::escape`, so the ordinary unquoted
        // macOS spelling (`Application\ Support`) needs the escaped form too.
        let path_regex = |path: &str| {
            regex::escape(path)
                .replace('/', r"[/\\]")
                .replace(' ', r"(?:\\ | )")
        };
        let leading = r#"(?:^|[/\\\s\"'`=:@(\[])"#;
        // Continue only across a real component boundary, so `.config/gh`
        // (GitHub CLI credentials) cannot prefix-match `.config/ghostty` and
        // blank half of an unrelated word. This mirrors the component-root
        // semantics of `path_definition_matches`. `$`, `(`, and `{` end the
        // token so an appended `$(curl ...)` substitution cannot ride inside a
        // path span and disappear from the record.
        let tail = r#"(?:[/\\][^\s\"'`,;)\]|&><${}()]*)?"#;
        // The boundary character is consumed but left OUT of the capture, so a
        // following sink command stays readable. Anything that cannot continue
        // a filename terminates the path, which keeps `-v ~/.ssh:/keys` (the
        // canonical Docker credential mount) matching while still rejecting
        // `.sshrc` and `.config/ghostty`.
        let trailing = r#"(?:$|[^A-Za-z0-9._\-])"#;
        let alternatives = SENSITIVE_PATH_DEFINITIONS
            .iter()
            .filter(|definition| definition.kind != SensitivePathKind::PrivilegedSystem)
            .filter(|definition| {
                // A storage-root directory name alone appears in ordinary
                // browser profiles; only the wallet extension IDs identify
                // wallet data. An unpacked extension source tree is not
                // wallet storage, matching `classify_path_for_flavor`.
                !matches!(
                    definition.match_mode,
                    SensitivePathMatchMode::BrowserStorageRoot
                        | SensitivePathMatchMode::BrowserSourceRoot
                )
            })
            .flat_map(|definition| match definition.match_mode {
                SensitivePathMatchMode::BasenameSuffix => {
                    vec![format!(r"[^/\\\s]*{}", path_regex(definition.match_root))]
                }
                _ => {
                    let mut spellings = vec![path_regex(definition.match_root)];
                    // `~/.config/Exodus` on its own already discloses which
                    // wallet the user holds, so the directory that mounting
                    // would expose is redacted alongside the exact file.
                    if let Some(bind_root) = definition
                        .bind_root
                        .filter(|bind_root| *bind_root != definition.match_root)
                    {
                        spellings.push(path_regex(bind_root));
                    }
                    // `%APPDATA%` already denotes `AppData\Roaming`, so the
                    // shell spelling never contains the catalog's literal
                    // prefix. Mirror `expand_windows_path_aliases` in reverse
                    // so the environment forms are recognized here too, instead
                    // of introducing a second alias table.
                    for (prefix, aliases) in [
                        (
                            "AppData/Roaming/",
                            [r"%APPDATA%", r"\$\{env:APPDATA\}", r"\$env:APPDATA"],
                        ),
                        (
                            "AppData/Local/",
                            [
                                r"%LOCALAPPDATA%",
                                r"\$\{env:LOCALAPPDATA\}",
                                r"\$env:LOCALAPPDATA",
                            ],
                        ),
                    ] {
                        if let Some(rest) = definition.match_root.strip_prefix(prefix) {
                            for alias in aliases {
                                // Quotes may separate the expansion from the
                                // rest of the path (`"$env:APPDATA"\Exodus`).
                                spellings.push(format!(r#"{alias}["']?[/\\]{}"#, path_regex(rest)));
                            }
                        }
                    }
                    spellings
                }
            })
            .collect::<Vec<_>>();
        assert!(
            !alternatives.is_empty(),
            "sensitive path catalog has no private definitions"
        );
        RegexBuilder::new(&format!(
            "{leading}(?P<path>(?:{}){tail}){trailing}",
            alternatives.join("|")
        ))
        .case_insensitive(true)
        .build()
        // Fail closed like every other production pattern in this module: a
        // silently missing regex would disable path redaction wholesale.
        .expect("private path redaction regex")
    });

    // Resume at the end of the PATH, not the end of the match. Both the
    // leading and trailing boundaries are consuming groups, so scanning from
    // the match end would eat the separator that the next path needs as its
    // own leading boundary and skip every second path in a run such as
    // `cp .npmrc .netrc /tmp`.
    // A reviewed root appearing inside a remote URL is a download or exfil
    // TARGET, not a local private path. Blanking it would delete the very
    // destination an operator needs from the record, so those ranges are left
    // intact; this also keeps `Evidence::Url` and `CommandPattern` consistent.
    let remote_url_ranges = BARE_RPC_URL_RE
        .find_iter(input)
        .map(|matched| matched.start()..matched.end())
        .collect::<Vec<_>>();

    let mut spans = Vec::new();
    let mut at = 0usize;
    while at <= input.len() {
        let Some(captures) = PRIVATE_PATH_RE.captures_at(input, at) else {
            break;
        };
        let Some(matched) = captures.name("path") else {
            break;
        };
        if !remote_url_ranges
            .iter()
            .any(|url| matched.start() >= url.start && matched.start() < url.end)
        {
            spans.push(matched.start()..matched.end());
        }
        // A zero-width capture cannot happen (every alternative is a literal
        // root), but guard the loop against one regardless.
        at = matched.end().max(at + 1);
    }
    spans
}

fn path_observation(
    kind: SensitiveAssetKind,
    location_class: SensitiveLocationClass,
) -> SensitiveAssetObservation {
    SensitiveAssetObservation {
        kind,
        confidence: Confidence::High,
        validation: ValidationMethod::ReviewedPath,
        source_class: if location_class == SensitiveLocationClass::FilePath {
            SensitiveSourceClass::LocalFile
        } else {
            SensitiveSourceClass::ApplicationStore
        },
        location_class,
        redaction_class: RedactionClass::PrivatePath,
    }
}

pub fn classify_path(path: &str) -> Option<SensitiveAssetObservation> {
    classify_path_for_platform(path, target_path_flavor())
}

fn classify_path_for_platform(
    path: &str,
    target_flavor: SensitivePathFlavor,
) -> Option<SensitiveAssetObservation> {
    classify_path_for_flavor(path, path_flavor_for_platform(path, target_flavor))
}

pub(crate) fn classify_path_for_flavor(
    path: &str,
    flavor: SensitivePathFlavor,
) -> Option<SensitiveAssetObservation> {
    let path = normalize_path_for_explicit_flavor(path, flavor);
    let basename = path.rsplit('/').next().unwrap_or(path.as_str());

    if path.split('/').any(|component| component == "..") {
        // Resolving this lexically could cross a symlink trust boundary. Treat
        // the unresolved path as privileged/unknown instead of proving it safe.
        return Some(path_kind_observation(SensitivePathKind::PrivilegedSystem));
    }

    // Generic credential/system/wallet roots have priority over the browser
    // source-tree carve-out. An extension-shaped subtree beneath `.ssh`,
    // `.aws`, etc. is still sensitive.
    if let Some(definition) = SENSITIVE_PATH_DEFINITIONS
        .iter()
        .filter(|definition| {
            !matches!(
                definition.match_mode,
                SensitivePathMatchMode::BrowserExtensionId
                    | SensitivePathMatchMode::BrowserStorageRoot
                    | SensitivePathMatchMode::BrowserSourceRoot
            )
        })
        .find(|definition| path_definition_matches(&path, basename, definition, flavor))
    {
        return Some(path_kind_observation(definition.kind));
    }

    // Browser extension source is not wallet data. Only storage roots qualify.
    let matches_mode = |mode| {
        SENSITIVE_PATH_DEFINITIONS.iter().any(|definition| {
            definition.match_mode == mode
                && path_definition_matches(&path, basename, definition, flavor)
        })
    };
    let is_wallet_extension = matches_mode(SensitivePathMatchMode::BrowserExtensionId);
    let is_storage_root = matches_mode(SensitivePathMatchMode::BrowserStorageRoot);
    if is_wallet_extension && is_storage_root {
        return Some(path_observation(
            SensitiveAssetKind::BrowserWalletStorage,
            SensitiveLocationClass::BrowserExtensionData,
        ));
    }

    if is_wallet_extension && matches_mode(SensitivePathMatchMode::BrowserSourceRoot) {
        return None;
    }

    None
}

pub fn is_sensitive_path(path: &str) -> bool {
    classify_path(path).is_some()
}

pub fn sensitive_path_match_count(text: &str) -> usize {
    let (normalized, flavor) = normalize_path_with_flavor(text);
    if classify_path(text).is_none() {
        return 0;
    }
    let basename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let defined = SENSITIVE_PATH_DEFINITIONS
        .iter()
        .filter(|definition| definition.match_mode != SensitivePathMatchMode::BrowserSourceRoot)
        .filter(|definition| path_definition_matches(&normalized, basename, definition, flavor))
        .count();
    defined.max(1)
}

pub fn is_valid_evm_private_key(value: &str) -> bool {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(bytes) = hex::decode(value) else {
        return false;
    };
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    bytes.iter().any(|byte| *byte != 0) && bytes.as_slice() < ORDER.as_slice()
}

pub fn is_valid_bip39_mnemonic(value: &str) -> bool {
    let mut indices = [0u16; MAX_BIP39_WORDS_PER_PHRASE];
    let mut count = 0usize;
    for word in value.split_whitespace() {
        if count == indices.len() {
            return false;
        }
        let Some(index) = bip39_word_index(word) else {
            return false;
        };
        indices[count] = index;
        count += 1;
    }
    if !matches!(count, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    is_valid_bip39_indices(&indices[..count])
}

fn is_valid_bip39_indices(indices: &[u16]) -> bool {
    let checksum_bits = indices.len() / 3;
    let entropy_bits = indices.len() * 11 - checksum_bits;
    let mut entropy = [0u8; 32];
    let mut appended_checksum = 0u8;
    for bit_pos in 0..(entropy_bits + checksum_bits) {
        let word = indices[bit_pos / 11];
        let bit_in_word = 10 - (bit_pos % 11);
        let bit = ((word >> bit_in_word) & 1) as u8;
        if bit_pos < entropy_bits {
            entropy[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
        } else {
            appended_checksum = (appended_checksum << 1) | bit;
        }
    }
    let digest = Sha256::digest(&entropy[..entropy_bits / 8]);
    let expected = digest[0] >> (8 - checksum_bits);
    appended_checksum == expected
}

pub fn is_valid_solana_keypair_array(value: &str) -> bool {
    let Ok(numbers) = serde_json::from_str::<Vec<u8>>(value) else {
        return false;
    };
    if numbers.len() != 64 {
        return false;
    }
    let Ok(secret) = <[u8; 32]>::try_from(&numbers[..32]) else {
        return false;
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
    signing.verifying_key().as_bytes() == &numbers[32..]
}

const MAX_KEYSTORE_JSON_BYTES: usize = 1024 * 1024;

fn json_hex_string(value: Option<&serde_json::Value>, min_bytes: usize) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| {
            text.len() >= min_bytes.saturating_mul(2)
                && text.len() % 2 == 0
                && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Bounded Ethereum V3 keystore validation. Only a top-level object with typed
/// V3 fields and reviewed cipher/KDF algorithms qualifies; prose and unrelated
/// JSON that merely mention field names remain clean.
pub fn is_encrypted_keystore_json(input: &str) -> bool {
    if input.is_empty() || input.len() > MAX_KEYSTORE_JSON_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(input) else {
        return false;
    };
    let Some(root) = value.as_object() else {
        return false;
    };
    let version_is_v3 = root
        .get("version")
        .is_some_and(|version| version.as_u64() == Some(3) || version.as_str() == Some("3"));
    if !version_is_v3 {
        return false;
    }
    let Some(crypto) = root
        .get("crypto")
        .or_else(|| root.get("Crypto"))
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    let cipher_ok = crypto
        .get("cipher")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|cipher| matches!(cipher, "aes-128-ctr" | "aes-128-cbc"));
    let kdf_ok = crypto
        .get("kdf")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kdf| matches!(kdf, "scrypt" | "pbkdf2"));
    cipher_ok
        && kdf_ok
        && crypto
            .get("cipherparams")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|params| json_hex_string(params.get("iv"), 16))
        && crypto
            .get("kdfparams")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|params| {
                json_hex_string(params.get("salt"), 16)
                    && params.get("dklen").and_then(serde_json::Value::as_u64) == Some(32)
            })
        && json_hex_string(crypto.get("ciphertext"), 1)
        && json_hex_string(crypto.get("mac"), 32)
}

fn record_bip39_word(result: &mut Bip39ScanResult) -> bool {
    if result.stats.bip39_word_tokens == MAX_BIP39_WORD_TOKENS {
        result.incomplete = true;
        return false;
    }
    result.stats.bip39_word_tokens += 1;
    true
}

fn check_bip39_candidate(result: &mut Bip39ScanResult, words: &[Bip39WordRecord]) -> Option<bool> {
    if result.stats.checksum_candidates == MAX_BIP39_CHECKSUM_CANDIDATES {
        result.incomplete = true;
        return None;
    }
    result.stats.checksum_candidates += 1;
    let mut indices = [0u16; MAX_BIP39_WORDS_PER_PHRASE];
    for (destination, word) in indices.iter_mut().zip(words) {
        *destination = word.index;
    }
    Some(is_valid_bip39_indices(&indices[..words.len()]))
}

fn check_bip39_window_candidate(
    result: &mut Bip39ScanResult,
    window: &VecDeque<Bip39WordRecord>,
    count: usize,
) -> Option<bool> {
    if result.stats.checksum_candidates == MAX_BIP39_CHECKSUM_CANDIDATES {
        result.incomplete = true;
        return None;
    }
    result.stats.checksum_candidates += 1;
    let mut indices = [0u16; MAX_BIP39_WORDS_PER_PHRASE];
    for (destination, word) in indices.iter_mut().zip(window.iter()).take(count) {
        *destination = word.index;
    }
    Some(is_valid_bip39_indices(&indices[..count]))
}

fn push_bip39_match(result: &mut Bip39ScanResult, range: Range<usize>) -> bool {
    if result.stats.confirmed_matches == MAX_BIP39_MATCHES {
        result.incomplete = true;
        return false;
    }
    result.stats.confirmed_matches += 1;
    result.spans.push(SensitiveSpan {
        kind: SensitiveAssetKind::Bip39Mnemonic,
        range,
    });
    true
}

fn explicit_mnemonic_spans(input: &str, result: &mut Bip39ScanResult) {
    if input.len() > MAX_BIP39_SCAN_INPUT_BYTES {
        result.incomplete = true;
        return;
    }
    let mut words = Vec::with_capacity(MAX_BIP39_WORDS_PER_PHRASE);
    for context in MNEMONIC_CONTEXT_START_RE.find_iter(input) {
        words.clear();
        let mut cursor = context.end();
        for matched in WORD_RE
            .find_iter(&input[context.end()..])
            .take(MAX_BIP39_WORDS_PER_PHRASE)
        {
            let range = (context.end() + matched.start())..(context.end() + matched.end());
            let gap = &input[cursor..range.start];
            if !gap
                .chars()
                .all(|ch| ch.is_whitespace() || matches!(ch, '\\' | '\'' | '\"'))
            {
                break;
            }
            let Some(index) = bip39_word_index(matched.as_str()) else {
                break;
            };
            if !record_bip39_word(result) {
                return;
            }
            words.push(Bip39WordRecord {
                range: range.clone(),
                index,
            });
            cursor = range.end;
        }
        for count in [24usize, 21, 18, 15, 12] {
            if words.len() < count {
                continue;
            }
            let valid = match check_bip39_candidate(result, &words[..count]) {
                Some(valid) => valid,
                None => return,
            };
            if valid {
                if !push_bip39_match(result, words[0].range.start..words[count - 1].range.end) {
                    return;
                }
                break;
            }
        }
    }
}

fn process_bip39_window_start(
    window: &mut VecDeque<Bip39WordRecord>,
    result: &mut Bip39ScanResult,
) -> bool {
    let available = window.len();
    for count in [24usize, 21, 18, 15, 12] {
        if count > available {
            continue;
        }
        match check_bip39_window_candidate(result, window, count) {
            Some(true) => {
                let range = window.front().expect("non-empty BIP-39 window").range.start
                    ..window
                        .get(count - 1)
                        .expect("bounded BIP-39 candidate")
                        .range
                        .end;
                if !push_bip39_match(result, range) {
                    return false;
                }
                for _ in 0..count {
                    window.pop_front();
                }
                return true;
            }
            Some(false) => {}
            None => return false,
        }
    }
    window.pop_front();
    true
}

fn flush_bip39_window(
    window: &mut VecDeque<Bip39WordRecord>,
    result: &mut Bip39ScanResult,
) -> bool {
    while window.len() >= 12 {
        if !process_bip39_window_start(window, result) {
            return false;
        }
    }
    window.clear();
    true
}

fn global_mnemonic_spans(input: &str, result: &mut Bip39ScanResult) {
    if input.len() > MAX_BIP39_SCAN_INPUT_BYTES {
        result.incomplete = true;
        return;
    }
    let mut window = VecDeque::with_capacity(MAX_BIP39_WORDS_PER_PHRASE);
    let mut cursor = 0usize;
    for matched in WORD_RE.find_iter(input) {
        if !input[cursor..matched.start()]
            .chars()
            .all(char::is_whitespace)
            && !flush_bip39_window(&mut window, result)
        {
            return;
        }
        cursor = matched.end();
        let Some(index) = bip39_word_index(matched.as_str()) else {
            if !flush_bip39_window(&mut window, result) {
                return;
            }
            continue;
        };
        if !record_bip39_word(result) {
            return;
        }
        if window.len() == MAX_BIP39_WORDS_PER_PHRASE
            && !process_bip39_window_start(&mut window, result)
        {
            return;
        }
        window.push_back(Bip39WordRecord {
            range: matched.range(),
            index,
        });
        result.stats.max_rolling_words = result.stats.max_rolling_words.max(window.len());
    }
    let _ = flush_bip39_window(&mut window, result);
}

fn structured_secret_spans(input: &str, context: DetectionContext) -> StructuredSecretScan {
    let mut spans = Vec::new();

    for captures in EVM_CONTEXT_RE.captures_iter(input) {
        if let Some(value) = captures.name("value") {
            if is_valid_evm_private_key(value.as_str()) {
                spans.push(SensitiveSpan {
                    kind: SensitiveAssetKind::EvmPrivateKey,
                    range: value.range(),
                });
            }
        }
    }

    let mut bip39 = Bip39ScanResult::default();
    if matches!(
        context,
        DetectionContext::Paste
            | DetectionContext::FileScan
            | DetectionContext::Exfiltration
            | DetectionContext::Redaction
    ) {
        // Deep contexts already recognize every checksum-valid phrase. Running
        // the explicit assignment scanner as well would scan the input twice
        // and charge the same confirmed span against the budgets twice.
        global_mnemonic_spans(input, &mut bip39);
    } else {
        // Exec stays assignment/flag scoped: ordinary mnemonic-looking prose
        // must not pay for or trigger global recovery-phrase recognition.
        explicit_mnemonic_spans(input, &mut bip39);
    }
    spans.append(&mut bip39.spans);

    for matched in SOLANA_ARRAY_RE.find_iter(input) {
        if is_valid_solana_keypair_array(matched.as_str()) {
            spans.push(SensitiveSpan {
                kind: SensitiveAssetKind::SolanaKeypair,
                range: matched.range(),
            });
        }
    }

    spans.sort_unstable_by_key(|span| (span.range.start, span.range.end));
    spans.dedup_by(|left, right| left.kind == right.kind && left.range == right.range);
    StructuredSecretScan {
        spans,
        incomplete: bip39.incomplete,
    }
}

fn observation_for_span(kind: SensitiveAssetKind) -> SensitiveAssetObservation {
    let validation = match kind {
        SensitiveAssetKind::EvmPrivateKey => ValidationMethod::Secp256k1Scalar,
        SensitiveAssetKind::Bip39Mnemonic => ValidationMethod::Bip39EnglishChecksum,
        SensitiveAssetKind::SolanaKeypair => ValidationMethod::Ed25519PublicHalf,
        _ => ValidationMethod::ReviewedPath,
    };
    SensitiveAssetObservation {
        kind,
        confidence: Confidence::Verified,
        validation,
        source_class: SensitiveSourceClass::Literal,
        location_class: SensitiveLocationClass::InlineValue,
        redaction_class: RedactionClass::SecretValue,
    }
}

pub(crate) fn observations_with_status(
    input: &str,
    context: DetectionContext,
) -> SensitiveAssetScan {
    let structured = structured_secret_spans(input, context);
    let mut observations = structured
        .spans
        .into_iter()
        .map(|span| observation_for_span(span.kind))
        .collect::<Vec<_>>();

    if contains_symbolic_env_reference(input) {
        observations.push(SensitiveAssetObservation {
            kind: SensitiveAssetKind::WalletEnvironmentReference,
            confidence: Confidence::High,
            validation: ValidationMethod::EnvironmentRegistry,
            source_class: SensitiveSourceClass::SymbolicReference,
            location_class: SensitiveLocationClass::EnvironmentName,
            redaction_class: RedactionClass::SensitiveReference,
        });
    }

    if is_encrypted_keystore_json(input) {
        observations.push(SensitiveAssetObservation {
            kind: SensitiveAssetKind::EncryptedKeystore,
            confidence: Confidence::High,
            validation: ValidationMethod::JsonKeystoreShape,
            source_class: SensitiveSourceClass::LocalFile,
            location_class: SensitiveLocationClass::FilePath,
            redaction_class: RedactionClass::SecretValue,
        });
    }
    SensitiveAssetScan {
        observations,
        incomplete: structured.incomplete,
    }
}

pub fn observations(input: &str, context: DetectionContext) -> Vec<SensitiveAssetObservation> {
    observations_with_status(input, context).observations
}

fn replace_spans(input: &str, spans: &[SensitiveSpan]) -> String {
    if spans.is_empty() {
        return input.to_string();
    }
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for span in spans {
        if span.range.start < cursor {
            continue;
        }
        output.push_str(&input[cursor..span.range.start]);
        let label = match span.kind {
            SensitiveAssetKind::EvmPrivateKey => "evm_private_key",
            SensitiveAssetKind::Bip39Mnemonic => "bip39_mnemonic",
            SensitiveAssetKind::SolanaKeypair => "solana_keypair",
            _ => "sensitive_asset",
        };
        output.push_str("[REDACTED:");
        output.push_str(label);
        output.push(']');
        cursor = span.range.end;
    }
    output.push_str(&input[cursor..]);
    output
}

/// Redact only structurally validated wallet values. This pass intentionally
/// excludes alias/RPC handling so callers can protect whole mnemonic/keypair
/// spans before running operator-controlled custom regexes without losing
/// provider-specific credential labels.
pub fn redact_structured_wallet_values(input: &str) -> String {
    let scan = structured_secret_spans(input, DetectionContext::Redaction);
    if scan.incomplete {
        return "[REDACTED:analysis_incomplete]".to_string();
    }
    replace_spans(input, &scan.spans)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedRpcPathGrammar {
    /// A credential occupies a slot after a reviewed service/version prefix.
    VersionedSlot,
    /// A secret-shaped non-public segment may be the provider credential.
    DirectToken,
    /// The provider exposes both versioned and direct credential URL forms.
    VersionedOrDirectToken,
    /// Provider authentication is carried outside the path (normally query or
    /// userinfo); ordinary network selectors in the path remain public.
    NoCredentialPath,
}

#[derive(Debug, Clone, Copy)]
struct HostedRpcProviderDefinition {
    suffix: &'static str,
    provider: RpcProvider,
    path_grammar: HostedRpcPathGrammar,
}

/// One hosted-RPC catalog drives endpoint detection, credential
/// classification, public projections, and URL sanitization. Entries mapped to
/// `Other` are still reviewed hosted providers; the closed evidence enum keeps
/// its existing compatibility surface until a later schema revision.
const HOSTED_RPC_PROVIDERS: &[HostedRpcProviderDefinition] = &[
    HostedRpcProviderDefinition {
        suffix: "infura.io",
        provider: RpcProvider::Infura,
        path_grammar: HostedRpcPathGrammar::VersionedSlot,
    },
    HostedRpcProviderDefinition {
        suffix: "alchemy.com",
        provider: RpcProvider::Alchemy,
        path_grammar: HostedRpcPathGrammar::VersionedSlot,
    },
    HostedRpcProviderDefinition {
        suffix: "moralis.io",
        provider: RpcProvider::Moralis,
        path_grammar: HostedRpcPathGrammar::VersionedOrDirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "chainstack.com",
        provider: RpcProvider::Chainstack,
        path_grammar: HostedRpcPathGrammar::VersionedOrDirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "getblock.io",
        provider: RpcProvider::GetBlock,
        path_grammar: HostedRpcPathGrammar::DirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "quiknode.pro",
        provider: RpcProvider::QuickNode,
        path_grammar: HostedRpcPathGrammar::VersionedOrDirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "quicknode.com",
        provider: RpcProvider::QuickNode,
        path_grammar: HostedRpcPathGrammar::VersionedOrDirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "ankr.com",
        provider: RpcProvider::Ankr,
        path_grammar: HostedRpcPathGrammar::VersionedOrDirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "blastapi.io",
        provider: RpcProvider::Other,
        path_grammar: HostedRpcPathGrammar::DirectToken,
    },
    HostedRpcProviderDefinition {
        suffix: "drpc.org",
        provider: RpcProvider::Other,
        path_grammar: HostedRpcPathGrammar::NoCredentialPath,
    },
    HostedRpcProviderDefinition {
        suffix: "llamarpc.com",
        provider: RpcProvider::Other,
        path_grammar: HostedRpcPathGrammar::NoCredentialPath,
    },
    HostedRpcProviderDefinition {
        suffix: "tenderly.co",
        provider: RpcProvider::Other,
        path_grammar: HostedRpcPathGrammar::DirectToken,
    },
];

const RPC_CREDENTIAL_PATH_PREFIXES: &[&str] =
    &["v1", "v2", "v3", "api", "rpc", "jsonrpc", "ext", "evm"];

fn hosted_rpc_provider(host: &str) -> Option<&'static HostedRpcProviderDefinition> {
    // URL parsers preserve a valid fully-qualified DNS root dot. Normalize
    // exactly one for provider identity; `host..` remains unmatched.
    let host = host.strip_suffix('.').unwrap_or(host);
    HOSTED_RPC_PROVIDERS.iter().find(|definition| {
        host == definition.suffix || host.ends_with(&format!(".{}", definition.suffix))
    })
}

fn rpc_provider(host: &str) -> (RpcProvider, Option<&'static str>) {
    hosted_rpc_provider(host).map_or((RpcProvider::Other, None), |definition| {
        (definition.provider, Some(definition.suffix))
    })
}

fn is_versioned_provider_credential_slot(segments: &[&str]) -> bool {
    segments.len() >= 2
        && RPC_CREDENTIAL_PATH_PREFIXES
            .iter()
            .any(|prefix| segments[0].eq_ignore_ascii_case(prefix))
}

fn provider_path_contains_credentials(
    definition: &HostedRpcProviderDefinition,
    segments: &[&str],
) -> bool {
    let versioned = is_versioned_provider_credential_slot(segments);
    // A catalog-declared direct path is the provider's credential slot, not a
    // public resource selector. Base58 shape therefore cannot exempt a token
    // here; public-identity exemptions remain limited to generic RPC paths and
    // explicit public query selectors.
    let direct = segments
        .iter()
        .any(|segment| looks_rpc_credential_token(segment));
    match definition.path_grammar {
        HostedRpcPathGrammar::VersionedSlot => versioned,
        HostedRpcPathGrammar::DirectToken => direct,
        HostedRpcPathGrammar::VersionedOrDirectToken => versioned || direct,
        HostedRpcPathGrammar::NoCredentialPath => false,
    }
}

/// Canonicalize a reviewed hosted-provider URL to its catalog suffix and remove
/// only a credential-bearing path suffix. Query, fragment, and userinfo
/// ownership remains with the calling URL boundary. Returns whether the host
/// belongs to the reviewed provider catalog.
pub(crate) fn sanitize_hosted_rpc_url_for_display(parsed: &mut url::Url) -> bool {
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let Some(definition) = hosted_rpc_provider(&host) else {
        return false;
    };
    let segments = parsed
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let borrowed = segments.iter().map(String::as_str).collect::<Vec<_>>();
    if provider_path_contains_credentials(definition, &borrowed) {
        if is_versioned_provider_credential_slot(&borrowed) {
            parsed.set_path(&format!("/{}", borrowed[0]));
        } else {
            parsed.set_path("/");
        }
    }
    parsed
        .set_host(Some(definition.suffix))
        .expect("reviewed hosted-RPC suffix must remain a valid URL host");
    true
}

fn validate_rpc_endpoint_projection(projection: &RpcEndpointProjection) -> bool {
    if !matches!(projection.scheme.as_str(), "http" | "https" | "ws" | "wss")
        || projection.host.is_empty()
        || projection.host.len() > 253
        || projection.host != projection.host.to_ascii_lowercase()
        || projection.host.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '@' | '/' | '?' | '#')
        })
    {
        return false;
    }
    let valid_host_grammar = if projection.host == "redacted-host" {
        true
    } else if let Some(ipv6) = projection
        .host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        ipv6.parse::<std::net::Ipv6Addr>().is_ok()
    } else if projection.host.contains([':', '[', ']']) {
        false
    } else if projection.host.parse::<std::net::Ipv4Addr>().is_ok() {
        true
    } else {
        let dns = projection
            .host
            .strip_suffix('.')
            .unwrap_or(&projection.host);
        !dns.is_empty()
            && dns.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    };
    if !valid_host_grammar {
        return false;
    }
    if projection.host != "redacted-host"
        && projection
            .host
            .trim_matches(['[', ']'])
            .split('.')
            .any(looks_rpc_credential_token)
    {
        return false;
    }
    let (provider, canonical_host) = rpc_provider(&projection.host);
    if provider != projection.provider {
        return false;
    }
    if canonical_host.is_some_and(|canonical_host| projection.host != canonical_host) {
        return false;
    }
    if projection.host == "redacted-host" && projection.provider != RpcProvider::Other {
        return false;
    }
    true
}

impl RpcEndpointSummary {
    pub fn is_hosted_provider(&self) -> bool {
        hosted_rpc_provider(&self.host).is_some()
    }
}

#[cfg(test)]
pub(crate) fn hosted_rpc_provider_credential_urls(secret: &str) -> Vec<(&'static str, String)> {
    HOSTED_RPC_PROVIDERS
        .iter()
        .map(|definition| {
            let url = match definition.path_grammar {
                HostedRpcPathGrammar::VersionedSlot => {
                    format!("https://node.{}/v3/{secret}", definition.suffix)
                }
                HostedRpcPathGrammar::DirectToken
                | HostedRpcPathGrammar::VersionedOrDirectToken => {
                    format!("https://node.{}/{secret}", definition.suffix)
                }
                HostedRpcPathGrammar::NoCredentialPath => {
                    format!("https://node.{}/rpc?api_key={secret}", definition.suffix)
                }
            };
            (definition.suffix, url)
        })
        .collect()
}

fn looks_rpc_credential_token(value: &str) -> bool {
    let value = value.trim_matches('/');
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    if hex.is_some_and(|hex| {
        matches!(hex.len(), 40 | 64) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return false;
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "mainnet"
            | "testnet"
            | "devnet"
            | "sepolia"
            | "holesky"
            | "goerli"
            | "latest"
            | "pending"
            | "finalized"
            | "safe"
    ) {
        return false;
    }
    value.len() >= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && (value.bytes().any(|byte| byte.is_ascii_digit()) || value.len() >= 24)
}

fn looks_public_solana_identifier(value: &str) -> bool {
    // Solana public keys are 32-byte base58 values (normally 32–44 chars), and
    // transaction signatures are 64-byte base58 values (normally 80–88 chars).
    // Keep this exemption scoped to public selector fields and RPC path
    // segments; it must not weaken generic token-valued query parameters.
    matches!(value.len(), 32..=44 | 80..=88)
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'1'..=b'9'
                    | b'A'..=b'H'
                    | b'J'..=b'N'
                    | b'P'..=b'Z'
                    | b'a'..=b'k'
                    | b'm'..=b'z'
            )
        })
}

fn host_has_rpc_service_label(host: &str) -> bool {
    host.split('.').any(|label| {
        let label = label.to_ascii_lowercase();
        matches!(label.as_str(), "rpc" | "node" | "nodes" | "jsonrpc")
            || label.strip_prefix("rpc").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
            || label.starts_with("rpc-")
            || label.ends_with("-rpc")
    })
}

fn rpc_query_contains_credentials(parsed: &url::Url) -> bool {
    parsed.query_pairs().any(|(key, value)| {
        let compact_key = key
            .bytes()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .map(|byte| byte.to_ascii_lowercase() as char)
            .collect::<String>();
        let sensitive_key = matches!(
            compact_key.as_str(),
            "key"
                | "apikey"
                | "token"
                | "authtoken"
                | "accesstoken"
                | "oauthtoken"
                | "secret"
                | "clientsecret"
                | "password"
                | "passwd"
                | "auth"
                | "authorization"
                | "projectid"
        );
        let solana_identity_selector = matches!(
            compact_key.as_str(),
            "account"
                | "address"
                | "blockhash"
                | "mint"
                | "programid"
                | "pubkey"
                | "sig"
                | "signature"
                | "transactionhash"
                | "txhash"
        );
        if solana_identity_selector && looks_public_solana_identifier(&value) {
            return false;
        }
        (!value.is_empty() && sensitive_key) || looks_rpc_credential_token(&value)
    })
}

fn rpc_fragment_contains_credentials(parsed: &url::Url) -> bool {
    parsed.fragment().is_some_and(|fragment| {
        let lower = fragment.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "mainnet" | "testnet" | "devnet" | "latest" | "finalized" | "safe"
        ) {
            return false;
        }
        !fragment.is_empty()
    })
}

pub fn rpc_endpoint_summary(value: &str) -> Option<RpcEndpointSummary> {
    let value = value.trim().trim_matches(|ch| matches!(ch, '\'' | '\"'));
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") {
        return None;
    }
    let raw_host = parsed.host_str()?.to_ascii_lowercase();
    let (provider, provider_host) = rpc_provider(&raw_host);
    let host_has_token = raw_host.split('.').any(looks_rpc_credential_token);
    let host_has_rpc_service = host_has_rpc_service_label(&raw_host);
    let hosted_provider = hosted_rpc_provider(&raw_host);
    let host = if let Some(provider_host) = provider_host {
        provider_host.to_string()
    } else if host_has_token || raw_host.len() > 253 {
        "redacted-host".to_string()
    } else if raw_host.starts_with('[') && raw_host.ends_with(']') {
        raw_host
    } else if raw_host.contains(':') {
        format!("[{raw_host}]")
    } else {
        raw_host
    };
    let segments = parsed
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let path_class = match segments.first().map(|segment| segment.to_ascii_lowercase()) {
        None => RpcPathClass::Root,
        Some(first) if first == "rpc" => RpcPathClass::Rpc,
        Some(first) if first == "jsonrpc" => RpcPathClass::JsonRpc,
        Some(first) if matches!(first.as_str(), "v1" | "v2" | "v3" | "api" | "ext" | "evm") => {
            RpcPathClass::Versioned
        }
        Some(_) => RpcPathClass::Opaque,
    };
    // Known hosted-provider credential slots take precedence over public-ID
    // shape exemptions: `/v2/<key>` and `/v3/<project-id>` routinely accept
    // base58-alphabet credentials. On a generic RPC host, however, an exact
    // Solana public key/signature path segment is public identity material.
    let provider_credential_slot = hosted_provider
        .is_some_and(|definition| provider_path_contains_credentials(definition, &segments));
    // `rpc_endpoint_summary` is also called defensively for arbitrary HTTP(S)
    // URLs found in public output. A long opaque path on an ordinary website is
    // not, by itself, evidence of an RPC credential; treating it as one erases
    // useful URL context and can swallow a canonical custom-DLP marker. Keep
    // generic path-token classification behind an RPC-shaped path or host,
    // while known providers retain their explicit credential-slot contract.
    let generic_rpc_path_context = matches!(
        path_class,
        RpcPathClass::Rpc | RpcPathClass::JsonRpc | RpcPathClass::Versioned
    ) || host_has_rpc_service;
    let path_has_token = provider_credential_slot
        || (hosted_provider.is_none()
            && generic_rpc_path_context
            && segments.iter().any(|segment| {
                looks_rpc_credential_token(segment) && !looks_public_solana_identifier(segment)
            }));
    let mut credentials = Vec::new();
    if !parsed.username().is_empty() || parsed.password().is_some() {
        credentials.push(RpcCredentialClass::UserInfo);
    }
    if rpc_query_contains_credentials(&parsed) {
        credentials.push(RpcCredentialClass::Query);
    }
    if rpc_fragment_contains_credentials(&parsed) {
        credentials.push(RpcCredentialClass::Fragment);
    }
    if host_has_token {
        credentials.push(RpcCredentialClass::HostToken);
    }
    if path_has_token {
        credentials.push(RpcCredentialClass::PathToken);
    }
    let credential_class = match credentials.as_slice() {
        [] => RpcCredentialClass::Public,
        [only] => *only,
        _ => RpcCredentialClass::Multiple,
    };
    RpcEndpointSummary::from_projection(RpcEndpointProjection {
        scheme: parsed.scheme().to_string(),
        host,
        port: parsed.port(),
        provider,
        path_class,
        credential_class,
    })
}

pub fn rpc_endpoint_contains_credentials(value: &str) -> bool {
    rpc_endpoint_summary(value)
        .is_some_and(|summary| summary.credential_class != RpcCredentialClass::Public)
}

pub fn is_sensitive_env_assignment(name: &str, value: &str) -> bool {
    let value = strip_unquoted_rc_comment(value);
    let trimmed = value.trim();
    let semantic_value = if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if semantic_value.is_empty() {
        return false;
    }
    match sensitive_env_kind(name) {
        Some(kind) if kind.is_secret() => true,
        Some(SensitiveEnvKind::RpcEndpoint) => rpc_endpoint_contains_credentials(semantic_value),
        _ => false,
    }
}

/// Return only non-secret RPC origin components for display.
pub fn canonicalize_rpc_for_display(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(|ch| matches!(ch, '\'' | '\"'));
    let symbolic = (value.starts_with('$') || value.starts_with('%'))
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "$_{}:%".contains(ch));
    if symbolic {
        return Some(value.to_string());
    }
    let summary = rpc_endpoint_summary(value)?;
    let mut canonical = format!("{}://{}", summary.scheme, summary.host);
    if let Some(port) = summary.port {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    Some(canonical)
}

#[cfg(test)]
fn redact_bare_credential_rpc_urls(input: &str) -> String {
    BARE_RPC_URL_RE
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let matched = captures.get(0).map_or("", |value| value.as_str());
            let core = matched.trim_end_matches([')', ']', '}']);
            if !rpc_endpoint_contains_credentials(core) {
                return matched.to_string();
            }
            let suffix = &matched[core.len()..];
            canonicalize_rpc_for_display(core)
                .map(|canonical| format!("{canonical}{suffix}"))
                .unwrap_or_else(|| "[REDACTED:rpc]".to_string())
        })
        .into_owned()
}

pub(crate) fn sensitive_value_redaction_spans(input: &str) -> Vec<SensitiveValueRedactionSpan> {
    let structured = structured_secret_spans(input, DetectionContext::Redaction);
    if structured.incomplete {
        return (!input.is_empty())
            .then(|| SensitiveValueRedactionSpan {
                range: 0..input.len(),
                replacement: "[REDACTED:analysis_incomplete]".to_string(),
                priority: 400,
            })
            .into_iter()
            .collect();
    }
    let mut spans = structured
        .spans
        .into_iter()
        .map(|span| {
            let label = match span.kind {
                SensitiveAssetKind::EvmPrivateKey => "evm_private_key",
                SensitiveAssetKind::Bip39Mnemonic => "bip39_mnemonic",
                SensitiveAssetKind::SolanaKeypair => "solana_keypair",
                _ => "sensitive_asset",
            };
            SensitiveValueRedactionSpan {
                range: span.range,
                replacement: format!("[REDACTED:{label}]"),
                priority: 300,
            }
        })
        .collect::<Vec<_>>();

    for matched in BARE_RPC_URL_RE.find_iter(input) {
        let core = matched.as_str().trim_end_matches([')', ']', '}']);
        if !rpc_endpoint_contains_credentials(core) {
            continue;
        }
        let replacement =
            canonicalize_rpc_for_display(core).unwrap_or_else(|| "[REDACTED:rpc]".to_string());
        spans.push(SensitiveValueRedactionSpan {
            range: matched.start()..matched.start() + core.len(),
            replacement,
            priority: 290,
        });
    }

    for captures in RPC_VALUE_RE.captures_iter(input) {
        let Some(value) = captures.name("value") else {
            continue;
        };
        let replacement = canonicalize_rpc_for_display(value.as_str())
            .unwrap_or_else(|| "[REDACTED:rpc]".to_string());
        spans.push(SensitiveValueRedactionSpan {
            range: value.range(),
            replacement,
            priority: 295,
        });
    }

    for captures in SENSITIVE_VALUE_RE.captures_iter(input) {
        let Some(value) = captures.name("value") else {
            continue;
        };
        if is_canonical_redaction_marker(value.as_str()) {
            continue;
        }
        spans.push(SensitiveValueRedactionSpan {
            range: value.range(),
            replacement: "[REDACTED:web3_secret]".to_string(),
            priority: 250,
        });
    }
    spans
}

fn render_sensitive_value_spans(
    input: &str,
    mut spans: Vec<SensitiveValueRedactionSpan>,
) -> String {
    if spans.is_empty() {
        return input.to_string();
    }
    spans.sort_by_key(|span| (span.range.start, span.range.end));
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut index = 0usize;
    while index < spans.len() {
        let mut start = spans[index].range.start;
        let mut end = spans[index].range.end;
        let mut winner = index;
        index += 1;
        while index < spans.len() && spans[index].range.start < end {
            start = start.min(spans[index].range.start);
            end = end.max(spans[index].range.end);
            if spans[index].priority > spans[winner].priority {
                winner = index;
            }
            index += 1;
        }
        if start < cursor || end > input.len() {
            continue;
        }
        output.push_str(&input[cursor..start]);
        output.push_str(&spans[winner].replacement);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

/// Always-on redactor for Web3 command/JSON forms and structurally validated
/// wallet secrets. It is idempotent and emits no secret-derived identifier.
pub fn redact_sensitive_values(input: &str) -> String {
    render_sensitive_value_spans(input, sensitive_value_redaction_spans(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solana_keypair(seed: [u8; 32]) -> String {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut bytes = seed.to_vec();
        bytes.extend_from_slice(signing.verifying_key().as_bytes());
        serde_json::to_string(&bytes).unwrap()
    }

    #[test]
    fn evm_scalar_requires_context_and_valid_range() {
        let scalar = format!("0x{}1", "0".repeat(63));
        assert!(is_valid_evm_private_key(&scalar));
        assert!(!is_valid_evm_private_key(&format!("0x{}", "0".repeat(64))));
        assert!(!is_valid_evm_private_key(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        assert!(
            observations(&format!("PRIVATE_KEY={scalar}"), DetectionContext::FileScan)
                .iter()
                .any(|observation| observation.kind == SensitiveAssetKind::EvmPrivateKey)
        );
        assert!(!observations(
            &format!("transaction_hash={scalar}"),
            DetectionContext::FileScan
        )
        .iter()
        .any(|observation| observation.kind == SensitiveAssetKind::EvmPrivateKey));
    }

    #[test]
    fn bip39_wordlist_count_checksum_and_nfkd_normalization() {
        assert_eq!(BIP39_ENGLISH.len(), 2048);
        let canonical = include_str!("../assets/data/bip39_english.txt")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let digest = Sha256::digest(canonical.as_bytes());
        assert_eq!(hex::encode(digest), BIP39_ENGLISH_SHA256);
        let source = include_str!("../assets/data/bip39_english.SOURCE");
        assert!(source.contains(BIP39_ENGLISH_SHA256));
        assert!(source.contains("SPDX-License-Identifier: MIT"));
        assert!(source.contains("ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e"));
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(is_valid_bip39_mnemonic(valid));
        assert!(!is_valid_bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability"
        ));
        let full_width = valid
            .chars()
            .map(|ch| match ch {
                'a'..='z' => char::from_u32(ch as u32 + 0xfee0).unwrap(),
                _ => ch,
            })
            .collect::<String>();
        assert!(is_valid_bip39_mnemonic(&full_width));
        assert!(observations(valid, DetectionContext::FileScan)
            .iter()
            .any(|observation| observation.kind == SensitiveAssetKind::Bip39Mnemonic));
        assert!(!observations(valid, DetectionContext::Exec)
            .iter()
            .any(|observation| observation.kind == SensitiveAssetKind::Bip39Mnemonic));
        let command = format!("cast wallet import deployer --mnemonic {valid}");
        let redacted = redact_sensitive_values(&command);
        assert!(!redacted.contains(valid));
        assert!(!redacted.contains("abandon"));
        assert!(!redacted.contains("about"));
        assert!(redacted.contains("[REDACTED:bip39_mnemonic]"));
    }

    #[test]
    fn solana_keypair_requires_matching_public_half() {
        let valid = solana_keypair([7u8; 32]);
        assert!(is_valid_solana_keypair_array(&valid));
        let mut invalid: Vec<u8> = serde_json::from_str(&valid).unwrap();
        invalid[63] ^= 1;
        assert!(!is_valid_solana_keypair_array(
            &serde_json::to_string(&invalid).unwrap()
        ));
    }

    #[test]
    fn path_matrix_distinguishes_wallet_storage_from_extension_source() {
        let storage = [
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
            r"C:\Users\Alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\000003.log",
            "/home/alice/.config/google-chrome/Default/IndexedDB/chrome-extension_acmacodkjbdgmoleebolmdjonilkdbch_0.indexeddb.leveldb/000003.log",
        ];
        for path in storage {
            assert_eq!(
                classify_path(path).map(|observation| observation.kind),
                Some(SensitiveAssetKind::BrowserWalletStorage),
                "{path}"
            );
            assert!(is_sensitive_bind_path(path), "{path}");
        }
        assert!(classify_path("/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/12.0/manifest.json").is_none());
        assert_eq!(
            classify_path(r"C:\Users\Alice\AppData\Roaming\Electrum\wallets\default_wallet")
                .map(|observation| observation.kind),
            Some(SensitiveAssetKind::WalletDatabase)
        );
        assert_eq!(
            classify_path("/home/alice/.ethereum/keystore/UTC--2026-01-01--abc")
                .map(|observation| observation.kind),
            Some(SensitiveAssetKind::EncryptedKeystore)
        );
        for path in [
            "/Users/alice/Library/Ethereum/keystore/UTC--2026--abc",
            "/uSeRs/Alice/lIbRaRy/aPpLiCaTiOn SuPpOrT/eXoDuS/eXoDuS.WaLlEt/seed.seco",
            "~/lIbRaRy/aPpLiCaTiOn SuPpOrT/aToMiC/Local Storage/leveldb/000003.log",
            "$HOME/LIBRARY/APPLICATION SUPPORT/LEDGER LIVE/wallet.db",
            "/Users/Alice/WALLET.DAT",
            r"C:\Users\Alice\AppData\Roaming\Ethereum\keystore\UTC--2026--abc",
            "/Users/alice/Library/Application Support/Exodus/exodus.wallet/seed.seco",
            r"C:\Users\Alice\AppData\Roaming\atomic\Local Storage\leveldb\000003.log",
            "/Users/alice/Library/Application Support/Ledger Live/wallet.db",
        ] {
            assert!(classify_path(path).is_some(), "{path}");
            assert!(is_sensitive_bind_path(path), "{path}");
        }
        for relative in [
            "wallet.dat",
            "./wallet.dat",
            "solana-keypair.json",
            "keys/deployer-keypair.json",
            "~/.ethereum/./keystore",
        ] {
            assert!(classify_path(relative).is_some(), "{relative}");
            assert!(is_sensitive_bind_path(relative), "{relative}");
        }
        for benign in [
            "mywallet.dat.bak",
            "solana-keypair.json.example",
            "~/.ethereum-not/keystore/UTC--example",
            "extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/manifest.json",
        ] {
            assert!(classify_path(benign).is_none(), "{benign}");
        }
        for foreign_posix in [
            "/home/alice/.SSH/notes",
            "/home/alice/library/ethereum/keystore/example",
            "/home/alice/library/application support/exodus/exodus.wallet/seed.seco",
            "/home/alice/Library/Application Support/exodus/exodus.wallet/seed.seco",
            "/home/alice/WALLET.DAT",
            "/home/alice/archive/a:WALLET.DAT",
        ] {
            assert!(
                classify_path_for_flavor(foreign_posix, SensitivePathFlavor::Posix).is_none(),
                "foreign POSIX path became case-insensitive: {foreign_posix}"
            );
        }
        for conservative in [
            "~/.ethereum/keystore/../documentation/index.md",
            "/home/alice/link/../etc/shadow",
            "/home/alice/.ssh/extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/private",
            r"C:wallet.dat",
            r"C:\Users\Alice\solana-keypair.json:secret",
        ] {
            assert!(classify_path(conservative).is_some(), "{conservative}");
        }
        for command in [
            r"type C:WALLET.DAT",
            r"type C:\Users\Alice\SOLANA-KEYPAIR.JSON:secret",
            "cat /uSeRs/Alice/lIbRaRy/aPpLiCaTiOn SuPpOrT/eXoDuS/eXoDuS.WaLlEt/seed.seco",
            "WALLET_PATH=/Users/Alice/LIBRARY/APPLICATION SUPPORT/ATOMIC/storage",
        ] {
            assert!(tier1_sensitive_asset_candidate(command), "{command}");
        }
        assert_eq!(
            normalize_path_for_match(r"C:\Users\Alice\.\Wallet\..\Electrum\wallets\default"),
            "c:/users/alice/wallet/../electrum/wallets/default"
        );
        assert_eq!(
            normalize_path_for_match(
                "/uSeRs/Alice/lIbRaRy/aPpLiCaTiOn SuPpOrT/eXoDuS/eXoDuS.WaLlEt"
            ),
            "/users/alice/library/application support/exodus/exodus.wallet"
        );
        assert_eq!(
            normalize_definition_root("Library/Ethereum", SensitivePathFlavor::Posix),
            "Library/Ethereum"
        );
        assert_eq!(
            normalize_definition_root("Library/Ethereum", SensitivePathFlavor::Windows),
            "library/ethereum"
        );
        let capsule_roots = capsule_deny_relative_paths().collect::<Vec<_>>();
        for root in [
            ".ethereum/keystore",
            "Library/Ethereum/keystore",
            "AppData/Roaming/Ethereum/keystore",
            ".config/Exodus/exodus.wallet",
            ".config/atomic",
            ".config/Ledger Live",
            "solana-keypair.json",
            "keys",
            ".config/google-chrome",
            "Library/Application Support/Google/Chrome",
            "AppData/Local/Google/Chrome/User Data",
        ] {
            assert!(capsule_roots.contains(&root), "{root}");
        }
        assert!(!is_sensitive_bind_path(
            "~/.ethereum-not/keystore/documentation"
        ));
        for required_mode in [
            SensitivePathMatchMode::BasenameExact,
            SensitivePathMatchMode::BasenameSuffix,
            SensitivePathMatchMode::BrowserExtensionId,
            SensitivePathMatchMode::BrowserStorageRoot,
            SensitivePathMatchMode::BrowserSourceRoot,
        ] {
            assert!(SENSITIVE_PATH_DEFINITIONS
                .iter()
                .any(|definition| definition.match_mode == required_mode));
        }
    }

    #[test]
    fn relative_path_case_semantics_follow_the_explicit_target_platform() {
        for (path, expected_kind) in [
            ("WALLET.DAT", SensitiveAssetKind::WalletDatabase),
            (
                ".CONFIG/EXODUS/EXODUS.WALLET/seed.seco",
                SensitiveAssetKind::DesktopWalletData,
            ),
        ] {
            assert_eq!(
                path_flavor_for_platform(path, SensitivePathFlavor::MacOs),
                SensitivePathFlavor::MacOs,
                "{path}"
            );
            assert_eq!(
                classify_path_for_flavor(path, SensitivePathFlavor::MacOs)
                    .map(|observation| observation.kind),
                Some(expected_kind),
                "macOS relative path missed: {path}"
            );
            assert_eq!(
                path_flavor_for_platform(path, SensitivePathFlavor::Posix),
                SensitivePathFlavor::Posix,
                "{path}"
            );
            assert!(
                classify_path_for_flavor(path, SensitivePathFlavor::Posix).is_none(),
                "Linux relative path became case-insensitive: {path}"
            );
        }

        for command in [
            "cat WALLET.DAT",
            "cat .CONFIG/EXODUS/EXODUS.WALLET/seed.seco",
        ] {
            assert!(
                has_registry_path_candidate_for_platform(command, SensitivePathFlavor::MacOs),
                "macOS Tier 1 missed: {command}"
            );
            assert!(
                !has_registry_path_candidate_for_platform(command, SensitivePathFlavor::Posix),
                "Linux Tier 1 became case-insensitive: {command}"
            );
        }
    }

    #[test]
    fn absolute_local_path_case_semantics_follow_the_explicit_target_platform() {
        for (path, expected_kind) in [
            ("/tmp/WALLET.DAT", SensitiveAssetKind::WalletDatabase),
            (
                "/Volumes/External/.CONFIG/EXODUS/EXODUS.WALLET/seed.seco",
                SensitiveAssetKind::DesktopWalletData,
            ),
            ("/home/alice/WALLET.DAT", SensitiveAssetKind::WalletDatabase),
        ] {
            assert_eq!(
                path_flavor_for_platform(path, SensitivePathFlavor::MacOs),
                SensitivePathFlavor::MacOs,
                "{path}"
            );
            assert_eq!(
                classify_path_for_platform(path, SensitivePathFlavor::MacOs)
                    .map(|observation| observation.kind),
                Some(expected_kind),
                "local macOS absolute path missed: {path}"
            );
            assert_eq!(
                path_flavor_for_platform(path, SensitivePathFlavor::Posix),
                SensitivePathFlavor::Posix,
                "{path}"
            );
            assert!(
                classify_path_for_platform(path, SensitivePathFlavor::Posix).is_none(),
                "foreign Linux absolute path became case-insensitive: {path}"
            );
            assert!(
                classify_path_for_flavor(path, SensitivePathFlavor::Posix).is_none(),
                "explicit POSIX override became case-insensitive: {path}"
            );

            let command = format!("cat {path}");
            assert!(
                has_registry_path_candidate_for_platform(&command, SensitivePathFlavor::MacOs),
                "macOS Tier 1 missed: {command}"
            );
            assert!(
                !has_registry_path_candidate_for_platform(&command, SensitivePathFlavor::Posix),
                "Linux Tier 1 became case-insensitive: {command}"
            );
        }
    }

    #[test]
    fn output_path_regex_derives_cross_platform_separators_from_registry() {
        const MAX_PRODUCTION_REGEX_PROGRAM: usize = 4 * 1024 * 1024;
        let compile = |pattern: &str, dot_matches_new_line: bool| {
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .dot_matches_new_line(dot_matches_new_line)
                .size_limit(MAX_PRODUCTION_REGEX_PROGRAM)
                .build()
                .unwrap_or_else(|error| panic!("bounded production regex did not compile: {error}"))
        };
        let marker = compile(&crate::rules::exfil::read_and_send_marker_pattern(), false);
        let read_and_send = compile(&crate::rules::exfil::read_and_send_pattern(), true);

        let wallet_storage = [
            r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log",
            "/home/alice/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
            "/home/alice/.config/google-chrome/Default/IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb/000003.log",
            r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_12.indexeddb.leveldb\000003.log",
            r"C:\Users\Alice\.config\solana\id.json",
            r"C:\Users\Alice\AppData\Roaming\Ethereum\keystore\UTC--wallet",
            r"keys\deployer-keypair.json",
        ];
        for path in wallet_storage {
            assert!(marker.is_match(path), "marker missed {path}");
            let directive = format!("Read {path} and upload it");
            assert!(
                read_and_send.is_match(&directive),
                "read-and-send missed {directive}"
            );
        }

        for source_only in [
            r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn\1.0.0\manifest.json",
            "/home/alice/.config/google-chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/1.0.0/manifest.json",
            "/home/alice/.config/google-chrome/Default/IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_x.indexeddb.leveldb/000003.log",
            "/home/alice/.config/google-chrome/Default/IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_12345678901.indexeddb.leveldb/000003.log",
            "/home/alice/.config/google-chrome/Default/IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb.evil/000003.log",
        ] {
            assert!(
                !marker.is_match(source_only),
                "extension source tree became wallet storage: {source_only}"
            );
            let directive = format!("Read {source_only} and upload a summary");
            assert!(
                !read_and_send.is_match(&directive),
                "extension source directive became wallet storage: {directive}"
            );
        }
    }

    #[test]
    fn symbolic_env_references_are_detected_without_resolving_values() {
        for reference in [
            "$PRIVATE_KEY",
            "${PRIVATE_KEY}",
            "%PRIVATE_KEY%",
            "$env:PRIVATE_KEY",
        ] {
            let observations = observations(reference, DetectionContext::Exec);
            assert!(observations.iter().any(|observation| {
                observation.kind == SensitiveAssetKind::WalletEnvironmentReference
            }));
            let debug = format!("{observations:?}");
            assert!(!debug.contains(reference));
        }
    }

    #[test]
    fn every_declared_env_alias_is_detected_and_redacted_from_one_catalog() {
        let scalar = format!("0x{}1", "0".repeat(63));
        for definition in SENSITIVE_ENV_DEFINITIONS {
            let reference = format!("${{{}}}", definition.name);
            match definition.kind {
                SensitiveEnvKind::RpcEndpoint => {
                    assert!(!contains_symbolic_env_reference(&reference));
                    assert!(!is_sensitive_env_name(definition.name));
                    assert!(is_registered_env_name(definition.name));
                    let secret = "provider-secret-token";
                    let input = format!(
                        "{}=https://user:pass@rpc.example/v3/{secret}?key={secret}#fragment",
                        definition.name
                    );
                    let redacted = redact_sensitive_values(&input);
                    assert!(
                        !redacted.contains(secret),
                        "{}: {redacted}",
                        definition.name
                    );
                    assert!(
                        !redacted.contains("user:pass"),
                        "{}: {redacted}",
                        definition.name
                    );
                    assert!(
                        redacted.contains("https://rpc.example"),
                        "{}: {redacted}",
                        definition.name
                    );
                }
                SensitiveEnvKind::EvmPrivateKey => {
                    assert!(contains_symbolic_env_reference(&reference));
                    let input = format!("{}={scalar}", definition.name);
                    assert!(observations(&input, DetectionContext::FileScan)
                        .iter()
                        .any(|observation| observation.kind == SensitiveAssetKind::EvmPrivateKey));
                    assert!(!redact_sensitive_values(&input).contains(&scalar));
                }
                _ => {
                    assert!(contains_symbolic_env_reference(&reference));
                    let input = format!("{}=synthetic-sensitive-value", definition.name);
                    assert!(
                        redact_sensitive_values(&input).contains("[REDACTED:web3_secret]"),
                        "missing redaction alias: {}",
                        definition.name
                    );
                }
            }
        }
        let definition_names = SENSITIVE_ENV_DEFINITIONS
            .iter()
            .map(|definition| definition.name)
            .collect::<Vec<_>>();
        let secret_names = secret_env_definitions()
            .map(|definition| definition.name)
            .collect::<Vec<_>>();
        assert_eq!(
            crate::safe_command::sensitive_env_vars(),
            secret_names.as_slice()
        );
        assert!(!secret_names.contains(&"RPC_URL"));
        assert!(secret_names.contains(&"RPC_API_KEY"));
        for prefix in SENSITIVE_ENV_PREFIX_DEFINITIONS {
            let name = format!("{}C04_SECRET", prefix.prefix);
            assert_eq!(sensitive_env_kind(&name), Some(prefix.kind));
            assert!(is_sensitive_env_name(&name));
            assert!(contains_symbolic_env_reference(&format!("${{{name}}}")));
            assert!(redact_sensitive_values(&format!("{name}=prefix-secret"))
                .contains("[REDACTED:web3_secret]"));
        }
        let unique = definition_names
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), definition_names.len());
        for public_name in [
            "AWS_REGION",
            "AWS_SESSION_NAME",
            "AWS_SECURITY_GROUP_ID",
            "GOOGLE_OAUTH_CLIENT_ID",
        ] {
            assert_eq!(sensitive_env_kind(public_name), None, "{public_name}");
            assert!(!is_sensitive_env_name(public_name), "{public_name}");
        }
    }

    #[test]
    fn every_env_definition_canonicalizes_all_supported_spellings() {
        for definition in SENSITIVE_ENV_DEFINITIONS {
            for spelling in alias_spellings(definition.name) {
                assert_eq!(
                    sensitive_env_kind(&spelling),
                    Some(definition.kind),
                    "{} alias {spelling}",
                    definition.name
                );
                assert!(
                    tier1_sensitive_asset_candidate(&format!("set -gx {spelling} value")),
                    "Fish/no-equals Tier-1 gap for {} alias {spelling}",
                    definition.name
                );
                assert!(
                    tier1_sensitive_asset_candidate(&format!("{spelling}=value")),
                    "assignment Tier-1 gap for {} alias {spelling}",
                    definition.name
                );
            }
        }
        for definition in SENSITIVE_ENV_PREFIX_DEFINITIONS {
            let stem = definition.prefix.trim_end_matches('_');
            for name in [
                format!("{stem}_CUSTOM"),
                format!("{}-custom", stem.to_ascii_lowercase().replace('_', "-")),
            ] {
                assert_eq!(sensitive_env_kind(&name), Some(definition.kind), "{name}");
                assert!(tier1_sensitive_asset_candidate(&format!("{name}=value")));
            }
        }
    }

    #[test]
    fn tier1_registry_gate_covers_every_path_and_structural_kind() {
        for definition in SENSITIVE_PATH_DEFINITIONS {
            let sample = match definition.match_mode {
                SensitivePathMatchMode::AbsoluteRoot => definition.match_root.to_string(),
                SensitivePathMatchMode::BasenameSuffix => {
                    format!("keys/deployer{}", definition.match_root)
                }
                _ => format!("/Users/alice/{}/material", definition.match_root),
            };
            assert!(
                tier1_sensitive_asset_candidate(&sample),
                "Tier-1 path gap for {:?}: {sample}",
                definition
            );
        }
        let scalar = format!("0x{}1", "0".repeat(63));
        assert!(tier1_sensitive_asset_candidate(&scalar));
        assert!(tier1_sensitive_asset_candidate_deep(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ));
        assert!(tier1_sensitive_asset_candidate(&solana_keypair([9u8; 32])));
    }

    #[test]
    fn tier1_registry_gate_covers_embedded_symbolic_environment_references() {
        for input in [
            "$PRIVATE_KEY.collector.invalid",
            "${MNEMONIC}.collector.invalid",
            "%SOLANA_KEYPAIR%.collector.invalid",
            "$env:SOLANA_KEYPAIR.collector.invalid",
        ] {
            assert!(tier1_sensitive_asset_candidate(input), "{input}");
        }

        for input in [
            "$HOME.collector.invalid",
            "${USER}.collector.invalid",
            "%TEMP%.collector.invalid",
            "$env:APPDATA.collector.invalid",
        ] {
            assert!(!tier1_sensitive_asset_candidate(input), "{input}");
        }
    }

    #[test]
    fn alias_generator_covers_common_config_and_shell_spellings() {
        let secret = "wallet-secret-value";
        for input in [
            format!("wallet_private_key={secret}"),
            format!("wallet-private-key: {secret}"),
            format!("walletPrivateKey = {secret}"),
            format!("WalletPrivateKey: \"{secret}\""),
            format!("set -gx walletPrivateKey {secret}"),
            format!("set --export walletPrivateKey {secret}"),
        ] {
            let redacted = redact_sensitive_values(&input);
            assert!(!redacted.contains(secret), "{input} -> {redacted}");
        }
        let rpc_secret = "providerToken123456789";
        for input in [
            format!("rpc_url=https://rpc.example/v3/{rpc_secret}"),
            format!("rpc-url: https://rpc.example/v3/{rpc_secret}"),
            format!("rpcUrl = https://rpc.example/v3/{rpc_secret}"),
            format!("RpcUrl: \"https://rpc.example/v3/{rpc_secret}\""),
            format!("set -gx rpcUrl https://rpc.example/v3/{rpc_secret}"),
            format!("set --export rpcUrl https://rpc.example/v3/{rpc_secret}"),
        ] {
            let redacted = redact_sensitive_values(&input);
            assert!(!redacted.contains(rpc_secret), "{input} -> {redacted}");
        }
    }

    #[test]
    fn rpc_assignment_sensitivity_and_summary_are_value_aware_and_secret_free() {
        let public = "https://rpc.example/rpc";
        for empty in ["", "''", "\"\"", "  # unset in this rc scope"] {
            assert!(!is_sensitive_env_assignment("AWS_SECRET_ACCESS_KEY", empty));
            assert!(!is_sensitive_env_assignment("RPC_URL", empty));
        }
        assert!(!is_sensitive_env_assignment("RPC_URL", public));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            "https://rpc.example/rpc # providerToken123456789 is only an rc comment"
        ));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            "\"https://rpc.example/rpc\" # public endpoint"
        ));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            "https://rpc.example/v3/mainnet?chain=mainnet#mainnet"
        ));
        let address = format!("0x{}", "ab".repeat(20));
        let hash = format!("0x{}", "cd".repeat(32));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://rpc.example/v3/{address}")
        ));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://rpc.example/rpc?block_hash={hash}")
        ));
        let solana_program = "Vote111111111111111111111111111111111111111";
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://rpc.example/v1/{solana_program}")
        ));
        assert!(!is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://rpc.example/rpc?program_id={solana_program}")
        ));
        assert!(is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://mainnet.infura.io/v3/{solana_program}")
        ));
        assert!(is_sensitive_env_assignment(
            "RPC_URL",
            &format!("https://rpc.example/rpc?api_key={solana_program}")
        ));
        for secret_url in [
            "https://user:pass@rpc.example/rpc",
            "https://rpc.example/rpc?api_key=hunter2",
            "https://rpc.example/rpc#hunter2",
            "https://rpc.example/rpc#fragment",
            "https://rpc.example/v3/providerToken123456789",
            "https://rpc.example/rpc?apikey=hunter2",
            "https://rpc.example/rpc?api-key=hunter2",
            "https://rpc.example/rpc?authToken=hunter2",
            "https://rpc.example/rpc?projectId=hunter2",
        ] {
            assert!(
                is_sensitive_env_assignment("RPC_URL", secret_url),
                "{secret_url}"
            );
        }

        let raw = "https://user:pass@mainnet.infura.io/v3/providerToken123456789?api_key=hunter2#fragment";
        let summary = rpc_endpoint_summary(raw).expect("valid endpoint");
        let json = serde_json::to_string(&summary).unwrap();
        let debug = format!("{summary:?}");
        for secret in [
            "user",
            "pass",
            "providerToken123456789",
            "hunter2",
            "fragment",
        ] {
            assert!(!json.contains(secret), "{json}");
            assert!(!debug.contains(secret), "{debug}");
        }
        assert_eq!(summary.host, "infura.io");
        assert_eq!(summary.path_class, RpcPathClass::Versioned);
        assert_eq!(summary.credential_class, RpcCredentialClass::Multiple);

        let round_trip: RpcEndpointSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, summary);
        for forged_host in [
            "providertoken123456789.example",
            "providertoken123456789:443",
        ] {
            let mut mutated = summary.clone();
            mutated.host = forged_host.to_string();
            assert_eq!(format!("{mutated:?}"), "RpcEndpointSummary(INVALID)");
            assert!(serde_json::to_string(&mutated).is_err());
        }
        for forged in [
            r#"{"scheme":"https","host":"providertoken123456789.example","provider":"other","path_class":"opaque","credential_class":"public"}"#,
            r#"{"scheme":"https","host":"providertoken123456789:443","provider":"other","path_class":"opaque","credential_class":"public"}"#,
            r#"{"scheme":"https","host":"infura.io/path-secret","provider":"infura","path_class":"versioned","credential_class":"public"}"#,
            r#"{"scheme":"https","host":"infura.io","provider":"other","path_class":"versioned","credential_class":"public"}"#,
            r#"{"scheme":"file","host":"infura.io","provider":"infura","path_class":"root","credential_class":"public"}"#,
            r#"{"scheme":"https","host":"infura.io","provider":"infura","path_class":"root","credential_class":"public","raw":"providerToken123456789"}"#,
        ] {
            assert!(
                serde_json::from_str::<RpcEndpointSummary>(forged).is_err(),
                "forged projection was accepted: {forged}"
            );
        }
    }

    #[test]
    fn hosted_rpc_catalog_classifies_and_redacts_each_credential_grammar() {
        let secret = "providerToken123456789";
        for (suffix, url) in hosted_rpc_provider_credential_urls(secret) {
            let summary = rpc_endpoint_summary(&url).expect("hosted RPC summary");
            assert!(summary.is_hosted_provider(), "{url}");
            assert_ne!(
                summary.credential_class,
                RpcCredentialClass::Public,
                "{url}"
            );
            assert!(rpc_endpoint_contains_credentials(&url), "{url}");
            let redacted = redact_sensitive_values(&format!("request failed for {url}"));
            assert!(!redacted.contains(secret), "{url} -> {redacted}");
            assert!(redacted.contains(suffix), "{url} -> {redacted}");
        }
    }

    #[test]
    fn hosted_direct_slots_do_not_confuse_base58_credentials_with_public_selectors() {
        let public_solana_id = "Vote111111111111111111111111111111111111111";
        for url in [
            "https://snowy-white-lake.solana-mainnet.quiknode.pro/mainnet".to_string(),
            format!("https://rpc.example/v1/{public_solana_id}"),
            format!("https://example.test/{public_solana_id}"),
            format!("https://example.test/0x{}", "ab".repeat(20)),
        ] {
            let summary = rpc_endpoint_summary(&url).expect("public URL summary");
            assert_eq!(
                summary.credential_class,
                RpcCredentialClass::Public,
                "{url}"
            );
            assert_eq!(redact_bare_credential_rpc_urls(&url), url);
        }

        for host in [
            "snowy-white-lake.solana-mainnet.quiknode.pro",
            "snowy-white-lake.solana-mainnet.quiknode.pro.",
        ] {
            for secret in ["providerToken123456789", "123456789ABCDEFGHJKLMNPQRSTUVWXY"] {
                let secret_url = format!("https://{host}/{secret}");
                let summary =
                    rpc_endpoint_summary(&secret_url).expect("QuickNode direct credential");
                assert_eq!(summary.credential_class, RpcCredentialClass::PathToken);
                assert!(!redact_sensitive_values(&secret_url).contains(secret));
            }
        }
    }

    #[test]
    fn rpc_redaction_covers_bare_urls_and_unquoted_multi_query_values() {
        let secret = "providerToken123456789";
        for input in [
            format!("RPC_URL: https://rpc.example/v3/mainnet?chain=mainnet&api_key={secret}"),
            format!("request failed for https://rpc.example/v3/{secret}?chain=mainnet"),
        ] {
            let redacted = redact_sensitive_values(&input);
            assert!(!redacted.contains(secret), "{redacted}");
            assert!(!redacted.contains("api_key="), "{redacted}");
            assert!(redacted.contains("https://rpc.example"), "{redacted}");
        }
        let public = "request failed for https://rpc.example/v3/mainnet?chain=mainnet";
        assert_eq!(redact_bare_credential_rpc_urls(public), public);
    }

    #[test]
    fn opaque_web_paths_do_not_masquerade_as_rpc_credentials_or_swallow_markers() {
        let token = "C02_SCORE_CUSTOM_RECONSTITUTION_CANARY";
        let ordinary = format!("https://example.test/{token}");
        let summary = rpc_endpoint_summary(&ordinary).expect("ordinary HTTPS URL parses");
        assert_eq!(summary.path_class, RpcPathClass::Opaque);
        assert_eq!(summary.credential_class, RpcCredentialClass::Public);
        assert_eq!(redact_bare_credential_rpc_urls(&ordinary), ordinary);

        let marker = "https://example.test/[REDACTED:custom]";
        assert_eq!(redact_bare_credential_rpc_urls(marker), marker);

        let rpc_host = format!("https://rpc.example/{token}");
        let summary = rpc_endpoint_summary(&rpc_host).expect("RPC-shaped HTTPS URL parses");
        assert_eq!(summary.credential_class, RpcCredentialClass::PathToken);
        let redacted = redact_bare_credential_rpc_urls(&rpc_host);
        assert!(!redacted.contains(token), "{redacted}");
        assert!(redacted.contains("https://rpc.example"), "{redacted}");
    }

    #[test]
    fn mandatory_redaction_covers_flags_json_multiline_and_rpc() {
        let key = format!("0x{}1", "0".repeat(63));
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let input = format!(
            "cast send --private-key {key} --rpc-url https://user:pass@mainnet.infura.io/v3/provider-secret?token=secret#fragment\n{{\"mnemonic\":\"{mnemonic}\"}}"
        );
        let redacted = redact_sensitive_values(&input);
        assert!(!redacted.contains(&key));
        assert!(!redacted.contains(mnemonic));
        assert!(!redacted.contains("provider-secret"));
        assert!(!redacted.contains("user:pass"));
        assert!(redacted.contains("https://infura.io"));
        assert_eq!(redact_sensitive_values(&redacted), redacted);
    }

    #[test]
    fn mandatory_redaction_covers_multiline_json_separators_and_shell_continuations() {
        let key = format!("0x{}", "11".repeat(32));
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for input in [
            format!("{{\n  \"PRIVATE_KEY\"\n  :\n  \"{key}\"\n}}"),
            format!("PRIVATE_KEY=\\\n{key}"),
            format!("MNEMONIC=\\\n{mnemonic}"),
            format!("{{\n  \"mnemonic\"\n  :\n  \"{mnemonic}\"\n}}"),
        ] {
            let redacted = redact_sensitive_values(&input);
            assert!(!redacted.contains(&key), "{input:?} -> {redacted:?}");
            assert!(!redacted.contains(&key[..18]), "{input:?} -> {redacted:?}");
            assert!(!redacted.contains(mnemonic), "{input:?} -> {redacted:?}");
            assert!(
                !redacted.contains("abandon abandon"),
                "{input:?} -> {redacted:?}"
            );
        }

        for input in [
            format!("{{\n  \"PRIVATE_KEY\"\n  :\n  \"{key}\"\n}}"),
            format!("PRIVATE_KEY=\\\n{key}"),
        ] {
            assert!(
                observations(&input, DetectionContext::FileScan)
                    .iter()
                    .any(|observation| observation.kind == SensitiveAssetKind::EvmPrivateKey),
                "multiline EVM assignment was redacted but not detected: {input:?}"
            );
        }
        for input in [
            format!("{{\n  \"mnemonic\"\n  :\n  \"{mnemonic}\"\n}}"),
            format!("MNEMONIC=\\\n{mnemonic}"),
        ] {
            assert!(
                observations(&input, DetectionContext::Exec)
                    .iter()
                    .any(|observation| observation.kind == SensitiveAssetKind::Bip39Mnemonic),
                "multiline mnemonic assignment was redacted but not detected: {input:?}"
            );
        }
    }

    #[test]
    fn ordinary_exec_prose_does_not_run_global_bip39_recognition() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let prose = format!("documentation example says {mnemonic} for a checksum fixture");
        let keyword_prose = format!("echo \"mnemonic {mnemonic}\"");
        for input in [&prose, &keyword_prose] {
            assert!(
                observations(input, DetectionContext::Exec).is_empty(),
                "{input}"
            );
            assert!(!tier1_sensitive_asset_candidate(input), "{input}");
        }
        assert!(tier1_sensitive_asset_candidate_deep(&prose));
        assert!(observations(&prose, DetectionContext::Paste)
            .iter()
            .any(|observation| observation.kind == SensitiveAssetKind::Bip39Mnemonic));
        assert!(
            observations(&format!("MNEMONIC={mnemonic}"), DetectionContext::Exec)
                .iter()
                .any(|observation| observation.kind == SensitiveAssetKind::Bip39Mnemonic)
        );
    }

    #[test]
    fn ten_mib_non_bip39_file_scan_is_complete_without_owned_word_records() {
        let input = "a ".repeat(5 * 1024 * 1024);
        assert_eq!(input.len(), 10 * 1024 * 1024);

        let mut scan = Bip39ScanResult::default();
        global_mnemonic_spans(&input, &mut scan);
        assert!(!scan.incomplete);
        assert!(scan.spans.is_empty());
        assert_eq!(scan.stats.bip39_word_tokens, 0);
        assert_eq!(scan.stats.checksum_candidates, 0);
        assert_eq!(scan.stats.max_rolling_words, 0);
        assert!(!tier1_sensitive_asset_candidate_deep(&input));
    }

    #[test]
    fn rolling_bip39_scan_is_24_words_and_checksum_budget_bounded() {
        let input = "abandon ".repeat(MAX_BIP39_CHECKSUM_CANDIDATES / 5 + 64);
        let mut scan = Bip39ScanResult::default();
        global_mnemonic_spans(&input, &mut scan);

        assert!(scan.incomplete);
        assert_eq!(
            scan.stats.checksum_candidates,
            MAX_BIP39_CHECKSUM_CANDIDATES
        );
        assert!(scan.stats.bip39_word_tokens <= MAX_BIP39_WORD_TOKENS);
        assert!(scan.stats.max_rolling_words <= MAX_BIP39_WORDS_PER_PHRASE);
    }

    #[test]
    fn oversized_deep_gate_routes_to_fail_closed_scan_before_tokenization() {
        let oversized = "qzxq ".repeat(MAX_BIP39_SCAN_INPUT_BYTES / 5 + 2);
        assert!(oversized.len() > MAX_BIP39_SCAN_INPUT_BYTES);
        assert!(tier1_sensitive_asset_candidate_deep(&oversized));

        let mut scan = Bip39ScanResult::default();
        global_mnemonic_spans(&oversized, &mut scan);
        assert!(scan.incomplete);
        assert_eq!(scan.stats, Bip39ScanStats::default());
    }

    #[test]
    fn punctuation_cannot_join_a_global_bip39_run() {
        let punctuated = format!("{}about", "abandon,".repeat(11));
        assert!(!is_valid_bip39_mnemonic(&punctuated));
        assert!(!has_bip39_word_run_candidate(&punctuated));

        let mut scan = Bip39ScanResult::default();
        global_mnemonic_spans(&punctuated, &mut scan);
        assert!(!scan.incomplete);
        assert!(scan.spans.is_empty());

        let whitespace = format!("{}about", "abandon ".repeat(11));
        assert!(has_bip39_word_run_candidate(&whitespace));
        global_mnemonic_spans(&whitespace, &mut scan);
        assert_eq!(scan.spans.len(), 1);
    }

    #[test]
    fn every_supported_bip39_length_survives_rolling_checksum_validation() {
        for mnemonic in [
            format!("{}about", "abandon ".repeat(11)),
            format!("{}address", "abandon ".repeat(14)),
            format!("{}agent", "abandon ".repeat(17)),
            format!("{}admit", "abandon ".repeat(20)),
            format!("{}art", "abandon ".repeat(23)),
        ] {
            assert!(is_valid_bip39_mnemonic(&mnemonic), "{mnemonic}");
            let mut scan = Bip39ScanResult::default();
            global_mnemonic_spans(&mnemonic, &mut scan);
            assert!(!scan.incomplete, "{mnemonic}");
            assert_eq!(scan.spans.len(), 1, "{mnemonic}");
            assert_eq!(scan.spans[0].range, 0..mnemonic.len(), "{mnemonic}");
            assert!(scan.stats.max_rolling_words <= MAX_BIP39_WORDS_PER_PHRASE);
        }
    }

    #[test]
    fn checksum_candidate_cap_accepts_the_last_budgeted_check_then_stops() {
        let word = Bip39WordRecord {
            range: 0..7,
            index: bip39_word_index("abandon").unwrap(),
        };
        let words = vec![word; 12];
        let mut scan = Bip39ScanResult {
            stats: Bip39ScanStats {
                checksum_candidates: MAX_BIP39_CHECKSUM_CANDIDATES - 1,
                ..Bip39ScanStats::default()
            },
            ..Bip39ScanResult::default()
        };
        assert_eq!(check_bip39_candidate(&mut scan, &words), Some(false));
        assert!(!scan.incomplete);
        assert_eq!(
            scan.stats.checksum_candidates,
            MAX_BIP39_CHECKSUM_CANDIDATES
        );
        assert_eq!(check_bip39_candidate(&mut scan, &words), None);
        assert!(scan.incomplete);
        assert_eq!(
            scan.stats.checksum_candidates,
            MAX_BIP39_CHECKSUM_CANDIDATES
        );
    }

    #[test]
    fn bip39_word_token_cap_is_exact_for_short_non_candidate_runs() {
        fn input_with_bip_words(count: usize) -> String {
            let mut input = String::with_capacity(count * 9);
            for index in 0..count {
                if index > 0 && index % 11 == 0 {
                    input.push_str("qzxq ");
                }
                input.push_str("abandon ");
            }
            input
        }

        assert!(bip39_word_index("qzxq").is_none());

        let at_cap = input_with_bip_words(MAX_BIP39_WORD_TOKENS);
        let mut complete = Bip39ScanResult::default();
        global_mnemonic_spans(&at_cap, &mut complete);
        assert!(!complete.incomplete);
        assert_eq!(complete.stats.bip39_word_tokens, MAX_BIP39_WORD_TOKENS);
        assert_eq!(complete.stats.checksum_candidates, 0);

        let over_cap = input_with_bip_words(MAX_BIP39_WORD_TOKENS + 1);
        let mut incomplete = Bip39ScanResult::default();
        global_mnemonic_spans(&over_cap, &mut incomplete);
        assert!(incomplete.incomplete);
        assert_eq!(incomplete.stats.bip39_word_tokens, MAX_BIP39_WORD_TOKENS);
    }

    #[test]
    fn bip39_input_and_match_caps_fail_closed_at_their_boundaries() {
        let at_input_cap = "a".repeat(MAX_BIP39_SCAN_INPUT_BYTES);
        let mut input_complete = Bip39ScanResult::default();
        global_mnemonic_spans(&at_input_cap, &mut input_complete);
        assert!(!input_complete.incomplete);
        drop(at_input_cap);

        let oversized = "a".repeat(MAX_BIP39_SCAN_INPUT_BYTES + 1);
        let mut input_limited = Bip39ScanResult::default();
        global_mnemonic_spans(&oversized, &mut input_limited);
        assert!(input_limited.incomplete);
        assert_eq!(input_limited.stats, Bip39ScanStats::default());

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let at_cap = format!("{mnemonic} qzxq ").repeat(MAX_BIP39_MATCHES);
        let mut complete = Bip39ScanResult::default();
        global_mnemonic_spans(&at_cap, &mut complete);
        assert!(!complete.incomplete);
        assert_eq!(complete.stats.confirmed_matches, MAX_BIP39_MATCHES);

        let over_cap = format!("{mnemonic} qzxq ").repeat(MAX_BIP39_MATCHES + 1);
        let mut incomplete = Bip39ScanResult::default();
        global_mnemonic_spans(&over_cap, &mut incomplete);
        assert!(incomplete.incomplete);
        assert_eq!(incomplete.stats.confirmed_matches, MAX_BIP39_MATCHES);
    }

    #[test]
    fn incomplete_bip39_redaction_replaces_the_entire_unproven_value() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let hostile = format!(
            "{}outside {mnemonic}",
            "abandon ".repeat(MAX_BIP39_CHECKSUM_CANDIDATES / 5 + 64)
        );
        let redacted = redact_sensitive_values(&hostile);
        assert_eq!(redacted, "[REDACTED:analysis_incomplete]");
        assert!(!redacted.contains(mnemonic));
    }

    #[test]
    fn windows_wallet_paths_expand_reviewed_environment_roots() {
        for path in [
            r#"%APPDATA%\Exodus\exodus.wallet"#,
            r#""$env:APPDATA"\Electrum\wallets\default_wallet"#,
            r#"${env:APPDATA}\atomic\Local Storage\leveldb"#,
            r#"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn"#,
            r#"'$Env:LOCALAPPDATA'\BraveSoftware\Brave-Browser\User Data\Profile 1\IndexedDB\chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb"#,
        ] {
            assert!(
                classify_path(path).is_some(),
                "wallet path not classified: {path}"
            );
            assert!(
                tier1_sensitive_asset_candidate(&format!("Get-Content {path}")),
                "wallet path did not enter Tier 3: {path}"
            );
        }
    }

    #[test]
    fn prefix_families_require_a_real_canonical_boundary() {
        for benign in ["AWS_SECRETARY", "TWINE_TOKENIZER"] {
            assert_eq!(sensitive_env_kind(benign), None, "{benign}");
            assert!(!contains_symbolic_env_reference(&format!("${{{benign}}}")));
            let input = format!("{benign}=ordinary-value");
            assert_eq!(redact_sensitive_values(&input), input);
        }
        for sensitive in [
            "AWS_SECRET_CUSTOM",
            "aws-secret-custom",
            "TWINE_TOKEN_CUSTOM",
        ] {
            assert!(is_sensitive_env_name(sensitive), "{sensitive}");
        }
    }

    #[test]
    fn only_exact_canonical_markers_are_idempotent() {
        for marker in [
            "[REDACTED]",
            "[REDACTED:web3_secret]",
            "[REDACTED:OpenAI API Key]",
        ] {
            let input = format!("WALLET_PASSWORD={marker}");
            assert_eq!(redact_sensitive_values(&input), input);
        }
        for adversarial in [
            "[REDACTED:hunter2]",
            "[REDACTED]actual-secret",
            "[REDACTED:web3_secret]actual-secret",
            "[REDACTED:bad.label]actual-secret",
            "[REDACTED:]actual-secret",
        ] {
            let input = format!("WALLET_PASSWORD={adversarial}");
            let redacted = redact_sensitive_values(&input);
            assert!(!redacted.contains(adversarial), "{redacted}");
            assert!(redacted.contains("[REDACTED:web3_secret]"), "{redacted}");
        }
    }

    #[test]
    fn observations_and_errors_never_expose_secret_material() {
        let key = format!("0x{}1", "0".repeat(63));
        let observations = observations(&format!("private_key={key}"), DetectionContext::FileScan);
        let public_projection = format!("{observations:?}");
        assert!(!public_projection.contains(&key));
        assert!(!public_projection.contains("0000000000000000"));
    }

    #[test]
    fn benign_hash_docs_and_application_paths_remain_clean() {
        let hash = format!("0x{}", "ab".repeat(32));
        assert!(observations(
            &format!("transaction_hash={hash}"),
            DetectionContext::FileScan
        )
        .is_empty());
        assert!(classify_path("/home/alice/.config/my-app/cache/wallet-icon.png").is_none());
        assert_eq!(
            redact_sensitive_values("docs: use --rpc-url $RPC_URL"),
            "docs: use --rpc-url $RPC_URL"
        );
    }

    #[test]
    fn keystore_validation_requires_typed_v3_object_shape() {
        let valid = r#"{
            "version": 3,
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": {"iv": "00000000000000000000000000000000"},
                "ciphertext": "0011",
                "kdf": "scrypt",
                "kdfparams": {"dklen": 32, "salt": "00000000000000000000000000000000"},
                "mac": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }"#;
        assert!(is_encrypted_keystore_json(valid));
        assert!(observations(valid, DetectionContext::FileScan)
            .iter()
            .any(|observation| observation.kind == SensitiveAssetKind::EncryptedKeystore));

        for benign in [
            r#"{"crypto":"docs","ciphertext":"example","kdf":"overview"}"#,
            r#"{"version":3,"crypto":{"cipher":"rot13","ciphertext":"00","kdf":"argon2"}}"#,
            r#"{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","kdf":"scrypt"}}"#,
            r#"source mentions "crypto", "ciphertext", and "kdf" but is not JSON"#,
            r#"{"version":3,"crypto":"truncated""#,
        ] {
            assert!(!is_encrypted_keystore_json(benign), "{benign}");
            assert!(observations(benign, DetectionContext::FileScan)
                .iter()
                .all(|observation| observation.kind != SensitiveAssetKind::EncryptedKeystore));
        }

        let oversized = " ".repeat(MAX_KEYSTORE_JSON_BYTES + 1);
        assert!(!is_encrypted_keystore_json(&oversized));
    }
}
