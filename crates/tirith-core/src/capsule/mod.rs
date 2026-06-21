//! Runtime containment capsule — portable type layer (Stack E, unit E1).
//!
//! This module holds **types only**: the [`Capsule`] trait, the [`CapsuleSpec`]
//! that describes what to contain, the per-capability [`CapsuleCoverage`] honesty
//! ledger, the policy sub-structs ([`NetworkPolicy`], [`FilesystemPolicy`],
//! [`EnvironmentPolicy`], [`ResourceLimits`], [`HandlePolicy`]), the
//! [`deny_default_paths`] baseline, and the always-degraded [`NoOpCapsule`]. The
//! OS-specific backends (Landlock/seccomp on Linux, Seatbelt on macOS,
//! AppContainer/Job Objects on Windows) arrive in E2-E4; the async egress broker
//! that funnels allow-listed traffic lives in the CLI crate
//! (`tirith::cli::capsule_proxy`) because it needs `tokio`/`hyper`, and
//! `tirith-core` stays async-free.
//!
//! ## Containment honesty + fail-closed (cross-cutting invariant 2)
//!
//! A backend NEVER reports a capability it did not actually enforce.
//! [`CapsuleCoverage`] carries an explicit boolean per capability; a backend sets
//! a flag to `true` only after the OS mechanism that enforces it is in place. A
//! surface that *promises* containment (e.g. `tirith pkg install`) consults
//! [`CapsuleCoverage::is_degraded`] / the specific flags and **fails closed**
//! under degraded coverage unless policy explicitly permits degraded operation.
//! [`NoOpCapsule`] reports everything `false` and, critically, never claims
//! egress — so a missing backend can never be mistaken for a working one.
//!
//! ## The egress proxy is a broker, not the boundary (cross-cutting invariant 3)
//!
//! [`NetworkPolicy::AllowListedDomains`] only describes *intent*. Domain-egress
//! enforcement (`domain_proxy_enforced = true`) may be claimed ONLY where the OS
//! backend blocks raw outbound sockets except to the loopback broker. The broker
//! itself (in the CLI crate) re-resolves once, validates every IP against the
//! same public/non-public classifier the URL validators use, pins the TLS SNI to
//! the approved CONNECT host, and caps connections/bytes/handshake/idle. These
//! types only carry the policy; they assert nothing about enforcement.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Linux runtime-containment backend (Stack E, unit E2): the
/// `LandlockSeccompCapsule` and the internal-launcher containment primitive that
/// applies rlimits -> `PR_SET_NO_NEW_PRIVS` -> Landlock -> seccomp -> env cleanup
/// in a freshly-`exec`'d single-threaded child, NOT inside `pre_exec`. Gated to
/// Linux so macOS / Windows targets compile without `landlock` / `extrasafe`.
#[cfg(target_os = "linux")]
pub mod linux;

/// macOS runtime-containment backend (Stack E, unit E3): the `SeatbeltCapsule`,
/// which builds an SBPL profile (`(deny default)` + the spec's grants, `(deny
/// network*)` except the loopback broker) and probes the system `sandbox-exec`
/// wrapper, reporting honest [`CapsuleCoverage`] (an absent/removed
/// `sandbox-exec` yields degraded coverage, never a silent NoOp success). Gated
/// to macOS; it needs no extra crates (Seatbelt is driven through the OS
/// `sandbox-exec` binary), so the profile/argv builders are pure and the other
/// targets compile without it.
#[cfg(target_os = "macos")]
pub mod macos;

/// Sensitive environment variables stripped from a contained child whenever
/// [`EnvironmentPolicy::deny_sensitive`] is set (the default).
///
/// These are credential / token / agent-socket variables whose mere presence in
/// a child process is a supply-chain exfiltration risk: a malicious install hook
/// or MCP server that inherits `AWS_*` or `GITHUB_TOKEN` can read and beacon them
/// even under filesystem containment. The list is deliberately a *known sensitive
/// set*, not "everything", so a contained build still sees benign config it needs
/// (`PATH`, `HOME` is replaced with a temp dir, locale, etc.).
///
/// Matching is by exact name OR, for the prefix families below, by prefix
/// (`AWS_`, `AZURE_`, `GOOGLE_`, `UV_INDEX`, `PIP_INDEX`, `TWINE_`). The prefix
/// set is kept separate so [`EnvironmentPolicy::is_sensitive`] can apply both
/// rules without ambiguity.
pub const SENSITIVE_ENV_EXACT: &[&str] = &[
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DOCKER_CONFIG",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
];

/// Prefix families stripped alongside [`SENSITIVE_ENV_EXACT`]. Any variable whose
/// name begins with one of these is treated as sensitive (e.g. `AWS_SECRET_ACCESS_KEY`,
/// `UV_INDEX_URL`, `PIP_INDEX_URL`, `TWINE_PASSWORD`, `AZURE_CLIENT_SECRET`).
pub const SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "UV_INDEX",
    "PIP_INDEX",
    "TWINE_",
];

/// Per-capability containment ledger. **The honesty contract of the whole
/// capsule layer (cross-cutting invariant 2).**
///
/// Each field is `true` ONLY when the backend put a real OS mechanism in place
/// that enforces that capability for the spawned child. A field left `false`
/// means "not enforced" — never "assumed". Enforcing surfaces read these flags
/// and fail closed when the coverage they require is missing.
///
/// Coverage is *descriptive*: producing a `CapsuleCoverage` does not contain
/// anything; a backend constructs it to report what it actually achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleCoverage {
    /// Filesystem **read** access is confined to the allow-listed roots.
    pub fs_read_enforced: bool,
    /// Filesystem **write** access is confined to the allow-listed roots.
    pub fs_write_enforced: bool,
    /// Process spawning / `exec` is restricted (e.g. seccomp denies `execve`
    /// outside the launcher, or no new privileges via `PR_SET_NO_NEW_PRIVS`).
    pub exec_limited: bool,
    /// Raw outbound sockets are denied at the OS layer (the precondition for any
    /// domain-egress claim). When this is `false`, the broker is NOT a boundary.
    pub network_raw_denied: bool,
    /// Domain egress is enforced *through the broker*. May be `true` ONLY when
    /// [`Self::network_raw_denied`] is also `true` (invariant 3).
    pub domain_proxy_enforced: bool,
    /// CPU / memory / process-count / open-files / output-size / wall-clock
    /// limits from [`ResourceLimits`] are applied.
    pub resource_limits_enforced: bool,
    /// The child's environment was scrubbed of sensitive variables and given an
    /// isolated HOME/TMPDIR per [`EnvironmentPolicy`].
    pub env_isolated: bool,
    /// Inherited handles/file descriptors were closed down to the explicit
    /// allow-list (Unix: stdio + broker FDs only; Windows: `bInheritHandles=FALSE`
    /// or an explicit allow-list) per [`HandlePolicy`].
    pub handles_isolated: bool,
}

impl CapsuleCoverage {
    /// A coverage ledger with every capability **unenforced**. The honest
    /// starting point for any backend (it raises flags as it applies mechanisms)
    /// and the permanent state of [`NoOpCapsule`].
    pub const NONE: CapsuleCoverage = CapsuleCoverage {
        fs_read_enforced: false,
        fs_write_enforced: false,
        exec_limited: false,
        network_raw_denied: false,
        domain_proxy_enforced: false,
        resource_limits_enforced: false,
        env_isolated: false,
        handles_isolated: false,
    };

    /// True when ANY capability the spec asked for is not enforced. Enforcing
    /// surfaces use this (against the spec's requirements) to decide whether to
    /// fail closed. Pure NoOp coverage is always degraded.
    ///
    /// `required` is the coverage the calling surface *demands*; this returns
    /// `true` if any required flag is not satisfied by `self`.
    pub fn is_degraded_against(&self, required: &CapsuleCoverage) -> bool {
        (required.fs_read_enforced && !self.fs_read_enforced)
            || (required.fs_write_enforced && !self.fs_write_enforced)
            || (required.exec_limited && !self.exec_limited)
            || (required.network_raw_denied && !self.network_raw_denied)
            || (required.domain_proxy_enforced && !self.domain_proxy_enforced)
            || (required.resource_limits_enforced && !self.resource_limits_enforced)
            || (required.env_isolated && !self.env_isolated)
            || (required.handles_isolated && !self.handles_isolated)
    }

    /// True when no capability at all is enforced (the NoOp / total-degradation
    /// signal). A convenience for surfaces that demand *some* containment.
    pub fn is_fully_unenforced(&self) -> bool {
        *self == CapsuleCoverage::NONE
    }

    /// Invariant 3 self-check: a coverage ledger is **incoherent** if it claims
    /// domain-egress enforcement without also denying raw sockets. A backend must
    /// never emit such a ledger; the broker is not a boundary on its own.
    pub fn egress_claim_is_coherent(&self) -> bool {
        !self.domain_proxy_enforced || self.network_raw_denied
    }
}

/// Network containment intent for the child.
///
/// This is *policy*, not enforcement. Whether `AllowListedDomains` is actually
/// honored depends on the backend setting
/// [`CapsuleCoverage::domain_proxy_enforced`] (which itself requires
/// [`CapsuleCoverage::network_raw_denied`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No network capability at all. The target for `pkg install` (installs never
    /// need outbound traffic once the artifacts are quarantined).
    DenyAll,
    /// Outbound traffic is permitted ONLY to the listed domains, and ONLY through
    /// the loopback broker. The `ports` set bounds which CONNECT ports the broker
    /// will honor. Claiming this is *enforced* requires a backend that blocks raw
    /// sockets (invariant 3); otherwise the surface degrades and (for enforcing
    /// commands) fails closed.
    AllowListedDomains {
        /// Lower-cased, trailing-dot-stripped domain names the child may reach.
        domains: BTreeSet<String>,
        /// CONNECT ports the broker may honor (typically `{443}`). Empty means
        /// "no port permitted" — a deliberately useless policy the caller should
        /// not construct.
        ports: BTreeSet<u16>,
    },
}

impl Default for NetworkPolicy {
    /// Deny-all by default: a capsule that does not opt into egress gets none.
    fn default() -> Self {
        NetworkPolicy::DenyAll
    }
}

impl NetworkPolicy {
    /// Whether this policy permits the broker to reach `host` on `port`. The
    /// broker re-checks this on every CONNECT in addition to its IP validation;
    /// this is the *policy* gate, not the SSRF gate.
    pub fn permits(&self, host: &str, port: u16) -> bool {
        match self {
            NetworkPolicy::DenyAll => false,
            NetworkPolicy::AllowListedDomains { domains, ports } => {
                let host_norm = host.trim_end_matches('.').to_ascii_lowercase();
                ports.contains(&port) && domains.contains(&host_norm)
            }
        }
    }

    /// True when the policy permits no egress at all.
    pub fn is_deny_all(&self) -> bool {
        matches!(self, NetworkPolicy::DenyAll)
    }
}

/// Filesystem containment intent: the read/write roots the child is confined to.
///
/// Paths are additive allow-lists layered over [`deny_default_paths`] (the
/// sensitive subtrees denied unless explicitly re-granted). The backend turns
/// these into Landlock rules / Seatbelt allow clauses / AppContainer ACLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Roots the child may read from (recursively).
    #[serde(default)]
    pub read_roots: Vec<PathBuf>,
    /// Roots the child may write to (recursively). A write root implies read.
    #[serde(default)]
    pub write_roots: Vec<PathBuf>,
    /// Sensitive subtrees to deny even if a broader read/write root would cover
    /// them. Seeded from [`deny_default_paths`]; callers may extend it.
    #[serde(default)]
    pub deny_roots: Vec<PathBuf>,
}

impl FilesystemPolicy {
    /// A policy that grants nothing beyond the implicit baseline and denies the
    /// default sensitive subtrees. Callers add the specific roots a task needs.
    pub fn deny_by_default() -> Self {
        FilesystemPolicy {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            deny_roots: deny_default_paths(),
        }
    }
}

/// Environment containment for the child (cross-cutting invariant 2: env
/// isolation is a tracked coverage flag).
///
/// By default the child does **not** inherit the parent environment
/// (`inherit = false`), sensitive variables are stripped even from anything
/// explicitly re-added, and HOME/XDG_*/TMPDIR are pointed at a temporary
/// directory so a contained process cannot read or poison the real user config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    /// Whether to start from the parent's environment. **Defaults to `false`** —
    /// a contained child gets only what is explicitly allowed.
    #[serde(default)]
    pub inherit: bool,
    /// Variables explicitly passed through (by exact name). Even a name listed
    /// here is dropped if [`Self::deny_sensitive`] is set and it matches the
    /// sensitive set, so an allow entry can never re-expose a credential.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Strip the known sensitive variables ([`SENSITIVE_ENV_EXACT`] +
    /// [`SENSITIVE_ENV_PREFIXES`]). **Defaults to `true`.**
    #[serde(default = "default_true")]
    pub deny_sensitive: bool,
    /// Replace HOME / XDG_* / TMPDIR with an isolated temporary directory so the
    /// child cannot reach the real user config tree. **Defaults to `true`.**
    #[serde(default = "default_true")]
    pub temporary_home: bool,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        EnvironmentPolicy {
            inherit: false,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        }
    }
}

impl EnvironmentPolicy {
    /// Whether `name` is a sensitive variable that [`Self::deny_sensitive`]
    /// strips. Matches an exact entry in [`SENSITIVE_ENV_EXACT`] or any prefix in
    /// [`SENSITIVE_ENV_PREFIXES`]. Case-sensitive: environment variable names are
    /// conventionally upper-case and these constants are written that way.
    pub fn is_sensitive(name: &str) -> bool {
        SENSITIVE_ENV_EXACT.contains(&name)
            || SENSITIVE_ENV_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
    }

    /// Compute the variable names that should survive into the child, given the
    /// parent environment's variable names. This is the testable core of env
    /// isolation: a backend applies the result, but the decision is pure.
    ///
    /// - When [`Self::inherit`] is false, start from `allow`; otherwise start
    ///   from every parent name.
    /// - When [`Self::deny_sensitive`] is true, drop every sensitive name from
    ///   the surviving set (even ones named in `allow`).
    ///
    /// HOME/TMPDIR replacement (from [`Self::temporary_home`]) is applied by the
    /// backend on top of this and is not reflected here.
    pub fn surviving_vars<'a, I>(&'a self, parent_names: I) -> BTreeSet<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut survivors: BTreeSet<String> = if self.inherit {
            parent_names.into_iter().map(|s| s.to_owned()).collect()
        } else {
            self.allow.iter().cloned().collect()
        };
        if self.deny_sensitive {
            survivors.retain(|name| !Self::is_sensitive(name));
        }
        survivors
    }
}

/// Inherited-handle / file-descriptor closure policy.
///
/// A contained child must not inherit handles to the parent's open files,
/// sockets, or pipes beyond a minimal allow-list. On Unix this is "stdio (0/1/2)
/// plus any broker FD"; on Windows it is `bInheritHandles = FALSE` (or an
/// explicit `STARTUPINFOEX` handle allow-list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlePolicy {
    /// Keep the standard streams (stdin/stdout/stderr) open in the child.
    /// **Defaults to `true`** — a contained process still needs its own stdio.
    #[serde(default = "default_true")]
    pub keep_stdio: bool,
    /// Extra Unix file descriptors the child is permitted to inherit (e.g. a
    /// broker socket FD). Everything not in `{0,1,2} ∪ extra_unix_fds` is closed.
    #[serde(default)]
    pub extra_unix_fds: Vec<i32>,
}

impl Default for HandlePolicy {
    fn default() -> Self {
        HandlePolicy {
            keep_stdio: true,
            extra_unix_fds: Vec::new(),
        }
    }
}

impl HandlePolicy {
    /// The complete set of Unix FDs the child may inherit: stdio (when
    /// [`Self::keep_stdio`]) plus the explicit extras. A Unix backend closes
    /// every other open descriptor down to this set.
    pub fn allowed_unix_fds(&self) -> BTreeSet<i32> {
        let mut fds: BTreeSet<i32> = BTreeSet::new();
        if self.keep_stdio {
            fds.insert(0);
            fds.insert(1);
            fds.insert(2);
        }
        for fd in &self.extra_unix_fds {
            fds.insert(*fd);
        }
        fds
    }
}

/// Resource ceilings applied on **every** backend (cross-cutting invariant 2:
/// resource limits are a tracked coverage flag).
///
/// `None` means "do not impose a tirith limit for this dimension" (the OS / cgroup
/// default applies). A backend that successfully applies the populated limits
/// sets [`CapsuleCoverage::resource_limits_enforced`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Max CPU time in seconds (rlimit `RLIMIT_CPU` on Unix; Job Object on Windows).
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    /// Max address-space / committed memory in bytes.
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// Max number of processes/threads the child tree may create.
    #[serde(default)]
    pub max_processes: Option<u32>,
    /// Max number of simultaneously open file descriptors / handles.
    #[serde(default)]
    pub max_open_files: Option<u32>,
    /// Max bytes the child may write to its captured stdout/stderr before it is
    /// cut off (output containment, enforced by the launcher/broker, not the OS).
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    /// Wall-clock deadline in seconds, after which the child tree is killed.
    #[serde(default)]
    pub wall_clock_seconds: Option<u64>,
}

impl ResourceLimits {
    /// A conservative default ceiling suitable for an install hook / MCP server:
    /// bounded CPU, memory, process count, open files, output, and wall-clock.
    /// Callers may relax individual dimensions; the point is that *something* is
    /// always set so a contained process cannot fork-bomb or exhaust memory.
    pub fn conservative() -> Self {
        ResourceLimits {
            cpu_seconds: Some(120),
            memory_bytes: Some(2 * 1024 * 1024 * 1024),
            max_processes: Some(256),
            max_open_files: Some(256),
            max_output_bytes: Some(16 * 1024 * 1024),
            wall_clock_seconds: Some(300),
        }
    }

    /// Whether any dimension is populated (used to decide if the
    /// `resource_limits_enforced` flag is even applicable).
    pub fn any_set(&self) -> bool {
        self.cpu_seconds.is_some()
            || self.memory_bytes.is_some()
            || self.max_processes.is_some()
            || self.max_open_files.is_some()
            || self.max_output_bytes.is_some()
            || self.wall_clock_seconds.is_some()
    }
}

/// Everything a backend needs to contain one child process. Constructed by the
/// caller (install, MCP spawn, `tirith run`) and handed to a [`Capsule`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleSpec {
    /// Filesystem confinement.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Network confinement (default deny-all).
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Environment scrubbing.
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    /// Inherited-handle closure.
    #[serde(default)]
    pub handles: HandlePolicy,
    /// Resource ceilings.
    #[serde(default)]
    pub resources: ResourceLimits,
}

impl CapsuleSpec {
    /// A maximally-locked spec: deny-all network, no inherited environment with
    /// the sensitive set stripped and a temporary HOME, default sensitive-subtree
    /// denies, minimal handle inheritance, and conservative resource limits. The
    /// baseline for `pkg install` (the caller then adds the specific read/write
    /// roots the install needs).
    pub fn locked_down() -> Self {
        CapsuleSpec {
            filesystem: FilesystemPolicy::deny_by_default(),
            network: NetworkPolicy::DenyAll,
            environment: EnvironmentPolicy::default(),
            handles: HandlePolicy::default(),
            resources: ResourceLimits::conservative(),
        }
    }

    /// The coverage an enforcing surface should *require* given this spec: every
    /// capability the spec actually constrains. Surfaces compare a backend's
    /// achieved [`CapsuleCoverage`] against this via
    /// [`CapsuleCoverage::is_degraded_against`] and fail closed on a shortfall.
    pub fn required_coverage(&self) -> CapsuleCoverage {
        let wants_egress = !self.network.is_deny_all();
        CapsuleCoverage {
            // A locked filesystem (any deny root or any constrained grant) means
            // we require FS read/write enforcement.
            fs_read_enforced: true,
            fs_write_enforced: true,
            // Always require exec limiting for a contained child.
            exec_limited: true,
            // Deny-all network requires raw sockets blocked; an allow-list also
            // requires raw-deny (the broker is the only path) plus the proxy.
            network_raw_denied: true,
            domain_proxy_enforced: wants_egress,
            resource_limits_enforced: self.resources.any_set(),
            env_isolated: true,
            handles_isolated: true,
        }
    }

    /// The containment level a spec asks a backend to deliver, derived purely from
    /// its [`NetworkPolicy`]. This is the host-independent classifier the OS
    /// backends branch on (so the decision is unit-testable on any platform, not
    /// just where the backend compiles).
    pub fn capability_level(&self) -> CapabilityLevel {
        if self.network.is_deny_all() {
            CapabilityLevel::DenyAll
        } else {
            CapabilityLevel::AllowListedDomains
        }
    }
}

/// The two containment levels an OS backend distinguishes (cross-cutting the E2-E4
/// units). Kept platform-independent so callers and tests can reason about the
/// level a [`CapsuleSpec`] requires without a working backend.
///
/// - [`DenyAll`](Self::DenyAll): no network capability at all. A Linux backend can
///   satisfy this *natively* with Landlock filesystem confinement + a seccomp
///   policy that grants no socket-creation syscalls, the target for
///   `tirith pkg install` (installs never need outbound traffic).
/// - [`AllowListedDomains`](Self::AllowListedDomains): outbound traffic only to
///   policy domains, only through the loopback broker. Claiming this is *enforced*
///   requires a backend that blocks every raw outbound socket except the broker
///   (cross-cutting invariant 3). E2's Linux backend has no such verified
///   raw-socket-blocking path yet (a complete netns+veth/slirp broker or a proven
///   `srt`/bubblewrap launcher), so it reports this level as **degraded** and an
///   enforcing command fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLevel {
    /// No network capability; satisfiable natively by an OS sandbox backend.
    DenyAll,
    /// Egress restricted to allow-listed domains via the broker; only honestly
    /// enforceable behind a verified raw-socket-blocking backend.
    AllowListedDomains,
}

/// The containment backend interface. Implemented by the OS backends (E2-E4) and
/// by [`NoOpCapsule`]. The trait is intentionally tiny and synchronous: it
/// reports its *static* capability ([`Self::available_coverage`]) so a caller can
/// decide, before spawning anything, whether the platform can satisfy the spec.
///
/// The actual process launch (which on Linux re-execs `tirith __capsule-child`)
/// lives in the CLI crate and is added in E2-E5; keeping the trait here lets
/// `tirith-core` reason about coverage without depending on the launcher.
pub trait Capsule {
    /// A stable identifier for the backend (e.g. `"landlock-seccomp"`,
    /// `"seatbelt"`, `"appcontainer"`, `"noop"`). Used in receipts and
    /// `tirith doctor` output.
    fn backend_id(&self) -> &'static str;

    /// The coverage this backend can achieve for `spec` on the current host
    /// *right now*, without launching anything. A backend probes for its OS
    /// mechanism (Landlock ABI, `sandbox-exec` presence, AppContainer support)
    /// and reports honestly: capabilities it cannot enforce are `false`.
    ///
    /// This is the value enforcing surfaces compare against
    /// [`CapsuleSpec::required_coverage`] to decide whether to proceed or fail
    /// closed. It must NEVER over-report.
    fn available_coverage(&self, spec: &CapsuleSpec) -> CapsuleCoverage;
}

/// The always-degraded backend. It contains **nothing** and, by contract, never
/// claims any coverage — in particular it never claims egress enforcement, so a
/// platform with no working sandbox can never be mistaken for one that contains.
///
/// Enforcing surfaces that receive a `NoOpCapsule` must fail closed (the spec's
/// required coverage will always be unsatisfied). Analysis-only surfaces may use
/// it to run uncontained while still emitting an honest "degraded" banner.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpCapsule;

impl Capsule for NoOpCapsule {
    fn backend_id(&self) -> &'static str {
        "noop"
    }

    fn available_coverage(&self, _spec: &CapsuleSpec) -> CapsuleCoverage {
        // Honest: nothing is enforced, ever. Notably `domain_proxy_enforced` and
        // `network_raw_denied` stay false, so `egress_claim_is_coherent` holds and
        // no caller can read an egress promise out of a NoOp.
        CapsuleCoverage::NONE
    }
}

/// The sensitive subtrees a contained child is denied by default, even when a
/// broader read/write root would otherwise cover them. **Deliberately a curated
/// set of known-sensitive paths, NOT all of `~/.config`** — over-denying breaks
/// legitimate tools, so the policy targets the high-value credential / key
/// stores specifically.
///
/// Paths are anchored under the real user HOME (resolved via the `home` crate's
/// equivalent in core, `crate::policy`-style home lookup is avoided here to keep
/// the function pure; the backend resolves `~` when it applies the rules). Each
/// entry is HOME-relative; an empty HOME yields an empty list (the backend then
/// relies on its other confinement).
pub fn deny_default_paths() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    // Known credential / key / token stores. Kept tight on purpose.
    let relative = [
        ".aws",
        ".azure",
        ".config/gcloud",
        ".ssh",
        ".gnupg",
        ".kube",
        ".docker/config.json",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".config/gh",
        ".cargo/credentials.toml",
    ];
    relative.iter().map(|r| home.join(r)).collect()
}

/// Resolve the real user home directory without pulling extra deps: prefer the
/// platform env var, matching how the rest of tirith-core finds HOME. Returns
/// `None` when unset (CI/sandbox), which makes [`deny_default_paths`] empty.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_capsule_never_claims_any_coverage() {
        // Invariant 2: a missing backend can never be mistaken for a working one.
        let cap = NoOpCapsule;
        let cov = cap.available_coverage(&CapsuleSpec::locked_down());
        assert_eq!(cov, CapsuleCoverage::NONE);
        assert!(cov.is_fully_unenforced());
        assert_eq!(cap.backend_id(), "noop");
    }

    #[test]
    fn noop_capsule_never_claims_egress() {
        // The single most important NoOp property: it must never report egress.
        let cap = NoOpCapsule;
        let cov = cap.available_coverage(&CapsuleSpec::locked_down());
        assert!(!cov.domain_proxy_enforced);
        assert!(!cov.network_raw_denied);
        assert!(cov.egress_claim_is_coherent());
    }

    #[test]
    fn egress_claim_requires_raw_deny() {
        // Invariant 3: a coherent ledger cannot claim the proxy without raw-deny.
        let incoherent = CapsuleCoverage {
            domain_proxy_enforced: true,
            network_raw_denied: false,
            ..CapsuleCoverage::NONE
        };
        assert!(!incoherent.egress_claim_is_coherent());

        let coherent = CapsuleCoverage {
            domain_proxy_enforced: true,
            network_raw_denied: true,
            ..CapsuleCoverage::NONE
        };
        assert!(coherent.egress_claim_is_coherent());
    }

    #[test]
    fn degraded_against_detects_shortfall() {
        let required = CapsuleSpec::locked_down().required_coverage();
        // NoOp coverage satisfies nothing required -> degraded.
        assert!(CapsuleCoverage::NONE.is_degraded_against(&required));

        // A ledger that meets every required flag is NOT degraded.
        let full = CapsuleCoverage {
            fs_read_enforced: true,
            fs_write_enforced: true,
            exec_limited: true,
            network_raw_denied: true,
            // locked_down is deny-all, so domain_proxy is NOT required.
            domain_proxy_enforced: false,
            resource_limits_enforced: true,
            env_isolated: true,
            handles_isolated: true,
        };
        assert!(!full.is_degraded_against(&required));
    }

    #[test]
    fn locked_down_spec_requires_egress_only_when_allowlisted() {
        // Deny-all spec must NOT require the proxy flag.
        let deny = CapsuleSpec::locked_down();
        assert!(!deny.required_coverage().domain_proxy_enforced);
        assert!(deny.required_coverage().network_raw_denied);

        // An allow-listed-domains spec DOES require the proxy flag (and raw-deny).
        let mut allow = CapsuleSpec::locked_down();
        allow.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let req = allow.required_coverage();
        assert!(req.domain_proxy_enforced);
        assert!(req.network_raw_denied);
    }

    #[test]
    fn capability_level_follows_network_policy() {
        // Deny-all network -> DenyAll level (natively satisfiable).
        assert_eq!(
            CapsuleSpec::locked_down().capability_level(),
            CapabilityLevel::DenyAll
        );
        // An allow-list -> AllowListedDomains level (broker-only egress).
        let mut allow = CapsuleSpec::locked_down();
        allow.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        assert_eq!(
            allow.capability_level(),
            CapabilityLevel::AllowListedDomains
        );
    }

    #[test]
    fn network_policy_permits_only_listed_domain_and_port() {
        let policy = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string(), "files.pythonhosted.org".to_string()]
                .into_iter()
                .collect(),
            ports: [443u16].into_iter().collect(),
        };
        assert!(policy.permits("pypi.org", 443));
        // Trailing dot + case are normalized.
        assert!(policy.permits("PyPI.org.", 443));
        // Wrong port rejected.
        assert!(!policy.permits("pypi.org", 80));
        // Unlisted domain rejected.
        assert!(!policy.permits("evil.example", 443));
        // Deny-all permits nothing.
        assert!(!NetworkPolicy::DenyAll.permits("pypi.org", 443));
    }

    #[test]
    fn env_policy_default_is_locked() {
        let env = EnvironmentPolicy::default();
        assert!(!env.inherit);
        assert!(env.deny_sensitive);
        assert!(env.temporary_home);
        assert!(env.allow.is_empty());
    }

    #[test]
    fn env_policy_strips_sensitive_even_when_allowed() {
        // Exact and prefix sensitive names are dropped even from the allow-list.
        let env = EnvironmentPolicy {
            inherit: false,
            allow: vec![
                "PATH".to_string(),
                "GITHUB_TOKEN".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "PIP_INDEX_URL".to_string(),
                "LANG".to_string(),
            ],
            deny_sensitive: true,
            temporary_home: true,
        };
        let survivors = env.surviving_vars(std::iter::empty());
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("LANG"));
        assert!(!survivors.contains("GITHUB_TOKEN"));
        assert!(!survivors.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!survivors.contains("PIP_INDEX_URL"));
    }

    #[test]
    fn env_policy_inherit_drops_sensitive_from_parent() {
        let env = EnvironmentPolicy {
            inherit: true,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        };
        let parent = [
            "PATH",
            "HOME",
            "ANTHROPIC_API_KEY",
            "AZURE_CLIENT_SECRET",
            "TWINE_PASSWORD",
        ];
        let survivors = env.surviving_vars(parent.iter().copied());
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("HOME"));
        assert!(!survivors.contains("ANTHROPIC_API_KEY"));
        assert!(!survivors.contains("AZURE_CLIENT_SECRET"));
        assert!(!survivors.contains("TWINE_PASSWORD"));
    }

    #[test]
    fn env_policy_no_inherit_no_allow_yields_nothing() {
        let env = EnvironmentPolicy::default();
        let parent = ["PATH", "HOME", "GITHUB_TOKEN"];
        let survivors = env.surviving_vars(parent.iter().copied());
        assert!(survivors.is_empty());
    }

    #[test]
    fn is_sensitive_matches_exact_and_prefix() {
        assert!(EnvironmentPolicy::is_sensitive("GITHUB_TOKEN"));
        assert!(EnvironmentPolicy::is_sensitive("AWS_SECRET_ACCESS_KEY"));
        assert!(EnvironmentPolicy::is_sensitive("UV_INDEX_URL"));
        assert!(EnvironmentPolicy::is_sensitive("TWINE_USERNAME"));
        assert!(!EnvironmentPolicy::is_sensitive("PATH"));
        assert!(!EnvironmentPolicy::is_sensitive("HOME"));
        // A var that merely contains a sensitive substring but doesn't match by
        // exact name or prefix is NOT stripped.
        assert!(!EnvironmentPolicy::is_sensitive("MY_GITHUB_TOKEN"));
    }

    #[test]
    fn handle_policy_default_keeps_stdio_only() {
        let h = HandlePolicy::default();
        let fds = h.allowed_unix_fds();
        assert_eq!(fds, [0, 1, 2].into_iter().collect());
    }

    #[test]
    fn handle_policy_extra_fds_are_allowed() {
        let h = HandlePolicy {
            keep_stdio: true,
            extra_unix_fds: vec![7, 9],
        };
        let fds = h.allowed_unix_fds();
        assert!(fds.contains(&0));
        assert!(fds.contains(&7));
        assert!(fds.contains(&9));
        assert_eq!(fds.len(), 5);
    }

    #[test]
    fn resource_limits_conservative_sets_every_dimension() {
        let r = ResourceLimits::conservative();
        assert!(r.any_set());
        assert!(r.cpu_seconds.is_some());
        assert!(r.memory_bytes.is_some());
        assert!(r.max_processes.is_some());
        assert!(r.max_open_files.is_some());
        assert!(r.max_output_bytes.is_some());
        assert!(r.wall_clock_seconds.is_some());

        let empty = ResourceLimits::default();
        assert!(!empty.any_set());
    }

    #[test]
    fn filesystem_deny_by_default_seeds_deny_roots() {
        // With HOME set, deny_by_default carries the sensitive subtrees.
        // (When HOME is unset the list is empty; either way read/write start bare.)
        let fs = FilesystemPolicy::deny_by_default();
        assert!(fs.read_roots.is_empty());
        assert!(fs.write_roots.is_empty());
        // deny_roots mirrors deny_default_paths().
        assert_eq!(fs.deny_roots, deny_default_paths());
    }

    #[test]
    fn capsule_spec_roundtrips_through_json() {
        // The spec is serde-serializable (receipts / capsule-child handoff).
        let mut spec = CapsuleSpec::locked_down();
        spec.filesystem.read_roots.push(PathBuf::from("/tmp/work"));
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let back: CapsuleSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn default_spec_is_deny_all_network() {
        let spec = CapsuleSpec::default();
        assert!(spec.network.is_deny_all());
        assert!(!spec.environment.inherit);
    }
}
