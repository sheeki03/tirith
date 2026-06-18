use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for each detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    // Hostname rules
    NonAsciiHostname,
    PunycodeDomain,
    MixedScriptInLabel,
    UserinfoTrick,
    ConfusableDomain,
    RawIpUrl,
    NonStandardPort,
    InvalidHostChars,
    TrailingDotWhitespace,
    LookalikeTld,

    // Path rules
    NonAsciiPath,
    HomoglyphInPath,
    DoubleEncoding,

    // Transport rules
    PlainHttpToSink,
    SchemelessToSink,
    InsecureTlsFlags,
    ShortenedUrl,

    // Terminal deception rules
    AnsiEscapes,
    ControlChars,
    BidiControls,
    ZeroWidthChars,
    HiddenMultiline,
    UnicodeTags,
    InvisibleMathOperator,
    VariationSelector,
    InvisibleWhitespace,
    HangulFiller,
    ConfusableText,

    // Command shape rules
    PipeToInterpreter,
    CurlPipeShell,
    WgetPipeShell,
    HttpiePipeShell,
    XhPipeShell,
    DotfileOverwrite,
    ArchiveExtract,
    ProcMemAccess,
    DockerRemotePrivEsc,
    CredentialFileSweep,
    Base64DecodeExecute,
    DataExfiltration,
    /// M13 — a pipe sink's interpreter could not be resolved because its wrapper
    /// chain (`sudo`/`env -S`/`command`/`exec`/`nohup`) nests deeper than
    /// `MAX_WRAPPER_DEPTH` (32). Emitted by `check_pipe_to_interpreter` only on
    /// depth-exhaustion, closing the evasion where `curl evil | sudo …(×32)… env
    /// -S "bash"` exhausts the budget. Medium/Warn — "obfuscated beyond analysis
    /// depth", not a confirmed exploit. Tier-1 rides the existing
    /// `pipe_to_interpreter` PATTERN_TABLE entry.
    WrapperChainTooDeep,
    /// M5 item 16 — PowerShell `Set-ExecutionPolicy Bypass` (cmdlet or
    /// `-ExecutionPolicy Bypass` flag). Disables script-signing enforcement.
    PsSetExecutionPolicyBypass,
    /// M5 item 16 — PowerShell `Add-MpPreference -Exclusion*`. Adds a Windows
    /// Defender exclusion to hide payloads from scanning.
    PsDefenderExclusion,
    /// M5 item 16 — PowerShell `iex (iwr https://...)` inline form. The pipe form
    /// (`iwr url | iex`) is handled by `pipe_to_interpreter`.
    PsInlineDownloadExecute,

    // Code file scan rules
    DynamicCodeExecution,
    ObfuscatedPayload,
    SuspiciousCodeExfiltration,

    // Environment rules
    ProxyEnvSet,
    SensitiveEnvExport,
    CodeInjectionEnv,
    InterpreterHijackEnv,
    ShellInjectionEnv,

    // Network destination rules
    MetadataEndpoint,
    PrivateNetworkAccess,
    CommandNetworkDeny,

    // Config file rules
    ConfigInjection,
    ConfigSuspiciousIndicator,
    ConfigMalformed,
    ConfigNonAscii,
    ConfigInvisibleUnicode,
    McpInsecureServer,
    McpUntrustedServer,
    McpDuplicateServerName,
    McpOverlyPermissive,
    McpSuspiciousArgs,
    McpServerDrift,

    // Ecosystem rules
    GitTyposquat,
    DockerUntrustedRegistry,
    PipUrlInstall,
    NpmUrlInstall,
    Web3RpcEndpoint,
    Web3AddressInUrl,
    VetNotConfigured,

    // Install-command rules (package-manager / infrastructure)
    RepoAddFromPipe,
    UnsignedRepoTrust,
    GpgCheckDisabled,
    KubectlApplyRemote,
    HelmUntrustedRepo,
    TerraformRemoteModule,
    BrewUntrustedTap,

    // CI / repo supply-chain scan rules (file-content scan)
    WorkflowUnpinnedAction,
    WorkflowDangerousTrigger,
    WorkflowCurlPipeShell,
    WorkflowUntrustedInput,
    DockerfileUnpinnedImage,
    PackageScriptDangerous,

    // AI-relevant file hidden-content scan rules (file-content scan)
    NotebookHiddenContent,
    NotebookSuspiciousOutput,
    AgentInstructionHidden,
    SvgScriptEmbedded,
    SvgExternalReference,

    // Threat intelligence rules — local DB
    ThreatMaliciousPackage,
    ThreatMaliciousIp,
    ThreatPackageTyposquat,
    ThreatPackageSimilarName,
    // Supplemental-feed rules are defined now so RuleId stays stable.
    ThreatMaliciousUrl,
    ThreatPhishingUrl,
    ThreatTorExitNode,
    ThreatThreatFoxIoc,
    // Real-time lookup rules
    ThreatOsvVulnerable,
    ThreatCisaKev,
    ThreatSuspiciousPackage,
    ThreatSafeBrowsing,

    // Package reputation rules (M6 ch6) — emitted by package_risk /
    // install_txn / ecosystem_scan from the registry-API path. Tier-1 attaches
    // via the existing `install_command` / package extractor; no new entry.
    /// M6 ch6 — the registry reports the package does not exist (HTTP 404).
    /// Distinct from `ApiSignals::Unavailable` (no "exists" claim). Medium
    /// baseline; elevated to Block via ch7 `block_not_found: true`.
    PackageNotFoundInRegistry,
    /// M6 ch6 — snapshot diff shows added/removed maintainers within the
    /// recency window. Medium severity.
    PackageMaintainerChangeRecent,
    /// M6 ch6 — snapshot diff confirms a real ownership transfer (all previous
    /// maintainers gone, non-empty new set). Medium severity.
    PackageOwnershipTransferred,
    /// M6 ch6 — OSV correlation surfaced an active advisory for `(eco, name,
    /// version)`. High when CVSS ≥ 7.
    PackageOsvAdvisoryActive,
    /// M6 ch6 — dependency-confusion: the name matches an operator-supplied
    /// internal name (or reserved `@org` scope) but was fetched from the public
    /// registry. High severity.
    PackageDependencyConfusion,
    /// M6 ch6 — install-script heuristic found a network call / shell spawn in an
    /// npm lifecycle script, `setup.py`, or `build.rs`. Medium; heuristic.
    PackageInstallScriptNetworkCall,
    /// M6 ch6 — registry-claimed repo URL fails verification under `--online`
    /// (dead host, non-git URL, or manifest omits the package name). High.
    PackageRepoMismatch,

    // Package-policy gated rules (M6 ch7) — fire from `install_txn` /
    // `ecosystem_scan` when the `package_policy` section crosses a configured
    // threshold; clean default at the M6 ch6 baseline.
    /// M6 ch7 — package newer than `block_newer_than_days` /
    /// `warn_newer_than_days`. Warn baseline; Block when the age is at or below
    /// a configured Block threshold.
    PackagePolicyNewerThanDays,
    /// M6 ch7 — `recent_downloads` at or below `warn_low_downloads_below`. Warn.
    /// Requires `--online`.
    PackagePolicyLowDownloads,
    /// M6 ch7 — name within `block_typosquat_distance` of a known-popular name.
    /// Block. Policy-distance based (vs the DB-confirmed `ThreatPackageTyposquat`).
    PackagePolicyTyposquatDistance,
    /// M6 ch7 — `NameVsPopular::Unknown` AND the install-script analysis flagged
    /// a network call / shell spawn. Block. Requires the install-script signal.
    PackagePolicyUnknownPackageWithInstallScripts,
    /// M6 ch7 — registry reports the package not found AND policy sets
    /// `block_not_found: true`. Block. Requires `--online` (offline → Unknown).
    PackagePolicyNotFound,

    // Rendered content rules
    HiddenCssContent,
    HiddenColorContent,
    HiddenHtmlAttribute,
    MarkdownComment,
    HtmlComment,

    // Cloaking rules
    ServerCloaking,

    // Clipboard rules
    ClipboardHidden,

    // PDF rules
    PdfHiddenText,

    // Credential rules
    CredentialInText,
    HighEntropySecret,
    PrivateKeyExposed,

    // Policy rules
    PolicyBlocklisted,
    /// M4 item 8 ch3 — the caller `AgentOrigin` matched a `deny` matcher in
    /// `agent_rules`; forces the verdict to [`Action::Block`] regardless of any
    /// finding. See `policy::agent_decision` and `docs/agent-governance-design.md` §5.
    AgentDeniedByPolicy,

    // Custom rules
    CustomRuleMatch,

    // License/infrastructure rules
    LicenseRequired,

    // Output-direction rules (M7 ch1) — fire from `engine::analyze_output` when
    // scanning a command's stdout/stderr, never the exec/paste hot path.
    // Byte-scan based (OSC52, OSC8, title, screen-clear); bypass `PATTERN_TABLE`.
    /// M7 ch1 — `\e]52;c;<base64>\a` writes to the system clipboard from a stream
    /// the user is only watching. High — silent exfil one keypress from a paste.
    OutputOsc52ClipboardWrite,
    /// M7 ch1 — text rendered invisibly. Narrow v1: (i) explicit ANSI fg == bg in
    /// one SGR, or (ii) a zero-width run > 8 chars. Theme-dependent detection is a
    /// documented follow-up.
    OutputHiddenText,
    /// M7 ch1 — a `[PS1-shaped text]` injected mid-stream looks like a fresh
    /// prompt, tricking the user into typing the next command into output. Medium.
    OutputFakePrompt,
    /// M7 ch1 — OSC 8 hyperlink whose visible text is a URL with a host differing
    /// from the `href` host. High. "Click here" vs a URL does NOT fire.
    OutputTerminalHyperlinkMismatch,
    /// M7 ch1 — terminal window-title rewrite (`\e]0;…\a` / `\e]2;…\a`) from an
    /// untrusted stream. Info. Masks a backgrounded shell as `$EDITOR foo.txt`.
    OutputTitleManipulation,
    /// M7 ch1 — screen-clear sequences (`\e[2J` / `\e[H`) mid-stream. Info —
    /// scrolls prior output off-screen so a fake banner can take its place.
    OutputClearScreen,
    /// M7 ch1 — an OSC/CSI escape open at end-of-stream without a terminator.
    /// Truncated `\e]52;<base64>` was silently dropped; emit Medium so a
    /// fail-closed caller can DENY (Sev-5).
    OutputTruncatedEscapeSequence,

    // Prompt-injection rules (M7 ch5) — fire from `rules::prompt_injection` when
    // a seed phrase appears, reached from `analyze_output` and from `analyze`
    // (Paste/FileScan, gated by the `prompt_injection_seed` PATTERN_TABLE entry).
    // Catch well-known patterns only — NOT a complete defense; see the module doc.
    /// M7 ch5 — a prompt-injection seed phrase ("act as <role>", "you are now",
    /// "system:", "DAN mode", …) appeared. High severity.
    PromptInjectionInOutput,
    /// M7 ch5 — the highest-confidence subset: an explicit instruction-override
    /// phrase ("ignore previous instructions", "override your instructions", …).
    /// High severity.
    IgnorePreviousInstructions,
    /// A prompt-injection seed phrase that matched ONLY after deobfuscation
    /// (base64/hex decode, confusable skeleton, invisible-char strip, NFKC,
    /// character-spacing collapse, or leetspeak fold) and did NOT match the raw
    /// text. Obfuscation of an injection phrase is itself a malice signal, so this
    /// is a distinct High finding from the raw `PromptInjectionInOutput` /
    /// `IgnorePreviousInstructions` rules. Names the defeated technique in evidence.
    PromptInjectionObfuscated,
    /// C7 — an output-side DATA-EXFILTRATION vector in scanned tool/file/MCP
    /// content: a markdown image/link beacon that auto-fetches a remote URL, a URL
    /// whose query carries a secret-shaped value or a canary, or a natural-language
    /// "read <sensitive path> … send/post/upload it" / "do not tell the user"
    /// directive. High severity (MITRE T1041). DISTINCT from the command-shape
    /// `DataExfiltration` rule, which fires on a command the user runs; this fires
    /// on adversarial content the agent reads. Emitted by `rules::exfil`.
    OutputDataExfiltration,

    // Operational-context rules (M8 ch1) — fire from `rules::context` when the
    // leader is a cloud/k8s CLI (kubectl, helm, aws, gcloud, az, …) and the active
    // provider context is labeled production/critical. Detection in
    // `crate::context_detect`; labels in `context-labels.yaml` (user or repo).
    /// M8 ch1 — destructive cloud/k8s command against a production-labeled
    /// context. High. E.g. `kubectl delete namespace`, `aws s3 rm --recursive`.
    ContextProdDestructiveCommand,
    /// M8 ch1 — write-shaped (not strictly destructive) cloud/k8s command against
    /// a production-labeled context. Medium. E.g. `kubectl apply`, `helm upgrade`.
    ContextProdWriteOperation,
    /// M8 ch1 — credential/IAM change against a production-labeled context. High.
    /// E.g. `aws iam create-access-key`, `kubectl create clusterrolebinding`.
    ContextProdCredentialChange,

    // SSH operational-context rules (M8 ch2) — fire from `rules::ssh_context`
    // when the leader is `ssh` and the target host is labeled critical/production
    // in `policy.ssh_host_labels`.
    /// M8 ch2 — destructive remote command against a labeled SSH host. High. The
    /// inner command is re-classified through the `rules::context` destructive-verb
    /// heuristic plus general shell verbs (`systemctl stop`, `rm -rf`, `dd`, …).
    SshRemoteDestructiveOnLabeledHost,
    /// M8 ch2 — opening a bare interactive remote shell against a labeled host.
    /// Info (does not block). tirith protects the LOCAL shell only; commands after
    /// the handshake are not intercepted without `tirith ssh bootstrap` (M8.1).
    SshRemoteShellOnLabeledHost,

    // IaC operational-context rules (M8 ch3) — fire from `rules::iac` when the
    // leader is an IaC CLI (`terraform`/`pulumi`/`tofu`). `apply <tfplan>` paths
    // also consult the plan-hash store (`state_dir()/iac_plans/<sha256>`) when
    // `policy.iac_require_plan_before_apply` is on.
    /// M8 ch3 — `terraform apply` with no saved plan where policy requires one
    /// (`iac_require_plan_before_apply: true`). High — a deliberate gate violation.
    IacApplyWithoutPlan,
    /// M8 ch3 — `apply -auto-approve` (or `pulumi up --yes`) outside a
    /// production-labeled context. Medium — a footgun, but not a Block default.
    IacApplyAutoApprove,
    /// M8 ch3 — `apply -auto-approve` inside a production-labeled context. High —
    /// the documented anti-pattern.
    IacApplyAutoApproveProd,
    /// M8 ch3 — `destroy` inside a production-labeled context. High — destroys
    /// resources that take hours to recreate.
    IacDestroyProd,
    /// M8 ch3 — `tirith iac check-plan` found high-risk changes (IAM, security
    /// groups, public-bucket grants, DB deletes, LB changes). Medium; heuristic.
    IacPlanHighRiskChanges,
    /// M8 ch3 — `terraform apply <tfplan>` where the plan file matches no hash in
    /// the `iac_plans` store (tampered or never checked). High when
    /// `iac_require_plan_before_apply: true`.
    IacPlanHashMismatch,

    // Sudo-escalation rules (M8 ch4) — fire from `rules::sudo` when the leader
    // resolves to `sudo` (direct or behind an `env`-style wrapper). Tier-1 gate is
    // the `sudo_cmd` PATTERN_TABLE entry. All five default High; an active tagged
    // sudo-session under `policy.sudo_require_reason` can downgrade to Medium.
    /// M8 ch4 — `sudo sh|bash|…` opens an interactive root shell whose subsequent
    /// commands run as root with zero tirith visibility. High.
    SudoShellSpawn,
    /// M8 ch4 — `sudo -E` / `--preserve-env[=LIST]` with a sensitive env var
    /// (`sensitive_env.toml`) set, making credentials readable via
    /// `/proc/<pid>/environ`. High.
    SudoEnvPreserveSensitive,
    /// M8 ch4 — `… | sudo tee <system-path>` writing to a privileged file
    /// (`/etc/…`, `/usr/local/bin/…`, `/etc/cron*`). `/tmp`/`~`/repo shapes never
    /// fire. High.
    SudoTeeSystemFile,
    /// M8 ch4 — `sudo curl|wget|fetch -o <system-path>` downloading to a
    /// privileged path as root, bypassing package signing. High.
    SudoDownloadInstall,
    /// M8 ch4 — `sudo chmod|chown -R …` against a broad system tree
    /// (`/`, `/home`, `/usr`, `/etc`). Strips setuid bits / breaks packages. High.
    SudoRecursivePermsBroadPath,

    // Container-runtime rules (M8 ch5) — fire from `rules::container` when the
    // leader is `docker`/`podman` and the subcommand is `run`/`create`/`exec`.
    // Tier-1 gates are the `docker_run` / `docker_exec` PATTERN_TABLE entries.
    /// M8 ch5 — `docker run --privileged …` disables every kernel security
    /// boundary (caps, seccomp, AppArmor, device cgroup); a container breakout
    /// becomes a host breakout. High.
    DockerRunPrivileged,
    /// M8 ch5 — `docker run -v <sensitive>:…` (or `--mount`) where `<sensitive>`
    /// is `/var/run/docker.sock`, `~/.ssh`, `~/.aws`, `/etc`. The socket is host
    /// root once mounted. High.
    DockerRunSensitiveBindMount,
    /// M8 ch5 — `docker exec <container> …` against a container labeled
    /// prod/critical/… in `policy.context_labels`. Medium — surface, don't block
    /// (reading logs is often legitimate).
    DockerExecProdContainer,

    // Workstation file-permission / credential-file hygiene rules (M9 ch1).
    // Fire ONLY from the `tirith hygiene scan|fix` filesystem walk
    // (`crate::hygiene`), never the hot path; no PATTERN_TABLE entry, live in
    // `EXTERNALLY_TRIGGERED_RULES`. Covered by unit tests in `hygiene.rs`.
    /// M9 ch1 — `~/.ssh/id_*` private key group/other-accessible
    /// (`mode & 0o077 != 0`). High. Auto-fix `chmod 0600`.
    HygienePrivateKeyLoosePerms,
    /// M9 ch1 — repo `.env`/`.env.*` world-readable (`mode & 0o004 != 0`). High.
    /// Auto-fix `chmod 0600`.
    HygieneEnvWorldReadable,
    /// M9 ch1 — `~/.kube/config` group/other-accessible. Medium (threat is
    /// local-multiuser). Auto-fix `chmod 0600`.
    HygieneKubeconfigGroupReadable,
    /// M9 ch1 — `~/.npmrc` carries a literal `_authToken`/`_password` (not
    /// `${ENV}`). High. Manual fix (rotate + env-indirect).
    HygieneNpmrcPlaintextToken,
    /// M9 ch1 — `~/.pypirc` carries a literal `password`/`pypi-…` token. High.
    /// Manual fix (keyring / env + rotate).
    HygienePypircPlaintextToken,
    /// M9 ch1 — `~/.ssh/config` `Include` resolving outside `~/.ssh` (abs path,
    /// `~/…` elsewhere, or `../` escape). Medium. Manual fix (review).
    HygieneSshConfigUnsafeInclude,
    /// M9 ch1 — `~/.gitconfig` sets `credential.helper = store` (persists git
    /// creds as cleartext). Medium. Manual fix (OS keychain helper).
    HygieneGitCredentialHelperStore,
    /// M9 ch1 — a shell history contains credential-shaped text (detected via the
    /// shipping `rules::credential` detector). Medium. Manual fix (scrub + rotate).
    HygieneShellHistorySecretLike,
    /// M9 ch1 — `~/.aws/credentials` (or `config`) group/other-accessible. High —
    /// long-lived cloud keys. Auto-fix `chmod 0600`.
    HygieneCloudCredsBadPerms,
    /// M9 ch1 — a `*.dump`/`*.sql` dump in the repo tree (outside
    /// `.git`/`node_modules`/`target`/`vendor`). Medium. Manual fix (move out +
    /// .gitignore; tirith never deletes files).
    HygieneDbDumpInRepo,

    // Persistence-mechanism state-change rules (M9 ch2). Fire ONLY from the
    // `tirith persistence diff|watch` snapshot comparison (`crate::persistence`),
    // never the hot path; detect a CHANGE vs a recorded snapshot, no PATTERN_TABLE
    // entry, live in `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `persistence.rs`.
    /// M9 ch2 — a shell rc/profile changed (sha256 differs) since the snapshot.
    /// Medium — a classic persistence foothold.
    PersistenceShellRcModified,
    /// M9 ch2 — a new line added to `~/.ssh/authorized_keys`. High — a direct
    /// remote-access backdoor.
    PersistenceAuthorizedKeysNewEntry,
    /// M9 ch2 — the user crontab (`crontab -l`) changed. Medium — a scheduled-
    /// execution persistence channel.
    PersistenceCrontabModified,
    /// M9 ch2 — a launchd/systemd-user unit was added (new `*.plist` /
    /// `*.service`). High — runs code at login / on a schedule.
    PersistenceLaunchAgentAdded,
    /// M9 ch2 — `~/.ssh/config` gained an `Include`. Medium — can pull in an
    /// attacker-controlled config fragment.
    PersistenceSshConfigInclude,
    /// M9 ch2 — a new `.envrc` (direnv) appeared in the cwd ancestry. Medium —
    /// direnv auto-sources it on `cd`.
    PersistenceDirenvNewEnvrc,

    // Shell-alias / function risk rules (M9 ch3). Fire ONLY from the
    // `tirith aliases scan|explain` parser (`crate::aliases`), which reads rc
    // files statically (opt-in shell-out), never the hot path; classify parsed
    // alias/function bodies, no PATTERN_TABLE entry, live in
    // `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `aliases.rs`
    // (`include_runtime=false` for CI hermeticity).
    /// M9 ch3 — an alias/function shadows a critical command (`ls`, `git`,
    /// `sudo`, `docker`, …). Medium — interposes a wrapper that can exfiltrate
    /// args (`alias sudo='sudo evil-wrapper'`).
    AliasOverridesCriticalCommand,
    /// M9 ch3 — an alias/function body makes a network call (`curl`/`wget`/`nc`).
    /// High — a stealthy exfil / download-execute channel.
    AliasContainsNetworkCall,
    /// M9 ch3 — an alias/function body reads a credential file
    /// (`~/.aws/credentials`, `~/.ssh/id_*`, `~/.netrc`, …). High — a
    /// credential-theft foothold.
    AliasContainsCredentialRead,
    /// M9 ch3 — the rc file an alias was defined in was modified within the last
    /// hour. Info — surfaces a recently-added alias for review.
    AliasRecentlyAdded,

    // Environment-variable lifecycle rules (M9 ch4). Two fire from the exec hot
    // path (gated by `policy.env_guard_enabled`); one only from `tirith env guard`.
    // Sensitive-var list is the same `sensitive_env.toml` M6 ch5 env-scrub uses.
    /// M9 ch4 — a sensitive env var is set AND the command pipes remote content
    /// into a shell (`curl … | bash`); the script inherits and can exfiltrate it.
    /// High. This is the dedicated rule the M6 ch5 env-scrub `safe_command`
    /// transform attaches to. Tier-1 rides the pipe-to-interpreter patterns; the
    /// std::env check is wired in `engine.rs`.
    EnvSensitiveExposedToUnknownScript,
    /// M9 ch4 — a sensitive env var `export`ed in a shell rc/profile. High — leaks
    /// into every shell. Fires only from `tirith env guard` → `EXTERNALLY_TRIGGERED`.
    EnvSensitivePersistedInShellRc,
    /// M9 ch4 — `printenv`/`env` (no command arg) piped into a network sink. Medium
    /// — dumps every var off the machine. Hot path under `env_guard_enabled`;
    /// tier-1 gate is `env_to_network_sink`.
    EnvPrintenvToNetworkSink,

    // Executable-provenance + PATH-shadowing rules (M9 ch5). Split into a CHEAP
    // hot-path subset and an EXPENSIVE off-hot-path subset.
    //
    // HOT (3) — fire from `engine::analyze` ONLY when `policy.exec_guard_enabled`;
    // stat-free string compares on the resolved leader path. No PATTERN_TABLE
    // entry; in `EXTERNALLY_TRIGGERED_RULES`. Producers in `crate::path_audit`;
    // unit-tested plus `command.toml` no-fire fixtures.
    //
    // COLD (7) — fire ONLY from explicit `tirith exec check|provenance` /
    // `tirith path audit|which`; they stat the file and shell out to `file` /
    // `codesign` (2s timeout). NEVER reached from the hot path. Producers in
    // `crate::exec_provenance` / `crate::path_audit`.
    /// M9 ch5 (HOT) — leader lives under `/tmp` (or `$TMPDIR`). Medium — a
    /// drop-and-run staging location. Stat-free.
    ExecInTmp,
    /// M9 ch5 (COLD) — executable modified within the last 5 min. High — the
    /// signature of a just-dropped payload.
    ExecRecentlyModified,
    /// M9 ch5 (COLD) — executable world-writable (`mode & 0o002 != 0`). High — any
    /// local process can replace it.
    ExecWorldWritable,
    /// M9 ch5 (COLD) — the resolved binary shadows a system command of the same
    /// name and is NOT the system copy. Medium.
    ExecShadowsSystemCommand,
    /// M9 ch5 (COLD) — executable has no valid code signature. Medium,
    /// macOS/Windows only (no-op on Linux). 2s `codesign` shell-out, never hot path.
    ExecUnsigned,
    /// M9 ch5 (HOT) — leader lives inside the current repo working tree (e.g.
    /// `./node_modules/.bin/<x>`). Medium — runs code an attacker can land via a
    /// PR. Stat-free.
    ExecInRepoBin,
    /// M9 ch5 (HOT) — a user-writable, repo-local or `/tmp` `$PATH` entry precedes
    /// a system dir and the leader resolves there. High. Repo-local/`/tmp` focused
    /// to avoid flagging `~/.local/bin` (see module doc). Stat-free + a
    /// `libc::access(W_OK)` probe.
    PathWritableDirBeforeSystem,
    /// M9 ch5 (COLD) — a command name resolves in more than one `$PATH` dir.
    /// Medium — shadowing ambiguity. `tirith path audit` only.
    PathDuplicateCommandName,
    /// M9 ch5 (COLD) — a `$PATH` entry resolves inside the repo. Medium. `tirith
    /// path audit` only (the hot-path equivalent is `ExecInRepoBin`).
    PathDirInRepo,
    /// M9 ch5 (COLD) — a `$PATH` entry under `/tmp` (or `$TMPDIR`). High —
    /// anything dropped there shadows real commands. `tirith path audit` only.
    PathDirInTmp,

    // Repo-hook / automation guard rules (M9 ch6). Fire from the
    // `crate::repo_hooks` scanner (`tirith hooks scan|guard|explain`), which
    // classifies a hook BODY (`.git/hooks/*`, `.husky/*`, lifecycle scripts,
    // `.envrc`, Make/just/Taskfile, …) as text and never executes it. Three
    // (network/credential/sudo) also surface on the exec hot path when a git /
    // package-manager command runs in a repo with triggered hooks, gated by
    // `policy.hooks_guard_enabled`. No PATTERN_TABLE entry;
    // `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `repo_hooks.rs`.
    /// M9 ch6 — a hook body makes a network call (`curl`/`wget`/`nc`). High — a
    /// stealthy download-execute / exfil channel firing on commit/install.
    RepoHookNetworkCall,
    /// M9 ch6 — a hook body reads a credential file/dir (`~/.aws`, `~/.ssh`,
    /// `.env`, …). High — a credential-theft foothold.
    RepoHookCredentialRead,
    /// M9 ch6 — a hook body uses `sudo`. High — auto-triggered privilege escalation.
    RepoHookSudo,
    /// M9 ch6 — a hook body pipes into a shell, base64-decodes then executes, or
    /// uses `eval`. Medium — the obfuscated-payload shape; heuristic.
    RepoHookSuspiciousShellPattern,
    /// M9 ch6 — a hook body fetches an external resource (bare `http(s)://` URL or
    /// a remote-package runner `npx`/`pnpm dlx`). Medium.
    RepoHookExternalFetch,

    // Blast-radius rules (M10 ch1). Split into a CHEAP hot-path subset and a
    // SIMULATOR-ONLY subset.
    //
    // HOT (4) — fire from `engine::analyze` via the filesystem-free
    // `blast_radius::cheap_check` when the leader is `rm|mv|chmod|find
    // -delete|rsync --delete` and a target is dangerous by STRING SHAPE (pure
    // string compares + an injected env-map lookup). Tier-1 gate is
    // `destructive_fs_op`; all four have `command.toml` fixtures.
    //
    // SIMULATOR-ONLY (3) — fire ONLY from `tirith preview` via
    // `blast_radius::simulate`, which WALKS the filesystem (depth ≤ 5, ≤ 100k
    // files). Never on the hot path; no fixture, `EXTERNALLY_TRIGGERED_RULES`.
    // Unit-tested in `blast_radius.rs`.
    /// M10 ch1 (SIM) — a `tirith preview` resolved a destructive target outside
    /// the repo root (or above cwd). High. Never on the hot path.
    BlastDeletesOutsideRepo,
    /// M10 ch1 (HOT) — a destructive command targets a broad system path (`/`,
    /// `/home`, `/usr`, `/etc`, `~`, …) by string shape. High.
    BlastWritesSystemPath,
    /// M10 ch1 (SIM) — `tirith preview` found symlinks in the target tree
    /// (counted, never followed). Medium — a tool may reach outside the tree.
    BlastSymlinkTraversal,
    /// M10 ch1 (HOT) — a destructive command targets a `"$VAR/"` path where `VAR`
    /// is empty (`rm -rf "$EMPTY/"` → `rm -rf "/"`). Severity by visibility (F2):
    /// High when `VAR` is PRESENT-and-empty in the env-map, Info when merely
    /// ABSENT (could be a set shell-local tirith can't observe). Pure (injected
    /// env-map); leading `sudo`/`doas` unwrapped (C1).
    BlastEmptyVarGlob,
    /// M10 ch1 (HOT) — `find … -delete` recursively unlinks matches. Medium. Run
    /// `tirith preview` for the file count.
    BlastFindDelete,
    /// M10 ch1 (HOT) — `rsync --delete` prunes destination files; a wrong
    /// source/dest pair wipes the destination. Medium.
    BlastRsyncDelete,
    /// M10 ch1 (SIM) — `tirith preview` counted > 1000 files in the target tree.
    /// Info (never blocks). Never on the hot path.
    BlastLargeFileCount,

    /// M10 ch2 (RUNTIME-STATE) — a `tirith watch -- <cmd>` run modified a shell
    /// rc/profile DURING the watched command. High — a "install a tool" command
    /// rewriting your login shell is the classic persistence foothold. Fires only
    /// from the `tirith watch` post-run diff; `EXTERNALLY_TRIGGERED_RULES`,
    /// unit-tested in `cli/checkpoint.rs`.
    PostRunShellRcModified,

    // Tainted-content tracking rules (M10 ch3). Fire from `engine::analyze` when
    // the leader (or, for `source`/`.`, the sourced file) is a path recorded as
    // tainted in `state_dir()/taint.jsonl` (`crate::taint`). A file becomes
    // tainted via `tirith fetch --save <path> <url>`. An empty/absent store never
    // forces past the tier-1 fast-exit, so an unused machine pays nothing. No
    // PATTERN_TABLE entry; `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `taint.rs`.
    /// M10 ch3 — the command leader is a path recorded as tainted (downloaded via
    /// `tirith fetch --save`). High — executing a freshly-downloaded file is the
    /// flow this exists to surface. The mark persists until `tirith taint clear`
    /// (NOT auto-cleared by `chmod +x` or `bash -n`).
    ExecOfTaintedFile,
    /// M10 ch3 — `source`/`.` of a tainted file. Medium (best-effort): the
    /// `source`/`.` shape is matched only as the leader, so a narrower,
    /// lower-confidence signal than `ExecOfTaintedFile`.
    CommandSourcedFromTaintedFile,

    // Anomaly-detection rules (M10 ch5, D2). Fire from `engine::analyze` ONLY
    // when `policy.baseline_enabled` (opt-in) AND another rule already fired: the
    // firing finding's privacy-hashed tuple `(rule_id, host_hash, ecosystem,
    // sudo_flag, cwd_repo_hash)` is looked up in the sliding window at
    // `state_dir()/baseline.jsonl` and, if new/rare, an Info finding is appended
    // (the observation is recorded regardless). No PATTERN_TABLE entry;
    // `EXTERNALLY_TRIGGERED_RULES`. Privacy: the store holds salted-sha256 hashes,
    // NEVER raw hostnames/paths — see the `baseline` module doc.
    /// M10 ch5 — the firing finding's tuple has never been seen in this user's
    /// baseline window (`count == 0`). Info — annotates "new for you", never
    /// changes the action. Only when `baseline_enabled`.
    AnomalyFirstTimeInThisRepo,
    /// M10 ch5 — the tuple has been seen rarely (`0 < count < 3`). Info. Only when
    /// `baseline_enabled`.
    AnomalyRareInBaseline,

    // Command-card rules (M11 ch1). A command card is an ed25519-signed
    // attestation of what a command does (`crate::command_card`). Fire from
    // `engine::analyze` when a card is supplied via `--card <path>` or a leading
    // `# tirith-card: <local-path>` comment. The card is ALWAYS read from disk —
    // a URL-shaped value emits a "fetch first" warning, never a fetch. v1 is
    // attestation-only: a verified card does NOT suppress or change any other
    // finding (v2 candidate). Needs runtime state (signed card + trusted pubkey
    // under `~/.config/tirith/trusted-card-keys/`), so `EXTERNALLY_TRIGGERED_RULES`;
    // unit-tested in `command_card.rs` plus a CLI integration test.
    /// M11 ch1 — a trusted, unexpired card signed the EXACT command. Info —
    /// improves audit confidence but does NOT change the verdict. Emitted ONLY for
    /// a genuine Match; a present-but-unverified card uses
    /// [`RuleId::CommandCardUnverified`], so a `command_card_verified` counter
    /// never miscounts a failed verification.
    CommandCardVerified,
    /// M11 ch1 — a card was supplied but could NOT be verified (untrusted key, bad
    /// signature, unsigned, expired, unreadable, or a remote URL v1 won't fetch).
    /// Info — a diagnostic note that claims no trust. A supplied unsigned card DOES
    /// surface this; only a card-LESS command is silent.
    CommandCardUnverified,
    /// M11 ch1 — a trusted card was found but the command being run differs from
    /// what it attests (tampering after publish). High.
    CommandCardMismatch,

    // Repo command-manifest rules (M11 ch2). A repo manifest
    // (`.tirith/commands.yaml`, `crate::commands_manifest`) is a
    // SUPPRESSION-BOUNDED allowlist. Fire from `engine::analyze` after the
    // engine's findings are assembled; the manifest is discovered relative to
    // `ctx.cwd` (walk to `.git`, or `TIRITH_POLICY_ROOT/.tirith/commands.yaml`).
    // No PATTERN_TABLE entry; `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in
    // `commands_manifest.rs` plus the load-bearing "manifest cannot weaken a High
    // finding" engine regression test.
    /// M11 ch2 — an `analyze()`-cleared command absent from `allowed[*]`. Info —
    /// a pure annotation. The SOLE rule a matching `allowed[*]` suppresses (and it
    /// suppresses nothing else). Never fires when no manifest exists.
    RepoCommandUnknown,
    /// M11 ch2 — the command matched a `dangerous[*]` glob (`*`-only in v1). High
    /// (→ Block) for `action: block`, Medium (→ Warn) for `action: warn`.
    /// ELEVATION ONLY: added regardless of what `analyze()` returned; the manifest
    /// can NEVER weaken an engine finding ≥ High.
    RepoCommandDangerousPattern,

    // Honeytoken / canary rule (M11 ch3, D3). A canary is a synthetic fake
    // secret the user planted as bait (`tirith canary create`), recorded at
    // `state_dir()/canaries.jsonl` (`crate::canary`). Fires from `engine::analyze`
    // (paste + exec) AND `analyze_output` when a REGISTERED token appears —
    // detection is a STORE lookup, not a shape match, so a real credential fires
    // `CredentialInText` / `HighEntropySecret`, never this. No PATTERN_TABLE entry;
    // `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `canary.rs`.
    /// M11 ch3 — a registered canary token was found in the scanned input. High —
    /// bait planted where it should never be read. ONLY the user's own tokens fire
    /// this (the store scopes detection).
    CanaryTokenTouched,

    // Paste-provenance rule (M12 ch1). A companion browser extension writes a JSON
    // record at `state_dir()/clipboard_source.json` on every clipboard set. Fires
    // from `engine::analyze` in `ScanContext::Paste` ONLY when
    // `sha256(pasted_input)` matches the record AND a destination host in the
    // paste differs from the recorded `source_url` host. No PATTERN_TABLE entry;
    // `EXTERNALLY_TRIGGERED_RULES`. Unit-tested in `rules/paste_provenance.rs`.
    // See `crate::clipboard::ClipboardSourceRecord` and `docs/paste-provenance.md`.
    /// M12 ch1 — pasted content matched a recorded clipboard source but a
    /// destination host differs from the source page's host.
    ///
    /// **Info** when the host mismatch stands alone (docs pages legitimately link
    /// install URLs on other hosts). **High** when corroborated by a risk signal:
    /// source flagged hidden text, a `ClipboardHidden` finding present, a URL
    /// shortener, `PipeToInterpreter` present, the host is outside
    /// `policy.allowed_install_domains`, or an OSC 8 visible/target host mismatch.
    PasteSourceMismatch,

    // AI-config drift rules (M13 ch5). Fire ONLY from `tirith ai diff`
    // (`aifile::diff_findings`), comparing each AI-config file to the
    // last-known-safe snapshot at `state_dir()/ai_config_snapshot.json`.
    // Diff-triggered, never from the `analyze` pipeline or FileScan, so — like
    // `PasteSourceMismatch` and the M11 card/manifest rules — no PATTERN_TABLE
    // entry, `EXTERNALLY_TRIGGERED_RULES`. Detection reuses the
    // `agent_instruction_hidden` logic; the diff layer normalizes both sides so a
    // reformat alone is not a finding. Unit-tested in `aifile.rs` plus a CLI test.
    /// M13 ch5 — `tirith ai diff` found a NEW instruction line added since the
    /// snapshot: hidden/invisible content (the `agent_instruction_hidden` shape)
    /// or a newly-added imperative directive. High — config-poisoning. Only lines
    /// in NEW but not the snapshot fire; a removal never fires.
    AiConfigHiddenInstructionAdded,
    /// M13 ch5 — `tirith ai diff` found a NEW tool-use directive added since the
    /// snapshot (run/exec/spawn a shell, network call, or file write). High —
    /// silently widening the agent's blast radius. Only ADDED lines fire.
    AiConfigToolUseEscalation,

    // Cross-event correlation rules (W7). Fire from `correlate_session` over a
    // bounded per-session ring of typed events recorded AFTER each verdict is
    // finalized (`crate::event_buffer`, `crate::session_warnings`), NOT from the
    // `analyze` hot path. They reason about "A THEN B within a window" sequences,
    // so no single input ever triggers them; like the M11/M12/M13 rules above they
    // have NO PATTERN_TABLE entry and live in `EXTERNALLY_TRIGGERED_RULES`.
    // Unit-tested in `event_buffer.rs`.
    /// W7: a secret-bearing file write was followed by a network egress within
    /// 30s. Critical, the canonical credential-exfiltration shape.
    SecretWriteThenNetwork,
    /// W7: a dependency manifest (package.json/Cargo.toml/requirements.txt/...)
    /// was modified, then a network call ran within 60s. Medium, a poisoned-install
    /// signal that is individually unremarkable but suspicious in sequence.
    DependencyChangeThenNetwork,
    /// W7: a file deletion was followed by a `git push --force` within 60s.
    /// Critical: deleting then force-pushing can erase history and overwrite a
    /// remote branch.
    DeleteThenForcePush,
    /// W7: three or more (non-build-artifact) file deletions occurred within
    /// 20s. Critical: a destructive burst (ransomware-like or an accidental
    /// recursive wipe). Build-artifact paths are excluded via
    /// `crate::util_build_dirs::is_build_artifact_path`.
    MassFileDeletion,
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        write!(f, "{s}")
    }
}

/// Severity level for findings. Serializes UPPERCASE; deserialization accepts
/// UPPERCASE or exact lowercase (per-variant alias) but NOT title case, so both
/// hand-written policy and the M13 ch4 DSL examples (`severity: critical`) load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    #[serde(alias = "info")]
    Info,
    #[serde(alias = "low")]
    Low,
    #[serde(alias = "medium")]
    Medium,
    #[serde(alias = "high")]
    High,
    #[serde(alias = "critical")]
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    Url {
        raw: String,
    },
    HostComparison {
        raw_host: String,
        similar_to: String,
    },
    CommandPattern {
        pattern: String,
        matched: String,
    },
    ByteSequence {
        offset: usize,
        hex: String,
        description: String,
    },
    EnvVar {
        name: String,
        value_preview: String,
    },
    Text {
        detail: String,
    },
    ThreatIntel {
        source: String,
        threat_type: String,
        confidence: crate::threatdb::Confidence,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
    },
    /// Detailed character analysis for homograph detection
    HomoglyphAnalysis {
        /// The raw input string
        raw: String,
        /// The ASCII/punycode escaped version
        escaped: String,
        /// Positions of suspicious characters (byte offset, char, description)
        suspicious_chars: Vec<SuspiciousChar>,
    },
}

/// A suspicious character with its position and details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousChar {
    /// Byte offset in the string
    pub offset: usize,
    /// The suspicious character
    #[serde(rename = "character")]
    pub character: char,
    /// Unicode codepoint (e.g., "U+0456")
    pub codepoint: String,
    /// Human description (e.g., "Cyrillic Small Letter Byelorussian-Ukrainian I")
    pub description: String,
    /// Hex bytes of this character
    pub hex_bytes: String,
}

/// A single detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    /// What a human sees (populated by Pro enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_view: Option<String>,
    /// What an AI agent processes (populated by Pro enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_view: Option<String>,
    /// MITRE ATT&CK technique ID (populated by Team enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<String>,
    /// User-defined custom rule ID (populated only for CustomRuleMatch findings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_rule_id: Option<String>,
}

/// The action to take based on analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Warn,
    Block,
    /// Warn findings require explicit interactive acknowledgement.
    /// Used by `strict_warn` in hook-driven mode (exit code 3).
    WarnAck,
}

impl Action {
    pub fn exit_code(self) -> i32 {
        match self {
            Action::Allow => 0,
            Action::Block => 1,
            Action::Warn => 2,
            Action::WarnAck => 3,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Action::Allow => 0,
            Action::Warn | Action::WarnAck => 1,
            Action::Block => 2,
        }
    }
}

impl std::str::FromStr for Action {
    type Err = String;
    /// Parse the strict lowercase tokens used by lab-corpus / fixture TOML
    /// (`allow`/`warn`/`block`/`warn_ack`). Case-sensitive on purpose, so a typo
    /// like `"blocK"` is a hard parse error instead of a silent always-FAIL.
    /// Centralised so callers share one table (the serde derive only covers
    /// deserialization; this is the explicit `&str` path).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Action::Allow),
            "warn" => Ok(Action::Warn),
            "block" => Ok(Action::Block),
            "warn_ack" => Ok(Action::WarnAck),
            other => Err(format!("unknown action: {other}")),
        }
    }
}

pub fn action_from_findings(findings: &[Finding]) -> Action {
    if findings.is_empty() {
        return Action::Allow;
    }

    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);

    match max_severity {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    }
}

pub fn upgraded_action_from_findings(findings: &[Finding], current: Action) -> Action {
    let derived = action_from_findings(findings);
    if derived.rank() > current.rank() {
        derived
    } else {
        current
    }
}

/// Complete analysis verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub tier_reached: u8,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub bypass_available: bool,
    pub interactive_detected: bool,
    pub policy_path_used: Option<String>,
    pub timings_ms: Timings,
    /// Number of URLs extracted during Tier 3 analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,

    /// Whether this verdict requires human approval before execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    /// Timeout in seconds for approval (0 = indefinite).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_timeout_secs: Option<u64>,
    /// Fallback action when approval times out: "block", "warn", or "allow".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_fallback: Option<String>,
    /// The rule_id that triggered the approval requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_rule: Option<String>,
    /// Sanitized single-line description of why approval is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_description: Option<String>,

    /// Human-readable reason when escalation upgraded the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_reason: Option<String>,

    /// Best-effort origin of the caller (M4 item 8). `agent_rules` is consulted
    /// against it by [`crate::escalation::apply_agent_rules`], where a `deny`
    /// forces [`Action::Block`] + a [`RuleId::AgentDeniedByPolicy`] finding. See
    /// [`crate::agent_origin`] for the trust model (caller-claimed, operator-trust,
    /// never adversary-resistant). `None` (unwired path / insufficient signal) is
    /// treated as `Unspecified` — no enforcement. Old JSON parses (serde-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_origin: Option<crate::agent_origin::AgentOrigin>,

    /// M11 ch2 — the `allowed[*].name` from the repo manifest that matched, if
    /// any. AUDIT-CONTEXT ONLY: records why a clean command was not annotated
    /// `RepoCommandUnknown`. NEVER read by `action_from_findings` (which takes
    /// `&[Finding]`), so a repo cannot weaken a verdict via this field. Old JSON
    /// parses (serde-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_allowed_match: Option<String>,
}

/// Per-tier timing information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timings {
    pub tier0_ms: f64,
    pub tier1_ms: f64,
    pub tier2_ms: Option<f64>,
    pub tier3_ms: Option<f64>,
    pub total_ms: f64,
}

impl Verdict {
    /// Create an allow verdict with no findings (fast path).
    pub fn allow_fast(tier_reached: u8, timings: Timings) -> Self {
        Self {
            action: Action::Allow,
            findings: Vec::new(),
            tier_reached,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        }
    }

    /// Determine action from findings: max severity → action mapping.
    pub fn from_findings(findings: Vec<Finding>, tier_reached: u8, timings: Timings) -> Self {
        let action = action_from_findings(&findings);
        Self {
            action,
            findings,
            tier_reached,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_severity_maps_to_allow() {
        let findings = vec![Finding {
            rule_id: RuleId::NonAsciiHostname, // arbitrary rule
            severity: Severity::Info,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        assert_eq!(verdict.action, Action::Allow);
    }

    #[test]
    fn test_info_severity_display() {
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }

    #[test]
    fn test_info_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn test_upgraded_action_from_findings_upgrades_when_findings_are_stronger() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        assert_eq!(
            upgraded_action_from_findings(&findings, Action::Allow),
            Action::Warn
        );
    }

    #[test]
    fn test_upgraded_action_from_findings_preserves_stronger_current_action() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        assert_eq!(
            upgraded_action_from_findings(&findings, Action::Block),
            Action::Block
        );
    }

    #[test]
    fn test_action_from_findings_empty_returns_allow() {
        assert_eq!(action_from_findings(&[]), Action::Allow);
    }

    #[test]
    fn test_action_from_findings_high_returns_block() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatOsvVulnerable,
            severity: Severity::High,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Block);
    }

    #[test]
    fn test_action_from_findings_critical_returns_block() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatMaliciousPackage,
            severity: Severity::Critical,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Block);
    }

    #[test]
    fn test_action_from_findings_low_returns_warn() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Low,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Warn);
    }

    #[test]
    fn test_upgraded_action_preserves_current_on_empty_findings() {
        assert_eq!(
            upgraded_action_from_findings(&[], Action::Block),
            Action::Block
        );
    }
}
