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
    /// PR3 — a shell-level reverse/bind shell: a bash `/dev/tcp/…` or `/dev/udp/…`
    /// network redirect, or `nc`/`ncat`/`netcat` with an exec-on-connect flag
    /// (`-e`/`-c`/`--exec`/`--sh-exec`), or `socat … EXEC:`/`SYSTEM:`. High
    /// (MITRE T1059). Interpreter-based reverse shells (`python -c 'socket…'`)
    /// classify as [`RuleId::InterpreterSuspiciousInlineExec`] instead, so the two
    /// rules never double-fire.
    ReverseShell,
    /// PR3 — an inline interpreter (`python -c`, `node -e`, `perl -e`, `ruby -e`,
    /// `php -r`, `bun -e`) whose inline code carries a SUSPICIOUS PAYLOAD: a
    /// dynamic code-exec call (`exec(`/`eval(`/`system(`/`os.system`/`__import__`),
    /// a process spawn (`subprocess`/`os.exec`/`child_process`/`execSync`), or a
    /// network primitive (`socket.socket`/`urllib`/`requests.`/`http.client`). Fires
    /// ONLY on (inline-interpreter form) AND (payload indicator) — a bare
    /// `python -c 'print(1)'` never fires. High (MITRE T1059). The base64
    /// decode-execute shape stays owned by [`RuleId::Base64DecodeExecute`] (this
    /// rule skips it), and `powershell -Command` inline is owned by
    /// `rules::powershell`.
    InterpreterSuspiciousInlineExec,

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
    WorkflowExcessivePermissions,
    WorkflowRunTrigger,
    WorkflowCheckoutUntrustedRef,
    WorkflowCachePoisoning,
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
    /// A1 — the package name is in the malicious-package DB but the requested
    /// version could not be resolved to a definite hit: an unpinned install
    /// (`pip install foo`) of a version-specific malicious record, or a version
    /// constraint that provably overlaps the affected versions. Distinct from
    /// `ThreatMaliciousPackage` (a confirmed exact/all-versions hit, which still
    /// fires and may short-circuit weaker signals); this one is Medium/Warn
    /// because the resolver MIGHT pick an affected version. A constraint that
    /// provably excludes every affected version does NOT fire this. Emitted by
    /// `rules::threatintel` (command path) and `ecosystem_scan` (manifest path).
    ThreatUnresolvedMaliciousPackage,
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
    /// M7 ch1 — an OSC/CSI escape open at EOF, or an OSC payload exceeding
    /// bounded analysis retention. Truncated/oversized `\e]52;<base64>` must
    /// remain High and fail closed instead of being silently dropped.
    OutputTruncatedEscapeSequence,
    /// repo-0279 — streamed-output evidence exceeded the analyzer's bounded
    /// retention, so hits were DROPPED. Attacker-amplified escape density must
    /// surface as an analysis-incomplete signal rather than silent evidence
    /// loss or unbounded allocation.
    OutputAnalysisOverflow,

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
    /// (central sensitive-asset registry) set, making credentials readable via
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
    // Sensitive-var list is the same central registry M6 ch5 guidance uses.
    /// M9 ch4 — a sensitive env var is set AND the command pipes remote content
    /// into a shell (`curl … | bash`); the script inherits and can exfiltrate it.
    /// High. This is the dedicated rule for M6 ch5 environment-scrubbing
    /// guidance; it never emits an executable rewrite. Tier-1 rides the
    /// pipe-to-interpreter patterns; the std::env check is wired in `engine.rs`.
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

    // Cross-event correlation rules (W7). Fire over a bounded per-session ring of
    // confirmed executed events plus a provisional current event
    // (`crate::event_buffer`, `crate::session_warnings`), NOT from the `analyze`
    // hot path. They reason about "A THEN B within a window" sequences,
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
    /// A2 — the scan could not fully cover a relevant file (an oversized
    /// priority/text file, an unreadable file, an unsupported native/packaging
    /// artifact like a `.so`/`.whl`, a file too large to even hash, or a
    /// rule panic), so the result is NOT "complete and clean". Assembled by the
    /// scan driver from the recorded `CoverageGap`s, NOT a fixture-driven rule,
    /// so it lives in `EXTERNALLY_TRIGGERED_RULES`. Medium by default; High when
    /// the gap's effective policy action is Fail (whence the action is Block).
    AnalysisIncomplete,
    /// B5: an installed Python distribution's integrity does not hold: a RECORD
    /// hash mismatch, a RECORD-listed file missing, an installed file owned by no
    /// distribution, a single path owned by two distributions, or an unowned
    /// `sitecustomize.py`/`usercustomize.py` startup hook. Correlated from the
    /// granular `crate::artifact::ArtifactSignalKind`s by the installed-tree scan,
    /// NOT a command/paste fixture, so it lives in `EXTERNALLY_TRIGGERED_RULES`
    /// with no PATTERN_TABLE entry. Medium by default (installed-environment drift
    /// is common: conda, distro packaging, instrumentation, editable installs);
    /// High/Critical/Block only with corroboration (a known malicious hash, an
    /// unowned startup hook, startup execution plus an integrity mismatch, an
    /// unowned native executable, or cross-distribution execution). A strict
    /// integrity policy upgrades the action to Block via `action_overrides`.
    PythonInstalledIntegrityViolation,
    /// B6: a Python startup hook (`.pth` `import` line, Python 3.15 `.start`
    /// entry-point file, or `sitecustomize.py`/`usercustomize.py`) executes
    /// suspicious code at interpreter start. Correlated from the granular
    /// `crate::artifact::ArtifactSignalKind`s by the installed-tree scan when an
    /// executing, non-template line is paired with a danger capability (a network
    /// download, a subprocess spawn, a `sys.path` search, obfuscated content, or an
    /// untrusted path addition). Canonical editable-install and namespace-package
    /// bootstraps are exempt because their COMPLETE line matches a known template.
    /// Fires over the filesystem from `ecosystem scan --installed`, never from a
    /// command/paste fixture, so it has no PATTERN_TABLE entry and lives in
    /// `EXTERNALLY_TRIGGERED_RULES`. High severity (whence the action is Block).
    PythonStartupHookSuspicious,
    /// B6: a Python startup hook launches a DIFFERENT language runtime
    /// (Bun/Node/Deno) at interpreter start, the cross-distribution loader/payload
    /// split the live campaign uses to hand execution from a Python `.pth` to a
    /// bundled JavaScript payload. The rule keys on the launched RUNTIME name, not
    /// the payload filename, so renaming the script does not evade. Correlated from
    /// the artifact signals by the installed-tree scan; no PATTERN_TABLE entry
    /// (`EXTERNALLY_TRIGGERED_RULES`). Critical severity (whence the action is
    /// Block).
    PythonStartupHookCrossRuntime,
    /// B7: a bundled native module (`.so`/`.dylib`/`.pyd`/`.node`) exposes a direct
    /// EXECUTION ENTRY (a `PyInit_*` export, an ELF constructor, a Mach-O
    /// `__mod_init_func`, or a PE TLS callback / `DllMain`) AND a DANGER CAPABILITY
    /// (a process spawn, an external-runtime loader, a downloader/network call, or
    /// dynamic code loading) AND CORROBORATION (an external runtime name, a sibling
    /// script/payload reference, a sensitive credential path, or a known-malicious
    /// indicator). The native-import trigger the live supply-chain campaign uses to
    /// hand execution from a compiled extension to a bundled payload at import time.
    /// The rule keys on GENERIC relationships (any sibling script, any unrelated
    /// runtime), so renaming the payload does not evade. Correlated from the
    /// granular `crate::artifact::ArtifactSignalKind`s by native triage over an
    /// archive member or an installed `.so`/`.pyd`/`.dylib`, never from a
    /// command/paste fixture, so it has no PATTERN_TABLE entry and lives in
    /// `EXTERNALLY_TRIGGERED_RULES`. Critical severity (whence the action is Block).
    /// Mere native-module presence yields at most an informational signal, never
    /// this finding.
    NativeImportExecutionChain,
    /// B8 + DB-D: an inspected artifact (a wheel/sdist) or one of its members has a
    /// SHA-256 that matches a KNOWN-MALICIOUS hash in the threat DB (MITRE T1195
    /// supply-chain compromise). The hash lookup is ACTIVATED behind the
    /// `artifact-hash-lookup` cargo feature, now that DB-D shipped the v2 hash
    /// indices and their readers (`ThreatDb::check_artifact_sha256` /
    /// `check_file_sha256`). With the feature ON and a v2 hash index present,
    /// `crate::artifact::correlate` decodes the artifact's whole-file hash and each
    /// member's content hash, queries the DB, and emits this finding on the first
    /// match (the test
    /// `crate::artifact::correlate::tests::hash_lookup::artifact_sha_match_fires_critical`
    /// exercises it). In the DEFAULT build the feature is OFF: the lookup compiles to
    /// a no-op and the RuleId is unreachable there. Registered unconditionally (the
    /// registry tests must see every variant), with NO PATTERN_TABLE entry and NO
    /// fixture, so it lives in `EXTERNALLY_TRIGGERED_RULES`. Critical severity
    /// (whence the action is Block).
    ArtifactKnownMalicious,
    /// A wheel/archive STRUCTURALLY REJECTED by the hardened reader (a path-traversal
    /// entry, an encrypted member, a CRC mismatch, or a duplicate-path collision) - a hard
    /// fault the B5/B6/B7 signal correlation does not surface as a finding. `package
    /// inspect` synthesizes this finding (carrying the violation detail strings) for a
    /// rejected artifact so the `findings` array is non-empty whenever the action is Block
    /// due to a rejection (a CI consumer gating on `findings.length` must not pass a
    /// path-traversal wheel). Triggered by artifact inspection, not a PATTERN_TABLE string,
    /// so it lives in `EXTERNALLY_TRIGGERED_RULES` with no fixture. High severity.
    WheelStructurallyRejected,
    /// D3: the bytes the package firewall is about to inspect/install do NOT hash
    /// to the digest the resolver pinned and the quarantine recorded (MITRE T1565
    /// data manipulation). The firewall operates only on content-addressed
    /// quarantine blobs and RE-HASHES each one immediately before evaluation
    /// (cross-cutting invariant 4, the TOCTOU re-bind); if the on-disk blob is
    /// absent, unreadable, or hashes to anything other than the approved digest,
    /// the approved bytes are gone and installing would run unapproved content, so
    /// this fires and the enforcing surface fails closed. DISTINCT from
    /// [`Self::ArtifactKnownMalicious`], which is a POSITIVE threat-DB match on a
    /// known-malicious hash: this is an integrity failure (the bytes are not the
    /// approved bytes), not a reputation hit. Produced by
    /// `crate::artifact::firewall`, not from a command/paste fixture, so it has no
    /// PATTERN_TABLE entry and lives in `EXTERNALLY_TRIGGERED_RULES`. Critical
    /// severity (whence the action is Block).
    ArtifactDownloadIntegrityMismatch,
    /// F2: a local release differential between two versions of the SAME
    /// distribution found that the NEW wheel changed its EXECUTION SHAPE versus the
    /// OLD wheel in a way that, in the live supply-chain campaign, marks a benign
    /// release turning malicious (MITRE T1195): a pure-Python release that now
    /// ships a compiled extension, a release that newly carries an
    /// interpreter-startup hook, a release that now bundles a multi-megabyte
    /// JavaScript payload, a changed distribution identity, or a newly-gained
    /// execution capability (a `.pth`/native subprocess spawn, a network/runtime
    /// download, a native execution entry) the prior release lacked. Each is a
    /// HEURISTIC delta a legitimate release can sometimes have, so this is MEDIUM
    /// severity (it WARNS, never auto-blocks; a strict policy can upgrade it via
    /// `action_overrides`); the conclusive conjunctions are caught at Block strength
    /// by `python_startup_hook_*` / `native_import_execution_chain` when the new
    /// wheel is inspected directly. Produced by `crate::artifact::release_diff`
    /// comparing two on-disk wheels (local-artifact-only), never from a
    /// command/paste fixture, so it has no PATTERN_TABLE entry and lives in
    /// `EXTERNALLY_TRIGGERED_RULES`.
    ArtifactReleaseAnomaly,
}

impl RuleId {
    /// Whether this rule's severity has a HIGH floor that a policy
    /// `severity_overrides` entry may not drop below.
    ///
    /// These are the integrity / reputation / malicious-supply-chain findings
    /// where a downgrade would let a tampered or known-bad install proceed: an
    /// override that lowered the severity below [`Severity::High`] would map the
    /// finding to Warn (via [`action_from_findings`]), `is_block()` would be
    /// false, and the firewall / install transaction would run on unapproved or
    /// malicious bytes. The override may still RAISE severity (e.g. to Critical);
    /// the floor only blocks lowering it past High. Enforced at the single
    /// chokepoint [`crate::policy::Policy::severity_override`], so it applies
    /// regardless of policy scope (user, org, and repo are all floored).
    pub const fn has_severity_floor(&self) -> bool {
        matches!(
            self,
            RuleId::ArtifactKnownMalicious
                | RuleId::ArtifactDownloadIntegrityMismatch
                | RuleId::PythonStartupHookCrossRuntime
                | RuleId::NativeImportExecutionChain
        )
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DataFlowSource {
    SensitiveFile,
    SensitiveEnvironmentReference,
    SensitiveCommandSubstitution,
    PipedSensitiveFile,
    MultipleSensitiveFiles,
    SensitiveAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DataFlowSink {
    Curl,
    Wget,
    RemoteHttp,
    LocalProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DataFlowOperation {
    UploadFile,
    MultipartForm,
    RequestBody,
    PostFile,
    PostData,
    CredentialSweep,
    UploadAnalysisUnresolved,
    CredentialSweepAnalysisUnresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputDataSource {
    SecretOrCanarySignal,
    ClassifiedSensitivePath,
    OutputText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputDataSink {
    RemoteRenderer,
    RemoteHttp,
    Directive,
    OperatorSuppression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputDataOperation {
    AutoFetch,
    UrlQuery,
    ReadAndSend,
    Stealth,
}

#[derive(Clone, Deserialize)]
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

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EvidenceProjection<'a> {
    Url {
        raw: &'a str,
    },
    HostComparison {
        raw_host: &'a str,
        similar_to: &'a str,
    },
    CommandPattern {
        pattern: &'a str,
        matched: &'a str,
    },
    ByteSequence {
        offset: usize,
        hex: &'a str,
        description: &'a str,
    },
    EnvVar {
        name: &'a str,
        value_preview: &'a str,
    },
    Text {
        detail: &'a str,
    },
    ThreatIntel {
        source: &'a str,
        threat_type: &'a str,
        confidence: crate::threatdb::Confidence,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference: Option<&'a str>,
    },
    HomoglyphAnalysis {
        raw: &'a str,
        escaped: &'a str,
        suspicious_chars: &'a [SuspiciousChar],
    },
}

impl<'a> From<&'a Evidence> for EvidenceProjection<'a> {
    fn from(value: &'a Evidence) -> Self {
        match value {
            Evidence::Url { raw } => Self::Url { raw },
            Evidence::HostComparison {
                raw_host,
                similar_to,
            } => Self::HostComparison {
                raw_host,
                similar_to,
            },
            Evidence::CommandPattern { pattern, matched } => {
                Self::CommandPattern { pattern, matched }
            }
            Evidence::ByteSequence {
                offset,
                hex,
                description,
            } => Self::ByteSequence {
                offset: *offset,
                hex,
                description,
            },
            Evidence::EnvVar {
                name,
                value_preview,
            } => Self::EnvVar {
                name,
                value_preview,
            },
            Evidence::Text { detail } => Self::Text { detail },
            Evidence::ThreatIntel {
                source,
                threat_type,
                confidence,
                reference,
            } => Self::ThreatIntel {
                source,
                threat_type,
                confidence: *confidence,
                reference: reference.as_deref(),
            },
            Evidence::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            } => Self::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            },
        }
    }
}

impl Serialize for Evidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let safe = crate::redact::mandatory_redacted_evidence(self);
        EvidenceProjection::from(&safe).serialize(serializer)
    }
}

impl fmt::Debug for Evidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe = crate::redact::mandatory_redacted_evidence(self);
        fmt::Debug::fmt(&EvidenceProjection::from(&safe), formatter)
    }
}

macro_rules! closed_token {
    ($value:expr, $($variant:path => $token:literal),+ $(,)?) => {
        match $value {
            $($variant => $token,)+
        }
    };
}

pub(crate) fn data_flow_evidence(
    source: DataFlowSource,
    sink: DataFlowSink,
    operation: DataFlowOperation,
) -> Evidence {
    let source = closed_token!(source,
        DataFlowSource::SensitiveFile => "sensitive_file",
        DataFlowSource::SensitiveEnvironmentReference => "sensitive_environment_reference",
        DataFlowSource::SensitiveCommandSubstitution => "sensitive_command_substitution",
        DataFlowSource::PipedSensitiveFile => "piped_sensitive_file",
        DataFlowSource::MultipleSensitiveFiles => "multiple_sensitive_files",
        DataFlowSource::SensitiveAsset => "sensitive_asset",
    );
    let sink = closed_token!(sink,
        DataFlowSink::Curl => "curl",
        DataFlowSink::Wget => "wget",
        DataFlowSink::RemoteHttp => "remote_http",
        DataFlowSink::LocalProcess => "local_process",
    );
    let operation = closed_token!(operation,
        DataFlowOperation::UploadFile => "upload_file",
        DataFlowOperation::MultipartForm => "multipart_form",
        DataFlowOperation::RequestBody => "request_body",
        DataFlowOperation::PostFile => "post_file",
        DataFlowOperation::PostData => "post_data",
        DataFlowOperation::CredentialSweep => "credential_sweep",
        DataFlowOperation::UploadAnalysisUnresolved => "upload_analysis_unresolved",
        DataFlowOperation::CredentialSweepAnalysisUnresolved => "credential_sweep_analysis_unresolved",
    );
    Evidence::Text {
        detail: format!("tirith:v1:data_flow;source={source};sink={sink};operation={operation}"),
    }
}

pub(crate) fn output_data_flow_evidence(
    source: OutputDataSource,
    sink: OutputDataSink,
    operation: OutputDataOperation,
    signal_count: usize,
    query_key_count: usize,
) -> Evidence {
    let source = closed_token!(source,
        OutputDataSource::SecretOrCanarySignal => "secret_or_canary_signal",
        OutputDataSource::ClassifiedSensitivePath => "classified_sensitive_path",
        OutputDataSource::OutputText => "output_text",
    );
    let sink = closed_token!(sink,
        OutputDataSink::RemoteRenderer => "remote_renderer",
        OutputDataSink::RemoteHttp => "remote_http",
        OutputDataSink::Directive => "directive",
        OutputDataSink::OperatorSuppression => "operator_suppression",
    );
    let operation = closed_token!(operation,
        OutputDataOperation::AutoFetch => "auto_fetch",
        OutputDataOperation::UrlQuery => "url_query",
        OutputDataOperation::ReadAndSend => "read_and_send",
        OutputDataOperation::Stealth => "stealth",
    );
    Evidence::Text {
        detail: format!(
            "tirith:v1:output_data_flow;source={source};sink={sink};operation={operation};signals={signal_count};query_keys={query_key_count}"
        ),
    }
}

fn web3_index_token(extraction_index: Option<usize>) -> String {
    extraction_index.map_or_else(|| "none".to_string(), |index| index.to_string())
}

pub(crate) fn web3_endpoint_evidence(
    endpoint: &crate::sensitive_assets::RpcEndpointSummary,
    extraction_index: Option<usize>,
) -> Evidence {
    use crate::sensitive_assets::{RpcCredentialClass as C, RpcPathClass as P, RpcProvider as R};
    let provider = closed_token!(endpoint.provider,
        R::Infura => "infura", R::Alchemy => "alchemy", R::Moralis => "moralis",
        R::Chainstack => "chainstack", R::GetBlock => "getblock",
        R::QuickNode => "quicknode", R::Ankr => "ankr", R::Other => "other",
    );
    let path = closed_token!(endpoint.path_class,
        P::Root => "root", P::Rpc => "rpc", P::JsonRpc => "jsonrpc",
        P::Versioned => "versioned", P::Opaque => "opaque",
    );
    let credential = closed_token!(endpoint.credential_class,
        C::Public => "public", C::UserInfo => "userinfo", C::Query => "query",
        C::Fragment => "fragment", C::HostToken => "host_token",
        C::PathToken => "path_token", C::Multiple => "multiple",
    );
    Evidence::Text {
        detail: format!(
            "tirith:v1:web3_endpoint;index={};provider={provider};path={path};credential={credential}",
            web3_index_token(extraction_index)
        ),
    }
}

pub(crate) fn web3_address_evidence(extraction_index: Option<usize>) -> Evidence {
    Evidence::Text {
        detail: format!(
            "tirith:v1:web3_address;index={}",
            web3_index_token(extraction_index)
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PdfTextEvidenceVisibility {
    Visible,
    Hidden,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PdfTextEvidenceJoin {
    Concatenated,
    Spaced,
}

fn take_categorical_field<'a>(
    input: &mut &'a str,
    field: &str,
    final_field: bool,
) -> Option<&'a str> {
    let value = input.strip_prefix(field)?;
    if final_field {
        if value.is_empty() || value.contains(';') {
            return None;
        }
        *input = "";
        return Some(value);
    }
    let (value, remaining) = value.split_once(';')?;
    if value.is_empty() {
        return None;
    }
    *input = remaining;
    Some(value)
}

fn canonical_usize_token(value: &str) -> bool {
    value
        .parse::<usize>()
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

fn canonical_index_token(value: &str) -> bool {
    value == "none" || canonical_usize_token(value)
}

const MAX_PDF_TEXT_EVIDENCE_PAGE: u32 = 100_000;
const MAX_PDF_TEXT_EVIDENCE_OBJECT: u32 = 100_000;
const MAX_PDF_TEXT_EVIDENCE_FRAGMENTS: u16 = 256;

fn canonical_bounded_u32_token(value: &str, min: u32, max: u32) -> bool {
    value
        .parse::<u32>()
        .ok()
        .is_some_and(|parsed| parsed >= min && parsed <= max && parsed.to_string() == value)
}

fn canonical_bounded_u16_token(value: &str, min: u16, max: u16) -> bool {
    value
        .parse::<u16>()
        .ok()
        .is_some_and(|parsed| parsed >= min && parsed <= max && parsed.to_string() == value)
}

fn canonical_pdf_object_token(value: &str) -> bool {
    if value == "unknown" {
        return true;
    }
    let Some(reference) = value.strip_prefix("ref:") else {
        return false;
    };
    let mut fields = reference.split(':');
    let (Some(number), Some(generation), None) = (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    canonical_bounded_u32_token(number, 1, MAX_PDF_TEXT_EVIDENCE_OBJECT)
        && canonical_bounded_u16_token(generation, 0, u16::MAX)
}

fn pdf_object_evidence_token(object: Option<&str>) -> String {
    let Some(object) = object else {
        return "unknown".to_string();
    };
    let candidate = format!("ref:{object}");
    if canonical_pdf_object_token(&candidate) {
        candidate
    } else {
        "unknown".to_string()
    }
}

pub(crate) fn pdf_text_fragment_evidence(
    page: u32,
    object: Option<&str>,
    visibility: PdfTextEvidenceVisibility,
) -> Evidence {
    let visibility = closed_token!(visibility,
        PdfTextEvidenceVisibility::Visible => "visible",
        PdfTextEvidenceVisibility::Hidden => "hidden",
        PdfTextEvidenceVisibility::Unknown => "unknown",
    );
    let object = pdf_object_evidence_token(object);
    Evidence::Text {
        detail: format!(
            "tirith:v1:pdf_text;mode=fragment;page={page};object={object};visibility={visibility}"
        ),
    }
}

pub(crate) fn pdf_text_reassembled_evidence(
    page: u32,
    join: PdfTextEvidenceJoin,
    ordered_fragments: usize,
) -> Evidence {
    let join = closed_token!(join,
        PdfTextEvidenceJoin::Concatenated => "concatenated",
        PdfTextEvidenceJoin::Spaced => "spaced",
    );
    Evidence::Text {
        detail: format!(
            "tirith:v1:pdf_text;mode=reassembled;page={page};join={join};fragments={ordered_fragments}"
        ),
    }
}

/// Validate the complete grammar of a Tirith-generated categorical record.
/// Every string field is a closed token and every numeric field must use its
/// canonical decimal spelling. Consequently, a public `Evidence::Text` value
/// cannot append opaque data and masquerade as an internal record to bypass DLP.
pub(crate) fn is_internal_categorical_evidence_record(detail: &str) -> bool {
    if let Some(mut tail) = detail.strip_prefix("tirith:v1:data_flow;") {
        let Some(source) = take_categorical_field(&mut tail, "source=", false) else {
            return false;
        };
        let Some(sink) = take_categorical_field(&mut tail, "sink=", false) else {
            return false;
        };
        let Some(operation) = take_categorical_field(&mut tail, "operation=", true) else {
            return false;
        };
        return tail.is_empty()
            && matches!(
                source,
                "sensitive_file"
                    | "sensitive_environment_reference"
                    | "sensitive_command_substitution"
                    | "piped_sensitive_file"
                    | "multiple_sensitive_files"
                    | "sensitive_asset"
            )
            && matches!(sink, "curl" | "wget" | "remote_http" | "local_process")
            && matches!(
                operation,
                "upload_file"
                    | "multipart_form"
                    | "request_body"
                    | "post_file"
                    | "post_data"
                    | "credential_sweep"
                    | "upload_analysis_unresolved"
                    | "credential_sweep_analysis_unresolved"
            );
    }
    if let Some(mut tail) = detail.strip_prefix("tirith:v1:output_data_flow;") {
        let Some(source) = take_categorical_field(&mut tail, "source=", false) else {
            return false;
        };
        let Some(sink) = take_categorical_field(&mut tail, "sink=", false) else {
            return false;
        };
        let Some(operation) = take_categorical_field(&mut tail, "operation=", false) else {
            return false;
        };
        let Some(signals) = take_categorical_field(&mut tail, "signals=", false) else {
            return false;
        };
        let Some(query_keys) = take_categorical_field(&mut tail, "query_keys=", true) else {
            return false;
        };
        return tail.is_empty()
            && matches!(
                source,
                "secret_or_canary_signal" | "classified_sensitive_path" | "output_text"
            )
            && matches!(
                sink,
                "remote_renderer" | "remote_http" | "directive" | "operator_suppression"
            )
            && matches!(
                operation,
                "auto_fetch" | "url_query" | "read_and_send" | "stealth"
            )
            && canonical_usize_token(signals)
            && canonical_usize_token(query_keys);
    }
    if let Some(mut tail) = detail.strip_prefix("tirith:v1:web3_endpoint;") {
        let Some(index) = take_categorical_field(&mut tail, "index=", false) else {
            return false;
        };
        let Some(provider) = take_categorical_field(&mut tail, "provider=", false) else {
            return false;
        };
        let Some(path) = take_categorical_field(&mut tail, "path=", false) else {
            return false;
        };
        let Some(credential) = take_categorical_field(&mut tail, "credential=", true) else {
            return false;
        };
        return tail.is_empty()
            && canonical_index_token(index)
            && matches!(
                provider,
                "infura"
                    | "alchemy"
                    | "moralis"
                    | "chainstack"
                    | "getblock"
                    | "quicknode"
                    | "ankr"
                    | "other"
            )
            && matches!(path, "root" | "rpc" | "jsonrpc" | "versioned" | "opaque")
            && matches!(
                credential,
                "public"
                    | "userinfo"
                    | "query"
                    | "fragment"
                    | "host_token"
                    | "path_token"
                    | "multiple"
            );
    }
    if let Some(mut tail) = detail.strip_prefix("tirith:v1:web3_address;") {
        let Some(index) = take_categorical_field(&mut tail, "index=", true) else {
            return false;
        };
        return tail.is_empty() && canonical_index_token(index);
    }
    if let Some(mut tail) = detail.strip_prefix("tirith:v1:pdf_text;") {
        let Some(mode) = take_categorical_field(&mut tail, "mode=", false) else {
            return false;
        };
        let Some(page) = take_categorical_field(&mut tail, "page=", false) else {
            return false;
        };
        if !canonical_bounded_u32_token(page, 1, MAX_PDF_TEXT_EVIDENCE_PAGE) {
            return false;
        }
        return match mode {
            "fragment" => {
                let Some(object) = take_categorical_field(&mut tail, "object=", false) else {
                    return false;
                };
                let Some(visibility) = take_categorical_field(&mut tail, "visibility=", true)
                else {
                    return false;
                };
                tail.is_empty()
                    && canonical_pdf_object_token(object)
                    && matches!(visibility, "visible" | "hidden" | "unknown")
            }
            "reassembled" => {
                let Some(join) = take_categorical_field(&mut tail, "join=", false) else {
                    return false;
                };
                let Some(fragments) = take_categorical_field(&mut tail, "fragments=", true) else {
                    return false;
                };
                tail.is_empty()
                    && matches!(join, "concatenated" | "spaced")
                    && canonical_bounded_u16_token(fragments, 2, MAX_PDF_TEXT_EVIDENCE_FRAGMENTS)
            }
            _ => false,
        };
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InternalWeb3Evidence {
    Endpoint { extraction_index: Option<usize> },
    Address { extraction_index: Option<usize> },
}

pub(crate) fn internal_web3_evidence(evidence: &Evidence) -> Option<InternalWeb3Evidence> {
    let Evidence::Text { detail } = evidence else {
        return None;
    };
    if !is_internal_categorical_evidence_record(detail) {
        return None;
    }
    let (kind, tail) = detail.strip_prefix("tirith:v1:")?.split_once(";index=")?;
    let index_token = tail.split(';').next()?;
    let extraction_index = if index_token == "none" {
        None
    } else {
        index_token.parse::<usize>().ok()
    };
    match kind {
        "web3_endpoint" => Some(InternalWeb3Evidence::Endpoint { extraction_index }),
        "web3_address" => Some(InternalWeb3Evidence::Address { extraction_index }),
        _ => None,
    }
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
#[derive(Clone, Deserialize)]
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

#[derive(Debug, Serialize)]
struct FindingProjection<'a> {
    rule_id: RuleId,
    severity: Severity,
    title: &'a str,
    description: &'a str,
    evidence: &'a [Evidence],
    #[serde(skip_serializing_if = "Option::is_none")]
    human_view: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_view: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitre_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_rule_id: Option<&'a str>,
}

impl<'a> From<&'a Finding> for FindingProjection<'a> {
    fn from(value: &'a Finding) -> Self {
        Self {
            rule_id: value.rule_id,
            severity: value.severity,
            title: &value.title,
            description: &value.description,
            evidence: &value.evidence,
            human_view: value.human_view.as_deref(),
            agent_view: value.agent_view.as_deref(),
            mitre_id: value.mitre_id.as_deref(),
            custom_rule_id: value.custom_rule_id.as_deref(),
        }
    }
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let safe = crate::redact::mandatory_redacted_finding(self);
        FindingProjection::from(&safe).serialize(serializer)
    }
}

impl fmt::Debug for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe = crate::redact::mandatory_redacted_finding(self);
        formatter
            .debug_struct("Finding")
            .field("rule_id", &safe.rule_id)
            .field("severity", &safe.severity)
            .field("title", &safe.title)
            .field("description", &safe.description)
            .field("evidence", &safe.evidence)
            .field("human_view", &safe.human_view)
            .field("agent_view", &safe.agent_view)
            .field("mitre_id", &safe.mitre_id)
            .field("custom_rule_id", &safe.custom_rule_id)
            .finish()
    }
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

pub const MAX_PRESENTED_FINDINGS: usize = 128;
pub const MAX_EVIDENCE_PER_FINDING: usize = 16;
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 64 * 1024;
const EVIDENCE_OMISSION_MARKER_RESERVE: usize = 64;
/// Hard presentation budget for a single machine-readable or text subject.
/// Enforcement and audit always use the complete pre-presentation result.
pub const MAX_PRESENTATION_BYTES: usize = 256 * 1024;
const MAX_JSON_PRESENTATION_BYTES: usize = MAX_PRESENTATION_BYTES - 1;
const MAX_PRIORITY_FINDINGS_IN_FALLBACK: usize = 32;

/// Measure serialized JSON without allocating a second attacker-sized buffer.
pub fn serialized_json_size(value: &impl serde::Serialize) -> Option<usize> {
    struct CountingWriter(usize);
    impl std::io::Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter(0);
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.0)
}

/// Measure pretty-printed JSON without allocating a second serialized buffer.
/// CLI JSON and SARIF sinks use pretty output, so their budget checks must
/// measure that exact representation.
pub fn serialized_json_pretty_size(value: &impl serde::Serialize) -> Option<usize> {
    struct CountingWriter(usize);
    impl std::io::Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter(0);
    let formatter = serde_json::ser::PrettyFormatter::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut writer, formatter);
    value.serialize(&mut serializer).ok()?;
    Some(writer.0)
}

/// Bound a redacted presentation without changing the decision that was made
/// over the complete internal finding set. Callers must redact first so
/// truncation cannot split a secret and defeat a redaction pattern.
pub fn bound_findings_for_output(findings: &mut Vec<Finding>) {
    let decision = action_from_findings(findings);
    let mut dropped_findings = 0usize;

    if findings.len() > MAX_PRESENTED_FINDINGS {
        let original = std::mem::take(findings);
        let retained_indices = retained_finding_indices_for_output(&original);
        let mut selected = vec![false; original.len()];
        for index in retained_indices {
            selected[index] = true;
        }
        let selected_count = selected.iter().filter(|chosen| **chosen).count();
        dropped_findings = original.len().saturating_sub(selected_count);
        findings.extend(
            original
                .into_iter()
                .enumerate()
                .filter_map(|(index, finding)| selected[index].then_some(finding)),
        );
        findings.push(Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity: match decision {
                Action::Block => Severity::High,
                Action::Warn | Action::WarnAck => Severity::Medium,
                Action::Allow => Severity::Info,
            },
            title: "Additional findings omitted from presentation".to_string(),
            description: format!(
                "{dropped_findings} finding(s) were omitted after the {MAX_PRESENTED_FINDINGS}-finding output budget; policy and action were evaluated before presentation bounding"
            ),
            evidence: vec![Evidence::Text {
                detail: format!("omitted_findings={dropped_findings}"),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    let mut evidence_bytes = 0usize;
    let mut omitted_evidence = 0usize;
    for finding in findings.iter_mut() {
        truncate_output_field(&mut finding.title, 128);
        truncate_output_field(&mut finding.description, 512);
        if let Some(value) = finding.human_view.as_mut() {
            truncate_output_field(value, 128);
        }
        if let Some(value) = finding.agent_view.as_mut() {
            truncate_output_field(value, 128);
        }
        if let Some(value) = finding.mitre_id.as_mut() {
            truncate_output_field(value, 64);
        }
        if let Some(value) = finding.custom_rule_id.as_mut() {
            truncate_output_field(value, 64);
        }

        if finding.evidence.len() > MAX_EVIDENCE_PER_FINDING {
            omitted_evidence += finding.evidence.len() - MAX_EVIDENCE_PER_FINDING;
            finding.evidence.truncate(MAX_EVIDENCE_PER_FINDING);
        }
        let mut retained = Vec::with_capacity(finding.evidence.len());
        for mut evidence in std::mem::take(&mut finding.evidence) {
            truncate_evidence_fields(&mut evidence);
            let size = evidence_text_bytes(&evidence);
            if evidence_bytes.saturating_add(size)
                > MAX_EVIDENCE_TEXT_BYTES.saturating_sub(EVIDENCE_OMISSION_MARKER_RESERVE)
            {
                omitted_evidence += 1;
            } else {
                evidence_bytes += size;
                retained.push(evidence);
            }
        }
        finding.evidence = retained;
    }

    if omitted_evidence > 0 {
        if let Some(first) = findings.first_mut() {
            // The omission receipt is mandatory presentation state, not optional
            // detail. Reserve its slot even when the first finding already used
            // all 16 evidence items; the displaced item is itself now omitted.
            if first.evidence.len() >= MAX_EVIDENCE_PER_FINDING && first.evidence.pop().is_some() {
                omitted_evidence = omitted_evidence.saturating_add(1);
            }
            first.evidence.push(Evidence::Text {
                detail: format!("omitted_evidence_items={omitted_evidence}"),
            });
        }
    }

    debug_assert_eq!(decision, action_from_findings(findings));
    let _ = dropped_findings;
}

/// Return the original finding indices that survive presentation bounding.
/// Consumers which must pair a bounded display finding with its exact raw
/// source (for example trust advisories) use this selection before redaction.
pub fn retained_finding_indices_for_output(findings: &[Finding]) -> Vec<usize> {
    if findings.len() <= MAX_PRESENTED_FINDINGS {
        return (0..findings.len()).collect();
    }

    let retain_slots = MAX_PRESENTED_FINDINGS.saturating_sub(1);
    let mut selected = vec![false; findings.len()];
    let mut selected_count = 0usize;
    for priority in [0u8, 1u8] {
        for (index, finding) in findings.iter().enumerate() {
            if selected_count == retain_slots {
                break;
            }
            let matches_priority = match priority {
                0 => finding.severity == Severity::Critical,
                _ => {
                    finding.severity == Severity::High
                        || finding.rule_id == RuleId::AnalysisIncomplete
                }
            };
            if matches_priority && !selected[index] {
                selected[index] = true;
                selected_count += 1;
            }
        }
    }
    for chosen in &mut selected {
        if selected_count == retain_slots {
            break;
        }
        if !*chosen {
            *chosen = true;
            selected_count += 1;
        }
    }
    selected
        .into_iter()
        .enumerate()
        .filter_map(|(index, chosen)| chosen.then_some(index))
        .collect()
}

pub fn bound_verdict_for_output(verdict: &mut Verdict) {
    let action = verdict.action;
    bound_findings_for_output(&mut verdict.findings);
    // `action` may include policy/escalation state stronger than raw findings.
    verdict.action = action;
}

/// Bound an already-redacted JSON projection. Ordinary projections pass
/// through unchanged. Oversized aggregate projections become a compact,
/// machine-readable omission envelope that preserves decision/count metadata
/// and a bounded sample of high-priority findings.
pub fn bound_json_value_for_output(value: serde_json::Value) -> serde_json::Value {
    // Measure the larger pretty form because the CLI JSON writer uses it; this
    // also guarantees the compact MCP/resource serialization stays within cap.
    let original_bytes = serialized_json_pretty_size(&value).unwrap_or(usize::MAX);
    if original_bytes <= MAX_JSON_PRESENTATION_BYTES {
        return value;
    }

    let mut summary = serde_json::Map::new();
    if let Some(object) = value.as_object() {
        for key in [
            "action",
            "status",
            "kind",
            "event",
            "name",
            "schema_version",
            "running",
            "refused",
            "executed",
            "exit_code",
            "analysis_complete",
            "runner_error",
            "execution_policy",
            "error",
            "scanned_count",
            "skipped_count",
            "total_findings",
            "findings_count",
            "original_findings_count",
            "presented_findings_count",
            "dropped_findings_count",
            "panic_count",
            "truncated",
            "truncation_reason",
            "analysis_incomplete",
            "scan_analysis_incomplete",
            "dlp_redaction_incomplete",
            "completeness_policy_violated",
            "policy_diagnostics_count",
        ] {
            if let Some(candidate) = object.get(key) {
                if candidate.is_boolean() || candidate.is_number() || candidate.is_null() {
                    summary.insert(key.to_string(), candidate.clone());
                } else if let Some(text) = candidate.as_str() {
                    summary.insert(
                        key.to_string(),
                        serde_json::Value::String(truncated_json_text(text, 128)),
                    );
                }
            }
        }
    }

    // The fallback itself is an incomplete presentation even when the scan was
    // complete. Keep that signal separate from the summarized scan status.
    let mut priority = Vec::new();
    let mut priority_count = 0usize;
    collect_priority_findings(&value, None, 0, &mut priority, &mut priority_count);
    collect_priority_findings(&value, None, 1, &mut priority, &mut priority_count);
    let policy_diagnostics_total = value
        .get("policy_diagnostics")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let policy_diagnostics = value
        .get("policy_diagnostics")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .take(8)
        .map(|diagnostic| serde_json::Value::String(truncated_json_text(diagnostic, 256)))
        .collect::<Vec<_>>();
    let mut fallback = serde_json::json!({
        "presentation_truncated": true,
        "analysis_incomplete": true,
        "original_serialized_bytes": original_bytes,
        "max_presentation_bytes": MAX_PRESENTATION_BYTES,
        "summary": summary.clone(),
        "priority_findings": priority,
        "priority_findings_omitted": priority_count.saturating_sub(MAX_PRIORITY_FINDINGS_IN_FALLBACK),
    });
    // Retain common top-level fields for existing machine consumers while also
    // collecting them under `summary` for generic clients.
    if let Some(object) = fallback.as_object_mut() {
        if policy_diagnostics_total > 0 {
            object.insert(
                "policy_diagnostics".to_string(),
                serde_json::Value::Array(policy_diagnostics),
            );
            object.insert(
                "policy_diagnostics_omitted".to_string(),
                serde_json::json!(policy_diagnostics_total.saturating_sub(8)),
            );
        }
        object.extend(
            summary
                .into_iter()
                .filter(|(key, _)| key != "analysis_incomplete"),
        );
    }

    // Defensive guarantee if a future compact-finding field grows: retain the
    // envelope and counts, dropping samples until the hard ceiling is met.
    while serialized_json_pretty_size(&fallback).unwrap_or(usize::MAX) > MAX_JSON_PRESENTATION_BYTES
    {
        let Some(findings) = fallback
            .get_mut("priority_findings")
            .and_then(serde_json::Value::as_array_mut)
        else {
            break;
        };
        if findings.pop().is_none() {
            break;
        }
        if let Some(omitted) = fallback
            .get_mut("priority_findings_omitted")
            .and_then(|value| value.as_u64())
        {
            fallback["priority_findings_omitted"] = serde_json::json!(omitted + 1);
        }
    }
    fallback
}

/// Bound display text without splitting UTF-8 and report the exact number of
/// original bytes omitted. Callers must sanitize/redact before this step.
pub fn bound_text_for_output(mut text: String) -> String {
    if text.len() <= MAX_PRESENTATION_BYTES {
        return text;
    }

    let original_bytes = text.len();
    // Reserve enough space for the fixed marker and a decimal usize count.
    let mut end = MAX_PRESENTATION_BYTES.saturating_sub(128).min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    // A trusted colorizer may have inserted ANSI around otherwise-sanitized
    // text. If the byte cut landed inside that sequence, scrub the truncated
    // prefix as a whole so the omission marker cannot inherit terminal state.
    text = crate::mcp::output_filter::sanitize_text_str(&text);
    let omitted = original_bytes.saturating_sub(text.len());
    text.push_str(&format!(
        "\n[presentation truncated: omitted_bytes={omitted}, original_bytes={original_bytes}]\n"
    ));
    debug_assert!(text.len() <= MAX_PRESENTATION_BYTES);
    text
}

/// Incremental text projection that never retains more than the presentation
/// budget. Once full, later chunks are counted but not materialized.
pub struct BoundedTextBuilder {
    text: String,
    source_bytes: usize,
    truncated: bool,
}

impl BoundedTextBuilder {
    const MARKER_RESERVE: usize = 160;

    pub fn new() -> Self {
        Self {
            text: String::new(),
            source_bytes: 0,
            truncated: false,
        }
    }

    pub fn push_str(&mut self, chunk: &str) {
        self.source_bytes = self.source_bytes.saturating_add(chunk.len());
        if self.truncated {
            return;
        }
        let limit = MAX_PRESENTATION_BYTES.saturating_sub(Self::MARKER_RESERVE);
        let available = limit.saturating_sub(self.text.len());
        if chunk.len() <= available {
            self.text.push_str(chunk);
            return;
        }

        let mut end = available.min(chunk.len());
        while end > 0 && !chunk.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&chunk[..end]);
        // Neutralize a trusted ANSI sequence if the byte boundary bisected it.
        self.text = crate::mcp::output_filter::sanitize_text_str(&self.text);
        self.truncated = true;
    }

    pub fn finish(mut self) -> String {
        if self.truncated {
            let omitted_bytes = self.source_bytes.saturating_sub(self.text.len());
            self.text.push_str(&format!(
                "\n[presentation truncated: omitted_bytes={omitted_bytes}]\n"
            ));
        }
        debug_assert!(self.text.len() <= MAX_PRESENTATION_BYTES);
        self.text
    }
}

impl Default for BoundedTextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Incrementally builds a JSON object with bounded arrays. Oversized items are
/// counted and skipped independently; later higher-value/smaller items are
/// still considered instead of being hidden behind a file-level early stop.
pub struct BoundedJsonProjection {
    root: serde_json::Map<String, serde_json::Value>,
    omitted: std::collections::BTreeMap<String, (usize, usize)>,
    truncated: bool,
    estimated_bytes: usize,
}

/// Schema error returned when a caller tries to append to a projection field
/// that already exists with a non-array value. Public input must never turn a
/// presentation helper into a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedJsonProjectionError {
    NonArrayKey { key: String },
}

impl std::fmt::Display for BoundedJsonProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonArrayKey { key } => {
                write!(
                    formatter,
                    "bounded projection field '{key}' is not an array"
                )
            }
        }
    }
}

impl std::error::Error for BoundedJsonProjectionError {}

impl BoundedJsonProjection {
    const OMISSION_RESERVE: usize = 2048;

    pub fn new(base: serde_json::Value) -> Self {
        let root = base.as_object().cloned().unwrap_or_default();
        let estimated_bytes = serialized_json_pretty_size(&root).unwrap_or(usize::MAX);
        Self {
            root,
            omitted: std::collections::BTreeMap::new(),
            truncated: false,
            estimated_bytes,
        }
    }

    /// `units` is the caller's semantic count (for example findings in a file),
    /// reported separately from the exact omitted item count.
    pub fn push_array_item(
        &mut self,
        key: &str,
        item: serde_json::Value,
        units: usize,
    ) -> Result<bool, BoundedJsonProjectionError> {
        if self.root.get(key).is_some_and(|value| !value.is_array()) {
            return Err(BoundedJsonProjectionError::NonArrayKey {
                key: key.to_string(),
            });
        }
        // Measure only the candidate item. Re-serializing the growing root for
        // every item makes an attacker-controlled projection quadratic in CPU.
        // The fixed overhead conservatively covers commas, indentation, and a
        // newly inserted array key; `finish` still enforces the exact cap once.
        let item_bytes = serialized_json_pretty_size(&item).unwrap_or(usize::MAX);
        let overhead = key.len().saturating_add(64);
        let projected = self
            .estimated_bytes
            .saturating_add(item_bytes)
            .saturating_add(overhead);
        if projected > MAX_JSON_PRESENTATION_BYTES.saturating_sub(Self::OMISSION_RESERVE) {
            self.truncated = true;
            self.record_omission(key, units);
            return Ok(false);
        }

        let value = self
            .root
            .entry(key.to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        let Some(array) = value.as_array_mut() else {
            // The pre-check and exclusive `&mut self` make this unreachable,
            // but keep the public boundary panic-free if the implementation is
            // refactored later.
            return Err(BoundedJsonProjectionError::NonArrayKey {
                key: key.to_string(),
            });
        };
        array.push(item);
        self.estimated_bytes = projected;
        Ok(true)
    }

    pub fn finish(mut self) -> serde_json::Value {
        if self.truncated {
            let omitted = self
                .omitted
                .into_iter()
                .map(|(key, (items, units))| {
                    (key, serde_json::json!({ "items": items, "units": units }))
                })
                .collect::<serde_json::Map<_, _>>();
            self.root.insert(
                "presentation_truncated".to_string(),
                serde_json::Value::Bool(true),
            );
            self.root.insert(
                "analysis_incomplete".to_string(),
                serde_json::Value::Bool(true),
            );
            self.root.insert(
                "presentation_omitted".to_string(),
                serde_json::Value::Object(omitted),
            );
        }
        bound_json_value_for_output(serde_json::Value::Object(self.root))
    }

    fn record_omission(&mut self, key: &str, units: usize) {
        let omitted = self.omitted.entry(key.to_string()).or_insert((0, 0));
        omitted.0 = omitted.0.saturating_add(1);
        omitted.1 = omitted.1.saturating_add(units);
    }
}

/// Restore the schema-v5 one-entry-per-file shape after findings have been
/// selected individually under the global output budget. Selection happens
/// first so a large early file cannot starve later critical findings.
pub fn regroup_file_finding_projection(value: &mut serde_json::Value) {
    let Some(files) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("files"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    let original = std::mem::take(files);
    let mut grouped: Vec<serde_json::Value> = Vec::new();
    let mut positions = std::collections::HashMap::<(String, bool), usize>::new();
    for item in original {
        let Some(object) = item.as_object() else {
            grouped.push(item);
            continue;
        };
        let Some(path) = object.get("path").and_then(serde_json::Value::as_str) else {
            grouped.push(item);
            continue;
        };
        let is_config = object
            .get("is_config_file")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let findings = object
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let grouping_path = object
            .get("_projection_file_id")
            .and_then(serde_json::Value::as_u64)
            .map(|id| format!("internal:{id}"))
            .unwrap_or_else(|| path.to_string());
        let key = (grouping_path, is_config);
        if let Some(index) = positions.get(&key).copied() {
            if let Some(existing) = grouped[index]
                .get_mut("findings")
                .and_then(serde_json::Value::as_array_mut)
            {
                existing.extend(findings);
            }
        } else {
            positions.insert(key, grouped.len());
            let mut item = item;
            if let Some(object) = item.as_object_mut() {
                object.remove("_projection_file_id");
            }
            grouped.push(item);
        }
    }
    *files = grouped;
}

fn collect_priority_findings(
    value: &serde_json::Value,
    inherited_path: Option<&str>,
    priority: u8,
    retained: &mut Vec<serde_json::Value>,
    total: &mut usize,
) {
    match value {
        serde_json::Value::Object(object) => {
            let path = object
                .get("path")
                .and_then(serde_json::Value::as_str)
                .or(inherited_path);
            let severity = object.get("severity").and_then(serde_json::Value::as_str);
            let rule_id = object.get("rule_id").and_then(serde_json::Value::as_str);
            let matches_priority = match priority {
                0 => matches!(severity, Some("critical" | "CRITICAL")),
                _ => {
                    !matches!(severity, Some("critical" | "CRITICAL"))
                        && (matches!(severity, Some("high" | "HIGH"))
                            || rule_id == Some("analysis_incomplete"))
                }
            };
            if matches_priority {
                *total = total.saturating_add(1);
                if retained.len() < MAX_PRIORITY_FINDINGS_IN_FALLBACK {
                    retained.push(compact_priority_finding(object, path));
                }
                return;
            }
            for child in object.values() {
                collect_priority_findings(child, path, priority, retained, total);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_priority_findings(child, inherited_path, priority, retained, total);
            }
        }
        _ => {}
    }
}

fn compact_priority_finding(
    finding: &serde_json::Map<String, serde_json::Value>,
    path: Option<&str>,
) -> serde_json::Value {
    let mut compact = serde_json::Map::new();
    if let Some(path) = path {
        compact.insert(
            "path".to_string(),
            serde_json::Value::String(truncated_json_text(path, 512)),
        );
    }
    for (key, cap) in [
        ("rule_id", 64),
        ("severity", 16),
        ("title", 128),
        ("description", 512),
    ] {
        if let Some(text) = finding.get(key).and_then(serde_json::Value::as_str) {
            compact.insert(
                key.to_string(),
                serde_json::Value::String(truncated_json_text(text, cap)),
            );
        }
    }
    serde_json::Value::Object(compact)
}

fn truncated_json_text(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_string();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = value[..end].to_string();
    truncated.push('…');
    truncated
}

fn truncate_output_field(value: &mut String, cap: usize) {
    if value.len() <= cap {
        return;
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push('…');
}

fn truncate_evidence_fields(evidence: &mut Evidence) {
    let truncate = |value: &mut String| truncate_output_field(value, 1024);
    match evidence {
        Evidence::Url { raw } => truncate(raw),
        Evidence::HostComparison {
            raw_host,
            similar_to,
        } => {
            truncate(raw_host);
            truncate(similar_to);
        }
        Evidence::CommandPattern { pattern, matched } => {
            truncate(pattern);
            truncate(matched);
        }
        Evidence::ByteSequence {
            hex, description, ..
        } => {
            truncate(hex);
            truncate(description);
        }
        Evidence::EnvVar {
            name,
            value_preview,
        } => {
            truncate(name);
            truncate(value_preview);
        }
        Evidence::Text { detail } => truncate(detail),
        Evidence::ThreatIntel {
            source,
            threat_type,
            reference,
            ..
        } => {
            truncate(source);
            truncate(threat_type);
            if let Some(reference) = reference {
                truncate(reference);
            }
        }
        Evidence::HomoglyphAnalysis {
            raw,
            escaped,
            suspicious_chars,
        } => {
            truncate(raw);
            truncate(escaped);
            suspicious_chars.truncate(64);
            for suspicious in suspicious_chars {
                truncate(&mut suspicious.codepoint);
                truncate(&mut suspicious.description);
                truncate(&mut suspicious.hex_bytes);
            }
        }
    }
}

fn evidence_text_bytes(evidence: &Evidence) -> usize {
    match evidence {
        Evidence::Url { raw } => raw.len(),
        Evidence::HostComparison {
            raw_host,
            similar_to,
        } => raw_host.len() + similar_to.len(),
        Evidence::CommandPattern { pattern, matched } => pattern.len() + matched.len(),
        Evidence::ByteSequence {
            hex, description, ..
        } => hex.len() + description.len(),
        Evidence::EnvVar {
            name,
            value_preview,
        } => name.len() + value_preview.len(),
        Evidence::Text { detail } => detail.len(),
        Evidence::ThreatIntel {
            source,
            threat_type,
            reference,
            ..
        } => source.len() + threat_type.len() + reference.as_ref().map_or(0, String::len),
        Evidence::HomoglyphAnalysis {
            raw,
            escaped,
            suspicious_chars,
        } => {
            raw.len()
                + escaped.len()
                + suspicious_chars
                    .iter()
                    .map(|item| {
                        item.character.len_utf8()
                            + item.codepoint.len()
                            + item.description.len()
                            + item.hex_bytes.len()
                    })
                    .sum::<usize>()
        }
    }
}

/// Complete analysis verdict.
#[derive(Clone, Deserialize)]
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

#[derive(Debug, Serialize)]
struct VerdictProjection<'a> {
    action: Action,
    findings: &'a [Finding],
    tier_reached: u8,
    bypass_requested: bool,
    bypass_honored: bool,
    bypass_available: bool,
    interactive_detected: bool,
    policy_path_used: Option<&'a str>,
    timings_ms: &'a Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    urls_extracted_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_fallback: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    escalation_reason: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_origin: Option<&'a crate::agent_origin::AgentOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_allowed_match: Option<&'a str>,
}

impl<'a> From<&'a Verdict> for VerdictProjection<'a> {
    fn from(value: &'a Verdict) -> Self {
        Self {
            action: value.action,
            findings: &value.findings,
            tier_reached: value.tier_reached,
            bypass_requested: value.bypass_requested,
            bypass_honored: value.bypass_honored,
            bypass_available: value.bypass_available,
            interactive_detected: value.interactive_detected,
            policy_path_used: value.policy_path_used.as_deref(),
            timings_ms: &value.timings_ms,
            urls_extracted_count: value.urls_extracted_count,
            requires_approval: value.requires_approval,
            approval_timeout_secs: value.approval_timeout_secs,
            approval_fallback: value.approval_fallback.as_deref(),
            approval_rule: value.approval_rule.as_deref(),
            approval_description: value.approval_description.as_deref(),
            escalation_reason: value.escalation_reason.as_deref(),
            agent_origin: value.agent_origin.as_ref(),
            manifest_allowed_match: value.manifest_allowed_match.as_deref(),
        }
    }
}

impl Serialize for Verdict {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let safe = crate::redact::mandatory_redacted_verdict(self);
        VerdictProjection::from(&safe).serialize(serializer)
    }
}

impl fmt::Debug for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe = crate::redact::mandatory_redacted_verdict(self);
        formatter
            .debug_struct("Verdict")
            .field("action", &safe.action)
            .field("findings", &safe.findings)
            .field("tier_reached", &safe.tier_reached)
            .field("bypass_requested", &safe.bypass_requested)
            .field("bypass_honored", &safe.bypass_honored)
            .field("bypass_available", &safe.bypass_available)
            .field("interactive_detected", &safe.interactive_detected)
            .field("policy_path_used", &safe.policy_path_used)
            .field("timings_ms", &safe.timings_ms)
            .field("urls_extracted_count", &safe.urls_extracted_count)
            .field("requires_approval", &safe.requires_approval)
            .field("approval_timeout_secs", &safe.approval_timeout_secs)
            .field("approval_fallback", &safe.approval_fallback)
            .field("approval_rule", &safe.approval_rule)
            .field("approval_description", &safe.approval_description)
            .field("escalation_reason", &safe.escalation_reason)
            .field("agent_origin", &safe.agent_origin)
            .field("manifest_allowed_match", &safe.manifest_allowed_match)
            .finish()
    }
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

    fn assert_secret_free_projection(label: &str, projection: &str, secret: &str) {
        assert!(!projection.contains(secret), "{label}: {projection}");
        assert!(
            !projection.contains(&secret[..18]),
            "{label} retained a stable secret prefix: {projection}"
        );
    }

    #[test]
    fn pdf_text_categorical_evidence_uses_closed_bounded_grammar() {
        let Evidence::Text { detail: fragment } =
            pdf_text_fragment_evidence(3, Some("9:0"), PdfTextEvidenceVisibility::Visible)
        else {
            panic!("PDF fragment provenance must be text evidence");
        };
        assert_eq!(
            fragment,
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:0;visibility=visible"
        );
        assert!(is_internal_categorical_evidence_record(&fragment));

        let Evidence::Text {
            detail: reassembled,
        } = pdf_text_reassembled_evidence(7, PdfTextEvidenceJoin::Spaced, 2)
        else {
            panic!("PDF reassembly provenance must be text evidence");
        };
        assert_eq!(
            reassembled,
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=spaced;fragments=2"
        );
        assert!(is_internal_categorical_evidence_record(&reassembled));
        assert!(is_internal_categorical_evidence_record(
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=concatenated;fragments=256"
        ));
        assert!(is_internal_categorical_evidence_record(
            "tirith:v1:pdf_text;mode=fragment;page=100000;object=unknown;visibility=hidden"
        ));

        let Evidence::Text {
            detail: malformed_object,
        } = pdf_text_fragment_evidence(
            3,
            Some("9:0;payload=PRIVATE_KEY"),
            PdfTextEvidenceVisibility::Unknown,
        )
        else {
            panic!("PDF fragment provenance must be text evidence");
        };
        assert_eq!(
            malformed_object,
            "tirith:v1:pdf_text;mode=fragment;page=3;object=unknown;visibility=unknown"
        );
        assert!(is_internal_categorical_evidence_record(&malformed_object));

        for near_miss in [
            "tirith:v1:pdf_text;mode=fragmented;page=3;object=ref:9:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=03;object=ref:9:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=0;object=ref:9:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=100001;object=ref:9:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:09:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:00;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:0:0;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:65536;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=private_key;visibility=visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:0;visibility=Visible",
            "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:0;visibility=visible;payload=secret",
            "tirith:v1:pdf_text;page=3;mode=fragment;object=ref:9:0;visibility=visible",
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=mixed;fragments=2",
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=spaced;fragments=1",
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=spaced;fragments=02",
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=spaced;fragments=257",
            "tirith:v1:pdf_text;mode=reassembled;page=7;join=spaced;fragments=2;visibility=unknown",
        ] {
            assert!(
                !is_internal_categorical_evidence_record(near_miss),
                "near-miss must use normal evidence redaction: {near_miss}"
            );
        }
    }

    #[test]
    fn pdf_text_categorical_near_miss_does_not_bypass_mandatory_redaction() {
        let secret = format!("0x{}", "11".repeat(32));
        let evidence = Evidence::Text {
            detail: format!(
                "tirith:v1:pdf_text;mode=fragment;page=3;object=ref:9:0;visibility=visible;payload=PRIVATE_KEY={secret}"
            ),
        };
        assert!(!is_internal_categorical_evidence_record(match &evidence {
            Evidence::Text { detail } => detail,
            _ => unreachable!(),
        }));
        assert_secret_free_projection(
            "PDF categorical near-miss",
            &serde_json::to_string(&evidence).unwrap(),
            &secret,
        );
    }

    #[test]
    fn public_evidence_finding_and_verdict_projections_are_mandatorily_secret_safe() {
        let secret = format!("0x{}", "11".repeat(32));
        let evidence = Evidence::Text {
            detail: format!("PRIVATE_KEY={secret}"),
        };
        let finding = Finding {
            rule_id: RuleId::CredentialInText,
            severity: Severity::High,
            title: format!("title PRIVATE_KEY={secret}"),
            description: format!("description PRIVATE_KEY={secret}"),
            evidence: vec![evidence.clone()],
            human_view: Some(format!("human PRIVATE_KEY={secret}")),
            agent_view: Some(format!("agent PRIVATE_KEY={secret}")),
            mitre_id: Some(format!("PRIVATE_KEY={secret}")),
            custom_rule_id: Some(format!("PRIVATE_KEY={secret}")),
        };
        let mut verdict = Verdict::from_findings(vec![finding.clone()], 3, Timings::default());
        verdict.policy_path_used = Some(format!("PRIVATE_KEY={secret}"));
        verdict.approval_description = Some(format!("PRIVATE_KEY={secret}"));
        verdict.escalation_reason = Some(format!("PRIVATE_KEY={secret}"));
        verdict.manifest_allowed_match = Some(format!("PRIVATE_KEY={secret}"));
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::Agent {
            tool: format!("PRIVATE_KEY={secret}"),
            version: Some(format!("PRIVATE_KEY={secret}")),
        });

        for (label, projection) in [
            ("evidence json", serde_json::to_string(&evidence).unwrap()),
            ("evidence debug", format!("{evidence:?}")),
            ("finding json", serde_json::to_string(&finding).unwrap()),
            ("finding debug", format!("{finding:?}")),
            ("verdict json", serde_json::to_string(&verdict).unwrap()),
            ("verdict debug", format!("{verdict:?}")),
        ] {
            assert_secret_free_projection(label, &projection, &secret);
        }

        let raw_wire = format!(r#"{{"type":"text","detail":"PRIVATE_KEY={secret}"}}"#);
        let restored: Evidence = serde_json::from_str(&raw_wire).expect("legacy evidence wire");
        let reserialized = serde_json::to_string(&restored).expect("safe evidence wire");
        assert_secret_free_projection("deserialized evidence", &reserialized, &secret);
        assert!(reserialized.contains(r#""type":"text""#), "{reserialized}");

        let mut raw_finding_wire = serde_json::to_value(&finding).expect("finding wire shape");
        raw_finding_wire["title"] = serde_json::Value::String(format!("PRIVATE_KEY={secret}"));
        raw_finding_wire["evidence"][0]["detail"] =
            serde_json::Value::String(format!("PRIVATE_KEY={secret}"));
        let restored: Finding =
            serde_json::from_value(raw_finding_wire).expect("legacy finding wire");
        assert_secret_free_projection(
            "deserialized finding",
            &serde_json::to_string(&restored).expect("safe finding wire"),
            &secret,
        );

        let mut raw_verdict_wire = serde_json::to_value(&verdict).expect("verdict wire shape");
        raw_verdict_wire["policy_path_used"] =
            serde_json::Value::String(format!("PRIVATE_KEY={secret}"));
        raw_verdict_wire["agent_origin"]["tool"] =
            serde_json::Value::String(format!("PRIVATE_KEY={secret}"));
        let restored: Verdict =
            serde_json::from_value(raw_verdict_wire).expect("legacy verdict wire");
        assert_secret_free_projection(
            "deserialized verdict",
            &serde_json::to_string(&restored).expect("safe verdict wire"),
            &secret,
        );
    }

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
    fn presentation_bounds_preserve_decision_and_compact_json() {
        let mut findings = (0..200)
            .map(|index| Finding {
                rule_id: if index == 190 {
                    RuleId::AnalysisIncomplete
                } else if index == 199 {
                    RuleId::ThreatMaliciousPackage
                } else {
                    RuleId::ConfigSuspiciousIndicator
                },
                severity: if index == 199 {
                    Severity::Critical
                } else if index == 190 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                title: "t".repeat(2_000),
                description: "d".repeat(8_000),
                evidence: (0..40)
                    .map(|_| Evidence::Text {
                        detail: "e".repeat(4_000),
                    })
                    .collect(),
                human_view: Some("h".repeat(2_000)),
                agent_view: Some("a".repeat(2_000)),
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        let action = action_from_findings(&findings);

        bound_findings_for_output(&mut findings);

        assert_eq!(findings.len(), MAX_PRESENTED_FINDINGS);
        assert_eq!(action_from_findings(&findings), action);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete));
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::Critical));
        assert!(findings
            .iter()
            .all(|finding| finding.evidence.len() <= MAX_EVIDENCE_PER_FINDING));
        let bytes = serde_json::to_vec(&findings).unwrap();
        assert!(
            bytes.len() <= 256 * 1024,
            "bounded single-subject JSON was {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn full_first_evidence_list_reserves_an_exact_omission_receipt() {
        let mut findings = vec![Finding {
            rule_id: RuleId::ConfigSuspiciousIndicator,
            severity: Severity::Medium,
            title: "bounded evidence".into(),
            description: "bounded evidence".into(),
            evidence: (0..=MAX_EVIDENCE_PER_FINDING)
                .map(|index| Evidence::Text {
                    detail: format!("evidence-{index}"),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        bound_findings_for_output(&mut findings);

        assert_eq!(findings[0].evidence.len(), MAX_EVIDENCE_PER_FINDING);
        assert!(matches!(
            findings[0].evidence.last(),
            Some(Evidence::Text { detail }) if detail == "omitted_evidence_items=2"
        ));
    }

    #[test]
    fn redaction_precedes_presentation_truncation() {
        let canary = "C02_RAW_SECRET_CANARY_abcdefghijklmnopqrstuvwxyz";
        let mut findings = vec![Finding {
            rule_id: RuleId::CredentialInText,
            severity: Severity::High,
            title: canary.repeat(100),
            description: canary.repeat(100),
            evidence: vec![Evidence::Text {
                detail: canary.repeat(100),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        crate::redact::redact_findings(&mut findings, &[regex::escape(canary)]);
        bound_findings_for_output(&mut findings);

        assert!(!serde_json::to_string(&findings).unwrap().contains(canary));
    }

    #[test]
    fn aggregate_json_cap_preserves_summary_and_priority_findings() {
        let files = (0..1_000)
            .map(|index| {
                serde_json::json!({
                    "path": format!("/project/{index}/{}", "p".repeat(1_000)),
                    "findings": [{
                        "rule_id": if index == 999 { "analysis_incomplete" } else { "config_injection" },
                        "severity": if index == 999 { "high" } else { "medium" },
                        "title": "t".repeat(1_000),
                        "description": "d".repeat(4_000),
                    }],
                })
            })
            .collect::<Vec<_>>();
        let bounded = bound_json_value_for_output(serde_json::json!({
            "scanned_count": 1_000,
            "skipped_count": 7,
            "total_findings": 1_000,
            "analysis_incomplete": false,
            "files": files,
        }));
        let serialized = serde_json::to_vec(&bounded).unwrap();

        assert!(serialized.len() <= MAX_PRESENTATION_BYTES);
        assert_eq!(bounded["presentation_truncated"], true);
        assert_eq!(bounded["summary"]["scanned_count"], 1_000);
        assert_eq!(bounded["summary"]["total_findings"], 1_000);
        assert!(bounded["priority_findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "analysis_incomplete"));
    }

    #[test]
    fn generic_json_fallback_prioritizes_late_critical_over_early_highs() {
        let mut findings = (0..MAX_PRIORITY_FINDINGS_IN_FALLBACK)
            .map(|index| {
                serde_json::json!({
                    "rule_id": format!("high_{index}"),
                    "severity": "high",
                    "description": "h".repeat(16_000),
                })
            })
            .collect::<Vec<_>>();
        findings.push(serde_json::json!({
            "rule_id": "late_critical",
            "severity": "critical",
            "description": "critical",
        }));
        let bounded = bound_json_value_for_output(serde_json::json!({
            "total_findings": findings.len(),
            "findings": findings,
        }));
        assert_eq!(bounded["priority_findings"][0]["rule_id"], "late_critical");
    }

    #[test]
    fn text_cap_reports_exact_omitted_bytes_without_splitting_utf8() {
        let input = "界".repeat(MAX_PRESENTATION_BYTES);
        let original_bytes = input.len();
        let bounded = bound_text_for_output(input);

        assert!(bounded.len() <= MAX_PRESENTATION_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.contains(&format!("original_bytes={original_bytes}")));
        let retained_bytes = bounded
            .find("\n[presentation truncated:")
            .expect("omission marker");
        assert!(bounded.contains(&format!(
            "omitted_bytes={}",
            original_bytes - retained_bytes
        )));
    }

    #[test]
    fn incremental_text_builder_caps_without_retaining_later_chunks() {
        let first = "界".repeat(MAX_PRESENTATION_BYTES / 3);
        let later = "z".repeat(MAX_PRESENTATION_BYTES * 2);
        let source_bytes = first.len() + later.len();
        let mut builder = BoundedTextBuilder::new();
        builder.push_str(&first);
        builder.push_str(&later);
        let output = builder.finish();

        assert!(output.len() <= MAX_PRESENTATION_BYTES);
        assert!(output.is_char_boundary(output.len()));
        let marker_start = output.find("\n[presentation truncated:").unwrap();
        assert!(output.contains(&format!("omitted_bytes={}", source_bytes - marker_start)));
    }

    #[test]
    fn incremental_json_projection_reports_exact_omitted_items_and_units() {
        let mut projection = BoundedJsonProjection::new(serde_json::json!({
            "total_findings": 2_000,
            "files": [],
        }));
        for index in 0..1_000 {
            projection
                .push_array_item(
                    "files",
                    serde_json::json!({
                        "path": format!("/project/{index}"),
                        "findings": [{ "description": "d".repeat(2_000) }],
                    }),
                    2,
                )
                .expect("test projection schema keeps files as an array");
        }
        let output = projection.finish();
        let retained = output["files"].as_array().unwrap().len();
        let omitted_items = output["presentation_omitted"]["files"]["items"]
            .as_u64()
            .unwrap() as usize;
        let omitted_units = output["presentation_omitted"]["files"]["units"]
            .as_u64()
            .unwrap() as usize;

        assert!(serialized_json_pretty_size(&output).unwrap() <= MAX_JSON_PRESENTATION_BYTES);
        assert_eq!(retained + omitted_items, 1_000);
        assert_eq!(omitted_units, omitted_items * 2);
        assert_eq!(output["total_findings"], 2_000);
        assert_eq!(output["presentation_truncated"], true);
    }

    #[test]
    fn incremental_json_projection_skips_oversized_low_and_keeps_later_critical() {
        let mut projection = BoundedJsonProjection::new(serde_json::json!({
            "total_findings": 2,
            "files": [],
        }));
        projection
            .push_array_item(
                "files",
                serde_json::json!({
                    "path": "low",
                    "findings": [{
                        "severity": "low",
                        "description": "x".repeat(MAX_JSON_PRESENTATION_BYTES),
                    }],
                }),
                1,
            )
            .expect("test projection schema keeps files as an array");
        projection
            .push_array_item(
                "files",
                serde_json::json!({
                    "path": "critical",
                    "findings": [{
                        "severity": "critical",
                        "rule_id": "bidi_controls",
                        "description": "retained",
                    }],
                }),
                1,
            )
            .expect("test projection schema keeps files as an array");
        let output = projection.finish();
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(serialized.contains("bidi_controls"));
        assert!(!serialized.contains(&"x".repeat(1024)));
        assert_eq!(output["presentation_omitted"]["files"]["items"], 1);
    }

    #[test]
    fn incremental_json_projection_returns_typed_error_for_non_array_key() {
        let mut projection = BoundedJsonProjection::new(serde_json::json!({
            "files": "not-an-array",
        }));

        let error = projection
            .push_array_item("files", serde_json::json!({ "path": "x" }), 1)
            .expect_err("public input must not panic for a non-array key");

        assert_eq!(
            error,
            BoundedJsonProjectionError::NonArrayKey {
                key: "files".to_string(),
            }
        );
        assert_eq!(projection.finish()["files"], "not-an-array");
    }

    #[test]
    fn directory_projection_regroups_selected_findings_by_file_schema_v5() {
        let mut projection = BoundedJsonProjection::new(serde_json::json!({
            "schema_version": 5,
            "files": [],
        }));
        for rule_id in ["critical_one", "high_two"] {
            projection
                .push_array_item(
                    "files",
                    serde_json::json!({
                        "path": "/project/CLAUDE.md",
                        "is_config_file": true,
                        "findings": [{ "rule_id": rule_id, "severity": "high" }],
                    }),
                    1,
                )
                .expect("test projection schema keeps files as an array");
        }
        let mut output = projection.finish();
        regroup_file_finding_projection(&mut output);
        assert_eq!(output["schema_version"], 5);
        assert_eq!(output["files"].as_array().unwrap().len(), 1);
        assert_eq!(output["files"][0]["findings"].as_array().unwrap().len(), 2);
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
