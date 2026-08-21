//! The single npm-family command grammar.
//!
//! Every consumer that needs to know "which npm-family launcher is this, what
//! is it doing, and which packages does it name" goes through this module.
//! Before C13 the grammar existed four times over with four different coverage
//! sets, and a form one copy missed was a form that reached a user unanalyzed:
//! the threat-intelligence extractor knew `install|i|add` and `npx` but not
//! `npm exec|x`, `pnpm exec|dlx`, `yarn dlx`, `bun x`, `bunx` or `pnpx`; the
//! repository-hook scanner knew the exec family only as an opaque string set
//! with no package identity; the Web3 runner grammar was the most complete but
//! was private and tool-specific.
//!
//! This module owns the LEXICAL layer only: launcher identity (including
//! platform executable suffixes), the subcommand/alias tables, the
//! value-taking option tables, the runner-option-versus-child boundary, and
//! package-spec parsing. Resolution semantics (which binary a project-local
//! `node_modules/.bin` entry actually is, whether a config layer is trusted,
//! whether an argument is statically bound) stay with their owners; this
//! module deliberately answers no question that needs the filesystem or a
//! policy.

use crate::rules::threatintel::PackageRef;
use crate::threatdb::Ecosystem;
use crate::tokenize::{Segment, ShellType};
use crate::version_intent::VersionIntent;

/// Hard cap on the explicit packages one invocation contributes.
///
/// This is a memory bound, NOT a detection window. Set low it becomes an
/// evasion primitive: padding a line with filler names until the real operand
/// falls off the end costs an attacker nothing, and the cap is per invocation
/// so it never bounded total work anyway (`npm i a...; npm i b...` doubles it).
/// It is therefore set far above any command a human writes, and every security
/// consumer MUST surface [`NpmInvocation::truncated`] rather than reporting a
/// truncated assessment as a complete one.
pub const MAX_PACKAGES_PER_INVOCATION: usize = 256;

/// How many leading positionals may precede the real subcommand.
///
/// The first positional is not always the subcommand. yarn spells several
/// installs behind a prefix word (`yarn global add`, `yarn workspace <name>
/// add`, `yarn workspaces foreach add`), and ANY manager can be handed a
/// value-carrying global option this grammar does not know, which shifts the
/// subcommand one token to the right. Pre-C13 the threat-intelligence extractor
/// scanned every argument for an install verb and caught all of these, so
/// stopping at the first positional would narrow coverage; this bound restores
/// them without walking an unbounded command line.
const MAX_SUBCOMMAND_PREFIX_WORDS: usize = 3;

/// The package manager behind a launcher word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpmManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

/// A launcher word, after wrapper resolution and executable-suffix stripping.
/// `npx`, `pnpx` and `bunx` are separate variants rather than
/// `(manager, subcommand)` pairs because they carry their operation in the
/// launcher itself and take no subcommand token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpmLauncher {
    Npm,
    Npx,
    Pnpm,
    Pnpx,
    Yarn,
    Bun,
    Bunx,
}

impl NpmLauncher {
    /// Resolve a normalized launcher basename. The caller must already have
    /// stripped wrappers, the directory prefix and any executable suffix; use
    /// [`launcher_basename`] for that.
    pub fn from_basename(name: &str) -> Option<Self> {
        Some(match name {
            "npm" => NpmLauncher::Npm,
            "npx" => NpmLauncher::Npx,
            "pnpm" => NpmLauncher::Pnpm,
            "pnpx" => NpmLauncher::Pnpx,
            "yarn" => NpmLauncher::Yarn,
            "bun" => NpmLauncher::Bun,
            "bunx" => NpmLauncher::Bunx,
            _ => return None,
        })
    }

    pub fn manager(self) -> NpmManager {
        match self {
            NpmLauncher::Npm | NpmLauncher::Npx => NpmManager::Npm,
            NpmLauncher::Pnpm | NpmLauncher::Pnpx => NpmManager::Pnpm,
            NpmLauncher::Yarn => NpmManager::Yarn,
            NpmLauncher::Bun | NpmLauncher::Bunx => NpmManager::Bun,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NpmLauncher::Npm => "npm",
            NpmLauncher::Npx => "npx",
            NpmLauncher::Pnpm => "pnpm",
            NpmLauncher::Pnpx => "pnpx",
            NpmLauncher::Yarn => "yarn",
            NpmLauncher::Bun => "bun",
            NpmLauncher::Bunx => "bunx",
        }
    }

    /// Launchers that carry their operation in the launcher word. They take no
    /// subcommand, so option parsing starts at the first argument.
    fn implicit_operation(self) -> Option<NpmOperation> {
        match self {
            // `npx`, `pnpx` and `bunx` all fetch a package on demand and run
            // its entrypoint. `pnpx` is pnpm's deprecated spelling of
            // `pnpm dlx`; it behaves identically here.
            NpmLauncher::Npx | NpmLauncher::Pnpx | NpmLauncher::Bunx => Some(NpmOperation::Exec),
            _ => None,
        }
    }
}

/// What the invocation does. The distinction that matters for security is
/// whether a package name on the command line becomes bytes fetched from a
/// registry, so a locally-resolved exec is a separate variant from a
/// fetch-and-run exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpmOperation {
    /// Adds packages to the project: `npm install|i|add`, `pnpm add|install|i`,
    /// `yarn add|install`, `bun add|install|i`.
    Install,
    /// Fetches a package on demand and runs its entrypoint: `npx`, `pnpx`,
    /// `bunx`, `npm exec|x`, `pnpm dlx`, `yarn dlx`, `bun x`.
    Exec,
    /// Runs an already-installed local binary: `pnpm exec`, `yarn exec`,
    /// `bun exec`. No package identity is named, so none is inferred.
    LocalExec,
    /// Runs a `package.json` script. The target is manifest indirection, never
    /// a package name, and this grammar does not read `package.json`.
    RunScript,
    /// A recognized launcher doing something this grammar does not model.
    Other,
}

/// The child command a runner hands control to, plus every token after it.
/// Once the entrypoint is located, its arguments belong to the child and are
/// never reconsidered as runner options or package specs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmChild {
    pub command: String,
    pub args: Vec<String>,
}

/// One parsed npm-family invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmInvocation {
    pub launcher: NpmLauncher,
    pub operation: NpmOperation,
    /// The subcommand token that selected the operation, when one was written.
    /// `None` for `npx`/`pnpx`/`bunx`, which carry the operation in the
    /// launcher.
    pub subcommand: Option<String>,
    /// Every package the command names, in written order, de-duplicated and
    /// bounded by [`MAX_PACKAGES_PER_INVOCATION`].
    pub explicit_packages: Vec<PackageRef>,
    pub child: Option<NpmChild>,
    /// True when the package list was cut at the cap. The list is still a
    /// deterministic prefix; the flag exists so a consumer can say the
    /// assessment is partial instead of pretending it is complete.
    pub truncated: bool,
}

impl NpmInvocation {
    pub fn manager(&self) -> NpmManager {
        self.launcher.manager()
    }

    /// Whether this invocation fetches a package from a registry and executes
    /// it in one step. `pnpm exec` and `yarn exec` run something already on
    /// disk and are deliberately excluded.
    pub fn fetches_remote_package(&self) -> bool {
        self.operation == NpmOperation::Exec
    }

    /// A stable human label for the runner: the launcher word, plus the
    /// subcommand when one was written (`npx`, `npm exec`, `pnpm dlx`).
    pub fn runner_label(&self) -> String {
        match &self.subcommand {
            Some(sub) => format!("{} {}", self.launcher.as_str(), sub),
            None => self.launcher.as_str().to_string(),
        }
    }
}

/// Return a normalized package-manager launcher name. Both path separators are
/// accepted deliberately: commands can arrive from copied cross-platform
/// snippets, and PowerShell accepts `/` as well as `\` in executable paths.
/// Windows launcher suffixes are stripped only at the final path component.
pub(crate) fn launcher_basename(command: &str, shell: ShellType) -> String {
    let normalized = crate::rules::command::normalize_shell_token(command.trim(), shell);
    let basename = normalized
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(normalized.as_str())
        .to_ascii_lowercase();

    for suffix in [".exe", ".cmd", ".bat", ".com", ".ps1"] {
        if let Some(stem) = basename.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    basename
}

/// Whether a normalized command word is an npm-family launcher. Used by the
/// Web3 runner grammar to detect a runner nested inside another runner.
pub fn is_package_runner_name(value: &str) -> bool {
    NpmLauncher::from_basename(value).is_some()
}

/// Parse one tokenized shell segment. Resolves `sudo` / `env -S` / `command` /
/// absolute-path wrappers through the same resolver the URL and command rules
/// use, then normalizes every argument for the selected shell.
pub fn parse_segment(segment: &Segment, shell: ShellType) -> Option<NpmInvocation> {
    let (command, args) = crate::extract::resolve_wrapped_command_for_shell(segment, shell)?;
    let launcher = NpmLauncher::from_basename(&launcher_basename(&command, shell))?;
    let args: Vec<String> = args
        .iter()
        .map(|arg| crate::rules::command::normalize_shell_token(arg, shell))
        .collect();
    Some(parse_resolved(launcher, &args))
}

/// Parse every npm-family invocation in a raw command line, including the
/// bodies of statically visible executable substitutions.
pub fn parse_input(input: &str, shell: ShellType) -> Vec<NpmInvocation> {
    let mut out = Vec::new();
    let execution_view = crate::extract::shell_execution_view(input, shell);
    for segment in crate::tokenize::tokenize(execution_view.as_ref(), shell) {
        if let Some(invocation) = parse_segment(&segment, shell) {
            out.push(invocation);
        }
    }
    out
}

/// Parse an invocation whose launcher and arguments are already resolved and
/// normalized. This is the seam repository-hook scanning uses, because it has
/// already run its own wrapper resolution and must not run a second one.
pub fn parse_resolved(launcher: NpmLauncher, args: &[String]) -> NpmInvocation {
    let mut invocation = NpmInvocation {
        launcher,
        operation: NpmOperation::Other,
        subcommand: None,
        explicit_packages: Vec::new(),
        child: None,
        truncated: false,
    };

    let body_start = match launcher.implicit_operation() {
        Some(operation) => {
            invocation.operation = operation;
            0
        }
        None => {
            let Some((index, subcommand, operation)) = resolve_subcommand(launcher, args) else {
                return invocation;
            };
            invocation.operation = operation;
            invocation.subcommand = Some(subcommand);
            index + 1
        }
    };

    match invocation.operation {
        NpmOperation::Install => parse_install_body(args, body_start, &mut invocation),
        NpmOperation::Exec => parse_exec_body(launcher, args, body_start, &mut invocation),
        NpmOperation::LocalExec | NpmOperation::RunScript => {
            if let Some(index) = first_positional_index(launcher, args, body_start) {
                invocation.child = Some(NpmChild {
                    command: args[index].clone(),
                    args: args[index + 1..].to_vec(),
                });
            }
        }
        NpmOperation::Other => {}
    }

    invocation
}

/// Locate the token that selects the operation, plus the operation it selects.
///
/// Returns the first positional whose word maps to a modelled operation, so a
/// prefix word or an unmodelled value-taking global option cannot hide an
/// install behind it. Falls back to the first positional when nothing within
/// [`MAX_SUBCOMMAND_PREFIX_WORDS`] resolves, so an unmodelled invocation still
/// reports the subcommand it was written with.
fn resolve_subcommand(
    launcher: NpmLauncher,
    args: &[String],
) -> Option<(usize, String, NpmOperation)> {
    let mut cursor = 0;
    let mut first: Option<(usize, String)> = None;
    for _ in 0..=MAX_SUBCOMMAND_PREFIX_WORDS {
        let Some(index) = first_positional_index(launcher, args, cursor) else {
            break;
        };
        let word = args[index].to_ascii_lowercase();
        let operation = operation_for(launcher, &word);
        if operation != NpmOperation::Other {
            return Some((index, word, operation));
        }
        if first.is_none() {
            first = Some((index, word));
        }
        cursor = index + 1;
    }
    first.map(|(index, word)| (index, word, NpmOperation::Other))
}

/// Map a launcher plus its subcommand token to an operation. Subcommand
/// spellings are kept in one table so no consumer has to guess that `bun x` is
/// `npm exec` and `pnpm exec` is not.
fn operation_for(launcher: NpmLauncher, subcommand: &str) -> NpmOperation {
    match (launcher, subcommand) {
        // `ci` / `clean-install` install the whole lockfile and name no
        // package, but they are still installs. The historical misspelling
        // aliases install exactly as `install` does, so omitting them would let
        // one extra keystroke (`npm isntall evil`) buy an unanalyzed install.
        // The list is the one `crate::repo_hooks` already treats as an install
        // for lifecycle-script purposes; the two tables must not disagree about
        // what an install is. The `*-test` family installs first and then runs
        // `npm test`, so it belongs here too.
        (
            NpmLauncher::Npm,
            "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt" | "isnta"
            | "isntal" | "isntall" | "add" | "ci" | "clean-install" | "ic" | "install-clean"
            | "isntall-clean" | "install-test" | "it" | "install-ci-test" | "cit"
            | "clean-install-test" | "sit",
        ) => NpmOperation::Install,
        (NpmLauncher::Npm, "exec" | "x") => NpmOperation::Exec,
        (NpmLauncher::Npm, "run" | "run-script") => NpmOperation::RunScript,

        (NpmLauncher::Pnpm, "add" | "install" | "i") => NpmOperation::Install,
        (NpmLauncher::Pnpm, "dlx") => NpmOperation::Exec,
        // `pnpm exec` runs a binary already present in the project's
        // `node_modules/.bin`; it never fetches, so its first positional is not
        // a package name.
        (NpmLauncher::Pnpm, "exec") => NpmOperation::LocalExec,
        (NpmLauncher::Pnpm, "run" | "run-script") => NpmOperation::RunScript,

        (NpmLauncher::Yarn, "add" | "install") => NpmOperation::Install,
        (NpmLauncher::Yarn, "dlx") => NpmOperation::Exec,
        (NpmLauncher::Yarn, "exec") => NpmOperation::LocalExec,
        (NpmLauncher::Yarn, "run" | "run-script") => NpmOperation::RunScript,

        (NpmLauncher::Bun, "add" | "install" | "i") => NpmOperation::Install,
        (NpmLauncher::Bun, "x") => NpmOperation::Exec,
        (NpmLauncher::Bun, "exec") => NpmOperation::LocalExec,
        (NpmLauncher::Bun, "run") => NpmOperation::RunScript,

        _ => NpmOperation::Other,
    }
}

/// Flags for npm/yarn/pnpm installs that consume the next argument.
const NPM_ARG_FLAGS: &[&str] = &[
    "--registry",
    "--tag",
    "--scope",
    "--otp",
    "--workspace",
    "-w",
    "--prefix",
];

fn parse_install_body(args: &[String], start: usize, invocation: &mut NpmInvocation) {
    let mut index = start;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg.starts_with('-') {
            if NPM_ARG_FLAGS.contains(&arg.to_lowercase().as_str()) {
                index += 1;
            }
            index += 1;
            continue;
        }
        // Registry identity only exists for a registry spec. A URL, a relative
        // path or an absolute path selects bytes that never pass through a
        // package name.
        if arg.contains("://") || arg.starts_with('.') || arg.starts_with('/') {
            index += 1;
            continue;
        }
        if let Some(package) = parse_npm_package_spec(arg) {
            push_package(invocation, package);
        }
        index += 1;
    }
}

/// Parse the body of a fetch-and-run invocation.
///
/// The runner boundary is the load-bearing part. Options belong to the runner
/// only until the first positional or an explicit `--`; from there every token
/// is the child's. `npx --package foo bar --package baz` therefore names one
/// package (`foo`), runs `bar`, and hands the second `--package baz` to `bar`.
fn parse_exec_body(
    launcher: NpmLauncher,
    args: &[String],
    start: usize,
    invocation: &mut NpmInvocation,
) {
    let mut has_explicit_package = false;
    let mut options_enabled = true;
    let mut entrypoint = None;
    let mut index = start;

    while index < args.len() {
        let arg = args[index].as_str();

        if options_enabled && arg == "--" {
            options_enabled = false;
            index += 1;
            continue;
        }

        if options_enabled {
            if let Some(spec) = attached_package_spec(launcher, arg) {
                if let Some(package) = parse_runner_package_spec(spec) {
                    push_package(invocation, package);
                    has_explicit_package = true;
                }
                index += 1;
                continue;
            }

            if is_split_package_option(launcher, arg) {
                if let Some(spec) = args.get(index + 1).map(String::as_str) {
                    if let Some(package) = parse_runner_package_spec(spec) {
                        push_package(invocation, package);
                        has_explicit_package = true;
                    }
                }
                index += 2;
                continue;
            }

            if split_option_takes_value(launcher, arg)
                || split_option_takes_conditional_value(
                    arg,
                    args.get(index + 1).map(String::as_str),
                )
            {
                // `--call`, workspace, shell, directory and legacy runner
                // options carry command/config values, never package identity.
                index += 2;
                continue;
            }

            if has_attached_non_package_value(arg) || arg.starts_with('-') {
                index += 1;
                continue;
            }
        }

        entrypoint = Some(index);
        break;
    }

    if let Some(index) = entrypoint {
        // Without an explicit `--package`, the entrypoint word IS the package
        // spec; with one, it is only the binary to run inside the packages
        // already named.
        if !has_explicit_package {
            if let Some(package) = parse_runner_package_spec(args[index].as_str()) {
                push_package(invocation, package);
            }
        }
        invocation.child = Some(NpmChild {
            command: args[index].clone(),
            args: args[index + 1..].to_vec(),
        });
    }
}

/// Index of the first token that is not a runner option or an option value,
/// starting at `from`.
fn first_positional_index(launcher: NpmLauncher, args: &[String], from: usize) -> Option<usize> {
    let mut index = from;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            return (index + 1 < args.len()).then_some(index + 1);
        }
        if !arg.starts_with('-') {
            return Some(index);
        }
        if split_option_takes_value(launcher, arg)
            || split_option_takes_conditional_value(arg, args.get(index + 1).map(String::as_str))
            || is_split_package_option(launcher, arg)
        {
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

/// Explicit package forms accepted with the value attached. `-p` is npx's
/// package shorthand; under `npm exec` the same short option means
/// `--parseable`, so it is deliberately not read as a package there.
fn attached_package_spec(launcher: NpmLauncher, arg: &str) -> Option<&str> {
    if launcher_accepts_package_option(launcher) {
        if let Some(spec) = arg.strip_prefix("--package=") {
            return Some(spec);
        }
    }
    if launcher != NpmLauncher::Npx {
        return None;
    }
    let spec = arg.strip_prefix("-p")?;
    if spec.is_empty() {
        return None;
    }
    Some(spec.strip_prefix('=').unwrap_or(spec))
}

fn is_split_package_option(launcher: NpmLauncher, arg: &str) -> bool {
    (launcher_accepts_package_option(launcher) && arg == "--package")
        || (launcher == NpmLauncher::Npx && arg == "-p")
}

/// Launchers whose fetch-and-run mode accepts `--package`. `bunx` and `bun x`
/// have no such option: their first positional is always the package.
fn launcher_accepts_package_option(launcher: NpmLauncher) -> bool {
    matches!(
        launcher,
        NpmLauncher::Npm
            | NpmLauncher::Npx
            | NpmLauncher::Pnpm
            | NpmLauncher::Pnpx
            | NpmLauncher::Yarn
    )
}

/// npm allows any config key before a runner positional. Keep the value-taking
/// keys in one explicit table so their following values cannot be mistaken for
/// the package/entrypoint. Boolean-only keys are intentionally absent: their
/// next token remains the inferred package. Array-valued keys consume one token
/// per occurrence, matching npm's argv parser.
const NPM_VALUE_LONG_OPTIONS: &[&str] = &[
    "--_auth",
    "--access",
    "--also",
    "--audit-level",
    "--auth-type",
    "--before",
    "--browser",
    "--ca",
    "--cache",
    "--cache-max",
    "--cache-min",
    "--cafile",
    "--call",
    "--cert",
    "--cidr",
    "--cpu",
    "--depth",
    "--diff",
    "--diff-dst-prefix",
    "--diff-src-prefix",
    "--diff-unified",
    "--editor",
    "--expect-result-count",
    "--fetch-retries",
    "--fetch-retry-factor",
    "--fetch-retry-maxtimeout",
    "--fetch-retry-mintimeout",
    "--fetch-timeout",
    "--git",
    "--globalconfig",
    "--heading",
    "--https-proxy",
    "--include",
    "--init-author-email",
    "--init-author-name",
    "--init-author-url",
    "--init-license",
    "--init-module",
    "--init-version",
    "--init.author.email",
    "--init.author.name",
    "--init.author.url",
    "--init.license",
    "--init.module",
    "--init.version",
    "--install-strategy",
    "--key",
    "--libc",
    "--local-address",
    "--location",
    "--lockfile-version",
    "--loglevel",
    "--logs-dir",
    "--logs-max",
    "--maxsockets",
    "--message",
    "--node-arg",
    "--node-options",
    "--noproxy",
    "--npm",
    "--omit",
    "--only",
    "--os",
    "--otp",
    "--pack-destination",
    "--prefix",
    "--preid",
    "--provenance-file",
    "--proxy",
    "--registry",
    "--replace-registry-host",
    "--save-prefix",
    "--sbom-format",
    "--sbom-type",
    "--scope",
    "--script-shell",
    "--searchexclude",
    "--searchlimit",
    "--searchopts",
    "--searchstaleness",
    "--shell",
    "--tag",
    "--tag-version-prefix",
    "--umask",
    "--user-agent",
    "--userconfig",
    "--viewer",
    "--which",
    "--workspace",
];

/// Value-taking options the non-npm managers add on top of the npm config
/// vocabulary. Without these, `pnpm dlx --dir /tmp pkg` would read `/tmp` as
/// the package and never assess `pkg`.
const PNPM_VALUE_LONG_OPTIONS: &[&str] = &[
    "--dir",
    "--filter",
    "--filter-prod",
    "--config",
    "--store-dir",
    "--virtual-store-dir",
    "--reporter",
    "--use-node-version",
    "--package",
    "--allow-build",
    "--resolution-mode",
    "--workspace-concurrency",
];

/// yarn's own value-taking globals. `--network-timeout` and `--cache-folder`
/// are ordinary CI idioms, and an unlisted value-taking option would otherwise
/// push its value into the subcommand slot.
const YARN_VALUE_LONG_OPTIONS: &[&str] = &[
    "--cwd",
    "--package",
    "--registry",
    "--modules-folder",
    "--cache-folder",
    "--preferred-cache-folder",
    "--global-folder",
    "--link-folder",
    "--mutex",
    "--network-timeout",
    "--network-concurrency",
    "--use-yarnrc",
];

const BUN_VALUE_LONG_OPTIONS: &[&str] = &[
    "--cwd",
    "--filter",
    "--config",
    "--backend",
    "--conditions",
    "--tsconfig-override",
];

const SHORT_VALUE_OPTIONS: &[&str] = &["-c", "-w", "-n", "-C", "-L", "-m"];

fn split_option_takes_value(launcher: NpmLauncher, arg: &str) -> bool {
    if NPM_VALUE_LONG_OPTIONS.contains(&arg) || SHORT_VALUE_OPTIONS.contains(&arg) {
        return true;
    }
    match launcher.manager() {
        NpmManager::Npm => false,
        NpmManager::Pnpm => PNPM_VALUE_LONG_OPTIONS.contains(&arg),
        NpmManager::Yarn => YARN_VALUE_LONG_OPTIONS.contains(&arg),
        NpmManager::Bun => BUN_VALUE_LONG_OPTIONS.contains(&arg),
    }
}

/// npm's `color` config is a Boolean with one extra enum value. Its following
/// token is consumed only when it is a Boolean spelling or `always`; an
/// arbitrary token remains the runner's entrypoint/package. Treating every
/// following token as the option value would hide `npx --color malicious-package`.
fn split_option_takes_conditional_value(arg: &str, next: Option<&str>) -> bool {
    arg == "--color"
        && next.is_some_and(|value| {
            value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("always")
        })
}

fn has_attached_non_package_value(arg: &str) -> bool {
    if arg.starts_with("--") && arg.contains('=') {
        return true;
    }

    SHORT_VALUE_OPTIONS
        .iter()
        .any(|prefix| arg.starts_with(prefix) && arg.len() > prefix.len())
}

fn parse_runner_package_spec(spec: &str) -> Option<PackageRef> {
    if spec.is_empty() || spec.starts_with('-') {
        return None;
    }
    parse_npm_package_spec(spec)
}

/// Parse an npm-style package spec: `@scope/name@version` or `name@version`.
pub fn parse_npm_package_spec(spec: &str) -> Option<PackageRef> {
    // npm accepts the protocol form as the whole spec (`npm:lodash@4.17.21`),
    // not only as the version half of an alias (`safe@npm:lodash@4.17.21`).
    // Strip it before splitting the declared name; otherwise the parser would
    // assess the fictitious package `npm:lodash` and miss `lodash` entirely.
    if let Some(target_spec) = spec.strip_prefix("npm:") {
        let (target_name, target_version) =
            crate::ecosystem_scan::split_npm_name_version(target_spec)?;
        return Some(PackageRef {
            ecosystem: Ecosystem::Npm,
            name: target_name.to_string(),
            alias: None,
            version: target_version
                .map(crate::ecosystem_scan::npm_manifest_intent)
                .unwrap_or(VersionIntent::Unspecified),
        });
    }

    let (declared_name, declared_version) = crate::ecosystem_scan::split_npm_name_version(spec)?;
    let (name, version, alias) = match declared_version.and_then(|v| v.strip_prefix("npm:")) {
        Some(target_spec) => {
            let (target_name, target_version) =
                crate::ecosystem_scan::split_npm_name_version(target_spec)?;
            (target_name, target_version, Some(declared_name.to_string()))
        }
        None => (declared_name, declared_version, None),
    };

    Some(PackageRef {
        ecosystem: Ecosystem::Npm,
        name: name.to_string(),
        alias,
        // npm treats a bare PARTIAL version as an X-range (`lodash@4` == `4.x`), so
        // classify the CLI spec the same way the manifest path does instead of a bogus
        // `Exact("4")` that would miss a threat record for the resolved `4.17.21`.
        version: match version {
            Some(v) => crate::ecosystem_scan::npm_manifest_intent(v),
            None => VersionIntent::Unspecified,
        },
    })
}

/// Append a package, preserving written order, skipping an exact repeat, and
/// stopping at the cap with an explicit truncation flag.
fn push_package(invocation: &mut NpmInvocation, package: PackageRef) {
    if invocation.explicit_packages.contains(&package) {
        return;
    }
    if invocation.explicit_packages.len() >= MAX_PACKAGES_PER_INVOCATION {
        invocation.truncated = true;
        return;
    }
    invocation.explicit_packages.push(package);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Vec<NpmInvocation> {
        parse_input(input, ShellType::Posix)
    }

    fn one(input: &str) -> NpmInvocation {
        let mut invocations = parse(input);
        assert_eq!(
            invocations.len(),
            1,
            "expected one invocation for {input:?}"
        );
        invocations.remove(0)
    }

    fn names(input: &str) -> Vec<String> {
        one(input)
            .explicit_packages
            .into_iter()
            .map(|package| package.name)
            .collect()
    }

    #[test]
    fn install_forms_across_every_manager() {
        for command in [
            "npm install left-pad",
            "npm i left-pad",
            "npm add left-pad",
            "pnpm add left-pad",
            "pnpm install left-pad",
            "pnpm i left-pad",
            "yarn add left-pad",
            "bun add left-pad",
            "bun install left-pad",
            "bun i left-pad",
        ] {
            let invocation = one(command);
            assert_eq!(
                invocation.operation,
                NpmOperation::Install,
                "operation for {command:?}"
            );
            assert_eq!(names(command), vec!["left-pad"], "packages for {command:?}");
        }
    }

    #[test]
    fn exec_forms_across_every_manager() {
        for command in [
            "npx some-tool",
            "npm exec some-tool",
            "npm x some-tool",
            "pnpm dlx some-tool",
            "pnpx some-tool",
            "yarn dlx some-tool",
            "bun x some-tool",
            "bunx some-tool",
        ] {
            let invocation = one(command);
            assert_eq!(
                invocation.operation,
                NpmOperation::Exec,
                "operation for {command:?}"
            );
            assert!(
                invocation.fetches_remote_package(),
                "{command:?} fetches a remote package"
            );
            assert_eq!(
                names(command),
                vec!["some-tool"],
                "packages for {command:?}"
            );
            assert_eq!(
                invocation
                    .child
                    .as_ref()
                    .map(|child| child.command.as_str()),
                Some("some-tool"),
                "child for {command:?}"
            );
        }
    }

    #[test]
    fn local_exec_names_no_package() {
        for command in [
            "pnpm exec some-tool",
            "yarn exec some-tool",
            "bun exec some-tool",
        ] {
            let invocation = one(command);
            assert_eq!(
                invocation.operation,
                NpmOperation::LocalExec,
                "operation for {command:?}"
            );
            assert!(
                !invocation.fetches_remote_package(),
                "{command:?} must not be a fetch-and-run"
            );
            assert!(
                invocation.explicit_packages.is_empty(),
                "{command:?} names no package"
            );
        }
    }

    #[test]
    fn run_script_is_manifest_indirection_not_a_package() {
        for command in [
            "npm run build",
            "npm run-script build",
            "pnpm run build",
            "yarn run build",
            "bun run build",
        ] {
            let invocation = one(command);
            assert_eq!(
                invocation.operation,
                NpmOperation::RunScript,
                "operation for {command:?}"
            );
            assert!(
                invocation.explicit_packages.is_empty(),
                "{command:?} names no package"
            );
        }
    }

    #[test]
    fn wrappers_and_executable_suffixes_resolve_to_the_same_grammar() {
        for command in [
            "sudo npm install left-pad",
            "sudo -u root npm install left-pad",
            "env NODE_ENV=production npm install left-pad",
            "env -S NODE_ENV=production npm install left-pad",
            "command npm install left-pad",
            "/usr/local/bin/npm install left-pad",
            "npm.cmd install left-pad",
            "npm.exe install left-pad",
            "npm.ps1 install left-pad",
        ] {
            assert_eq!(names(command), vec!["left-pad"], "packages for {command:?}");
        }
    }

    #[test]
    fn every_shell_sees_the_same_packages() {
        for shell in [ShellType::Posix, ShellType::Fish, ShellType::PowerShell] {
            let invocations = parse_input("npx some-tool", shell);
            assert_eq!(invocations.len(), 1, "one invocation under {shell:?}");
            assert_eq!(
                invocations[0]
                    .explicit_packages
                    .iter()
                    .map(|package| package.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["some-tool"],
                "packages under {shell:?}"
            );
        }
    }

    #[test]
    fn repeated_and_attached_package_options() {
        assert_eq!(names("npx -p alpha -p beta runner"), vec!["alpha", "beta"]);
        assert_eq!(
            names("npx --package=alpha --package=beta runner"),
            vec!["alpha", "beta"]
        );
        assert_eq!(names("npx -palpha runner"), vec!["alpha"]);
        assert_eq!(
            names("npm exec --package alpha --package beta -- runner"),
            vec!["alpha", "beta"]
        );
        assert_eq!(names("pnpm dlx --package alpha runner"), vec!["alpha"]);
    }

    #[test]
    fn child_arguments_are_never_reinterpreted_as_packages() {
        // The second `--package` belongs to `bar`, not to the runner.
        let invocation = one("npx --package foo bar --package baz");
        assert_eq!(
            invocation
                .explicit_packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["foo"]
        );
        let child = invocation.child.expect("child entrypoint");
        assert_eq!(child.command, "bar");
        assert_eq!(child.args, vec!["--package", "baz"]);

        assert_eq!(names("npx cowsay --package evil"), vec!["cowsay"]);
        assert_eq!(names("npm exec -- pkg --package evil"), vec!["pkg"]);
        assert_eq!(names("bunx cowsay --package evil"), vec!["cowsay"]);
    }

    #[test]
    fn value_options_never_swallow_or_expose_the_package() {
        assert_eq!(names("npx --registry https://r.example pkg"), vec!["pkg"]);
        assert_eq!(names("npx --call echo pkg"), vec!["pkg"]);
        assert_eq!(names("npx -C /tmp pkg"), vec!["pkg"]);
        assert_eq!(names("pnpm dlx --dir /tmp pkg"), vec!["pkg"]);
        assert_eq!(names("pnpm dlx --filter web pkg"), vec!["pkg"]);
        assert_eq!(names("yarn dlx --cwd /tmp pkg"), vec!["pkg"]);
        assert_eq!(names("bun x --cwd /tmp pkg"), vec!["pkg"]);
        // A Boolean-with-enum config must not eat an arbitrary next token.
        assert_eq!(
            names("npx --color malicious-package"),
            vec!["malicious-package"]
        );
        assert_eq!(names("npx --color always pkg"), vec!["pkg"]);
    }

    #[test]
    fn scoped_alias_and_version_specs() {
        let scoped = one("npm install @scope/pkg@1.2.3");
        assert_eq!(scoped.explicit_packages[0].name, "@scope/pkg");
        assert_eq!(
            scoped.explicit_packages[0].version,
            VersionIntent::from_npm_version("1.2.3")
        );
        assert_eq!(names("npm install @scope/pkg@^1"), vec!["@scope/pkg"]);
        assert_eq!(names("npm install @scope/pkg@next"), vec!["@scope/pkg"]);

        let alias = one("npm install safe@npm:lodash@4.17.21");
        assert_eq!(alias.explicit_packages[0].name, "lodash");
        assert_eq!(
            alias.explicit_packages[0].alias.as_deref(),
            Some("safe"),
            "the alias never becomes the looked-up identity"
        );

        let protocol = one("npm install npm:lodash@4.17.21");
        assert_eq!(protocol.explicit_packages[0].name, "lodash");
        assert!(protocol.explicit_packages[0].alias.is_none());
    }

    /// The subcommand is not always the word right after the launcher. Each of
    /// these really does install the named package, and each was invisible when
    /// only the first positional was considered.
    #[test]
    fn a_prefix_word_or_unmodelled_option_cannot_hide_the_subcommand() {
        for command in [
            "yarn global add evil-pkg",
            "yarn workspace child add evil-pkg",
            "yarn workspaces foreach add evil-pkg",
            "yarn --network-timeout 100000 add evil-pkg",
            "yarn --cache-folder /tmp/c add evil-pkg",
            "yarn --mutex network add evil-pkg",
            // An option no table knows: the grammar must still find the verb.
            "yarn --some-future-flag value add evil-pkg",
            "npm --some-future-flag value install evil-pkg",
            "pnpm --some-future-flag value add evil-pkg",
        ] {
            let invocation = one(command);
            assert_eq!(
                invocation.operation,
                NpmOperation::Install,
                "operation for {command:?}"
            );
            assert_eq!(names(command), vec!["evil-pkg"], "packages for {command:?}");
        }
    }

    /// A word that already selects an operation is the subcommand; the rescan
    /// must not run past it and re-classify the invocation.
    #[test]
    fn a_resolved_subcommand_stops_the_prefix_rescan() {
        let run = one("npm run add");
        assert_eq!(run.operation, NpmOperation::RunScript);
        assert!(run.explicit_packages.is_empty());

        let local = one("pnpm exec add");
        assert_eq!(local.operation, NpmOperation::LocalExec);
        assert!(local.explicit_packages.is_empty());

        // Nothing resolves within the bound: the invocation stays unmodelled
        // and still reports the subcommand it was written with.
        let other = one("npm view left-pad versions");
        assert_eq!(other.operation, NpmOperation::Other);
        assert_eq!(other.subcommand.as_deref(), Some("view"));
        assert!(other.explicit_packages.is_empty());
    }

    /// npm's historical install misspellings and the install-test family
    /// install exactly as `install` does, so one extra keystroke must not buy
    /// an unanalyzed install.
    #[test]
    fn every_documented_npm_install_alias_is_an_install() {
        for alias in [
            "install",
            "i",
            "in",
            "ins",
            "inst",
            "insta",
            "instal",
            "isnt",
            "isnta",
            "isntal",
            "isntall",
            "add",
            "install-test",
            "it",
        ] {
            let command = format!("npm {alias} evil-pkg");
            assert_eq!(
                one(&command).operation,
                NpmOperation::Install,
                "operation for {command:?}"
            );
            assert_eq!(
                names(&command),
                vec!["evil-pkg"],
                "packages for {command:?}"
            );
        }
        // The whole-lockfile forms name no package but are still installs.
        for alias in [
            "ci",
            "clean-install",
            "ic",
            "install-clean",
            "isntall-clean",
            "install-ci-test",
            "cit",
            "clean-install-test",
            "sit",
        ] {
            let command = format!("npm {alias}");
            assert_eq!(
                one(&command).operation,
                NpmOperation::Install,
                "operation for {command:?}"
            );
        }
    }

    #[test]
    fn packages_are_bounded_and_deduplicated_in_order() {
        let mut command = String::from("npm install");
        for index in 0..(MAX_PACKAGES_PER_INVOCATION + 10) {
            command.push_str(&format!(" pkg{index}"));
        }
        let invocation = one(&command);
        assert_eq!(
            invocation.explicit_packages.len(),
            MAX_PACKAGES_PER_INVOCATION
        );
        assert_eq!(invocation.explicit_packages[0].name, "pkg0");
        assert!(invocation.truncated, "the cut must be reported, not silent");

        let deduped = one("npm install left-pad left-pad left-pad");
        assert_eq!(deduped.explicit_packages.len(), 1);
        assert!(!deduped.truncated);
    }

    #[test]
    fn runner_labels_are_stable() {
        assert_eq!(one("npx pkg").runner_label(), "npx");
        assert_eq!(one("npm exec pkg").runner_label(), "npm exec");
        assert_eq!(one("pnpm dlx pkg").runner_label(), "pnpm dlx");
        assert_eq!(one("bun x pkg").runner_label(), "bun x");
    }

    #[test]
    fn non_registry_install_arguments_are_not_packages() {
        assert!(names("npm install ./local-dir").is_empty());
        assert!(names("npm install /abs/path").is_empty());
        assert!(names("npm install https://example.com/pkg.tgz").is_empty());
    }
}
