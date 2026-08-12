use super::config::{
    anchor_selectors, foundry_selectors, rpc_reference, solana_selectors, StaticSelectors,
    Web3ParseContext, Web3ParseContextV2, MAX_CONFIG_BYTES, MAX_CONTEXT_SELECTORS,
    MAX_SELECTOR_BYTES,
};
use super::model::*;
use crate::effects::{
    BoundaryCapability, CommandEffectKind, CommandEffectV2 as CommandEffect,
    CommandEffectsV2 as CommandEffects, CompletenessV2 as Completeness, EffectEvidence,
    EffectEvidenceKind, IncompleteReasonV2 as IncompleteReason, SourceSpan, MAX_COMMAND_EFFECTS,
};
use crate::rules::command::{
    command_word_is_statically_bound, normalize_cmd_base, normalize_powershell_parameter_token,
    normalize_shell_token, resolve_effective_command_bounded, EffectiveCommand,
    EffectiveCommandError, EffectiveEnvironment, EffectiveEnvironmentValue, INTERPRETERS,
};
use crate::tokenize::{self, ShellType};
use crate::util::OpenRegularError;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub const MAX_SHELL_SEGMENTS: usize = 64;
pub const MAX_WRAPPER_DEPTH: usize = 8;
pub const MAX_ARGV_ITEMS: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_WEB3_PARSE_WORK_UNITS: usize = MAX_SHELL_SEGMENTS * MAX_SHELL_SEGMENTS;
const MAX_WEB3_PARSE_EXPANSIONS: usize = MAX_SHELL_SEGMENTS * MAX_WRAPPER_DEPTH;
const MAX_WEB3_SERIALIZED_COMMAND_BYTES: usize = MAX_WEB3_PARSE_RESULT_JSON_BYTES / 2;
const MAX_RUNNER_SHEBANG_BYTES: usize = 4096;
const MAX_YARN_BOOTSTRAP_CONFIG_FILES: usize = 16;

#[derive(Clone)]
struct Arg {
    raw: String,
    value: String,
    span: Option<SourceSpan>,
    statically_bound: bool,
}

#[derive(Clone)]
struct Invocation {
    command: String,
    args: Vec<Arg>,
}

#[derive(Clone)]
struct FlagOccurrence {
    name: String,
    flag_span: Option<SourceSpan>,
    value: Option<Arg>,
}

struct ParsedArgs {
    flags: Vec<FlagOccurrence>,
    positionals: Vec<Arg>,
    completeness: Completeness,
}

#[derive(Clone, Copy)]
struct FlagSpec<'a> {
    canonical: &'a str,
    aliases: &'a [&'a str],
    takes_value: bool,
}

fn spec_for<'a>(name: &str, specs: &'a [FlagSpec<'a>]) -> Option<FlagSpec<'a>> {
    specs
        .iter()
        .copied()
        .find(|spec| spec.canonical == name || spec.aliases.contains(&name))
}

fn split_attached_flag(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('=')
        .map_or((value, None), |(name, value)| (name, Some(value)))
}

fn parse_args(args: &[Arg], shell: ShellType, specs: &[FlagSpec<'_>]) -> ParsedArgs {
    let mut parsed = ParsedArgs {
        flags: Vec::new(),
        positionals: Vec::new(),
        completeness: Completeness::complete(),
    };
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        let arg = &args[index];
        let parameter = normalize_powershell_parameter_token(&arg.raw, shell);
        if options && parameter == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && parameter.starts_with('-') && parameter != "-" {
            let (name, attached) = split_attached_flag(&parameter);
            if let Some(spec) = spec_for(name, specs) {
                let value = if spec.takes_value {
                    if let Some(attached) = attached {
                        if attached.is_empty() {
                            parsed.completeness.add(IncompleteReason::MissingFlagValue);
                            None
                        } else {
                            Some(Arg {
                                raw: attached.to_string(),
                                value: normalize_shell_token(attached, shell),
                                span: arg.span,
                                statically_bound: command_word_is_statically_bound(attached, shell),
                            })
                        }
                    } else if args.get(index + 1).is_some_and(|next| {
                        let next = normalize_powershell_parameter_token(&next.raw, shell);
                        next != "--" && (!next.starts_with('-') || next == "-")
                    }) {
                        index += 1;
                        Some(args[index].clone())
                    } else {
                        parsed.completeness.add(IncompleteReason::MissingFlagValue);
                        None
                    }
                } else {
                    if attached.is_some() {
                        // A switch carries no value, so `--dry-run=false` is not
                        // a spelling this grammar models. Dropping the attached
                        // text and still counting the switch as present let
                        // `cast send --dry-run=false` report a complete,
                        // gap-free NoChainWrite for a command that broadcasts.
                        // Record the gap and do not let the occurrence satisfy
                        // the flag.
                        parsed.completeness.add(IncompleteReason::UnknownOption);
                        index += 1;
                        continue;
                    }
                    None
                };
                if value.as_ref().is_some_and(|value| !value.statically_bound) {
                    parsed
                        .completeness
                        .add(IncompleteReason::UnresolvedIndirection);
                }
                parsed.flags.push(FlagOccurrence {
                    name: spec.canonical.to_string(),
                    flag_span: arg.span,
                    value,
                });
            } else {
                parsed.completeness.add(IncompleteReason::UnknownOption);
            }
            index += 1;
            continue;
        }
        if !arg.statically_bound {
            parsed
                .completeness
                .add(IncompleteReason::UnresolvedIndirection);
        }
        parsed.positionals.push(arg.clone());
        index += 1;
    }
    parsed
}

fn values<'a>(parsed: &'a ParsedArgs, name: &str) -> Vec<&'a Arg> {
    parsed
        .flags
        .iter()
        .filter(move |flag| flag.name == name)
        .filter_map(|flag| flag.value.as_ref())
        .collect()
}

fn has_flag(parsed: &ParsedArgs, name: &str) -> bool {
    parsed.flags.iter().any(|flag| flag.name == name)
}

fn flag_span(parsed: &ParsedArgs, name: &str) -> Option<SourceSpan> {
    parsed
        .flags
        .iter()
        .find(|flag| flag.name == name)
        .and_then(|flag| flag.flag_span)
}

fn selected_value(parsed: &ParsedArgs, name: &str, completeness: &mut Completeness) -> Option<Arg> {
    let mut candidates = values(parsed, name).into_iter();
    let first = candidates.next()?.clone();
    if candidates.any(|candidate| candidate.value != first.value) {
        completeness.add(IncompleteReason::ConflictingSelector);
        return None;
    }
    Some(first)
}

fn selector(value: &Arg, source: SelectorSource) -> Option<SelectorReference> {
    value.statically_bound.then(|| SelectorReference {
        value: value.value.clone(),
        source,
        span: value.span,
    })
}

fn source_span(segment: &tokenize::Segment) -> SourceSpan {
    SourceSpan::new(segment.byte_range.start, segment.byte_range.end)
}

fn spans_for_effective_args(
    input: &str,
    original: &tokenize::Segment,
    args: &[String],
    shell: ShellType,
) -> Vec<Arg> {
    let segment_text = input
        .get(original.byte_range.clone())
        .unwrap_or(original.raw.as_str());
    let mut cursor = 0usize;
    args.iter()
        .map(|raw| {
            let span = segment_text
                .get(cursor..)
                .and_then(|tail| tail.find(raw))
                .map(|relative| {
                    let start = original.byte_range.start + cursor + relative;
                    cursor += relative + raw.len();
                    SourceSpan::new(start, start + raw.len())
                });
            Arg {
                raw: raw.clone(),
                value: normalize_shell_token(raw, shell),
                span,
                statically_bound: command_word_is_statically_bound(raw, shell),
            }
        })
        .collect()
}

fn has_incomplete_quoting(input: &str, shell: ShellType) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        let escape = match shell {
            ShellType::PowerShell => '`',
            ShellType::Cmd => '^',
            ShellType::Posix | ShellType::Fish => '\\',
        };
        if ch == escape && !single {
            escaped = true;
        } else if ch == '"' && !single {
            double = !double;
        } else if ch == '\'' && shell != ShellType::Cmd && !double {
            single = !single;
        }
    }
    single || double || escaped
}

fn contains_web3_token(segment: &tokenize::Segment, shell: ShellType) -> bool {
    segment
        .command
        .iter()
        .chain(segment.args.iter())
        .map(|word| normalize_cmd_base(word, shell))
        .any(|word| {
            matches!(
                word.as_str(),
                "cast" | "forge" | "hardhat" | "solana" | "anchor"
            )
        })
}

fn grouped_command_base(value: &str, shell: ShellType) -> String {
    let normalized = normalize_shell_token(value, shell);
    let stripped = normalized.trim_matches(|ch| matches!(ch, '(' | ')' | '{' | '}' | ';'));
    normalize_cmd_base(stripped, shell)
}

fn contains_whole_web3_executable_token(value: &str, shell: ShellType) -> bool {
    value
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '\\'))
        })
        .filter(|token| !token.is_empty())
        .any(|token| is_web3_tool_name(&normalize_cmd_base(token, shell)))
}

fn inert_ripgrep(segment: &tokenize::Segment, shell: ShellType) -> bool {
    if !segment.command.as_deref().is_some_and(|command| {
        matches!(
            normalize_shell_token(command, shell)
                .to_ascii_lowercase()
                .as_str(),
            "rg" | "rg.exe"
        ) && command_word_is_statically_bound(command, shell)
    }) || !segment
        .args
        .iter()
        .all(|argument| command_word_is_statically_bound(argument, shell))
    {
        return false;
    }
    let mut options = true;
    let mut no_config = false;
    for argument in &segment.args {
        let argument = normalize_shell_token(argument, shell).to_ascii_lowercase();
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            if argument != "--no-config" {
                return false;
            }
            no_config = true;
        }
    }
    no_config
}

fn inert_git_grep(segment: &tokenize::Segment, shell: ShellType) -> bool {
    if segment.command.as_deref().is_none_or(|command| {
        !matches!(
            normalize_shell_token(command, shell)
                .to_ascii_lowercase()
                .as_str(),
            "git" | "git.exe"
        )
    }) || !segment
        .command
        .iter()
        .chain(segment.args.iter())
        .all(|word| command_word_is_statically_bound(word, shell))
    {
        return false;
    }
    let arguments = segment
        .args
        .iter()
        .map(|argument| normalize_shell_token(argument, shell).to_ascii_lowercase())
        .collect::<Vec<_>>();
    let Some(grep_index) = arguments.iter().position(|argument| argument == "grep") else {
        return false;
    };
    let global = &arguments[..grep_index];
    let grep = &arguments[grep_index + 1..];
    if global.is_empty() || !global.iter().all(|argument| argument == "--no-pager") {
        return false;
    }
    let mut options = true;
    let mut no_textconv = false;
    for argument in grep {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            if argument != "--no-textconv" {
                return false;
            }
            no_textconv = true;
        }
    }
    no_textconv
}

fn contains_potential_executable_web3_token(segment: &tokenize::Segment, shell: ShellType) -> bool {
    // A bounded tokenizer deliberately erases argv identity when either word
    // budget is exceeded. Do not feed that adversarial raw segment into the
    // richer nested-body recovery pass; the global typed budget gap already
    // makes the parse incomplete, and this lexical check is allocation-light.
    if segment.command.is_none() {
        return contains_whole_web3_executable_token(&segment.raw, shell);
    }
    let substitutions = match crate::extract::executable_substitutions_bounded(
        &segment.raw,
        shell,
        MAX_SHELL_SEGMENTS,
    ) {
        Ok(substitutions) => substitutions,
        Err(crate::extract::ExecutableSubstitutionLimitError::CardinalityExceeded) => return true,
    };
    for body in &substitutions {
        let (nested, budget) = tokenize::tokenize_bounded(
            body,
            shell,
            MAX_SHELL_SEGMENTS,
            MAX_ARGV_ITEMS + 1,
            MAX_ARGUMENT_BYTES,
        );
        if budget.segments_truncated
            || budget.words_truncated
            || budget.word_bytes_truncated
            || nested
                .iter()
                .any(|nested| contains_web3_token(nested, shell))
        {
            return true;
        }
    }
    let executable_words = segment
        .command
        .iter()
        .chain(segment.args.iter())
        .map(|word| grouped_command_base(word, shell))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let outer = executable_words.first().map(String::as_str);
    if outer.is_some_and(|command| {
        matches!(
            command,
            "echo" | "printf" | "true" | "false" | "test" | "[" | ":" | "pwd" | "sleep" | "grep"
        )
    }) || inert_ripgrep(segment, shell)
        || inert_git_grep(segment, shell)
    {
        return false;
    }
    contains_whole_web3_executable_token(&segment.raw, shell)
}

fn is_web3_tool_name(value: &str) -> bool {
    matches!(value, "cast" | "forge" | "hardhat" | "solana" | "anchor")
}

fn is_package_runner_name(value: &str) -> bool {
    matches!(value, "npx" | "npm" | "pnpm" | "yarn" | "bun" | "bunx")
}

fn is_project_local_bin_command(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    normalized.starts_with("node_modules/.bin/") || normalized.contains("/node_modules/.bin/")
}

enum ReviewedPackageTool {
    Known(&'static str),
    Other,
    UnsafeKnownSpec,
}

fn reviewed_package_tool(value: &str) -> ReviewedPackageTool {
    for tool in ["cast", "forge", "hardhat", "solana", "anchor"] {
        if value == tool {
            return ReviewedPackageTool::Known(tool);
        }
        if let Some(version) = value
            .strip_prefix(tool)
            .and_then(|tail| tail.strip_prefix('@'))
        {
            let safe_version = !version.is_empty()
                && version.len() <= 128
                && version.chars().all(|ch| {
                    ch.is_ascii_alphanumeric()
                        || matches!(
                            ch,
                            '.' | '-' | '_' | '+' | '^' | '~' | '<' | '>' | '=' | '*'
                        )
                });
            return if safe_version {
                ReviewedPackageTool::Known(tool)
            } else {
                ReviewedPackageTool::UnsafeKnownSpec
            };
        }
    }
    ReviewedPackageTool::Other
}

const RUNNER_OPTIONS: &[FlagSpec<'_>] = &[
    FlagSpec {
        canonical: "package",
        aliases: &["--package", "-p"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "workspace",
        aliases: &["--workspace", "-w"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "prefix",
        aliases: &["--prefix"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "registry",
        aliases: &["--registry"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "userconfig",
        aliases: &["--userconfig"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "globalconfig",
        aliases: &["--globalconfig"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "strict-ssl",
        aliases: &["--strict-ssl"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "no-strict-ssl",
        aliases: &["--no-strict-ssl"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "ca",
        aliases: &["--ca"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "cafile",
        aliases: &["--cafile"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "cert",
        aliases: &["--cert"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "key",
        aliases: &["--key"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "proxy",
        aliases: &["--proxy"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "https-proxy",
        aliases: &["--https-proxy"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "cache",
        aliases: &["--cache"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "script-shell",
        aliases: &["--script-shell"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "yes",
        aliases: &["--yes", "-y"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "quiet",
        aliases: &["--quiet", "--silent", "-s"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "workspace-mode",
        aliases: &["--workspaces", "--include-workspace-root"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "unsafe-runner-mode",
        aliases: &[
            "--offline",
            "--prefer-offline",
            "--no-install",
            "--ignore-existing",
            "--shell",
            "--shell-mode",
            "--bun",
            "--top-level",
            "-T",
            "--binaries-only",
        ],
        takes_value: false,
    },
    FlagSpec {
        canonical: "runner-mode",
        aliases: &["--verbose"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "dynamic-call",
        aliases: &["--call", "-c"],
        takes_value: true,
    },
];

fn runner_option_value(arg: &Arg, attached: &str) -> Arg {
    Arg {
        raw: attached.to_string(),
        value: attached.to_string(),
        span: arg.span,
        statically_bound: arg.statically_bound,
    }
}

#[derive(Clone, Default)]
struct NpmConfigLayer {
    values: BTreeMap<String, String>,
    userconfig: Option<Arg>,
    globalconfig: Option<Arg>,
    prefix: Option<Arg>,
}

#[derive(Default)]
struct RunnerProvenance {
    packages: Vec<Arg>,
    workspaces: Vec<Arg>,
    workspace_mode: bool,
    cli: NpmConfigLayer,
    environment: NpmConfigLayer,
    environment_prefix_default: Option<Arg>,
    raw_http_proxy: Option<String>,
    raw_https_proxy: Option<String>,
    custom_configuration: bool,
    configuration_incomplete: bool,
    binary_resolution_proven: bool,
}

const NPM_PREFIX_FALLBACK_ENV: &[&str] = &["PREFIX"];
const NPM_PROXY_FALLBACK_ENV: &[&str] = &["HTTP_PROXY", "http_proxy"];
const NPM_HTTPS_PROXY_FALLBACK_ENV: &[&str] = &["HTTPS_PROXY", "https_proxy"];
const NODE_TLS_REJECT_UNAUTHORIZED_ENV: &[&str] = &[
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "node_tls_reject_unauthorized",
];
const NODE_EXTRA_CA_CERTS_ENV: &[&str] = &["NODE_EXTRA_CA_CERTS", "node_extra_ca_certs"];
const NODE_OPTIONS_ENV: &[&str] = &["NODE_OPTIONS", "node_options"];
const NPM_CONFIG_NODE_OPTIONS_ENV: &[&str] =
    &["NPM_CONFIG_NODE_OPTIONS", "npm_config_node_options"];
const NODE_PATH_ENV: &[&str] = &["NODE_PATH", "node_path"];
const YARN_PATH_ENV: &[&str] = &["YARN_PATH", "yarn_path", "YARN_YARN_PATH", "yarn_yarn_path"];
const YARN_RC_FILENAME_ENV: &[&str] = &["YARN_RC_FILENAME", "yarn_rc_filename"];
const BUN_OPTIONS_ENV: &[&str] = &["BUN_OPTIONS", "bun_options"];
const MAX_NPMRC_ANCESTORS: usize = 64;
const MAX_NPMRC_CONFIG_FILES: usize = 16;
const MAX_NPM_CONFIG_KEYS: usize = 128;

fn default_npm_registry(value: &str) -> bool {
    value.trim().trim_end_matches('/') == "https://registry.npmjs.org"
}

fn mark_runner_configuration_unresolved(
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    provenance.configuration_incomplete = true;
    completeness.add(IncompleteReason::UnresolvedIndirection);
}

fn config_arg(value: String, statically_bound: bool) -> Arg {
    Arg {
        raw: value.clone(),
        value,
        span: None,
        statically_bound,
    }
}

fn valid_npm_setting_value(value: &str) -> bool {
    value.len() <= MAX_SELECTOR_BYTES && !value.contains('$') && !value.contains('`')
}

fn valid_npm_path_value(value: &str) -> bool {
    !value.is_empty() && valid_npm_setting_value(value) && !value.starts_with('~')
}

fn relevant_npm_setting(name: &str) -> bool {
    name == "registry"
        || name.ends_with(":registry")
        || matches!(
            name,
            "strict-ssl"
                | "ca"
                | "cafile"
                | "cert"
                | "key"
                | "proxy"
                | "https-proxy"
                | "cache"
                | "npx-cache"
                | "script-shell"
                | "shell"
                | "call"
                | "package"
                | "ignore-existing"
                | "no-install"
                | "always-spawn"
                | "node-arg"
                | "npm"
                | "global"
                | "location"
                | "workspace"
                | "workspaces"
                | "include-workspace-root"
                | "node-options"
        )
}

fn insert_npm_setting(
    layer: &mut NpmConfigLayer,
    name: &str,
    value: &str,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
    let (name, array_entry) = normalized
        .strip_suffix("[]")
        .map_or((normalized.as_str(), false), |name| (name, true));
    if !relevant_npm_setting(name) {
        return;
    }
    if !valid_npm_setting_value(value)
        || (layer.values.len() == MAX_NPM_CONFIG_KEYS && !layer.values.contains_key(name))
    {
        mark_runner_configuration_unresolved(provenance, completeness);
        if value.len() > MAX_SELECTOR_BYTES {
            completeness.add(IncompleteReason::SelectorBytesExceeded);
        }
        return;
    }
    let value = value.trim();
    let value = if array_entry
        && (!safe_disabled_npm_setting(value)
            || layer
                .values
                .get(name)
                .is_some_and(|value| !safe_disabled_npm_setting(value)))
    {
        // npm's INI grammar accumulates `ca[]=` values. Preserve that an
        // effective trust array is configured without retaining certificate
        // material; a higher-precedence scalar null/empty value can still
        // safely override this layer during the normal merge.
        "configured-array".to_string()
    } else {
        value.to_string()
    };
    layer.values.insert(name.to_string(), value);
}

fn effective_environment_config_value(
    names: &[&str],
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<String> {
    let mut selected: Option<String> = None;
    for name in names {
        let candidate = match environment.values.get(*name) {
            Some(EffectiveEnvironmentValue::Set(value)) => Some(value.clone()),
            Some(EffectiveEnvironmentValue::Unresolved) => {
                mark_runner_configuration_unresolved(provenance, completeness);
                continue;
            }
            // An explicitly unset uppercase alias must not hide a live lowercase
            // alias (or vice versa); continue evaluating the remaining names.
            Some(EffectiveEnvironmentValue::Unset) => continue,
            None => context.environment.get(*name).cloned(),
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if candidate.is_empty() && name.to_ascii_lowercase().starts_with("npm_config_") {
            continue;
        }
        if !valid_npm_setting_value(&candidate) {
            mark_runner_configuration_unresolved(provenance, completeness);
            continue;
        }
        if selected
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConflictingSelector);
            return None;
        }
        selected = Some(candidate);
    }
    selected
}

fn scan_runner_bootstrap_environment_provenance(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    if effective_environment_config_value(
        NODE_TLS_REJECT_UNAUTHORIZED_ENV,
        environment,
        context,
        provenance,
        completeness,
    )
    .is_some_and(|value| !matches!(value.trim(), "" | "1"))
    {
        provenance.custom_configuration = true;
    }
    for names in [
        NODE_EXTRA_CA_CERTS_ENV,
        NODE_OPTIONS_ENV,
        NPM_CONFIG_NODE_OPTIONS_ENV,
        NODE_PATH_ENV,
        YARN_PATH_ENV,
        YARN_RC_FILENAME_ENV,
        BUN_OPTIONS_ENV,
    ] {
        if effective_environment_config_value(names, environment, context, provenance, completeness)
            .is_some_and(|value| !value.trim().is_empty())
        {
            provenance.custom_configuration = true;
        }
    }
}

fn scan_runner_environment_provenance(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    // npm treats every `npm_config_*` environment key case-insensitively and
    // normalizes underscores in setting names. Group the actual spellings
    // first so mixed-case aliases cannot evade a reviewed setting or conceal a
    // conflicting value.
    let mut npm_aliases = BTreeMap::<String, BTreeSet<String>>::new();
    let mut alias_count = 0usize;
    for name in context.environment.keys().chain(environment.values.keys()) {
        let lower = name.to_ascii_lowercase();
        let Some(setting) = lower.strip_prefix("npm_config_") else {
            continue;
        };
        if name.len() > MAX_SELECTOR_BYTES {
            mark_runner_configuration_unresolved(provenance, completeness);
            completeness.add(IncompleteReason::SelectorBytesExceeded);
            continue;
        }
        let setting = setting.replace('_', "-");
        if npm_aliases.entry(setting).or_default().insert(name.clone()) {
            alias_count += 1;
            if alias_count > MAX_CONTEXT_SELECTORS {
                mark_runner_configuration_unresolved(provenance, completeness);
                break;
            }
        }
    }

    for (setting, names) in &npm_aliases {
        if matches!(setting.as_str(), "proxy" | "https-proxy") {
            continue;
        }
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        let Some(value) = effective_environment_config_value(
            &names,
            environment,
            context,
            provenance,
            completeness,
        ) else {
            continue;
        };
        match setting.as_str() {
            "userconfig" => provenance.environment.userconfig = Some(config_arg(value, true)),
            "globalconfig" => provenance.environment.globalconfig = Some(config_arg(value, true)),
            "prefix" => provenance.environment.prefix = Some(config_arg(value, true)),
            setting if relevant_npm_setting(setting) => {
                let mut layer = std::mem::take(&mut provenance.environment);
                insert_npm_setting(&mut layer, setting, &value, provenance, completeness);
                provenance.environment = layer;
            }
            _ => {}
        }
    }

    for (name, fallback) in [
        ("proxy", NPM_PROXY_FALLBACK_ENV),
        ("https-proxy", NPM_HTTPS_PROXY_FALLBACK_ENV),
    ] {
        let primary = npm_aliases.get(name).and_then(|names| {
            let names = names.iter().map(String::as_str).collect::<Vec<_>>();
            effective_environment_config_value(
                &names,
                environment,
                context,
                provenance,
                completeness,
            )
        });
        if let Some(value) = primary {
            let mut layer = std::mem::take(&mut provenance.environment);
            insert_npm_setting(&mut layer, name, &value, provenance, completeness);
            provenance.environment = layer;
        }
        let raw_fallback = effective_environment_config_value(
            fallback,
            environment,
            context,
            provenance,
            completeness,
        );
        if name == "proxy" {
            provenance.raw_http_proxy = raw_fallback;
        } else {
            provenance.raw_https_proxy = raw_fallback;
        }
    }

    if provenance.environment.prefix.is_none() {
        if let Some(value) = effective_environment_config_value(
            NPM_PREFIX_FALLBACK_ENV,
            environment,
            context,
            provenance,
            completeness,
        ) {
            provenance.environment_prefix_default = Some(config_arg(value, true));
        }
    }

    scan_runner_bootstrap_environment_provenance(environment, context, provenance, completeness);
}

fn add_runner_config_read_gap(completeness: &mut Completeness, error: OpenRegularError) {
    completeness.add(match error {
        OpenRegularError::NotFound => IncompleteReason::ConfigMissing,
        OpenRegularError::NotRegularFile => IncompleteReason::ConfigNotRegular,
        OpenRegularError::TooLarge => IncompleteReason::ConfigBytesExceeded,
        OpenRegularError::Io(_) => IncompleteReason::ConfigIo,
    });
}

fn yarn_classic_bootstrap_configured(content: &str) -> Result<bool, ()> {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let first_end = line.find(char::is_whitespace).unwrap_or(line.len());
        let first = &line[..first_end];
        let (raw_key, attached) = first
            .split_once('=')
            .map_or((first, None), |(key, value)| (key, Some(value)));
        let key = raw_key.trim_start_matches("--");
        let trailing = line[first_end..].trim();
        let remainder = match attached {
            Some(value) if trailing.is_empty() => value.trim(),
            Some(_) => return Ok(true),
            None => trailing,
        };
        if key == "yarn-path" {
            return if remainder.is_empty() {
                Err(())
            } else {
                Ok(true)
            };
        }
        let benign_control = matches!(
            key,
            "install.check-files" | "no-progress" | "emoji" | "color"
        ) && (remainder.is_empty()
            || matches!(
                remainder.to_ascii_lowercase().as_str(),
                "true" | "false" | "0" | "1"
            ));
        if !benign_control {
            // Classic rc settings include modules/link/cache/global folders,
            // registry overrides, PnP, alternate rc files, and script PATH
            // controls. Rather than partially reproduce Yarn's precedence,
            // reject every setting outside the small display/install-only
            // allowlist above.
            return Ok(true);
        }
    }
    Ok(false)
}

fn yarn_modern_bootstrap_configured(content: &str) -> Result<(bool, bool), ()> {
    let document = serde_yaml::from_str::<serde_yaml::Value>(content).map_err(|_| ())?;
    let settings = match document {
        serde_yaml::Value::Null => return Ok((false, false)),
        serde_yaml::Value::Mapping(settings) => settings,
        _ => return Err(()),
    };
    let mut node_modules_mode = false;
    for (key, value) in settings {
        let key = key.as_str().ok_or(())?;
        // YAML merge keys and nonliteral keys can inject settings without a
        // directly reviewable spelling. Treat those grammars as dynamic.
        if key == "<<" {
            return Err(());
        }
        match key {
            "nodeLinker" if value.as_str() == Some("node-modules") => node_modules_mode = true,
            "enableColors" | "enableHyperlinks" | "enableProgressBars"
                if value.as_bool().is_some() => {}
            // This includes yarnPath, plugins, every pnp* setting, alternate
            // cache/global/install-state paths, npm registries/scopes, package
            // extensions/resolutions, and any future setting whose execution
            // or bin-resolution semantics have not been modeled here.
            _ => return Ok((true, false)),
        }
    }
    Ok((false, node_modules_mode))
}

#[derive(Clone, Copy)]
enum YarnBootstrapConfigSyntax {
    Classic,
    Modern,
}

#[allow(clippy::too_many_arguments)]
fn inspect_yarn_bootstrap_file(
    path: &Path,
    syntax: YarnBootstrapConfigSyntax,
    directory_is_inert: bool,
    files_scanned: &mut usize,
    visited: &mut BTreeSet<PathBuf>,
    node_modules_mode_proven: &mut bool,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    if !visited.insert(path.to_path_buf()) {
        return true;
    }
    if directory_is_inert {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Ok(_) => {}
            Err(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return false;
            }
        }
    }
    if *files_scanned == MAX_YARN_BOOTSTRAP_CONFIG_FILES {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Ok(metadata) if directory_is_inert && metadata.file_type().is_dir() => return true,
            _ => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return false;
            }
        }
    }
    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_CONFIG_BYTES) {
        Ok(bytes) => {
            *files_scanned += 1;
            bytes
        }
        Err(OpenRegularError::NotFound) => return true,
        Err(error) => {
            provenance.configuration_incomplete = true;
            add_runner_config_read_gap(completeness, error);
            return false;
        }
    };
    let content = match std::str::from_utf8(&bytes) {
        Ok(content) => content,
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigMalformed);
            return false;
        }
    };
    let configured = match syntax {
        YarnBootstrapConfigSyntax::Classic => {
            yarn_classic_bootstrap_configured(content).map(|configured| (configured, false))
        }
        YarnBootstrapConfigSyntax::Modern => yarn_modern_bootstrap_configured(content),
    };
    match configured {
        Ok((false, explicit_node_modules_mode)) => {
            *node_modules_mode_proven |= explicit_node_modules_mode;
            true
        }
        Ok((true, _)) => {
            provenance.custom_configuration = true;
            mark_runner_configuration_unresolved(provenance, completeness);
            false
        }
        Err(()) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigMalformed);
            false
        }
    }
}

fn optional_canonical_yarn_directory(
    path: &Path,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Result<Option<PathBuf>, ()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigNotRegular);
            mark_runner_configuration_unresolved(provenance, completeness);
            return Err(());
        }
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            return Err(());
        }
    };
    let canonical = std::fs::canonicalize(path).map_err(|_| {
        provenance.configuration_incomplete = true;
        completeness.add(IncompleteReason::ConfigIo);
    })?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical).map_err(|_| {
        provenance.configuration_incomplete = true;
        completeness.add(IncompleteReason::ConfigIo);
    })?;
    if !canonical.is_absolute() || !canonical_metadata.file_type().is_dir() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() != canonical_metadata.dev() || metadata.ino() != canonical_metadata.ino()
        {
            mark_runner_configuration_unresolved(provenance, completeness);
            return Err(());
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(Some(canonical))
}

fn inspect_yarn_bootstrap_environment(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    let mut names = BTreeSet::new();
    for name in context.environment.keys().chain(environment.values.keys()) {
        let normalized = name.to_ascii_uppercase();
        if !normalized.starts_with("YARN_") && !normalized.starts_with("COREPACK_") {
            continue;
        }
        if name.len() > MAX_SELECTOR_BYTES || names.len() == MAX_CONTEXT_SELECTORS {
            if name.len() > MAX_SELECTOR_BYTES {
                completeness.add(IncompleteReason::SelectorBytesExceeded);
            }
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
        names.insert(name.clone());
    }
    for name in names {
        let value = match environment.values.get(&name) {
            Some(EffectiveEnvironmentValue::Set(value)) => Some(value.as_str()),
            Some(EffectiveEnvironmentValue::Unset) => None,
            Some(EffectiveEnvironmentValue::Unresolved) => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return false;
            }
            None if environment.clear_ambient => None,
            None => context.environment.get(&name).map(String::as_str),
        };
        let Some(value) = value else {
            continue;
        };
        if value.len() > MAX_SELECTOR_BYTES {
            completeness.add(IncompleteReason::SelectorBytesExceeded);
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
        if value.trim().is_empty() {
            continue;
        }
        let normalized = name.to_ascii_uppercase();
        let benign_control = matches!(
            normalized.as_str(),
            "YARN_ENABLE_COLORS" | "YARN_ENABLE_HYPERLINKS" | "YARN_ENABLE_PROGRESS_BARS"
        ) && matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "false" | "0" | "1"
        );
        if !benign_control {
            provenance.custom_configuration = true;
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
    }
    true
}

fn effective_runner_home(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    let selected = match environment.values.get("HOME") {
        Some(EffectiveEnvironmentValue::Set(value)) => Some(value.clone()),
        Some(EffectiveEnvironmentValue::Unset | EffectiveEnvironmentValue::Unresolved) => None,
        None if environment.clear_ambient => None,
        None => context.environment.get("HOME").cloned(),
    };
    let Some(selected) = selected else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    };
    if selected.is_empty() || selected.len() > MAX_SELECTOR_BYTES {
        if selected.len() > MAX_SELECTOR_BYTES {
            completeness.add(IncompleteReason::SelectorBytesExceeded);
        }
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let home = PathBuf::from(selected);
    home.is_absolute().then_some(home).or_else(|| {
        mark_runner_configuration_unresolved(provenance, completeness);
        None
    })
}

fn effective_runner_xdg_config_home(
    canonical_home: &Path,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    let selected = match environment.values.get("XDG_CONFIG_HOME") {
        Some(EffectiveEnvironmentValue::Set(value)) if !value.is_empty() => Some(value.clone()),
        Some(EffectiveEnvironmentValue::Set(_) | EffectiveEnvironmentValue::Unset) => None,
        Some(EffectiveEnvironmentValue::Unresolved) => {
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        }
        None if environment.clear_ambient => None,
        None => context
            .environment
            .get("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .cloned(),
    };
    let Some(selected) = selected else {
        return Some(canonical_home.join(".config"));
    };
    if selected.len() > MAX_SELECTOR_BYTES || !valid_npm_path_value(&selected) {
        if selected.len() > MAX_SELECTOR_BYTES {
            completeness.add(IncompleteReason::SelectorBytesExceeded);
        }
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let configured = PathBuf::from(selected);
    configured.is_absolute().then_some(configured).or_else(|| {
        mark_runner_configuration_unresolved(provenance, completeness);
        None
    })
}

fn inspect_yarn_bootstrap_configuration(
    cwd: &Path,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    if !inspect_yarn_bootstrap_environment(environment, context, provenance, completeness) {
        return false;
    }
    let Some(home) = effective_runner_home(environment, context, provenance, completeness) else {
        return false;
    };
    let Some(canonical_home) = trusted_root_canonical_identity(&home, provenance, completeness)
    else {
        return false;
    };
    let mut files_scanned = 0usize;
    let mut visited = BTreeSet::new();
    let mut node_modules_mode_proven = false;
    let mut directories = cwd
        .ancestors()
        .take(MAX_NPMRC_ANCESTORS)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    if !directories.contains(&canonical_home) {
        directories.push(canonical_home.clone());
    }
    for directory in directories {
        for name in [".pnp.js", ".pnp.cjs", ".pnp.loader.mjs"] {
            match std::fs::symlink_metadata(directory.join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    provenance.configuration_incomplete = true;
                    completeness.add(IncompleteReason::ConfigIo);
                    return false;
                }
                Ok(metadata) => {
                    if !metadata.file_type().is_file() {
                        completeness.add(IncompleteReason::ConfigNotRegular);
                    }
                    provenance.custom_configuration = true;
                    mark_runner_configuration_unresolved(provenance, completeness);
                    return false;
                }
            }
        }
        for (name, syntax) in [
            (".yarnrc", YarnBootstrapConfigSyntax::Classic),
            (".yarnrc.yml", YarnBootstrapConfigSyntax::Modern),
        ] {
            if !inspect_yarn_bootstrap_file(
                &directory.join(name),
                syntax,
                false,
                &mut files_scanned,
                &mut visited,
                &mut node_modules_mode_proven,
                provenance,
                completeness,
            ) {
                return false;
            }
        }
    }
    if cwd.ancestors().nth(MAX_NPMRC_ANCESTORS).is_some() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    }

    // Yarn Classic's startup rc search is broader than the ancestor `.yarnrc`
    // chain. It also reads a fixed system layer and several per-user `config`
    // locations before deciding whether `yarn-path`, `modules-folder`, or CLI
    // options alter execution. Inspect each real file with the same bounded,
    // no-follow, inert-only policy used above.
    let home_config_root = match optional_canonical_yarn_directory(
        &canonical_home.join(".config"),
        provenance,
        completeness,
    ) {
        Ok(root) => root,
        Err(()) => return false,
    };
    if let Some(home_config_root) = home_config_root.as_ref() {
        let home_yarn_config = home_config_root.join("yarn");
        if !inspect_yarn_bootstrap_file(
            &home_yarn_config,
            YarnBootstrapConfigSyntax::Classic,
            true,
            &mut files_scanned,
            &mut visited,
            &mut node_modules_mode_proven,
            provenance,
            completeness,
        ) {
            return false;
        }
        match optional_canonical_yarn_directory(&home_yarn_config, provenance, completeness) {
            Ok(Some(home_yarn_config)) => {
                if !inspect_yarn_bootstrap_file(
                    &home_yarn_config.join("config"),
                    YarnBootstrapConfigSyntax::Classic,
                    false,
                    &mut files_scanned,
                    &mut visited,
                    &mut node_modules_mode_proven,
                    provenance,
                    completeness,
                ) {
                    return false;
                }
            }
            Ok(None) => {}
            Err(()) => return false,
        }
    }
    match optional_canonical_yarn_directory(&canonical_home.join(".yarn"), provenance, completeness)
    {
        Ok(Some(home_yarn)) => {
            if !inspect_yarn_bootstrap_file(
                &home_yarn.join("config"),
                YarnBootstrapConfigSyntax::Classic,
                false,
                &mut files_scanned,
                &mut visited,
                &mut node_modules_mode_proven,
                provenance,
                completeness,
            ) {
                return false;
            }
        }
        Ok(None) => {}
        Err(()) => return false,
    }

    #[cfg(not(windows))]
    {
        let Some(xdg_config_home) = effective_runner_xdg_config_home(
            &canonical_home,
            environment,
            context,
            provenance,
            completeness,
        ) else {
            return false;
        };
        match optional_canonical_yarn_directory(&xdg_config_home, provenance, completeness) {
            Ok(Some(xdg_config_home)) => {
                if !inspect_yarn_bootstrap_file(
                    &xdg_config_home.join("yarn"),
                    YarnBootstrapConfigSyntax::Classic,
                    true,
                    &mut files_scanned,
                    &mut visited,
                    &mut node_modules_mode_proven,
                    provenance,
                    completeness,
                ) {
                    return false;
                }
            }
            Ok(None) => {}
            Err(()) => return false,
        }

        let canonical_etc = match std::fs::canonicalize("/etc") {
            Ok(path) if path.is_absolute() => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PathBuf::new(),
            _ => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return false;
            }
        };
        if !canonical_etc.as_os_str().is_empty() {
            match optional_canonical_yarn_directory(
                &canonical_etc.join("yarn"),
                provenance,
                completeness,
            ) {
                Ok(Some(system_yarn)) => {
                    if !inspect_yarn_bootstrap_file(
                        &system_yarn.join("config"),
                        YarnBootstrapConfigSyntax::Classic,
                        false,
                        &mut files_scanned,
                        &mut visited,
                        &mut node_modules_mode_proven,
                        provenance,
                        completeness,
                    ) {
                        return false;
                    }
                }
                Ok(None) => {}
                Err(()) => return false,
            }
            if !inspect_yarn_bootstrap_file(
                &canonical_etc.join("yarnrc"),
                YarnBootstrapConfigSyntax::Classic,
                false,
                &mut files_scanned,
                &mut visited,
                &mut node_modules_mode_proven,
                provenance,
                completeness,
            ) {
                return false;
            }
        }
    }
    if !node_modules_mode_proven {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    }
    true
}

fn resolved_npmrc_path(path: &Path, value: &str) -> Option<PathBuf> {
    let configured = PathBuf::from(value);
    let configured = if configured.is_absolute() {
        configured
    } else {
        path.parent()?.join(configured)
    };
    configured.is_absolute().then_some(configured)
}

fn scan_npmrc_layer(
    path: &Path,
    required: bool,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
    files_scanned: &mut usize,
    visited: &mut BTreeSet<PathBuf>,
) -> NpmConfigLayer {
    if !visited.insert(path.to_path_buf()) {
        return NpmConfigLayer::default();
    }
    if *files_scanned == MAX_NPMRC_CONFIG_FILES {
        mark_runner_configuration_unresolved(provenance, completeness);
        return NpmConfigLayer::default();
    }
    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_CONFIG_BYTES) {
        Ok(bytes) => {
            *files_scanned += 1;
            bytes
        }
        Err(OpenRegularError::NotFound) if !required => {
            visited.remove(path);
            return NpmConfigLayer::default();
        }
        Err(OpenRegularError::NotFound) => {
            visited.remove(path);
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigMissing);
            return NpmConfigLayer::default();
        }
        Err(error) => {
            provenance.configuration_incomplete = true;
            add_runner_config_read_gap(completeness, error);
            return NpmConfigLayer::default();
        }
    };
    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigMalformed);
            return NpmConfigLayer::default();
        }
    };
    let mut layer = NpmConfigLayer::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase().replace('_', "-");
        let value = value.trim();
        if relevant_npm_setting(name.strip_suffix("[]").unwrap_or(&name)) {
            insert_npm_setting(&mut layer, &name, value, provenance, completeness);
            continue;
        }
        if matches!(name.as_str(), "userconfig" | "globalconfig" | "prefix") {
            if !valid_npm_path_value(value) {
                mark_runner_configuration_unresolved(provenance, completeness);
                continue;
            }
            let value = if name == "prefix" {
                config_arg(value.to_string(), true)
            } else {
                let Some(path) = resolved_npmrc_path(path, value) else {
                    mark_runner_configuration_unresolved(provenance, completeness);
                    continue;
                };
                config_arg(path.to_string_lossy().into_owned(), true)
            };
            match name.as_str() {
                "userconfig" => layer.userconfig = Some(value),
                "globalconfig" => layer.globalconfig = Some(value),
                "prefix" => layer.prefix = Some(value),
                _ => unreachable!(),
            }
        }
    }
    layer
}

fn resolve_runner_config_path(
    value: &Arg,
    base: Option<&Path>,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    if !value.statically_bound || !valid_npm_path_value(&value.value) {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let path = resolve_cwd(base, &value.value);
    if path.as_ref().is_none_or(|path| !path.is_absolute()) {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    path
}

fn read_runner_package_json(
    path: &Path,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<serde_json::Value> {
    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            provenance.configuration_incomplete = true;
            add_runner_config_read_gap(completeness, error);
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigMalformed);
            None
        }
    }
}

fn workspace_glob_matches(pattern: &str, relative: &Path) -> Option<bool> {
    if pattern.is_empty()
        || pattern.starts_with('!')
        || pattern
            .chars()
            .any(|character| matches!(character, '?' | '[' | ']' | '{' | '}'))
        || Path::new(pattern).is_absolute()
    {
        return None;
    }
    let pattern = pattern.trim_end_matches('/');
    let pattern = pattern
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let relative = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if pattern.len() > MAX_NPMRC_ANCESTORS
        || relative.len() > MAX_NPMRC_ANCESTORS
        || pattern.iter().filter(|part| **part == "**").count() > 1
    {
        return None;
    }
    fn matches_components(pattern: &[&str], relative: &[&str]) -> bool {
        match pattern {
            [] => relative.is_empty(),
            ["**", tail @ ..] => {
                matches_components(tail, relative)
                    || (!relative.is_empty() && matches_components(pattern, &relative[1..]))
            }
            [head, tail @ ..] if !relative.is_empty() && (*head == "*" || *head == relative[0]) => {
                matches_components(tail, &relative[1..])
            }
            _ => false,
        }
    }
    Some(matches_components(&pattern, &relative))
}

fn package_workspace_match(package: &serde_json::Value, relative: &Path) -> Option<Option<bool>> {
    let Some(workspaces) = package.get("workspaces") else {
        return Some(None);
    };
    let patterns = workspaces
        .as_array()
        .or_else(|| workspaces.as_object()?.get("packages")?.as_array())?;
    let mut matched = false;
    for pattern in patterns {
        let pattern = pattern.as_str()?;
        matched |= workspace_glob_matches(pattern, relative)?;
    }
    Some(Some(matched))
}

fn npm_local_prefix(
    cwd: &Path,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    let mut count = 0usize;
    let mut nearest = None;
    for directory in cwd.ancestors().take(MAX_NPMRC_ANCESTORS) {
        count += 1;
        for (name, expect_directory) in [("package.json", false), ("node_modules", true)] {
            match std::fs::symlink_metadata(directory.join(name)) {
                Ok(metadata)
                    if (!expect_directory && metadata.file_type().is_file())
                        || (expect_directory && metadata.file_type().is_dir()) =>
                {
                    nearest = Some(directory.to_path_buf());
                    break;
                }
                Ok(_) => {
                    mark_runner_configuration_unresolved(provenance, completeness);
                    return None;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    provenance.configuration_incomplete = true;
                    completeness.add(IncompleteReason::ConfigIo);
                    return None;
                }
            }
        }
        if nearest.is_some() {
            break;
        }
    }
    let found_nearest = nearest.is_some();
    let mut local_prefix = nearest.unwrap_or_else(|| cwd.to_path_buf());
    if !found_nearest
        && count == MAX_NPMRC_ANCESTORS
        && cwd.ancestors().nth(MAX_NPMRC_ANCESTORS).is_some()
    {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }

    // npm promotes a nested package to an ancestor workspace root. Inspect
    // every ancestor package manifest instead of stopping at the safe-looking
    // leaf: root config and root node_modules participate in exec resolution.
    let workspace_member = local_prefix.clone();
    let workspace_ancestor_limit_exceeded = local_prefix
        .ancestors()
        .skip(1)
        .nth(MAX_NPMRC_ANCESTORS)
        .is_some();
    let workspace_ancestors = local_prefix
        .ancestors()
        .skip(1)
        .take(MAX_NPMRC_ANCESTORS)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    let mut matched_workspace_root = None;
    for ancestor in workspace_ancestors {
        let manifest = ancestor.join("package.json");
        match std::fs::symlink_metadata(&manifest) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return None;
            }
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
        }
        let package = read_runner_package_json(&manifest, provenance, completeness)?;
        let Some(relative) = workspace_member.strip_prefix(&ancestor).ok() else {
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        };
        match package_workspace_match(&package, relative) {
            Some(Some(true)) if matched_workspace_root.is_none() => {
                matched_workspace_root = Some(ancestor)
            }
            Some(Some(true)) => {
                // Nested workspace declarations make npm's effective root
                // version/config dependent. Refuse to choose one implicitly.
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
            Some(Some(false) | None) => {}
            None => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
        }
    }
    if workspace_ancestor_limit_exceeded {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    if let Some(workspace_root) = matched_workspace_root {
        local_prefix = workspace_root;
    }
    Some(local_prefix)
}

fn merge_npm_layer(effective: &mut BTreeMap<String, String>, layer: &NpmConfigLayer) {
    for (name, value) in &layer.values {
        effective.insert(name.clone(), value.clone());
    }
}

fn safe_disabled_npm_setting(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "null" | "false" | "0" | "no"
    )
}

fn safe_unconfigured_path_setting(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "" | "null")
}

fn evaluate_effective_npm_settings(
    layers: [&NpmConfigLayer; 5],
    provenance: &mut RunnerProvenance,
) {
    let mut effective = BTreeMap::new();
    for layer in layers {
        merge_npm_layer(&mut effective, layer);
    }
    // npm's proxy agent treats null/false/empty npm config as absent even at
    // CLI precedence, then falls back to the matching raw process proxy. Apply
    // that selection only after every npm layer has been merged so a CLI null
    // cannot conceal a live HTTP(S)_PROXY value from provenance review.
    for (name, raw_fallback) in [
        ("proxy", provenance.raw_http_proxy.as_ref()),
        ("https-proxy", provenance.raw_https_proxy.as_ref()),
    ] {
        if effective
            .get(name)
            .is_none_or(|value| safe_disabled_npm_setting(value))
        {
            if let Some(raw_fallback) = raw_fallback {
                effective.insert(name.to_string(), raw_fallback.clone());
            }
        }
    }
    for (name, value) in effective {
        let safe = if name == "registry" || name.ends_with(":registry") {
            default_npm_registry(&value)
        } else if name == "strict-ssl" {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes"
            )
        } else if name == "workspace" {
            value.trim().is_empty()
        } else if matches!(
            name.as_str(),
            "ca" | "cafile"
                | "cert"
                | "key"
                | "cache"
                | "npx-cache"
                | "script-shell"
                | "shell"
                | "call"
                | "package"
                | "node-arg"
                | "npm"
                | "location"
                | "node-options"
        ) {
            safe_unconfigured_path_setting(&value)
        } else {
            safe_disabled_npm_setting(&value)
        };
        provenance.custom_configuration |= !safe;
    }
}

fn safe_package_bin_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (!path.is_absolute()
        && !value.is_empty()
        && value.len() <= MAX_SELECTOR_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir)))
    .then_some(path)
}

fn declared_package_bin(
    package: &serde_json::Value,
    tool: &str,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    if package.get("name").and_then(serde_json::Value::as_str) != Some(tool) {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let value = match package.get("bin") {
        Some(serde_json::Value::String(value)) => value.as_str(),
        Some(serde_json::Value::Object(values)) => {
            let Some(value) = values.get(tool).and_then(serde_json::Value::as_str) else {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            };
            value
        }
        _ => {
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        }
    };
    safe_package_bin_path(value).or_else(|| {
        mark_runner_configuration_unresolved(provenance, completeness);
        None
    })
}

fn reviewed_package_bin_file(metadata: &std::fs::Metadata) -> bool {
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn runner_entrypoint_has_native_magic(prefix: &[u8]) -> bool {
    let unix_native = prefix.starts_with(b"\x7fELF")
        || prefix.starts_with(b"\xfe\xed\xfa\xce")
        || prefix.starts_with(b"\xce\xfa\xed\xfe")
        || prefix.starts_with(b"\xfe\xed\xfa\xcf")
        || prefix.starts_with(b"\xcf\xfa\xed\xfe")
        || prefix.starts_with(b"\xca\xfe\xba\xbe")
        || prefix.starts_with(b"\xbe\xba\xfe\xca");
    #[cfg(windows)]
    {
        unix_native || prefix.starts_with(b"MZ")
    }
    #[cfg(not(windows))]
    {
        unix_native
    }
}

fn effective_runner_path(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<String> {
    let selected = match environment.values.get("PATH") {
        Some(EffectiveEnvironmentValue::Set(value)) => Some(value.clone()),
        Some(EffectiveEnvironmentValue::Unset | EffectiveEnvironmentValue::Unresolved) => None,
        None if environment.clear_ambient => None,
        None => context.environment.get("PATH").cloned(),
    };
    let Some(selected) = selected else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    };
    if selected.is_empty() || selected.len() > MAX_SELECTOR_BYTES {
        if selected.len() > MAX_SELECTOR_BYTES {
            completeness.add(IncompleteReason::SelectorBytesExceeded);
        }
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let mut entries = std::env::split_paths(std::ffi::OsStr::new(&selected));
    if entries.any(|entry| entry.as_os_str().is_empty() || !entry.is_absolute()) {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    Some(selected)
}

fn trusted_absolute_runner_interpreter(interpreter: &Path) -> bool {
    crate::trusted_child::TrustedExecutable::from_absolute(interpreter, &[])
        .and_then(|executable| executable.require_forced_interpreter_provenance())
        .is_ok()
}

fn reviewed_node_interpreter_name(name: &str) -> bool {
    matches!(name, "node" | "nodejs")
}

fn runner_shebang_is_proven(
    shebang: &str,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    let mut words = shebang.split_ascii_whitespace();
    let Some(interpreter) = words.next() else {
        return false;
    };
    let interpreter_path = Path::new(interpreter);
    if !interpreter_path.is_absolute() {
        return false;
    }
    let Some(interpreter_name) = interpreter_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if interpreter_name == "env" {
        if !trusted_absolute_runner_interpreter(interpreter_path) {
            return false;
        }
        let Some(requested) = words.next() else {
            return false;
        };
        if words.next().is_some()
            || requested.is_empty()
            || requested.len() > 128
            || requested.contains(['/', '\\'])
            || !requested.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '+')
            })
            || !reviewed_node_interpreter_name(requested)
        {
            return false;
        }
        let Some(path) = effective_runner_path(environment, context, provenance, completeness)
        else {
            return false;
        };
        return crate::trusted_child::resolve_forced_interpreter_on_path(
            requested,
            std::ffi::OsStr::new(&path),
        )
        .is_ok();
    }
    if !reviewed_node_interpreter_name(interpreter_name)
        || !trusted_absolute_runner_interpreter(interpreter_path)
    {
        return false;
    }
    // Interpreter arguments have platform-dependent shebang tokenization and
    // may themselves select preload/configuration behavior. Keep that grammar
    // outside the exact-local proof until it has a typed model.
    words.next().is_none()
}

fn validate_runner_entrypoint(
    path: &Path,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    let file = match crate::util::open_read_no_follow_capped(path, u64::MAX) {
        Ok(file) => file,
        Err(error) => {
            provenance.configuration_incomplete = true;
            add_runner_config_read_gap(completeness, error);
            return false;
        }
    };
    let mut prefix = Vec::with_capacity(MAX_RUNNER_SHEBANG_BYTES + 1);
    if file
        .take((MAX_RUNNER_SHEBANG_BYTES + 1) as u64)
        .read_to_end(&mut prefix)
        .is_err()
    {
        provenance.configuration_incomplete = true;
        completeness.add(IncompleteReason::ConfigIo);
        return false;
    }
    let proven = if let Some(shebang) = prefix.strip_prefix(b"#!") {
        let line_end = shebang
            .iter()
            .position(|byte| *byte == b'\n')
            .or_else(|| (prefix.len() <= MAX_RUNNER_SHEBANG_BYTES).then_some(shebang.len()));
        line_end
            .and_then(|line_end| std::str::from_utf8(&shebang[..line_end]).ok())
            .is_some_and(|shebang| {
                runner_shebang_is_proven(
                    shebang.trim_end_matches('\r'),
                    environment,
                    context,
                    provenance,
                    completeness,
                )
            })
    } else {
        runner_entrypoint_has_native_magic(&prefix)
    };
    if !proven {
        mark_runner_configuration_unresolved(provenance, completeness);
    }
    proven
}

fn validate_local_package_bin(
    candidate: &Path,
    package_dir: &Path,
    tool: &str,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    let node_modules = package_dir.parent().unwrap_or(package_dir);
    let bin_directory = candidate.parent().unwrap_or(candidate);
    for directory in [node_modules, bin_directory] {
        if !std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
    }
    match std::fs::symlink_metadata(package_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            return false;
        }
    }
    let package =
        match read_runner_package_json(&package_dir.join("package.json"), provenance, completeness)
        {
            Some(package) => package,
            None => return false,
        };
    let Some(bin) = declared_package_bin(&package, tool, provenance, completeness) else {
        return false;
    };
    let Some(expected) = resolve_cwd(Some(package_dir), &bin.to_string_lossy()) else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    };
    let Some(relative_expected) = expected.strip_prefix(package_dir).ok() else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    };
    let components = relative_expected.components().collect::<Vec<_>>();
    if components.is_empty() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    }
    let mut checked = package_dir.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = *component else {
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        };
        checked.push(component);
        let is_last = index + 1 == components.len();
        let valid = std::fs::symlink_metadata(&checked).is_ok_and(|metadata| {
            if is_last {
                reviewed_package_bin_file(&metadata)
            } else {
                metadata.file_type().is_dir()
            }
        });
        if !valid {
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        }
    }
    let metadata = match std::fs::symlink_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if !metadata.file_type().is_symlink() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    }
    let target = match std::fs::read_link(candidate) {
        Ok(target) => target,
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            return false;
        }
    };
    let resolved = resolve_cwd(candidate.parent(), &target.to_string_lossy());
    if resolved.as_deref() != Some(expected.as_path()) {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    }
    validate_runner_entrypoint(&expected, environment, context, provenance, completeness)
}

#[allow(clippy::too_many_arguments)]
fn prove_runner_binary_resolution(
    project_cwd: &Path,
    local_prefix: &Path,
    global_prefix: Option<&Path>,
    tool: &str,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    // An explicit npm `--package`/`-p` selector always enters npm's package
    // resolution path, even when its text is identical to the child command.
    // It may consult a local package, registry, or cache and therefore cannot
    // inherit the direct local-bin proof below.
    if !provenance.packages.is_empty() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return;
    }
    // npm exec gives the active project/workspace package's own `bin` mapping
    // precedence over node_modules/.bin. A reviewed dependency shim cannot
    // prove which program runs when any applicable project manifest declares
    // the same binary name.
    let mut reached_local_prefix = false;
    for directory in project_cwd.ancestors().take(MAX_NPMRC_ANCESTORS) {
        let manifest = directory.join("package.json");
        match std::fs::symlink_metadata(&manifest) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return;
            }
            Ok(metadata) if metadata.file_type().is_file() => {
                let Some(package) = read_runner_package_json(&manifest, provenance, completeness)
                else {
                    return;
                };
                let shadows = match package.get("bin") {
                    None => false,
                    Some(serde_json::Value::String(_)) => package
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|name| name.rsplit('/').next())
                        .is_none_or(|name| name == tool),
                    Some(serde_json::Value::Object(values)) => values.contains_key(tool),
                    Some(_) => true,
                };
                if shadows {
                    mark_runner_configuration_unresolved(provenance, completeness);
                    return;
                }
            }
            Ok(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigNotRegular);
                return;
            }
        }
        if directory == local_prefix {
            reached_local_prefix = true;
            break;
        }
    }
    if !reached_local_prefix {
        mark_runner_configuration_unresolved(provenance, completeness);
        return;
    }
    for directory in project_cwd.ancestors().take(MAX_NPMRC_ANCESTORS) {
        let candidate = directory.join("node_modules/.bin").join(tool);
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return;
            }
            Ok(_) => {
                provenance.binary_resolution_proven = validate_local_package_bin(
                    &candidate,
                    &directory.join("node_modules").join(tool),
                    tool,
                    environment,
                    context,
                    provenance,
                    completeness,
                );
                return;
            }
        }
    }
    if let Some(prefix) = global_prefix {
        let candidate = prefix.join("bin").join(tool);
        if std::fs::symlink_metadata(candidate).is_ok() {
            mark_runner_configuration_unresolved(provenance, completeness);
            return;
        }
    }
    // Without a verified local package shim npm may infer/download a package,
    // consult the npx cache, or fall through to another PATH/global binary.
    mark_runner_configuration_unresolved(provenance, completeness);
}

fn scan_runner_file_provenance(
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    tool: &str,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) {
    if !context.static_config_enabled {
        mark_runner_configuration_unresolved(provenance, completeness);
        return;
    }
    let Some(selected_process_cwd) = context.cwd.clone().filter(|cwd| cwd.is_absolute()) else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return;
    };
    let Some(process_cwd) =
        trusted_root_canonical_identity(&selected_process_cwd, provenance, completeness)
    else {
        return;
    };
    // CLI --prefix selects npm's localPrefix and package/bin lookup root, but
    // npm still launches the child in the caller's process cwd. Keep those two
    // roots distinct so nested npm metadata cannot relocate Foundry/Solana
    // configuration and stale root node_modules cannot prove the child binary.
    let explicit_cli_prefix = provenance.cli.prefix.clone();
    let cli_local_prefix = explicit_cli_prefix.as_ref().and_then(|prefix| {
        resolve_runner_config_path(prefix, Some(&process_cwd), provenance, completeness)
    });
    let (resolution_cwd, local_prefix) = if explicit_cli_prefix.is_some() {
        let Some(prefix) = cli_local_prefix.clone() else {
            return;
        };
        (prefix.clone(), prefix)
    } else {
        let Some(prefix) = npm_local_prefix(&process_cwd, provenance, completeness) else {
            return;
        };
        (process_cwd.clone(), prefix)
    };

    let mut files_scanned = 0usize;
    let mut visited = BTreeSet::new();
    let selected_userconfig = provenance
        .cli
        .userconfig
        .clone()
        .or_else(|| provenance.environment.userconfig.clone());
    let user_path = if let Some(userconfig) = selected_userconfig.as_ref() {
        provenance.custom_configuration = true;
        resolve_runner_config_path(userconfig, context.cwd.as_deref(), provenance, completeness)
    } else {
        let home = context.environment.get("HOME").map(PathBuf::from);
        match home.filter(|home| home.is_absolute()) {
            Some(home) => Some(home.join(".npmrc")),
            None => {
                mark_runner_configuration_unresolved(provenance, completeness);
                None
            }
        }
    };
    let user_layer = user_path
        .as_deref()
        .map(|path| {
            scan_npmrc_layer(
                path,
                selected_userconfig.is_some(),
                provenance,
                completeness,
                &mut files_scanned,
                &mut visited,
            )
        })
        .unwrap_or_default();

    let explicit_global = provenance
        .cli
        .globalconfig
        .clone()
        .or_else(|| provenance.environment.globalconfig.clone())
        .or_else(|| user_layer.globalconfig.clone());
    let selected_prefix = provenance
        .cli
        .prefix
        .clone()
        .or_else(|| provenance.environment.prefix.clone())
        .or_else(|| user_layer.prefix.clone())
        .or_else(|| provenance.environment_prefix_default.clone());
    let resolved_prefix = selected_prefix.as_ref().and_then(|prefix| {
        resolve_runner_config_path(prefix, Some(&process_cwd), provenance, completeness)
    });
    let global_path = if let Some(globalconfig) = explicit_global.as_ref() {
        provenance.custom_configuration = true;
        resolve_runner_config_path(
            globalconfig,
            context.cwd.as_deref(),
            provenance,
            completeness,
        )
    } else if let Some(prefix) = resolved_prefix.as_ref() {
        Some(prefix.join("etc/npmrc"))
    } else {
        mark_runner_configuration_unresolved(provenance, completeness);
        None
    };
    let global_layer = global_path
        .as_deref()
        .map(|path| {
            scan_npmrc_layer(
                path,
                explicit_global.is_some(),
                provenance,
                completeness,
                &mut files_scanned,
                &mut visited,
            )
        })
        .unwrap_or_default();
    let project_layer = scan_npmrc_layer(
        &local_prefix.join(".npmrc"),
        false,
        provenance,
        completeness,
        &mut files_scanned,
        &mut visited,
    );

    provenance.custom_configuration |= [&global_layer, &user_layer, &project_layer]
        .into_iter()
        .any(|layer| layer.userconfig.is_some() || layer.globalconfig.is_some());
    // User/CLI/environment prefix participate in the typed bootstrap above.
    // A prefix discovered only after loading global/project config can relocate
    // npm's global bin/config roots after that bootstrap, so keep it unsupported
    // rather than claiming the earlier paths remain authoritative.
    provenance.custom_configuration |=
        global_layer.prefix.is_some() || project_layer.prefix.is_some();

    let environment_layer = provenance.environment.clone();
    let cli_layer = provenance.cli.clone();
    evaluate_effective_npm_settings(
        [
            &global_layer,
            &user_layer,
            &project_layer,
            &environment_layer,
            &cli_layer,
        ],
        provenance,
    );
    prove_runner_binary_resolution(
        &resolution_cwd,
        &local_prefix,
        resolved_prefix.as_deref(),
        tool,
        environment,
        context,
        provenance,
        completeness,
    );
}

fn record_runner_selector(
    selector: Arg,
    values: &mut Vec<Arg>,
    completeness: &mut Completeness,
) -> Option<()> {
    let safe = selector.statically_bound
        && !selector.value.is_empty()
        && selector.value.len() <= 128
        && selector.value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '/' | '.' | '-' | '_' | '+' | '^' | '~' | '<' | '>' | '=' | '*'
                )
        });
    if !safe {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    if values
        .iter()
        .any(|existing| existing.value != selector.value)
    {
        completeness.add(IncompleteReason::ConflictingSelector);
        return None;
    }
    values.push(selector);
    Some(())
}

fn record_runner_config_path(
    value: Arg,
    selected: &mut Option<Arg>,
    completeness: &mut Completeness,
) -> Option<()> {
    if !value.statically_bound || !valid_npm_path_value(&value.value) {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    *selected = Some(value);
    Some(())
}

fn scan_runner_options(
    args: &[Arg],
    index: &mut usize,
    end: usize,
    completeness: &mut Completeness,
    provenance: &mut RunnerProvenance,
) -> Option<()> {
    while *index < end {
        let parameter = args[*index].value.as_str();
        if parameter == "--" {
            *index += 1;
            break;
        }
        if !parameter.starts_with('-') || parameter == "-" {
            break;
        }
        let (name, attached) = split_attached_flag(parameter);
        let scoped_registry = name
            .strip_prefix("--")
            .filter(|name| name.starts_with('@') && name.ends_with(":registry"));
        let spec = spec_for(name, RUNNER_OPTIONS);
        let Some(canonical) = spec
            .map(|spec| spec.canonical)
            .or_else(|| scoped_registry.map(|_| "scoped-registry"))
        else {
            completeness.add(IncompleteReason::UnknownOption);
            return None;
        };
        if canonical == "dynamic-call" {
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        if canonical == "unsafe-runner-mode" {
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        let value = if spec.is_some_and(|spec| spec.takes_value) || scoped_registry.is_some() {
            match attached {
                Some("") => {
                    completeness.add(IncompleteReason::MissingFlagValue);
                    return None;
                }
                Some(attached) => Some(runner_option_value(&args[*index], attached)),
                None => {
                    let Some(value) = args.get(*index + 1).filter(|_| *index + 1 < end) else {
                        completeness.add(IncompleteReason::MissingFlagValue);
                        return None;
                    };
                    *index += 1;
                    Some(value.clone())
                }
            }
        } else if attached.is_some() {
            completeness.add(IncompleteReason::UnknownOption);
            return None;
        } else {
            None
        };
        if canonical == "prefix" {
            let value = value?;
            record_runner_config_path(value.clone(), &mut provenance.cli.prefix, completeness)?;
        } else if canonical == "package" {
            record_runner_selector(value?, &mut provenance.packages, completeness)?;
        } else if canonical == "workspace" {
            record_runner_selector(value?, &mut provenance.workspaces, completeness)?;
        } else if canonical == "registry" || canonical == "scoped-registry" {
            let value = value?;
            if !value.statically_bound || !valid_npm_setting_value(&value.value) {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
            let setting = scoped_registry.unwrap_or("registry");
            let mut layer = std::mem::take(&mut provenance.cli);
            insert_npm_setting(&mut layer, setting, &value.value, provenance, completeness);
            provenance.cli = layer;
        } else if canonical == "userconfig" {
            record_runner_config_path(value?, &mut provenance.cli.userconfig, completeness)?;
        } else if canonical == "globalconfig" {
            record_runner_config_path(value?, &mut provenance.cli.globalconfig, completeness)?;
        } else if matches!(
            canonical,
            "strict-ssl"
                | "ca"
                | "cafile"
                | "cert"
                | "key"
                | "proxy"
                | "https-proxy"
                | "cache"
                | "script-shell"
        ) {
            let value = value?;
            if !value.statically_bound || !valid_npm_setting_value(&value.value) {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
            let mut layer = std::mem::take(&mut provenance.cli);
            insert_npm_setting(
                &mut layer,
                canonical,
                &value.value,
                provenance,
                completeness,
            );
            provenance.cli = layer;
        } else if canonical == "no-strict-ssl" {
            provenance
                .cli
                .values
                .insert("strict-ssl".to_string(), "false".to_string());
        } else if canonical == "workspace-mode" {
            provenance.workspace_mode = true;
        }
        *index += 1;
    }
    Some(())
}

fn package_runner_child(
    args: &[Arg],
    start: usize,
    script_mode: bool,
    completeness: &mut Completeness,
    provenance: &mut RunnerProvenance,
) -> Option<Invocation> {
    let mut index = start;
    scan_runner_options(args, &mut index, args.len(), completeness, provenance)?;
    let Some(command) = args.get(index).cloned() else {
        completeness.add(IncompleteReason::AmbiguousSubcommand);
        return None;
    };
    if !command.statically_bound {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    if script_mode {
        // npm/yarn script names are package.json indirection, not executable
        // identities. This parser never evaluates package.json scripts, so a
        // script named `hardhat`/`forge` cannot impersonate that tool.
        completeness.add(IncompleteReason::DynamicExecutionUnsupported);
        return None;
    }
    if matches!(
        reviewed_package_tool(&command.value),
        ReviewedPackageTool::Other
    ) && (command.value.starts_with('@')
        || command.value.starts_with('.')
        || command.value.contains('/')
        || command.value.contains('\\')
        || command.value.contains(':'))
    {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    let child_value = command.value.clone();
    let command = match reviewed_package_tool(&command.value) {
        ReviewedPackageTool::Known(tool) if command.value == tool => tool.to_string(),
        ReviewedPackageTool::Known(_) => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
        ReviewedPackageTool::UnsafeKnownSpec => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
        ReviewedPackageTool::Other => command.raw,
    };
    if !provenance.packages.is_empty() {
        let mut selected_tool = None;
        for package in &provenance.packages {
            let ReviewedPackageTool::Known(tool) = reviewed_package_tool(&package.value) else {
                completeness.add(IncompleteReason::UnresolvedIndirection);
                return None;
            };
            if selected_tool.is_some_and(|existing| existing != tool) {
                completeness.add(IncompleteReason::ConflictingSelector);
                return None;
            }
            selected_tool = Some(tool);
        }
        if selected_tool != Some(child_value.as_str()) {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
    }
    Some(Invocation {
        command,
        // Once the child command is located, every remaining token belongs to
        // it. Child flags must never be reconsidered as runner options.
        args: args[index + 1..].to_vec(),
    })
}

fn literal_runner_child(
    args: &[Arg],
    start: usize,
    completeness: &mut Completeness,
) -> Option<Invocation> {
    let mut index = start;
    if args
        .get(index)
        .is_some_and(|argument| argument.value == "--")
    {
        index += 1;
    }
    let Some(command) = args.get(index).cloned() else {
        completeness.add(IncompleteReason::AmbiguousSubcommand);
        return None;
    };
    if !command.statically_bound {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    let command = match reviewed_package_tool(&command.value) {
        ReviewedPackageTool::Known(tool) if command.value == tool => tool.to_string(),
        ReviewedPackageTool::Known(_) | ReviewedPackageTool::UnsafeKnownSpec => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
        ReviewedPackageTool::Other
            if !command.value.is_empty()
                && command.value.len() <= 128
                && command.value.chars().all(|character| {
                    character == '-' || character == '_' || character.is_ascii_alphanumeric()
                }) =>
        {
            command.raw
        }
        ReviewedPackageTool::Other => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
    };
    Some(Invocation {
        command,
        args: args[index + 1..].to_vec(),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiteralRunnerKind {
    Pnpm,
    Yarn,
    Bun,
    Bunx,
}

#[derive(Default)]
struct LiteralRunnerPrefix {
    cwd: Option<Arg>,
    dynamic_scope: bool,
}

fn record_literal_runner_cwd(
    value: Arg,
    selected: &mut Option<Arg>,
    completeness: &mut Completeness,
) -> Option<()> {
    if !value.statically_bound || !valid_npm_path_value(&value.value) {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    if selected
        .as_ref()
        .is_some_and(|existing| existing.value != value.value)
    {
        completeness.add(IncompleteReason::ConflictingSelector);
        return None;
    }
    *selected = Some(value);
    Some(())
}

fn literal_runner_prefix_value(
    args: &[Arg],
    index: &mut usize,
    attached: Option<&str>,
    completeness: &mut Completeness,
) -> Option<Arg> {
    match attached {
        Some("") => {
            completeness.add(IncompleteReason::MissingFlagValue);
            None
        }
        Some(value) => Some(runner_option_value(&args[*index], value)),
        None => {
            let Some(value) = args.get(*index + 1) else {
                completeness.add(IncompleteReason::MissingFlagValue);
                return None;
            };
            *index += 1;
            Some(value.clone())
        }
    }
}

fn scan_literal_runner_prefix_option(
    kind: LiteralRunnerKind,
    args: &[Arg],
    index: &mut usize,
    prefix: &mut LiteralRunnerPrefix,
    completeness: &mut Completeness,
) -> Option<()> {
    let parameter = args[*index].value.as_str();
    if !args[*index].statically_bound {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        completeness.add(IncompleteReason::DynamicExecutionUnsupported);
        return None;
    }
    let (mut name, mut attached) = split_attached_flag(parameter);
    if attached.is_none() && kind == LiteralRunnerKind::Pnpm {
        for short in ["-C", "-F"] {
            if parameter
                .strip_prefix(short)
                .is_some_and(|value| !value.is_empty())
            {
                name = short;
                attached = parameter.strip_prefix(short);
                break;
            }
        }
    }
    let cwd_option = matches!(
        (kind, name),
        (LiteralRunnerKind::Pnpm, "--dir" | "--prefix" | "-C")
            | (LiteralRunnerKind::Yarn | LiteralRunnerKind::Bun, "--cwd")
            | (LiteralRunnerKind::Bunx, "--cwd")
    );
    if cwd_option {
        let value = literal_runner_prefix_value(args, index, attached, completeness)?;
        record_literal_runner_cwd(value, &mut prefix.cwd, completeness)?;
        *index += 1;
        return Some(());
    }
    if matches!((kind, name), (LiteralRunnerKind::Pnpm, "--filter" | "-F")) {
        let value = literal_runner_prefix_value(args, index, attached, completeness)?;
        let mut values = Vec::new();
        record_runner_selector(value, &mut values, completeness)?;
        prefix.dynamic_scope = true;
        *index += 1;
        return Some(());
    }
    if matches!((kind, name), (LiteralRunnerKind::Pnpm, "--reporter")) {
        let value = literal_runner_prefix_value(args, index, attached, completeness)?;
        if !value.statically_bound || !valid_npm_setting_value(&value.value) {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return None;
        }
        *index += 1;
        return Some(());
    }
    let safe_flag = matches!(
        (kind, name),
        (LiteralRunnerKind::Pnpm, "--silent")
            | (LiteralRunnerKind::Yarn, "--silent" | "--verbose" | "--json")
            | (LiteralRunnerKind::Bun, "--silent" | "--no-clear-screen")
            | (LiteralRunnerKind::Bunx, "--silent" | "--bun")
    );
    if safe_flag && attached.is_none() {
        *index += 1;
        return Some(());
    }
    if matches!(
        (kind, name),
        (
            LiteralRunnerKind::Pnpm,
            "--workspace-root" | "-w" | "--recursive" | "-r"
        )
    ) && attached.is_none()
    {
        prefix.dynamic_scope = true;
        *index += 1;
        return Some(());
    }
    completeness.add(IncompleteReason::UnknownOption);
    completeness.add(IncompleteReason::DynamicExecutionUnsupported);
    None
}

fn scan_literal_runner_mode_prefix(
    kind: LiteralRunnerKind,
    args: &[Arg],
    modes: &[&str],
    completeness: &mut Completeness,
) -> Option<(usize, LiteralRunnerPrefix)> {
    let mut index = 0usize;
    let mut prefix = LiteralRunnerPrefix::default();
    while let Some(argument) = args.get(index) {
        if !argument.statically_bound {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        if modes.contains(&argument.value.as_str()) {
            return Some((index, prefix));
        }
        if !argument.value.starts_with('-') || argument.value == "-" {
            completeness.add(IncompleteReason::AmbiguousSubcommand);
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        scan_literal_runner_prefix_option(kind, args, &mut index, &mut prefix, completeness)?;
    }
    completeness.add(IncompleteReason::AmbiguousSubcommand);
    None
}

fn scan_bunx_child_prefix(
    args: &[Arg],
    completeness: &mut Completeness,
) -> Option<(usize, LiteralRunnerPrefix)> {
    let mut index = 0usize;
    let mut prefix = LiteralRunnerPrefix::default();
    while let Some(argument) = args.get(index) {
        if !argument.statically_bound {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        if !argument.value.starts_with('-') || argument.value == "-" {
            return Some((index, prefix));
        }
        scan_literal_runner_prefix_option(
            LiteralRunnerKind::Bunx,
            args,
            &mut index,
            &mut prefix,
            completeness,
        )?;
    }
    completeness.add(IncompleteReason::AmbiguousSubcommand);
    None
}

fn project_local_bin_tool(command: &str, shell: ShellType) -> Option<String> {
    let normalized = normalize_shell_token(command, shell).replace('\\', "/");
    let relative = normalized.strip_prefix("./").unwrap_or(normalized.as_str());
    let tool = relative.strip_prefix("node_modules/.bin/").or_else(|| {
        relative
            .rsplit_once("/node_modules/.bin/")
            .map(|(_, tool)| tool)
    })?;
    (!tool.is_empty() && !tool.contains('/') && is_web3_tool_name(tool)).then(|| tool.to_string())
}

fn invocation_may_execute_web3(invocation: &Invocation, shell: ShellType) -> bool {
    let base = normalize_cmd_base(&invocation.command, shell);
    is_web3_tool_name(&base)
        || INTERPRETERS.contains(&base.as_str())
        || invocation
            .args
            .iter()
            .any(|argument| is_web3_tool_name(&normalize_cmd_base(&argument.value, shell)))
}

fn trusted_root_canonical_identity(
    trusted_root: &Path,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    if !trusted_root.is_absolute() {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    let Some(normalized_root) = trusted_root
        .to_str()
        .and_then(|root| resolve_cwd(None, root))
    else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    };
    let root_metadata = match std::fs::symlink_metadata(&normalized_root) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Ok(_) => {
            // In particular, a symlink supplied as the project root must not
            // become the authority from which descendant package paths are
            // trusted.
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        }
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            return None;
        }
    };
    match std::fs::canonicalize(&normalized_root) {
        Ok(canonical) if canonical.is_absolute() => {
            let Ok(canonical_metadata) = std::fs::symlink_metadata(&canonical) else {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return None;
            };
            if !canonical_metadata.file_type().is_dir() {
                mark_runner_configuration_unresolved(provenance, completeness);
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if root_metadata.dev() != canonical_metadata.dev()
                    || root_metadata.ino() != canonical_metadata.ino()
                {
                    mark_runner_configuration_unresolved(provenance, completeness);
                    return None;
                }
            }
            #[cfg(not(unix))]
            let _ = root_metadata;
            Some(canonical)
        }
        Ok(_) => {
            mark_runner_configuration_unresolved(provenance, completeness);
            None
        }
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            None
        }
    }
}

fn trusted_descendant_directory(
    trusted_root: &Path,
    candidate: &Path,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> bool {
    let Some(canonical_root) =
        trusted_root_canonical_identity(trusted_root, provenance, completeness)
    else {
        return false;
    };
    let Ok(relative) = candidate.strip_prefix(trusted_root) else {
        mark_runner_configuration_unresolved(provenance, completeness);
        return false;
    };
    let mut checked = trusted_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            mark_runner_configuration_unresolved(provenance, completeness);
            return false;
        };
        checked.push(component);
        match std::fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return false;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                mark_runner_configuration_unresolved(provenance, completeness);
                return false;
            }
            Err(_) => {
                provenance.configuration_incomplete = true;
                completeness.add(IncompleteReason::ConfigIo);
                return false;
            }
        }
    }
    match std::fs::canonicalize(candidate) {
        Ok(canonical_candidate) if canonical_candidate.starts_with(&canonical_root) => true,
        Ok(_) => {
            mark_runner_configuration_unresolved(provenance, completeness);
            false
        }
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            false
        }
    }
}

fn trusted_runner_cwd(
    context: &Web3ParseContextV2,
    selected: Option<&Arg>,
    provenance: &mut RunnerProvenance,
    completeness: &mut Completeness,
) -> Option<PathBuf> {
    let trusted_root = context.cwd.as_deref().filter(|cwd| cwd.is_absolute())?;
    let cwd = match selected {
        None => trusted_root.to_path_buf(),
        Some(value) if value.statically_bound && valid_npm_path_value(&value.value) => {
            resolve_cwd(Some(trusted_root), &value.value)?
        }
        Some(_) => {
            mark_runner_configuration_unresolved(provenance, completeness);
            return None;
        }
    };
    if !cwd.is_absolute()
        || !cwd.starts_with(trusted_root)
        || !trusted_descendant_directory(trusted_root, &cwd, provenance, completeness)
    {
        mark_runner_configuration_unresolved(provenance, completeness);
        return None;
    }
    match std::fs::canonicalize(&cwd) {
        Ok(canonical) => Some(canonical),
        Err(_) => {
            provenance.configuration_incomplete = true;
            completeness.add(IncompleteReason::ConfigIo);
            None
        }
    }
}

fn exact_project_local_bin_is_proven(
    command: &str,
    shell: ShellType,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    completeness: &mut Completeness,
) -> Option<String> {
    let tool = project_local_bin_tool(command, shell)?;
    let mut provenance = RunnerProvenance::default();
    if !context.static_config_enabled || !command_word_is_statically_bound(command, shell) {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    }
    let trusted_root = context.cwd.as_deref().filter(|cwd| cwd.is_absolute())?;
    let normalized = normalize_shell_token(command, shell).replace('\\', "/");
    let Some(candidate) = resolve_cwd(Some(trusted_root), &normalized) else {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    };
    if !candidate.starts_with(trusted_root) {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    }
    let Some(bin_directory) = candidate.parent().filter(|path| path.ends_with(".bin")) else {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    };
    let Some(node_modules) = bin_directory
        .parent()
        .filter(|path| path.ends_with("node_modules"))
    else {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    };
    let Some(project_directory) = node_modules.parent() else {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return None;
    };
    if !trusted_descendant_directory(
        trusted_root,
        project_directory,
        &mut provenance,
        completeness,
    ) || !validate_local_package_bin(
        &candidate,
        &node_modules.join(&tool),
        &tool,
        environment,
        context,
        &mut provenance,
        completeness,
    ) {
        return None;
    }
    Some(tool)
}

fn yarn_manifest_changes_tool_resolution(package: &serde_json::Value, tool: &str) -> bool {
    if package.get("packageManager").is_some()
        || package.pointer("/devEngines/packageManager").is_some()
        || package.get("installConfig").is_some()
        || package.get("workspaces").is_some()
        || package.get("volta").is_some()
    {
        return true;
    }
    if let Some(scripts) = package.get("scripts") {
        let Some(scripts) = scripts.as_object() else {
            return true;
        };
        if [
            tool.to_string(),
            format!("pre{tool}"),
            format!("post{tool}"),
        ]
        .iter()
        .any(|name| scripts.contains_key(name))
        {
            return true;
        }
    }
    match package.get("bin") {
        None => false,
        Some(serde_json::Value::String(_)) => package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(|name| name.rsplit('/').next())
            .is_none_or(|name| name == tool),
        Some(serde_json::Value::Object(values)) => values.contains_key(tool),
        Some(_) => true,
    }
}

fn exact_project_bin_is_proven(
    context: &Web3ParseContextV2,
    environment: &EffectiveEnvironment,
    cwd: &Path,
    tool: &str,
    reject_package_script: bool,
    completeness: &mut Completeness,
) -> bool {
    let mut provenance = RunnerProvenance::default();
    if !context.static_config_enabled {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return false;
    }
    if !cwd.is_absolute() {
        mark_runner_configuration_unresolved(&mut provenance, completeness);
        return false;
    }
    if reject_package_script {
        if !inspect_yarn_bootstrap_configuration(
            cwd,
            environment,
            context,
            &mut provenance,
            completeness,
        ) {
            return false;
        }
        for directory in cwd.ancestors().take(MAX_NPMRC_ANCESTORS) {
            let manifest = directory.join("package.json");
            match std::fs::symlink_metadata(&manifest) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    completeness.add(IncompleteReason::ConfigIo);
                    return false;
                }
                Ok(metadata) if metadata.file_type().is_file() => {
                    let Some(package) =
                        read_runner_package_json(&manifest, &mut provenance, completeness)
                    else {
                        return false;
                    };
                    if yarn_manifest_changes_tool_resolution(&package, tool) {
                        mark_runner_configuration_unresolved(&mut provenance, completeness);
                        return false;
                    }
                }
                Ok(_) => {
                    completeness.add(IncompleteReason::ConfigNotRegular);
                    return false;
                }
            }
        }
        if cwd.ancestors().nth(MAX_NPMRC_ANCESTORS).is_some() {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return false;
        }
    }
    validate_local_package_bin(
        &cwd.join("node_modules/.bin").join(tool),
        &cwd.join("node_modules").join(tool),
        tool,
        environment,
        context,
        &mut provenance,
        completeness,
    )
}

#[derive(Clone, Copy)]
enum RunnerResolutionMode {
    Npm,
    ExactLocal { reject_package_script: bool },
    RemoteExact,
}

struct UnwrappedInvocation {
    invocation: Invocation,
    selected_cwd: Option<Arg>,
}

fn unwrap_package_runners(
    mut invocation: Invocation,
    shell: ShellType,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
    completeness: &mut Completeness,
) -> Option<UnwrappedInvocation> {
    let mut runner_provenance = RunnerProvenance::default();
    let mut runner_mode = None;
    let mut selected_runner_cwd = None;
    let mut dynamic_runner_scope = false;
    for _ in 0..MAX_WRAPPER_DEPTH {
        if is_project_local_bin_command(&invocation.command) {
            let Some(_) = project_local_bin_tool(&invocation.command, shell) else {
                if invocation_may_execute_web3(&invocation, shell) {
                    completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                }
                return None;
            };
            scan_runner_bootstrap_environment_provenance(
                environment,
                context,
                &mut runner_provenance,
                completeness,
            );
            if runner_provenance.custom_configuration || runner_provenance.configuration_incomplete
            {
                completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                return None;
            }
            let Some(tool) = exact_project_local_bin_is_proven(
                &invocation.command,
                shell,
                environment,
                context,
                completeness,
            ) else {
                completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                return None;
            };
            invocation.command = tool;
            return Some(UnwrappedInvocation {
                invocation,
                selected_cwd: None,
            });
        }
        let base = normalize_cmd_base(&invocation.command, shell);
        if is_package_runner_name(&base) && runner_mode.is_some() {
            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            return None;
        }
        let next = match base.as_str() {
            "npx" => {
                runner_mode = Some(RunnerResolutionMode::Npm);
                package_runner_child(
                    &invocation.args,
                    0,
                    false,
                    completeness,
                    &mut runner_provenance,
                )?
            }
            "npm" => {
                runner_mode = Some(RunnerResolutionMode::Npm);
                let Some(task) = invocation
                    .args
                    .iter()
                    .position(|arg| matches!(arg.value.as_str(), "exec" | "run" | "run-script"))
                else {
                    completeness.add(IncompleteReason::AmbiguousSubcommand);
                    return None;
                };
                let script_mode =
                    matches!(invocation.args[task].value.as_str(), "run" | "run-script");
                let mut prefix_index = 0;
                scan_runner_options(
                    &invocation.args,
                    &mut prefix_index,
                    task,
                    completeness,
                    &mut runner_provenance,
                )?;
                if prefix_index != task {
                    completeness.add(IncompleteReason::AmbiguousSubcommand);
                    return None;
                }
                package_runner_child(
                    &invocation.args,
                    task + 1,
                    script_mode,
                    completeness,
                    &mut runner_provenance,
                )?
            }
            "pnpm" => {
                let (mode_index, prefix) = scan_literal_runner_mode_prefix(
                    LiteralRunnerKind::Pnpm,
                    &invocation.args,
                    &["exec", "dlx"],
                    completeness,
                )?;
                let mode = invocation.args[mode_index].value.as_str();
                runner_mode = Some(match mode {
                    "exec" => RunnerResolutionMode::ExactLocal {
                        reject_package_script: false,
                    },
                    "dlx" => RunnerResolutionMode::RemoteExact,
                    _ => unreachable!("bounded mode grammar"),
                });
                selected_runner_cwd = prefix.cwd;
                dynamic_runner_scope = prefix.dynamic_scope;
                literal_runner_child(&invocation.args, mode_index + 1, completeness)?
            }
            "yarn" => {
                let (mode_index, prefix) = scan_literal_runner_mode_prefix(
                    LiteralRunnerKind::Yarn,
                    &invocation.args,
                    &["run", "dlx"],
                    completeness,
                )?;
                let mode = invocation.args[mode_index].value.as_str();
                runner_mode = Some(match mode {
                    "run" => RunnerResolutionMode::ExactLocal {
                        reject_package_script: true,
                    },
                    "dlx" => RunnerResolutionMode::RemoteExact,
                    _ => unreachable!("bounded mode grammar"),
                });
                selected_runner_cwd = prefix.cwd;
                dynamic_runner_scope = prefix.dynamic_scope;
                literal_runner_child(&invocation.args, mode_index + 1, completeness)?
            }
            "bunx" => {
                let (child_index, prefix) = scan_bunx_child_prefix(&invocation.args, completeness)?;
                runner_mode = Some(RunnerResolutionMode::RemoteExact);
                selected_runner_cwd = prefix.cwd;
                literal_runner_child(&invocation.args, child_index, completeness)?
            }
            "bun" => {
                let (mode_index, prefix) = scan_literal_runner_mode_prefix(
                    LiteralRunnerKind::Bun,
                    &invocation.args,
                    &["x"],
                    completeness,
                )?;
                runner_mode = Some(RunnerResolutionMode::RemoteExact);
                selected_runner_cwd = prefix.cwd;
                literal_runner_child(&invocation.args, mode_index + 1, completeness)?
            }
            _ => {
                let Some(mode) = runner_mode else {
                    return Some(UnwrappedInvocation {
                        invocation,
                        selected_cwd: None,
                    });
                };
                let tool = normalize_cmd_base(&invocation.command, shell);
                if !is_web3_tool_name(&tool) {
                    if matches!(
                        mode,
                        RunnerResolutionMode::ExactLocal {
                            reject_package_script: true
                        }
                    ) {
                        completeness.add(IncompleteReason::UnresolvedIndirection);
                    }
                    if invocation_may_execute_web3(&invocation, shell) {
                        completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                    }
                    return None;
                }
                match mode {
                    RunnerResolutionMode::Npm => {
                        scan_runner_environment_provenance(
                            environment,
                            context,
                            &mut runner_provenance,
                            completeness,
                        );
                        scan_runner_file_provenance(
                            environment,
                            context,
                            &tool,
                            &mut runner_provenance,
                            completeness,
                        );
                        if !runner_provenance.workspaces.is_empty()
                            || runner_provenance.workspace_mode
                            || runner_provenance.custom_configuration
                            || runner_provenance.configuration_incomplete
                            || !runner_provenance.binary_resolution_proven
                        {
                            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                            return None;
                        }
                    }
                    RunnerResolutionMode::ExactLocal {
                        reject_package_script,
                    } => {
                        scan_runner_bootstrap_environment_provenance(
                            environment,
                            context,
                            &mut runner_provenance,
                            completeness,
                        );
                        if runner_provenance.custom_configuration
                            || runner_provenance.configuration_incomplete
                            || dynamic_runner_scope
                        {
                            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                            return None;
                        }
                        let Some(cwd) = trusted_runner_cwd(
                            context,
                            selected_runner_cwd.as_ref(),
                            &mut runner_provenance,
                            completeness,
                        ) else {
                            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                            return None;
                        };
                        if !exact_project_bin_is_proven(
                            context,
                            environment,
                            &cwd,
                            &tool,
                            reject_package_script,
                            completeness,
                        ) {
                            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                            return None;
                        }
                    }
                    RunnerResolutionMode::RemoteExact => {
                        if selected_runner_cwd.is_some()
                            && trusted_runner_cwd(
                                context,
                                selected_runner_cwd.as_ref(),
                                &mut runner_provenance,
                                completeness,
                            )
                            .is_none()
                        {
                            completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                            return None;
                        }
                        // The exact Web3 child is visible, but dlx/bunx may
                        // fetch mutable package contents. Emit conservative
                        // facts while retaining an explicit execution gap.
                        completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                    }
                }
                return Some(UnwrappedInvocation {
                    invocation,
                    selected_cwd: selected_runner_cwd,
                });
            }
        };
        invocation = next;
    }
    completeness.add(IncompleteReason::PackageRunnerDepthExceeded);
    None
}

fn environment_value(
    environment: &EffectiveEnvironment,
    names: &[&str],
    completeness: &mut Completeness,
) -> Option<SelectorReference> {
    if environment.values.len() > MAX_CONTEXT_SELECTORS {
        completeness.add(IncompleteReason::ContextSelectorBudgetExceeded);
    }
    names
        .iter()
        .find_map(|name| match environment.values.get(*name) {
            Some(EffectiveEnvironmentValue::Set(value)) if value.len() <= MAX_SELECTOR_BYTES => {
                Some(SelectorReference {
                    value: value.clone(),
                    source: SelectorSource::LeadingEnvironment,
                    span: None,
                })
            }
            Some(EffectiveEnvironmentValue::Set(_)) => {
                completeness.add(IncompleteReason::SelectorBytesExceeded);
                None
            }
            _ => None,
        })
}

fn environment_unresolved(environment: &EffectiveEnvironment, names: &[&str]) -> bool {
    names.iter().any(|name| {
        matches!(
            environment.values.get(*name),
            Some(EffectiveEnvironmentValue::Unresolved)
        )
    })
}

fn bounded_selector_map(
    source: &BTreeMap<String, String>,
    completeness: &mut Completeness,
) -> BTreeMap<String, String> {
    if source.len() > MAX_CONTEXT_SELECTORS {
        completeness.add(IncompleteReason::ContextSelectorBudgetExceeded);
        return BTreeMap::new();
    }
    source
        .iter()
        .filter_map(|(name, value)| {
            if name.len() > MAX_SELECTOR_BYTES || value.len() > MAX_SELECTOR_BYTES {
                completeness.add(IncompleteReason::SelectorBytesExceeded);
                None
            } else {
                Some((name.clone(), value.clone()))
            }
        })
        .collect()
}

fn bounded_parse_context(context: &Web3ParseContextV2) -> (Web3ParseContextV2, Completeness) {
    let mut completeness = Completeness::complete();
    let environment = bounded_selector_map(&context.environment, &mut completeness);
    let ambient_selectors = bounded_selector_map(&context.ambient_selectors, &mut completeness);
    let trusted_rpc_path_prefixes = match context.trusted_rpc_path_prefixes.as_ref() {
        None => None,
        Some(matchers)
            if matchers.len() > MAX_TRUSTED_RPC_PATH_MATCHERS
                || matchers
                    .iter()
                    .try_fold(0usize, |total, matcher| {
                        total.checked_add(matcher.prefix_len())
                    })
                    .is_none_or(|total| total > MAX_TRUSTED_RPC_MATCHER_BYTES) =>
        {
            completeness.add(IncompleteReason::RpcPathMatcherBudgetExceeded);
            Some(Vec::new())
        }
        Some(matchers) => Some(matchers.clone()),
    };
    (
        Web3ParseContextV2 {
            cwd: context.cwd.clone(),
            environment,
            ambient_selectors,
            foundry_config_path: context.foundry_config_path.clone(),
            solana_config_path: context.solana_config_path.clone(),
            anchor_config_path: context.anchor_config_path.clone(),
            trusted_rpc_path_prefixes,
            static_config_enabled: context.static_config_enabled,
        },
        completeness,
    )
}

fn bounded_v1_parse_context(context: &Web3ParseContext) -> (Web3ParseContextV2, Completeness) {
    let mut completeness = Completeness::complete();
    let environment = bounded_selector_map(&context.environment, &mut completeness);
    let ambient_selectors = bounded_selector_map(&context.ambient_selectors, &mut completeness);
    (
        Web3ParseContextV2 {
            cwd: context.cwd.clone(),
            environment,
            ambient_selectors,
            foundry_config_path: context.foundry_config_path.clone(),
            solana_config_path: context.solana_config_path.clone(),
            anchor_config_path: context.anchor_config_path.clone(),
            trusted_rpc_path_prefixes: None,
            static_config_enabled: context.static_config_enabled,
        },
        completeness,
    )
}

fn invalidate_context_paths(context: &mut Web3ParseContextV2) {
    context.foundry_config_path = None;
    context.solana_config_path = None;
    context.anchor_config_path = None;
}

fn config_home_changed(environment: &EffectiveEnvironment) -> bool {
    environment.clear_ambient
        || environment
            .values
            .keys()
            .any(|name| name.as_str() == "HOME")
}

fn rederive_default_context_paths(
    context: &mut Web3ParseContextV2,
    completeness: &mut Completeness,
) {
    invalidate_context_paths(context);
    let config_home = context
        .environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join(".config"));
    context.solana_config_path = config_home.and_then(|base| {
        if base.is_absolute() {
            Some(base.join("solana/cli/config.yml"))
        } else {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            None
        }
    });
    // Foundry and Anchor defaults are project-relative. Leaving their explicit
    // overrides empty makes the bounded readers derive them from the effective
    // cwd instead of retaining a caller-derived path.
}

fn resolve_cwd(base: Option<&Path>, value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    let selected = PathBuf::from(value);
    let joined = if selected.is_absolute() {
        selected
    } else {
        base?.join(selected)
    };
    let absolute = joined.is_absolute();
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::ParentDir) | None if !absolute => normalized.push(".."),
                _ => {}
            },
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(value) => normalized.push(value),
        }
    }
    Some(normalized)
}

fn set_context_cwd(context: &mut Web3ParseContextV2, value: &Arg, completeness: &mut Completeness) {
    if value.statically_bound {
        context.cwd = resolve_cwd(context.cwd.as_deref(), &value.value);
    } else {
        context.cwd = None;
    }
    invalidate_context_paths(context);
    if context.cwd.is_none() {
        completeness.add(IncompleteReason::WorkingDirectoryUnresolved);
    }
}

fn effective_parse_context(
    context: &Web3ParseContextV2,
    effective: &EffectiveCommand,
) -> (Web3ParseContextV2, Completeness) {
    let mut completeness = Completeness::complete();
    if effective.execution_context_changed && effective.privileged_context_changed {
        completeness.add(IncompleteReason::ExecutionContextChanged);
        return (
            Web3ParseContextV2 {
                static_config_enabled: context.static_config_enabled,
                ..Web3ParseContextV2::default()
            },
            completeness,
        );
    }
    let mut resolved = context.clone();
    let rederive_config_paths = config_home_changed(&effective.environment);
    if effective.environment.clear_ambient {
        resolved.environment.clear();
        resolved.ambient_selectors.clear();
    }
    if effective.environment.values.len() > MAX_CONTEXT_SELECTORS {
        resolved.environment.clear();
        resolved.ambient_selectors.clear();
        completeness.add(IncompleteReason::ContextSelectorBudgetExceeded);
    } else {
        for (name, value) in &effective.environment.values {
            if name.len() > MAX_SELECTOR_BYTES {
                completeness.add(IncompleteReason::SelectorBytesExceeded);
                continue;
            }
            match value {
                EffectiveEnvironmentValue::Set(value) if value.len() <= MAX_SELECTOR_BYTES => {
                    resolved.environment.insert(name.clone(), value.clone());
                    resolved
                        .ambient_selectors
                        .insert(name.clone(), value.clone());
                }
                EffectiveEnvironmentValue::Set(_) => {
                    resolved.environment.remove(name);
                    resolved.ambient_selectors.remove(name);
                    completeness.add(IncompleteReason::SelectorBytesExceeded);
                }
                EffectiveEnvironmentValue::Unset => {
                    resolved.environment.remove(name);
                    resolved.ambient_selectors.remove(name);
                }
                EffectiveEnvironmentValue::Unresolved => {
                    resolved.environment.remove(name);
                    resolved.ambient_selectors.remove(name);
                    completeness.add(IncompleteReason::UnresolvedIndirection);
                }
            }
        }
    }
    if resolved.environment.len() > MAX_CONTEXT_SELECTORS
        || resolved.ambient_selectors.len() > MAX_CONTEXT_SELECTORS
    {
        resolved.environment.clear();
        resolved.ambient_selectors.clear();
        completeness.add(IncompleteReason::ContextSelectorBudgetExceeded);
    }
    match effective.environment.cwd.as_ref() {
        Some(EffectiveEnvironmentValue::Set(value)) => {
            let selected = PathBuf::from(value);
            resolved.cwd = if selected.is_absolute() {
                Some(selected)
            } else {
                context.cwd.as_ref().map(|cwd| cwd.join(selected))
            };
            invalidate_context_paths(&mut resolved);
            if resolved.cwd.is_none() {
                completeness.add(IncompleteReason::WorkingDirectoryUnresolved);
            }
        }
        Some(EffectiveEnvironmentValue::Unset | EffectiveEnvironmentValue::Unresolved) => {
            resolved.cwd = None;
            invalidate_context_paths(&mut resolved);
            completeness.add(IncompleteReason::WorkingDirectoryUnresolved);
        }
        None => {}
    }
    if rederive_config_paths {
        rederive_default_context_paths(&mut resolved, &mut completeness);
    }
    (resolved, completeness)
}

fn ambient_value(
    context: &Web3ParseContextV2,
    names: &[&str],
    completeness: &mut Completeness,
) -> Option<SelectorReference> {
    names.iter().find_map(|name| {
        context
            .ambient_selectors
            .get(*name)
            .filter(|value| {
                if value.len() > MAX_SELECTOR_BYTES {
                    completeness.add(IncompleteReason::SelectorBytesExceeded);
                    false
                } else {
                    true
                }
            })
            .map(|value| SelectorReference {
                value: value.clone(),
                source: SelectorSource::AmbientEnvironment,
                span: None,
            })
    })
}

fn merge_static(facts: &mut Web3CommandFactsV2, selectors: StaticSelectors) {
    facts.completeness.merge(&selectors.completeness);
    let replace_rpc_alias = facts.rpc.as_ref().is_some_and(|rpc| {
        rpc.host.is_none() && rpc.alias.is_some() && rpc.source != SelectorSource::Unresolved
    });
    if (facts.rpc.is_none() || replace_rpc_alias) && selectors.rpc.is_some() {
        facts.rpc = selectors.rpc;
    }
    if facts.network.network.is_none() {
        facts.network.network = selectors.network.network;
    }
    if facts.network.chain.is_none() {
        facts.network.chain = selectors.network.chain;
    }
    for signer in selectors.signers {
        push_signer(facts, signer.role, signer.signer);
    }
}

fn merge_foundry_static(facts: &mut Web3CommandFactsV2, selectors: StaticSelectors) {
    let higher_precedence = facts
        .rpc
        .as_ref()
        .filter(|rpc| rpc.host.is_none() && rpc.alias.is_some())
        .map(|rpc| (rpc.source, rpc.span));
    merge_static(facts, selectors);
    if let (Some((source, span)), Some(rpc)) = (higher_precedence, facts.rpc.as_mut()) {
        rpc.source = source;
        rpc.span = span;
    }
}

fn resolved_solana_rpc(facts: &Web3CommandFactsV2) -> bool {
    facts.rpc.as_ref().is_some_and(|rpc| {
        rpc.host.is_some()
            || matches!(
                rpc.alias.as_deref(),
                Some(
                    "mainnet-beta"
                        | "mainnet"
                        | "testnet"
                        | "devnet"
                        | "localhost"
                        | "m"
                        | "t"
                        | "d"
                        | "l"
                )
            )
    })
}

fn has_signer_role(facts: &Web3CommandFactsV2, role: SignerRole) -> bool {
    facts.signers.iter().any(|signer| signer.role == role)
}

fn resolved_signer_role(facts: &Web3CommandFactsV2, role: SignerRole) -> bool {
    facts
        .signer(role)
        .is_some_and(|signer| match signer.kind() {
            SignerKindV2::RawPrivateKey
            | SignerKindV2::RawKeypair
            | SignerKindV2::Mnemonic
            | SignerKindV2::Ledger
            | SignerKindV2::Trezor
            | SignerKindV2::AwsKms
            | SignerKindV2::UnlockedNode
            | SignerKindV2::Stdin
            | SignerKindV2::Prompt => true,
            SignerKindV2::KeypairFile | SignerKindV2::Keystore | SignerKindV2::AccountAlias => {
                signer
                    .nonsecret_reference()
                    .is_some_and(|reference| !reference.is_empty())
            }
            SignerKindV2::Unknown => false,
        })
}

fn push_signer(facts: &mut Web3CommandFactsV2, role: SignerRole, signer: SignerReferenceV2) {
    if signer.kind() == SignerKindV2::Unknown || signer.source() == SelectorSource::Unresolved {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
    if !has_signer_role(facts, role) {
        facts.signers.push(RoleTaggedSigner { role, signer });
        facts.signers.sort_by_key(|signer| signer.role);
    }
    refresh_legacy_signer(facts);
}

fn refresh_legacy_signer(facts: &mut Web3CommandFactsV2) {
    facts.signer = [
        SignerRole::Default,
        SignerRole::Keypair,
        SignerRole::Wallet,
        SignerRole::Authority,
        SignerRole::FeePayer,
        SignerRole::ProgramId,
    ]
    .into_iter()
    .find_map(|role| facts.signer(role).cloned());
}

fn push_destination(facts: &mut Web3CommandFactsV2, mut destination: DestinationReference) {
    if destination
        .value
        .as_deref()
        .is_some_and(retained_value_is_secret)
    {
        destination.value = None;
        destination.source = SelectorSource::Unresolved;
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
    if facts.destination.is_none() {
        facts.destination = Some(destination.clone());
    }
    if !facts.destinations.contains(&destination) {
        facts.destinations.push(destination);
    }
}

fn redact_public_fact_secret_shapes(facts: &mut Web3CommandFactsV2) {
    let mut redacted = false;
    for selector in [facts.network.network.as_mut(), facts.network.chain.as_mut()]
        .into_iter()
        .flatten()
    {
        if retained_value_is_secret(&selector.value) {
            selector.value = "<redacted>".to_string();
            selector.source = SelectorSource::Unresolved;
            redacted = true;
        }
    }
    if let Some(rpc) = facts.rpc.as_mut() {
        let mut rpc_redacted = false;
        for value in [&mut rpc.scheme, &mut rpc.host, &mut rpc.alias] {
            if value.as_deref().is_some_and(retained_value_is_secret) {
                *value = None;
                rpc_redacted = true;
            }
        }
        if rpc_redacted {
            rpc.source = SelectorSource::Unresolved;
            redacted = true;
        }
    }
    for destination in facts
        .destination
        .iter_mut()
        .chain(facts.destinations.iter_mut())
    {
        if destination
            .value
            .as_deref()
            .is_some_and(retained_value_is_secret)
        {
            destination.value = None;
            destination.source = SelectorSource::Unresolved;
            redacted = true;
        }
    }
    if let Some(artifact) = facts.artifact.as_mut() {
        if artifact
            .value
            .as_deref()
            .is_some_and(retained_value_is_secret)
        {
            artifact.value = None;
            artifact.source = SelectorSource::Unresolved;
            redacted = true;
        }
    }
    if redacted {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
}

fn base58_value(character: u8) -> Option<u32> {
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        .iter()
        .position(|candidate| *candidate == character)
        .and_then(|value| u32::try_from(value).ok())
}

fn is_solana_pubkey(value: &str) -> bool {
    // A 32-byte value is 32..=44 Base58 characters. Reject outside that
    // envelope before decoding so adversarial argv cannot make decode work or
    // storage scale with operand length.
    if !(32..=44).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
    let mut decoded_le = [0u8; 32];
    let mut decoded_len = 0usize;
    for character in value.bytes() {
        let Some(mut carry) = base58_value(character) else {
            return false;
        };
        for byte in &mut decoded_le[..decoded_len] {
            let expanded = u32::from(*byte) * 58 + carry;
            *byte = (expanded & 0xff) as u8;
            carry = expanded >> 8;
        }
        while carry > 0 {
            if decoded_len == decoded_le.len() {
                return false;
            }
            decoded_le[decoded_len] = (carry & 0xff) as u8;
            decoded_len += 1;
            carry >>= 8;
        }
    }
    leading_zeroes.saturating_add(decoded_len) == 32
}

fn program_keypair_signer(
    facts: &mut Web3CommandFactsV2,
    value: &Arg,
) -> Option<SignerReferenceV2> {
    if !value.statically_bound {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    let signer = if value.value == "-" {
        SignerReferenceV2::reference(
            SignerKindV2::Stdin,
            SelectorSource::ExplicitFlag,
            value.span,
            None,
        )
    } else if value.value.eq_ignore_ascii_case("ASK") {
        SignerReferenceV2::reference(
            SignerKindV2::Prompt,
            SelectorSource::ExplicitFlag,
            value.span,
            None,
        )
    } else if value.value.contains("://") {
        let signer = SignerReferenceV2::reference(
            SignerKindV2::KeypairFile,
            SelectorSource::ExplicitFlag,
            value.span,
            Some(value.value.clone()),
        );
        if signer.kind() == SignerKindV2::KeypairFile {
            facts
                .completeness
                .add(IncompleteReason::UnresolvedIndirection);
            SignerReferenceV2::reference(
                SignerKindV2::Unknown,
                SelectorSource::Unresolved,
                value.span,
                None,
            )
        } else {
            signer
        }
    } else {
        SignerReferenceV2::reference(
            SignerKindV2::KeypairFile,
            SelectorSource::ExplicitFlag,
            value.span,
            Some(value.value.clone()),
        )
    };
    Some(signer)
}

fn retain_program_keypair(facts: &mut Web3CommandFactsV2, value: &Arg, signer: SignerReferenceV2) {
    let retained_file = if signer.kind() == SignerKindV2::KeypairFile {
        signer.nonsecret_reference().map(str::to_string)
    } else {
        None
    };
    push_destination(
        facts,
        DestinationReference {
            kind: DestinationKind::ProgramIdFile,
            value: retained_file,
            source: SelectorSource::ExplicitFlag,
            span: value.span,
        },
    );
    push_signer(facts, SignerRole::ProgramId, signer);
}

fn apply_program_id_selector(facts: &mut Web3CommandFactsV2, value: Arg) {
    if !value.statically_bound {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
        return;
    }
    if is_solana_pubkey(&value.value) {
        push_destination(
            facts,
            DestinationReference {
                kind: DestinationKind::Address,
                value: Some(value.value),
                source: SelectorSource::ExplicitFlag,
                span: value.span,
            },
        );
        return;
    }
    if let Some(signer) = program_keypair_signer(facts, &value) {
        retain_program_keypair(facts, &value, signer);
    }
}

fn apply_anchor_program_keypair(facts: &mut Web3CommandFactsV2, value: Arg) {
    if !value.statically_bound {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
        return;
    }
    // Anchor documents this flag as a path. Do not reuse Solana's broader
    // program-id signer grammar: `-`, `ASK`, and URI-looking values are still
    // filenames here. URI-shaped paths remain secret reads but are not retained
    // in facts because their path/query components may contain credentials.
    let retained = (!value.value.contains("://")).then(|| value.value.clone());
    let signer = SignerReferenceV2::literal_reference(
        SignerKindV2::KeypairFile,
        SelectorSource::ExplicitFlag,
        value.span,
        retained,
    );
    retain_program_keypair(facts, &value, signer);
}

fn default_solana_keypair(context: &Web3ParseContextV2) -> SignerReferenceV2 {
    let reference = context
        .environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join(".config"))
        .filter(|path| path.is_absolute())
        .map(|path| path.join("solana/id.json").to_string_lossy().into_owned());
    SignerReferenceV2::reference(
        SignerKindV2::KeypairFile,
        SelectorSource::ToolDefault,
        None,
        reference,
    )
}

fn base_facts(tool: Web3ToolFamily, segment: &tokenize::Segment) -> Web3CommandFactsV2 {
    Web3CommandFactsV2 {
        tool,
        operation: Web3OperationV2::Unknown,
        write_mode: Web3WriteMode::Unknown,
        network: NetworkEvidence::default(),
        rpc: None,
        signer: None,
        signers: Vec::new(),
        destination: None,
        destinations: Vec::new(),
        artifact: None,
        safety_flags: Vec::new(),
        source_span: source_span(segment),
        completeness: Completeness::complete(),
    }
}

struct SignerCandidate {
    kind: SignerKindV2,
    source: SelectorSource,
    span: Option<SourceSpan>,
    reference: Option<String>,
    comparison: String,
}

fn choose_signer(
    candidates: Vec<SignerCandidate>,
    completeness: &mut Completeness,
) -> Option<SignerReferenceV2> {
    let first = candidates.first()?;
    if candidates
        .iter()
        .skip(1)
        .any(|candidate| candidate.kind != first.kind || candidate.comparison != first.comparison)
    {
        completeness.add(IncompleteReason::ConflictingSelector);
        return Some(SignerReferenceV2::reference(
            SignerKindV2::Unknown,
            SelectorSource::Unresolved,
            None,
            None,
        ));
    }
    if first.kind.is_raw_secret() {
        Some(SignerReferenceV2::raw(first.kind, first.source, first.span))
    } else {
        Some(SignerReferenceV2::reference(
            first.kind,
            first.source,
            first.span,
            first.reference.clone(),
        ))
    }
}

const FOUNDRY_FLAGS: &[FlagSpec<'_>] = &[
    FlagSpec {
        canonical: "rpc",
        aliases: &["--rpc-url", "-r", "--fork-url"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "chain",
        aliases: &["--chain", "-c"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "profile",
        aliases: &["--profile"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "private-key",
        aliases: &["--private-key"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "mnemonic",
        aliases: &["--mnemonic", "--mnemonics"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "keystore",
        aliases: &["--keystore"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "account",
        aliases: &["--account", "--sender", "--from"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "ledger",
        aliases: &["--ledger"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "trezor",
        aliases: &["--trezor"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "aws",
        aliases: &["--aws"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "unlocked",
        aliases: &["--unlocked"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "broadcast",
        aliases: &["--broadcast"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "resume",
        aliases: &["--resume"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "create",
        aliases: &["--create"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "dry-run",
        aliases: &["--dry-run"],
        takes_value: false,
    },
    // Only `--no-send` suppresses broadcast. `--offline` merely forbids network
    // access during dependency/solc resolution, and `--generate-unsigned` is not
    // a Foundry suppression flag at all, so neither may downgrade a `cast send`
    // out of StateChanging. Grouping them here made `cast send --offline` report
    // a complete, gap-free NoChainWrite and deleted its Web3Write effect.
    FlagSpec {
        canonical: "no-send",
        aliases: &["--no-send"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "offline",
        aliases: &["--offline"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "force",
        aliases: &["--force"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "skip-simulation",
        aliases: &["--skip-simulation"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "slow",
        aliases: &["--slow"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "verify",
        aliases: &["--verify"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "root",
        aliases: &["--root"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "contracts",
        aliases: &["--contracts"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "sig",
        aliases: &["--sig"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "value",
        aliases: &["--value"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "gas-limit",
        aliases: &["--gas-limit"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "gas-price",
        aliases: &["--gas-price"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "nonce",
        aliases: &["--nonce"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "json",
        aliases: &["--json"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "legacy",
        aliases: &["--legacy"],
        takes_value: false,
    },
];

fn parse_foundry_common(
    parsed: &ParsedArgs,
    facts: &mut Web3CommandFactsV2,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
) -> (Option<String>, Option<String>) {
    facts.completeness.merge(&parsed.completeness);
    let rpc = selected_value(parsed, "rpc", &mut facts.completeness);
    let chain = selected_value(parsed, "chain", &mut facts.completeness);
    let profile = selected_value(parsed, "profile", &mut facts.completeness);
    if let Some(value) = chain
        .as_ref()
        .and_then(|value| selector(value, SelectorSource::ExplicitFlag))
    {
        facts.network.chain = Some(value);
    } else if let Some(value) = environment_value(
        environment,
        &["CHAIN", "FOUNDRY_CHAIN"],
        &mut facts.completeness,
    ) {
        facts.network.chain = Some(value);
    } else {
        if environment_unresolved(environment, &["CHAIN", "FOUNDRY_CHAIN"]) {
            facts
                .completeness
                .add(IncompleteReason::UnresolvedIndirection);
        }
        facts.network.chain = ambient_value(
            context,
            &["CHAIN", "FOUNDRY_CHAIN"],
            &mut facts.completeness,
        );
    }
    let mut requested_alias = rpc.as_ref().map(|value| value.value.clone());
    if let Some(value) = rpc {
        if value.statically_bound {
            facts.rpc = Some(rpc_reference(
                &value.value,
                SelectorSource::ExplicitFlag,
                value.span,
                context.trusted_rpc_path_prefixes.as_deref(),
                &mut facts.completeness,
            ));
        } else {
            facts
                .completeness
                .add(IncompleteReason::UnresolvedIndirection);
        }
    } else if let Some(value) = environment_value(
        environment,
        &["ETH_RPC_URL", "FOUNDRY_ETH_RPC_URL"],
        &mut facts.completeness,
    )
    .or_else(|| {
        ambient_value(
            context,
            &["ETH_RPC_URL", "FOUNDRY_ETH_RPC_URL"],
            &mut facts.completeness,
        )
    }) {
        requested_alias = Some(value.value.clone());
        facts.rpc = Some(rpc_reference(
            &value.value,
            value.source,
            value.span,
            context.trusted_rpc_path_prefixes.as_deref(),
            &mut facts.completeness,
        ));
    } else if environment_unresolved(environment, &["ETH_RPC_URL", "FOUNDRY_ETH_RPC_URL"]) {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
    let profile = profile.map(|value| value.value).or_else(|| {
        environment_value(environment, &["FOUNDRY_PROFILE"], &mut facts.completeness)
            .map(|value| value.value)
    });
    let profile = profile.or_else(|| {
        ambient_value(context, &["FOUNDRY_PROFILE"], &mut facts.completeness)
            .map(|value| value.value)
    });
    (profile, requested_alias)
}

fn foundry_signer(
    parsed: &ParsedArgs,
    completeness: &mut Completeness,
    fallback_span: SourceSpan,
) -> Option<SignerReferenceV2> {
    let mut candidates = Vec::new();
    for value in values(parsed, "private-key") {
        candidates.push(SignerCandidate {
            kind: SignerKindV2::RawPrivateKey,
            source: SelectorSource::ExplicitFlag,
            span: value.span.or(Some(fallback_span)),
            reference: None,
            comparison: value.value.clone(),
        });
    }
    for value in values(parsed, "mnemonic") {
        candidates.push(SignerCandidate {
            kind: SignerKindV2::Mnemonic,
            source: SelectorSource::ExplicitFlag,
            span: value.span.or(Some(fallback_span)),
            reference: None,
            comparison: value.value.clone(),
        });
    }
    for (name, kind) in [
        ("keystore", SignerKindV2::Keystore),
        ("account", SignerKindV2::AccountAlias),
    ] {
        for value in values(parsed, name) {
            candidates.push(SignerCandidate {
                kind,
                source: SelectorSource::ExplicitFlag,
                span: value.span.or(Some(fallback_span)),
                reference: Some(value.value.clone()),
                comparison: value.value.clone(),
            });
        }
    }
    for (name, kind) in [
        ("ledger", SignerKindV2::Ledger),
        ("trezor", SignerKindV2::Trezor),
        ("aws", SignerKindV2::AwsKms),
        ("unlocked", SignerKindV2::UnlockedNode),
    ] {
        if has_flag(parsed, name) {
            candidates.push(SignerCandidate {
                kind,
                source: SelectorSource::ExplicitFlag,
                span: flag_span(parsed, name).or(Some(fallback_span)),
                reference: None,
                comparison: name.to_string(),
            });
        }
    }
    choose_signer(candidates, completeness)
}

fn foundry_context(
    parsed: &ParsedArgs,
    facts: &mut Web3CommandFactsV2,
    context: &Web3ParseContextV2,
) -> Web3ParseContextV2 {
    let mut resolved = context.clone();
    if !has_flag(parsed, "root") {
        return resolved;
    }
    let root = selected_value(parsed, "root", &mut facts.completeness);
    let root = root
        .as_ref()
        .filter(|root| root.statically_bound)
        .and_then(|root| resolve_cwd(context.cwd.as_deref(), &root.value));
    resolved.cwd = root.clone();
    resolved.foundry_config_path = root.map(|root| root.join("foundry.toml"));
    if resolved.cwd.is_none() {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
    resolved
}

fn solana_context(
    parsed: &ParsedArgs,
    facts: &mut Web3CommandFactsV2,
    context: &Web3ParseContextV2,
) -> Web3ParseContextV2 {
    let mut resolved = context.clone();
    if !has_flag(parsed, "config") {
        return resolved;
    }
    let config = selected_value(parsed, "config", &mut facts.completeness);
    resolved.solana_config_path = config
        .as_ref()
        .filter(|config| config.statically_bound)
        .and_then(|config| resolve_cwd(context.cwd.as_deref(), &config.value));
    if resolved.solana_config_path.is_none() {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
    }
    resolved
}

fn parse_cast(
    invocation: &Invocation,
    shell: ShellType,
    segment: &tokenize::Segment,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
) -> Web3CommandFactsV2 {
    let parsed = parse_args(&invocation.args, shell, FOUNDRY_FLAGS);
    let mut facts = base_facts(Web3ToolFamily::Cast, segment);
    facts.completeness.merge(&parsed.completeness);
    let subcommand = parsed.positionals.first().map(|value| value.value.as_str());
    match subcommand {
        Some("send") => {
            facts.operation = if has_flag(&parsed, "create") {
                Web3OperationV2::Create
            } else {
                Web3OperationV2::Send
            };
            facts.write_mode = if has_flag(&parsed, "dry-run") || has_flag(&parsed, "no-send") {
                Web3WriteMode::NoChainWrite
            } else {
                Web3WriteMode::StateChanging
            };
            if let Some(operand) = parsed.positionals.get(1) {
                if has_flag(&parsed, "create") {
                    facts.artifact = Some(ArtifactReference {
                        kind: ArtifactKind::ContractBytecode,
                        value: None,
                        source: SelectorSource::Positional,
                        span: operand.span,
                    });
                } else {
                    push_destination(
                        &mut facts,
                        DestinationReference {
                            kind: DestinationKind::Address,
                            value: operand.statically_bound.then(|| operand.value.clone()),
                            source: SelectorSource::Positional,
                            span: operand.span,
                        },
                    );
                }
            }
        }
        Some("call") => {
            facts.operation = Web3OperationV2::Call;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        Some("balance") => {
            facts.operation = Web3OperationV2::Balance;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        Some("code") => {
            facts.operation = Web3OperationV2::Code;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        Some("mktx") | Some("make-tx") => {
            facts.operation = Web3OperationV2::MakeTransaction;
            facts.write_mode = Web3WriteMode::NoChainWrite;
        }
        Some(_) | None => {
            facts.operation = Web3OperationV2::Unknown;
            facts.write_mode = Web3WriteMode::Unknown;
            facts
                .completeness
                .add(IncompleteReason::AmbiguousSubcommand);
        }
    }
    let uses_selectors = facts.operation != Web3OperationV2::Unknown;
    let selector_context = uses_selectors.then(|| foundry_context(&parsed, &mut facts, context));
    let selectors = selector_context.as_ref().map(|context| {
        let (profile, requested_rpc) =
            parse_foundry_common(&parsed, &mut facts, environment, context);
        (context, profile, requested_rpc)
    });
    if uses_selectors
        && matches!(
            facts.operation,
            Web3OperationV2::Send | Web3OperationV2::Create | Web3OperationV2::MakeTransaction
        )
    {
        if let Some(signer) = foundry_signer(&parsed, &mut facts.completeness, facts.source_span) {
            push_signer(&mut facts, SignerRole::Default, signer);
        }
    }
    if has_flag(&parsed, "dry-run") {
        facts.safety_flags.push(Web3SafetyFlag::DryRun);
    }
    if has_flag(&parsed, "no-send") {
        facts.safety_flags.push(Web3SafetyFlag::NoSend);
    }
    if has_flag(&parsed, "offline") {
        facts.safety_flags.push(Web3SafetyFlag::Offline);
    }
    if has_flag(&parsed, "unlocked") {
        facts.safety_flags.push(Web3SafetyFlag::Unlocked);
    }
    if has_flag(&parsed, "force") {
        facts.safety_flags.push(Web3SafetyFlag::Force);
    }
    if let Some((context, profile, requested_rpc)) = selectors {
        if facts.rpc.as_ref().is_some_and(|rpc| rpc.host.is_none()) || facts.rpc.is_none() {
            merge_foundry_static(
                &mut facts,
                foundry_selectors(context, profile.as_deref(), requested_rpc.as_deref()),
            );
        }
        // Only claim the tool default when the operator named no endpoint at
        // all. If an `--rpc-url` occurrence exists but did not resolve, the
        // endpoint is unknown, and reporting `http://localhost:8545` would
        // describe a live-network send as a local dev one.
        if facts.rpc.is_none() && !has_flag(&parsed, "rpc") {
            facts.rpc = Some(rpc_reference(
                "http://localhost:8545",
                SelectorSource::ToolDefault,
                None,
                context.trusted_rpc_path_prefixes.as_deref(),
                &mut facts.completeness,
            ));
        }
    }
    facts
}

fn parse_forge(
    invocation: &Invocation,
    shell: ShellType,
    segment: &tokenize::Segment,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
) -> Web3CommandFactsV2 {
    let parsed = parse_args(&invocation.args, shell, FOUNDRY_FLAGS);
    let mut facts = base_facts(Web3ToolFamily::Forge, segment);
    facts.completeness.merge(&parsed.completeness);
    match parsed.positionals.first().map(|value| value.value.as_str()) {
        Some("script") => {
            facts.operation = Web3OperationV2::Script;
            facts.write_mode = if has_flag(&parsed, "broadcast") || has_flag(&parsed, "resume") {
                Web3WriteMode::StateChanging
            } else {
                Web3WriteMode::DryRun
            };
            if let Some(script) = parsed.positionals.get(1) {
                facts.artifact = Some(ArtifactReference {
                    kind: ArtifactKind::Script,
                    value: script.statically_bound.then(|| script.value.clone()),
                    source: SelectorSource::Positional,
                    span: script.span,
                });
            } else {
                facts
                    .completeness
                    .add(IncompleteReason::AmbiguousSubcommand);
            }
        }
        Some("build") => {
            facts.operation = Web3OperationV2::Build;
            facts.write_mode = Web3WriteMode::NoChainWrite;
        }
        Some("test") => {
            facts.operation = Web3OperationV2::Test;
            facts.write_mode = Web3WriteMode::NoChainWrite;
        }
        _ => facts
            .completeness
            .add(IncompleteReason::AmbiguousSubcommand),
    }
    let uses_selectors = matches!(
        facts.operation,
        Web3OperationV2::Script | Web3OperationV2::Test
    );
    let selector_context = uses_selectors.then(|| foundry_context(&parsed, &mut facts, context));
    let selectors = selector_context.as_ref().map(|context| {
        let (profile, requested_rpc) =
            parse_foundry_common(&parsed, &mut facts, environment, context);
        (context, profile, requested_rpc)
    });
    if uses_selectors {
        if let Some(signer) = foundry_signer(&parsed, &mut facts.completeness, facts.source_span) {
            push_signer(&mut facts, SignerRole::Default, signer);
        }
    }
    if has_flag(&parsed, "broadcast") {
        facts.safety_flags.push(Web3SafetyFlag::Broadcast);
    }
    if has_flag(&parsed, "resume") {
        facts.safety_flags.push(Web3SafetyFlag::Resume);
    }
    if facts.write_mode == Web3WriteMode::StateChanging {
        if has_flag(&parsed, "skip-simulation") {
            facts.safety_flags.push(Web3SafetyFlag::SkipSimulation);
        }
        if has_flag(&parsed, "slow") {
            facts.safety_flags.push(Web3SafetyFlag::Slow);
        }
        if has_flag(&parsed, "verify") {
            facts.safety_flags.push(Web3SafetyFlag::Verify);
        }
    }
    if let Some((context, profile, requested_rpc)) = selectors {
        if facts.rpc.as_ref().is_some_and(|rpc| rpc.host.is_none()) || facts.rpc.is_none() {
            merge_foundry_static(
                &mut facts,
                foundry_selectors(context, profile.as_deref(), requested_rpc.as_deref()),
            );
        }
    }
    facts
}

const HARDHAT_FLAGS: &[FlagSpec<'_>] = &[
    FlagSpec {
        canonical: "network",
        aliases: &["--network"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "config",
        aliases: &["--config"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "verify",
        aliases: &["--verify"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "deployment-id",
        aliases: &["--deployment-id"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "parameters",
        aliases: &["--parameters"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "reset",
        aliases: &["--reset"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "write-localhost-deployment",
        aliases: &["--write-localhost-deployment"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "show-stack-traces",
        aliases: &["--show-stack-traces"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "version",
        aliases: &["--version"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "help",
        aliases: &["--help"],
        takes_value: false,
    },
];

fn deployment_filename(path: &str) -> bool {
    let stem = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .split('.')
        .next()
        .unwrap_or(path);
    stem.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|component| {
            matches!(
                component.to_ascii_lowercase().as_str(),
                "deploy" | "deployment" | "upgrade" | "migrate" | "migration"
            )
        })
}

fn parse_hardhat(
    invocation: &Invocation,
    shell: ShellType,
    segment: &tokenize::Segment,
) -> Web3CommandFactsV2 {
    let parsed = parse_args(&invocation.args, shell, HARDHAT_FLAGS);
    let mut facts = base_facts(Web3ToolFamily::Hardhat, segment);
    facts.completeness.merge(&parsed.completeness);
    let tasks: Vec<&str> = parsed
        .positionals
        .iter()
        .map(|value| value.value.as_str())
        .collect();
    match tasks.as_slice() {
        ["ignition", "deploy", ..] => {
            facts.operation = Web3OperationV2::IgnitionDeploy;
            facts.write_mode = Web3WriteMode::StateChanging;
            if let Some(module) = parsed.positionals.get(2) {
                facts.artifact = Some(ArtifactReference {
                    kind: ArtifactKind::IgnitionModule,
                    value: module.statically_bound.then(|| module.value.clone()),
                    source: SelectorSource::Positional,
                    span: module.span,
                });
            }
        }
        [task, ..]
            if matches!(
                *task,
                "deploy" | "deploy-zksync" | "deploy:main" | "migrate"
            ) =>
        {
            facts.operation = Web3OperationV2::PluginDeploy;
            facts.write_mode = Web3WriteMode::StateChanging;
        }
        ["run", script, ..] => {
            facts.operation = Web3OperationV2::RunScript;
            facts.write_mode = if deployment_filename(script) {
                Web3WriteMode::PotentialWrite
            } else {
                Web3WriteMode::Unknown
            };
            let value = parsed.positionals.get(1).unwrap();
            facts.artifact = Some(ArtifactReference {
                kind: ArtifactKind::Script,
                value: value.statically_bound.then(|| value.value.clone()),
                source: SelectorSource::Positional,
                span: value.span,
            });
            if facts.write_mode == Web3WriteMode::Unknown {
                facts
                    .completeness
                    .add(IncompleteReason::UnresolvedIndirection);
            }
        }
        ["compile", ..] => {
            facts.operation = Web3OperationV2::Build;
            facts.write_mode = Web3WriteMode::NoChainWrite;
        }
        ["test", ..] => {
            facts.operation = Web3OperationV2::Test;
            facts.write_mode = Web3WriteMode::PotentialWrite;
        }
        _ => facts
            .completeness
            .add(IncompleteReason::AmbiguousSubcommand),
    }
    if matches!(
        facts.write_mode,
        Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
    ) {
        if let Some(network) = selected_value(&parsed, "network", &mut facts.completeness) {
            facts.network.network = selector(&network, SelectorSource::ExplicitFlag);
        }
    }
    if matches!(
        facts.write_mode,
        Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
    ) {
        // v1 intentionally never imports or evaluates hardhat.config.ts. Even
        // with an explicit network, signer/provider details remain dynamic.
        facts
            .completeness
            .add(IncompleteReason::DynamicConfigUnsupported);
    }
    facts
}

const SOLANA_FLAGS: &[FlagSpec<'_>] = &[
    FlagSpec {
        canonical: "rpc",
        aliases: &["--url", "-u", "--json-rpc-url"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "keypair",
        aliases: &["--keypair", "-k"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "program-id",
        aliases: &["--program-id"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "authority",
        aliases: &["--upgrade-authority", "--authority"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "fee-payer",
        aliases: &["--fee-payer"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "config",
        aliases: &["--config"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "commitment",
        aliases: &["--commitment"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "output",
        aliases: &["--output", "-o"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "skip-preflight",
        aliases: &["--skip-preflight"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "final",
        aliases: &["--final"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "use-rpc",
        aliases: &["--use-rpc"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "verbose",
        aliases: &["--verbose", "-v"],
        takes_value: false,
    },
];

fn parse_solana(
    invocation: &Invocation,
    shell: ShellType,
    segment: &tokenize::Segment,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
) -> Web3CommandFactsV2 {
    let parsed = parse_args(&invocation.args, shell, SOLANA_FLAGS);
    let mut facts = base_facts(Web3ToolFamily::Solana, segment);
    facts.completeness.merge(&parsed.completeness);
    let operations: Vec<&str> = parsed
        .positionals
        .iter()
        .map(|value| value.value.as_str())
        .collect();
    match operations.as_slice() {
        ["program", "deploy", ..] => {
            facts.operation = Web3OperationV2::ProgramDeploy;
            facts.write_mode = Web3WriteMode::StateChanging;
            if let Some(program) = parsed.positionals.get(2) {
                facts.artifact = Some(ArtifactReference {
                    kind: ArtifactKind::SolanaProgram,
                    value: program.statically_bound.then(|| program.value.clone()),
                    source: SelectorSource::Positional,
                    span: program.span,
                });
            } else {
                facts
                    .completeness
                    .add(IncompleteReason::AmbiguousSubcommand);
            }
            if let Some(program_id) = selected_value(&parsed, "program-id", &mut facts.completeness)
            {
                apply_program_id_selector(&mut facts, program_id);
            }
        }
        ["program", "show", ..] => {
            facts.operation = Web3OperationV2::ProgramShow;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        ["program", "dump", ..] => {
            facts.operation = Web3OperationV2::ProgramDump;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        ["address", ..] => {
            facts.operation = Web3OperationV2::Address;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        [query, ..]
            if matches!(
                *query,
                "balance"
                    | "account"
                    | "block"
                    | "block-height"
                    | "block-time"
                    | "cluster-date"
                    | "epoch"
                    | "fees"
                    | "genesis-hash"
                    | "inflation"
                    | "largest-accounts"
            ) =>
        {
            facts.operation = Web3OperationV2::Query;
            facts.write_mode = Web3WriteMode::ReadOnly;
        }
        _ => facts
            .completeness
            .add(IncompleteReason::AmbiguousSubcommand),
    }

    let uses_rpc = facts.write_mode == Web3WriteMode::StateChanging
        || (facts.write_mode == Web3WriteMode::ReadOnly
            && facts.operation != Web3OperationV2::Address);
    let uses_signer = facts.write_mode == Web3WriteMode::StateChanging
        || facts.operation == Web3OperationV2::Address;
    if facts.operation == Web3OperationV2::Address && has_flag(&parsed, "use-rpc") {
        facts.completeness.add(IncompleteReason::UnknownOption);
    }
    if uses_rpc || uses_signer {
        let selector_context = solana_context(&parsed, &mut facts, context);
        if uses_rpc {
            if let Some(rpc) = selected_value(&parsed, "rpc", &mut facts.completeness) {
                if rpc.statically_bound {
                    facts.rpc = Some(rpc_reference(
                        &rpc.value,
                        SelectorSource::ExplicitFlag,
                        rpc.span,
                        selector_context.trusted_rpc_path_prefixes.as_deref(),
                        &mut facts.completeness,
                    ));
                }
            }
            if facts.rpc.is_none() {
                if let Some(value) =
                    environment_value(environment, &["SOLANA_URL"], &mut facts.completeness)
                        .or_else(|| {
                            ambient_value(
                                &selector_context,
                                &["SOLANA_URL"],
                                &mut facts.completeness,
                            )
                        })
                {
                    facts.rpc = Some(rpc_reference(
                        &value.value,
                        value.source,
                        value.span,
                        selector_context.trusted_rpc_path_prefixes.as_deref(),
                        &mut facts.completeness,
                    ));
                } else if environment_unresolved(environment, &["SOLANA_URL"]) {
                    facts
                        .completeness
                        .add(IncompleteReason::UnresolvedIndirection);
                }
            }
        }

        if uses_signer {
            // These roles may legitimately refer to different keypairs.
            let signer_roles: &[(&str, SignerRole)] = if facts.operation == Web3OperationV2::Address
            {
                &[("keypair", SignerRole::Keypair)]
            } else {
                &[
                    ("keypair", SignerRole::Keypair),
                    ("authority", SignerRole::Authority),
                    ("fee-payer", SignerRole::FeePayer),
                ]
            };
            for (name, role) in signer_roles {
                if let Some(value) = selected_value(&parsed, name, &mut facts.completeness) {
                    push_signer(
                        &mut facts,
                        *role,
                        SignerReferenceV2::reference(
                            SignerKindV2::KeypairFile,
                            SelectorSource::ExplicitFlag,
                            value.span,
                            value.statically_bound.then(|| value.value.clone()),
                        ),
                    );
                }
            }
            if !has_signer_role(&facts, SignerRole::Keypair) {
                if let Some(value) =
                    environment_value(environment, &["SOLANA_KEYPAIR"], &mut facts.completeness)
                        .or_else(|| {
                            ambient_value(
                                &selector_context,
                                &["SOLANA_KEYPAIR"],
                                &mut facts.completeness,
                            )
                        })
                {
                    push_signer(
                        &mut facts,
                        SignerRole::Keypair,
                        SignerReferenceV2::reference(
                            SignerKindV2::KeypairFile,
                            value.source,
                            value.span,
                            Some(value.value),
                        ),
                    );
                } else if environment_unresolved(environment, &["SOLANA_KEYPAIR"]) {
                    facts
                        .completeness
                        .add(IncompleteReason::UnresolvedIndirection);
                }
            }
        }

        if (uses_rpc && !resolved_solana_rpc(&facts))
            || (uses_signer && !resolved_signer_role(&facts, SignerRole::Keypair))
        {
            let needs_rpc = uses_rpc && !resolved_solana_rpc(&facts);
            let needs_signer = uses_signer && !resolved_signer_role(&facts, SignerRole::Keypair);
            let selectors = solana_selectors(&selector_context, needs_rpc, needs_signer);
            merge_static(&mut facts, selectors);
        }
        if facts.operation == Web3OperationV2::Address
            && !has_signer_role(&facts, SignerRole::Keypair)
        {
            push_signer(
                &mut facts,
                SignerRole::Keypair,
                default_solana_keypair(&selector_context),
            );
        }
    }
    if has_flag(&parsed, "skip-preflight") {
        facts.safety_flags.push(Web3SafetyFlag::SkipPreflight);
    }
    if has_flag(&parsed, "final") {
        facts.safety_flags.push(Web3SafetyFlag::Final);
    }
    if facts.operation != Web3OperationV2::Address && has_flag(&parsed, "use-rpc") {
        facts.safety_flags.push(Web3SafetyFlag::UseRpc);
    }
    if uses_rpc && !resolved_solana_rpc(&facts) {
        facts.completeness.add(IncompleteReason::ConfigMissing);
    }
    if uses_signer && !resolved_signer_role(&facts, SignerRole::Keypair) {
        facts.completeness.add(IncompleteReason::SignerMissing);
    }
    facts
}

const ANCHOR_FLAGS: &[FlagSpec<'_>] = &[
    FlagSpec {
        canonical: "provider-cluster",
        aliases: &["--provider.cluster"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "provider-wallet",
        aliases: &["--provider.wallet"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "program-name",
        aliases: &["--program-name", "-p"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "program-keypair",
        aliases: &["--program-keypair"],
        takes_value: true,
    },
    FlagSpec {
        canonical: "skip-lint",
        aliases: &["--skip-lint"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "skip-build",
        aliases: &["--skip-build"],
        takes_value: false,
    },
    FlagSpec {
        canonical: "verify",
        aliases: &["--verify"],
        takes_value: false,
    },
];

fn anchor_has_endpoint(facts: &Web3CommandFactsV2) -> bool {
    facts.network.network.is_some() || resolved_solana_rpc(facts)
}

fn anchor_has_primary_signer(facts: &Web3CommandFactsV2) -> bool {
    resolved_signer_role(facts, SignerRole::Keypair)
        || resolved_signer_role(facts, SignerRole::Wallet)
}

fn apply_anchor_endpoint(
    facts: &mut Web3CommandFactsV2,
    value: &Arg,
    context: &Web3ParseContextV2,
) {
    if !value.statically_bound {
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
        return;
    }
    if value.value.len() > MAX_SELECTOR_BYTES {
        facts
            .completeness
            .add(IncompleteReason::SelectorBytesExceeded);
        facts
            .completeness
            .add(IncompleteReason::UnresolvedIndirection);
        return;
    }
    facts.rpc = Some(rpc_reference(
        &value.value,
        SelectorSource::ExplicitFlag,
        value.span,
        context.trusted_rpc_path_prefixes.as_deref(),
        &mut facts.completeness,
    ));
    project_anchor_network_from_rpc(facts);
}

fn project_anchor_network_from_rpc(facts: &mut Web3CommandFactsV2) {
    if facts.network.network.is_none() {
        facts.network.network = facts.rpc.as_ref().map(|rpc| SelectorReference {
            value: if rpc.source == SelectorSource::Unresolved {
                "unresolved".to_string()
            } else {
                rpc.alias
                    .clone()
                    .unwrap_or_else(|| "custom_rpc".to_string())
            },
            source: rpc.source,
            span: rpc.span,
        });
    }
}

fn parse_anchor(
    invocation: &Invocation,
    shell: ShellType,
    segment: &tokenize::Segment,
    environment: &EffectiveEnvironment,
    context: &Web3ParseContextV2,
) -> Web3CommandFactsV2 {
    let forwarded_at = invocation
        .args
        .iter()
        .position(|argument| argument.value == "--");
    let anchor_args = forwarded_at
        .map(|index| &invocation.args[..index])
        .unwrap_or(invocation.args.as_slice());
    let forwarded_args = forwarded_at.map(|index| &invocation.args[index + 1..]);
    let parsed = parse_args(anchor_args, shell, ANCHOR_FLAGS);
    let mut facts = base_facts(Web3ToolFamily::Anchor, segment);
    facts.completeness.merge(&parsed.completeness);
    let program_name = selected_value(&parsed, "program-name", &mut facts.completeness);
    if let Some(program) = program_name.as_ref() {
        push_destination(
            &mut facts,
            DestinationReference {
                kind: DestinationKind::Program,
                value: (program.statically_bound && !program.value.is_empty())
                    .then(|| program.value.clone()),
                source: SelectorSource::ExplicitFlag,
                span: program.span,
            },
        );
    }
    match parsed.positionals.first().map(|value| value.value.as_str()) {
        Some("deploy") => {
            facts.operation = Web3OperationV2::AnchorDeploy;
            facts.write_mode = Web3WriteMode::StateChanging;
            facts.artifact = Some(ArtifactReference {
                kind: ArtifactKind::AnchorWorkspace,
                value: None,
                source: SelectorSource::StaticConfig,
                span: None,
            });
        }
        Some("build") => {
            facts.operation = Web3OperationV2::Build;
            facts.write_mode = Web3WriteMode::NoChainWrite;
        }
        Some("test") => {
            facts.operation = Web3OperationV2::Test;
            facts.write_mode = Web3WriteMode::PotentialWrite;
            facts
                .completeness
                .add(IncompleteReason::UnresolvedIndirection);
        }
        _ => facts
            .completeness
            .add(IncompleteReason::AmbiguousSubcommand),
    }
    let forwarded = forwarded_args.map(|arguments| parse_args(arguments, shell, SOLANA_FLAGS));
    if let Some(forwarded) = forwarded.as_ref() {
        facts.completeness.merge(&forwarded.completeness);
        if facts.operation != Web3OperationV2::AnchorDeploy
            || forwarded_args.is_some_and(|arguments| arguments.is_empty())
        {
            facts
                .completeness
                .add(IncompleteReason::AmbiguousSubcommand);
        }
        if !forwarded.positionals.is_empty() {
            // Anchor appends these tokens after its own `solana program deploy`
            // argv. A second positional grammar is not proven by the reviewed
            // help surface, so do not guess which operand it would replace.
            facts
                .completeness
                .add(IncompleteReason::AmbiguousSubcommand);
        }
    }
    let uses_provider = matches!(
        facts.write_mode,
        Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
    );
    if uses_provider {
        let mut forwarded_context = context.clone();
        let mut forwarded_rpc = None;
        let mut forwarded_keypair = None;
        let mut forwarded_config = false;
        let native_program_keypair =
            selected_value(&parsed, "program-keypair", &mut facts.completeness);
        if let Some(program_keypair) = native_program_keypair.as_ref() {
            match program_name.as_ref() {
                Some(name) if name.statically_bound && !name.value.is_empty() => {}
                Some(name) if !name.statically_bound => facts
                    .completeness
                    .add(IncompleteReason::UnresolvedIndirection),
                Some(_) => facts.completeness.add(IncompleteReason::MissingFlagValue),
                None => facts
                    .completeness
                    .add(IncompleteReason::AmbiguousSubcommand),
            }
            apply_anchor_program_keypair(&mut facts, program_keypair.clone());
        }
        if let Some(forwarded) = forwarded.as_ref() {
            forwarded_rpc = selected_value(forwarded, "rpc", &mut facts.completeness);
            forwarded_keypair = selected_value(forwarded, "keypair", &mut facts.completeness);
            forwarded_config = has_flag(forwarded, "config");
            if let Some(program_id) =
                selected_value(forwarded, "program-id", &mut facts.completeness)
            {
                if let Some(native) = native_program_keypair.as_ref() {
                    if native.value != program_id.value {
                        facts
                            .completeness
                            .add(IncompleteReason::ConflictingSelector);
                    }
                } else {
                    apply_program_id_selector(&mut facts, program_id);
                }
            }
            for (name, role) in [
                ("authority", SignerRole::Authority),
                ("fee-payer", SignerRole::FeePayer),
            ] {
                if let Some(value) = selected_value(forwarded, name, &mut facts.completeness) {
                    push_signer(
                        &mut facts,
                        role,
                        SignerReferenceV2::reference(
                            SignerKindV2::KeypairFile,
                            SelectorSource::ExplicitFlag,
                            value.span,
                            value.statically_bound.then(|| value.value.clone()),
                        ),
                    );
                }
            }
            for (name, flag) in [
                ("skip-preflight", Web3SafetyFlag::SkipPreflight),
                ("final", Web3SafetyFlag::Final),
                ("use-rpc", Web3SafetyFlag::UseRpc),
            ] {
                if has_flag(forwarded, name) {
                    facts.safety_flags.push(flag);
                }
            }
        }
        let provider_cluster = selected_value(&parsed, "provider-cluster", &mut facts.completeness);
        let provider_wallet = selected_value(&parsed, "provider-wallet", &mut facts.completeness);
        if forwarded_rpc
            .as_ref()
            .zip(provider_cluster.as_ref())
            .is_some_and(|(forwarded, anchor)| {
                forwarded.statically_bound
                    && anchor.statically_bound
                    && forwarded.value != anchor.value
            })
        {
            facts
                .completeness
                .add(IncompleteReason::ConflictingSelector);
        }
        if forwarded_keypair
            .as_ref()
            .zip(provider_wallet.as_ref())
            .is_some_and(|(forwarded, anchor)| {
                forwarded.statically_bound
                    && anchor.statically_bound
                    && forwarded.value != anchor.value
            })
        {
            facts
                .completeness
                .add(IncompleteReason::ConflictingSelector);
        }
        if let Some(endpoint) = forwarded_rpc.as_ref().or(provider_cluster.as_ref()) {
            apply_anchor_endpoint(&mut facts, endpoint, &forwarded_context);
        }
        if let Some(keypair) = forwarded_keypair.as_ref() {
            push_signer(
                &mut facts,
                SignerRole::Keypair,
                SignerReferenceV2::reference(
                    SignerKindV2::KeypairFile,
                    SelectorSource::ExplicitFlag,
                    keypair.span,
                    keypair.statically_bound.then(|| keypair.value.clone()),
                ),
            );
        } else if let Some(wallet) = provider_wallet.as_ref() {
            push_signer(
                &mut facts,
                SignerRole::Wallet,
                SignerReferenceV2::reference(
                    SignerKindV2::KeypairFile,
                    SelectorSource::ExplicitFlag,
                    wallet.span,
                    wallet.statically_bound.then(|| wallet.value.clone()),
                ),
            );
        }
        if !anchor_has_endpoint(&facts) {
            if let Some(value) = environment_value(
                environment,
                &["ANCHOR_PROVIDER_CLUSTER", "ANCHOR_PROVIDER_URL"],
                &mut facts.completeness,
            )
            .or_else(|| {
                ambient_value(
                    &forwarded_context,
                    &["ANCHOR_PROVIDER_CLUSTER", "ANCHOR_PROVIDER_URL"],
                    &mut facts.completeness,
                )
            }) {
                facts.rpc = Some(rpc_reference(
                    &value.value,
                    value.source,
                    value.span,
                    forwarded_context.trusted_rpc_path_prefixes.as_deref(),
                    &mut facts.completeness,
                ));
                project_anchor_network_from_rpc(&mut facts);
            } else if environment_unresolved(
                environment,
                &["ANCHOR_PROVIDER_CLUSTER", "ANCHOR_PROVIDER_URL"],
            ) {
                facts
                    .completeness
                    .add(IncompleteReason::UnresolvedIndirection);
            }
        }
        if !anchor_has_primary_signer(&facts) {
            if let Some(value) =
                environment_value(environment, &["ANCHOR_WALLET"], &mut facts.completeness).or_else(
                    || {
                        ambient_value(
                            &forwarded_context,
                            &["ANCHOR_WALLET"],
                            &mut facts.completeness,
                        )
                    },
                )
            {
                push_signer(
                    &mut facts,
                    SignerRole::Wallet,
                    SignerReferenceV2::reference(
                        SignerKindV2::KeypairFile,
                        value.source,
                        value.span,
                        Some(value.value),
                    ),
                );
            } else if environment_unresolved(environment, &["ANCHOR_WALLET"]) {
                facts
                    .completeness
                    .add(IncompleteReason::UnresolvedIndirection);
            }
        }
        if !anchor_has_endpoint(&facts) || !anchor_has_primary_signer(&facts) {
            let mut selectors = anchor_selectors(context);
            if anchor_has_endpoint(&facts) {
                selectors.rpc = None;
                selectors.network.network = None;
                selectors.network.chain = None;
            }
            if anchor_has_primary_signer(&facts) {
                selectors.signers.clear();
            }
            merge_static(&mut facts, selectors);
            project_anchor_network_from_rpc(&mut facts);
        }
        if forwarded_config {
            if let Some(forwarded) = forwarded.as_ref() {
                forwarded_context = solana_context(forwarded, &mut facts, context);
            }
            let needs_rpc = !anchor_has_endpoint(&facts);
            let needs_signer = !anchor_has_primary_signer(&facts);
            merge_static(
                &mut facts,
                solana_selectors(&forwarded_context, needs_rpc, needs_signer),
            );
            project_anchor_network_from_rpc(&mut facts);
        }
        if !anchor_has_endpoint(&facts) || !anchor_has_primary_signer(&facts) {
            let needs_rpc = !anchor_has_endpoint(&facts);
            let needs_signer = !anchor_has_primary_signer(&facts);
            merge_static(
                &mut facts,
                solana_selectors(context, needs_rpc, needs_signer),
            );
            project_anchor_network_from_rpc(&mut facts);
        }
    }
    if has_flag(&parsed, "verify") {
        facts.safety_flags.push(Web3SafetyFlag::Verify);
    }
    if facts.write_mode == Web3WriteMode::StateChanging
        && (!anchor_has_endpoint(&facts) || !anchor_has_primary_signer(&facts))
    {
        facts.completeness.add(IncompleteReason::ConfigMissing);
    }
    facts
}

fn effects_for(commands: &[Web3CommandFactsV2], completeness: &mut Completeness) -> CommandEffects {
    let mut effects = Vec::new();
    let mut budget_exceeded = false;
    let mut push_effect = |effect: CommandEffect| {
        if effects.len() == MAX_COMMAND_EFFECTS {
            budget_exceeded = true;
            return false;
        }
        effects.push(effect);
        true
    };
    'commands: for facts in commands {
        let evidence = EffectEvidence {
            kind: EffectEvidenceKind::CommandOperation,
            span: Some(facts.source_span),
        };
        if matches!(
            facts.write_mode,
            Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
        ) && !push_effect(CommandEffect {
            kind: CommandEffectKind::Web3Write,
            source: evidence,
            enforceability: BoundaryCapability::BoundaryDependent,
            completeness: facts.completeness.clone(),
        }) {
            break 'commands;
        }
        for tagged in &facts.signers {
            if !push_effect(CommandEffect {
                kind: CommandEffectKind::Web3SignerUse,
                source: EffectEvidence {
                    kind: EffectEvidenceKind::CommandFlag,
                    span: tagged.signer.span(),
                },
                enforceability: BoundaryCapability::BoundaryDependent,
                completeness: facts.completeness.clone(),
            }) {
                break 'commands;
            }
            if matches!(
                tagged.signer.kind(),
                SignerKindV2::RawPrivateKey
                    | SignerKindV2::RawKeypair
                    | SignerKindV2::Mnemonic
                    | SignerKindV2::KeypairFile
                    | SignerKindV2::Keystore
                    | SignerKindV2::Stdin
                    | SignerKindV2::Prompt
            ) && !push_effect(CommandEffect {
                kind: CommandEffectKind::SecretRead,
                source: EffectEvidence {
                    kind: EffectEvidenceKind::CommandFlag,
                    span: tagged.signer.span(),
                },
                enforceability: BoundaryCapability::BoundaryDependent,
                completeness: facts.completeness.clone(),
            }) {
                break 'commands;
            }
        }
        if (facts.rpc.is_some()
            || matches!(
                facts.write_mode,
                Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
            )
            || (facts.tool == Web3ToolFamily::Solana
                && facts.write_mode == Web3WriteMode::ReadOnly
                && facts.operation != Web3OperationV2::Address))
            && !push_effect(CommandEffect {
                kind: CommandEffectKind::NetworkEgress,
                source: evidence,
                enforceability: BoundaryCapability::BoundaryDependent,
                completeness: facts.completeness.clone(),
            })
        {
            break 'commands;
        }
    }
    if budget_exceeded {
        completeness.add(IncompleteReason::EffectBudgetExceeded);
        for effect in &mut effects {
            effect
                .completeness
                .add(IncompleteReason::EffectBudgetExceeded);
        }
    }
    CommandEffects::new(effects, completeness.clone())
}

fn finalize_bounded_parse_result(
    mut commands: Vec<Web3CommandFactsV2>,
    mut completeness: Completeness,
) -> Web3ParseResultV2 {
    loop {
        for facts in &mut commands {
            facts.completeness.merge(&completeness);
        }
        let effects = effects_for(&commands, &mut completeness);
        if completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::EffectBudgetExceeded)
        {
            for facts in &mut commands {
                facts
                    .completeness
                    .add(IncompleteReason::EffectBudgetExceeded);
            }
        }
        let result = Web3ParseResultV2 {
            commands,
            effects,
            completeness,
        };
        if serde_json::to_vec(&result)
            .is_ok_and(|encoded| encoded.len() <= MAX_WEB3_PARSE_RESULT_JSON_BYTES)
        {
            return result;
        }

        commands = result.commands;
        completeness = result.completeness;
        completeness.add(IncompleteReason::SegmentBudgetExceeded);
        completeness.add(IncompleteReason::UnresolvedIndirection);
        if commands.is_empty() {
            return empty_parse_result(completeness);
        }
        commands.truncate(commands.len() / 2);
    }
}

enum NestedExecution {
    NotNested,
    StaticShell(String),
    Unsupported,
}

impl NestedExecution {
    fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported)
    }

    fn is_not_nested(&self) -> bool {
        matches!(self, Self::NotNested)
    }
}

fn nested_execution(invocation: &Invocation, shell: ShellType) -> NestedExecution {
    let base = normalize_cmd_base(&invocation.command, shell);
    if !matches!(base.as_str(), "bash" | "sh" | "zsh" | "dash") {
        return if INTERPRETERS.contains(&base.as_str())
            || base == "powershell"
            || matches!(
                base.as_str(),
                "eval"
                    | "source"
                    | "."
                    | "builtin"
                    | "nice"
                    | "timeout"
                    | "setsid"
                    | "flock"
                    | "taskset"
                    | "ionice"
                    | "noglob"
                    | "nocorrect"
                    | "repeat"
                    | "xargs"
                    | "find"
                    | "parallel"
                    | "make"
                    | "just"
                    | "task"
                    | "call"
                    | "start"
                    | "pkexec"
                    | "runuser"
                    | "su"
                    | "chroot"
                    | "setpriv"
                    | "capsh"
                    | "nsenter"
                    | "unshare"
                    | "systemd-run"
                    | "osascript"
            ) {
            NestedExecution::Unsupported
        } else {
            NestedExecution::NotNested
        };
    }

    let mut index = 0usize;
    while let Some(argument) = invocation.args.get(index) {
        let value = argument.value.as_str();
        if value == "--" || !value.starts_with('-') || value == "-" {
            return NestedExecution::Unsupported;
        }
        if matches!(value, "--noprofile" | "--norc" | "--posix" | "--login") {
            index += 1;
            continue;
        }
        let Some(cluster) = value
            .strip_prefix('-')
            .filter(|value| !value.starts_with('-'))
        else {
            return NestedExecution::Unsupported;
        };
        if !cluster.is_empty()
            && cluster
                .chars()
                .all(|flag| matches!(flag, 'c' | 'l' | 'i' | 'e' | 'u' | 'x'))
            && cluster.contains('c')
        {
            let Some(body) = invocation.args.get(index + 1) else {
                return NestedExecution::Unsupported;
            };
            return if body.statically_bound {
                NestedExecution::StaticShell(body.value.clone())
            } else {
                NestedExecution::Unsupported
            };
        }
        if cluster
            .chars()
            .all(|flag| matches!(flag, 'l' | 'i' | 'e' | 'u' | 'x'))
        {
            index += 1;
            continue;
        }
        return NestedExecution::Unsupported;
    }
    NestedExecution::Unsupported
}

fn rebase_nested_fact(facts: &mut Web3CommandFactsV2, span: SourceSpan) {
    facts.source_span = span;
    if let Some(rpc) = facts.rpc.as_mut().filter(|rpc| rpc.span.is_some()) {
        rpc.span = Some(span);
    }
    for tagged in &mut facts.signers {
        if tagged.signer.span().is_some() {
            tagged.signer.replace_span(span);
        }
    }
    refresh_legacy_signer(facts);
    for destination in &mut facts.destinations {
        if destination.span.is_some() {
            destination.span = Some(span);
        }
    }
    facts.destination = facts.destinations.first().cloned();
    if let Some(artifact) = facts
        .artifact
        .as_mut()
        .filter(|artifact| artifact.span.is_some())
    {
        artifact.span = Some(span);
    }
}

enum PendingCdChange {
    Static(PathBuf),
    Unresolved,
}

struct PendingCd {
    change: PendingCdChange,
    incoming_pipeline: bool,
}

#[derive(Clone)]
enum ShellVariable {
    Missing,
    Static(String),
    Unresolved,
}

#[derive(Clone, PartialEq, Eq)]
struct PosixFunctionBinding {
    body: Option<Arc<str>>,
    body_kind: crate::extract::PosixFunctionBodyKind,
    readonly: bool,
}

struct PosixFunctionBudget {
    remaining_calls: usize,
    stack: Vec<String>,
    function_state_unresolved: bool,
}

impl Default for PosixFunctionBudget {
    fn default() -> Self {
        Self {
            remaining_calls: MAX_SHELL_SEGMENTS,
            stack: Vec::new(),
            function_state_unresolved: false,
        }
    }
}

/// Root-owned budget shared by every parser/function/subshell/static-shell
/// expansion. The historical name is retained internally, but facts are only
/// one of four independently bounded resources.
struct CommandFactBudget {
    remaining_facts: usize,
    remaining_work: usize,
    remaining_expansions: usize,
    remaining_serialized_command_bytes: usize,
}

impl Default for CommandFactBudget {
    fn default() -> Self {
        Self {
            remaining_facts: MAX_WEB3_WIRE_COMMANDS,
            remaining_work: MAX_WEB3_PARSE_WORK_UNITS,
            remaining_expansions: MAX_WEB3_PARSE_EXPANSIONS,
            remaining_serialized_command_bytes: MAX_WEB3_SERIALIZED_COMMAND_BYTES,
        }
    }
}

impl CommandFactBudget {
    fn retain(&mut self, facts: &Web3CommandFactsV2, completeness: &mut Completeness) -> bool {
        if self.remaining_facts == 0 {
            completeness.add(IncompleteReason::SegmentBudgetExceeded);
            return false;
        }
        let serialized_bytes = serde_json::to_vec(facts)
            .ok()
            .and_then(|encoded| encoded.len().checked_add(1));
        let Some(serialized_bytes) =
            serialized_bytes.filter(|encoded| *encoded <= self.remaining_serialized_command_bytes)
        else {
            completeness.add(IncompleteReason::SegmentBudgetExceeded);
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return false;
        };
        self.remaining_facts -= 1;
        self.remaining_serialized_command_bytes -= serialized_bytes;
        true
    }

    fn enter_parse(&mut self, completeness: &mut Completeness) -> bool {
        if self.remaining_expansions == 0 {
            completeness.add(IncompleteReason::SegmentBudgetExceeded);
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return false;
        }
        self.remaining_expansions -= 1;
        true
    }

    fn retain_work(&mut self, requested: usize, completeness: &mut Completeness) -> usize {
        let retained = requested.min(self.remaining_work);
        self.remaining_work -= retained;
        if retained != requested {
            completeness.add(IncompleteReason::SegmentBudgetExceeded);
            completeness.add(IncompleteReason::UnresolvedIndirection);
        }
        retained
    }
}

struct PosixShellState<'a> {
    context: &'a mut Web3ParseContextV2,
    shell_variables: &'a mut BTreeMap<String, ShellVariable>,
    exported_variables: &'a mut BTreeSet<String>,
    export_all: &'a mut bool,
    cwd_tainted: &'a mut bool,
    cwd_conditionally_set: &'a mut bool,
    functions: &'a mut BTreeMap<String, PosixFunctionBinding>,
}

struct PendingAssignments {
    values: Vec<(String, ShellVariable)>,
    conditionally_executed: bool,
    incoming_pipeline: bool,
}

fn shell_variable(
    segment: &tokenize::Segment,
    shell_variables: &BTreeMap<String, ShellVariable>,
    name: &str,
    shell: ShellType,
) -> ShellVariable {
    let mut selected = shell_variables
        .get(name)
        .cloned()
        .unwrap_or(ShellVariable::Missing);
    let (assignments, _, _) = tokenize::leading_env_assignments_bounded(
        &segment.raw,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    );
    for (candidate, value) in assignments {
        if candidate == name {
            selected = if command_word_is_statically_bound(&value, shell) {
                ShellVariable::Static(normalize_shell_token(&value, shell))
            } else {
                ShellVariable::Unresolved
            };
        }
    }
    selected
}

fn assignment_only_segment(
    segment: &tokenize::Segment,
    shell: ShellType,
) -> Option<Vec<(String, ShellVariable)>> {
    let (words, words_truncated, bytes_truncated) =
        tokenize::split_words_bounded(&segment.raw, MAX_ARGV_ITEMS + 1, MAX_ARGUMENT_BYTES);
    if words_truncated || bytes_truncated || words.is_empty() {
        return None;
    }
    let assignments = words
        .iter()
        .map(|word| word.split_once('='))
        .collect::<Option<Vec<_>>>()?;
    if assignments
        .iter()
        .any(|(name, _)| !valid_shell_variable_name(name))
    {
        return None;
    }
    Some(
        assignments
            .into_iter()
            .map(|(name, value)| {
                let value = if command_word_is_statically_bound(value, shell) {
                    ShellVariable::Static(normalize_shell_token(value, shell))
                } else {
                    ShellVariable::Unresolved
                };
                (name.to_string(), value)
            })
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_pending_assignments(
    assignments: PendingAssignments,
    separator: Option<&str>,
    shell: ShellType,
    shell_variables: &mut BTreeMap<String, ShellVariable>,
    context: &mut Web3ParseContextV2,
    exported_variables: &BTreeSet<String>,
    export_all: bool,
    completeness: &mut Completeness,
) {
    if assignments.incoming_pipeline
        || matches!(separator, Some("|" | "|&"))
        || (separator == Some("&") && shell != ShellType::Cmd)
    {
        return;
    }
    let conditionally_executed = assignments.conditionally_executed;
    for (name, value) in assignments.values {
        let value = if conditionally_executed {
            ShellVariable::Unresolved
        } else {
            value
        };
        shell_variables.insert(name.clone(), value.clone());
        if !export_all && !exported_variables.contains(&name) {
            continue;
        }
        match value {
            ShellVariable::Static(value) => {
                context.environment.insert(name.clone(), value.clone());
                context.ambient_selectors.insert(name.clone(), value);
                if name == "HOME" {
                    rederive_default_context_paths(context, completeness);
                }
            }
            ShellVariable::Missing | ShellVariable::Unresolved => {
                context.environment.remove(&name);
                context.ambient_selectors.remove(&name);
                completeness.add(IncompleteReason::UnresolvedIndirection);
                if name == "HOME" {
                    invalidate_context_paths(context);
                }
            }
        }
    }
}

fn valid_shell_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn update_exported_variable(
    name: &str,
    value: ShellVariable,
    shell_variables: &mut BTreeMap<String, ShellVariable>,
    context: &mut Web3ParseContextV2,
    exported_variables: &mut BTreeSet<String>,
    completeness: &mut Completeness,
) {
    shell_variables.insert(name.to_string(), value.clone());
    exported_variables.insert(name.to_string());
    match value {
        ShellVariable::Static(value) => {
            context.environment.insert(name.to_string(), value.clone());
            context.ambient_selectors.insert(name.to_string(), value);
            if name == "HOME" {
                rederive_default_context_paths(context, completeness);
            }
        }
        ShellVariable::Missing => {
            context.environment.remove(name);
            context.ambient_selectors.remove(name);
            if name == "HOME" {
                invalidate_context_paths(context);
            }
        }
        ShellVariable::Unresolved => {
            context.environment.remove(name);
            context.ambient_selectors.remove(name);
            completeness.add(IncompleteReason::UnresolvedIndirection);
            if name == "HOME" {
                invalidate_context_paths(context);
            }
        }
    }
}

fn taint_shell_environment(
    shell_variables: &mut BTreeMap<String, ShellVariable>,
    context: &mut Web3ParseContextV2,
    completeness: &mut Completeness,
) {
    for value in shell_variables.values_mut() {
        *value = ShellVariable::Unresolved;
    }
    context.environment.clear();
    context.ambient_selectors.clear();
    invalidate_context_paths(context);
    completeness.add(IncompleteReason::UnresolvedIndirection);
}

#[allow(clippy::too_many_arguments)]
fn handle_posix_environment_mutation(
    segment: &tokenize::Segment,
    separator: Option<&str>,
    outgoing_separator: Option<&str>,
    shell_variables: &mut BTreeMap<String, ShellVariable>,
    context: &mut Web3ParseContextV2,
    exported_variables: &mut BTreeSet<String>,
    export_all: &mut bool,
    completeness: &mut Completeness,
) -> bool {
    let Some(command) = segment.command.as_deref() else {
        return false;
    };
    let base = normalize_cmd_base(command, ShellType::Posix);
    let delegated_mutation = matches!(base.as_str(), "command" | "builtin")
        && segment
            .args
            .iter()
            .map(|argument| normalize_cmd_base(argument, ShellType::Posix))
            .find(|argument| !(argument == "--" || (base == "command" && argument == "-p")))
            .is_some_and(|argument| {
                matches!(
                    argument.as_str(),
                    "export"
                        | "unset"
                        | "set"
                        | "readonly"
                        | "declare"
                        | "typeset"
                        | "local"
                        | "printf"
                        | "read"
                )
            });
    let mut remaining_trap_bodies = MAX_SHELL_SEGMENTS;
    if posix_trap_may_mutate_environment(segment, 0, &mut remaining_trap_bodies) {
        taint_shell_environment(shell_variables, context, completeness);
        return true;
    }
    let printf_v = base == "printf"
        && segment.args.iter().any(|argument| {
            let argument = normalize_shell_token(argument, ShellType::Posix);
            argument == "-v"
                || argument
                    .strip_prefix("-v")
                    .is_some_and(|name| !name.is_empty())
        });
    if delegated_mutation
        || printf_v
        || matches!(
            base.as_str(),
            "readonly" | "declare" | "typeset" | "local" | "read"
        )
    {
        taint_shell_environment(shell_variables, context, completeness);
        return true;
    }
    if !matches!(base.as_str(), "export" | "unset" | "set") {
        return false;
    }
    if matches!(separator, Some("&&" | "||" | "|" | "|&"))
        || matches!(outgoing_separator, Some("|" | "|&"))
    {
        taint_shell_environment(shell_variables, context, completeness);
        return true;
    }
    let arguments = segment
        .args
        .iter()
        .map(|argument| normalize_shell_token(argument, ShellType::Posix))
        .collect::<Vec<_>>();
    match base.as_str() {
        "set" => match arguments.as_slice() {
            [] => {}
            [option] if option == "-a" => *export_all = true,
            [option] if option == "+a" => *export_all = false,
            [option, name] if option == "-o" && name == "allexport" => *export_all = true,
            [option, name] if option == "+o" && name == "allexport" => *export_all = false,
            _ => taint_shell_environment(shell_variables, context, completeness),
        },
        "unset" => {
            let mut options = true;
            for argument in arguments {
                if options && argument == "--" {
                    options = false;
                    continue;
                }
                if options && argument == "-v" {
                    continue;
                }
                if options && argument.starts_with('-') {
                    taint_shell_environment(shell_variables, context, completeness);
                    return true;
                }
                options = false;
                if !valid_shell_variable_name(&argument) {
                    taint_shell_environment(shell_variables, context, completeness);
                    return true;
                }
                shell_variables.insert(argument.clone(), ShellVariable::Missing);
                exported_variables.remove(&argument);
                context.environment.remove(&argument);
                context.ambient_selectors.remove(&argument);
                if argument == "HOME" {
                    invalidate_context_paths(context);
                }
            }
        }
        "export" => {
            let mut unexport = false;
            let mut options = true;
            for argument in arguments {
                if options && argument == "--" {
                    options = false;
                    continue;
                }
                if options && argument == "-p" {
                    continue;
                }
                if options && argument == "-n" {
                    unexport = true;
                    continue;
                }
                if options && argument.starts_with('-') {
                    taint_shell_environment(shell_variables, context, completeness);
                    return true;
                }
                options = false;
                let (name, assigned) = argument
                    .split_once('=')
                    .map_or((argument.as_str(), None), |(name, value)| {
                        (name, Some(value))
                    });
                if !valid_shell_variable_name(name) {
                    taint_shell_environment(shell_variables, context, completeness);
                    return true;
                }
                if unexport {
                    if let Some(value) = assigned {
                        let value = if command_word_is_statically_bound(value, ShellType::Posix) {
                            ShellVariable::Static(normalize_shell_token(value, ShellType::Posix))
                        } else {
                            ShellVariable::Unresolved
                        };
                        shell_variables.insert(name.to_string(), value);
                    }
                    exported_variables.remove(name);
                    context.environment.remove(name);
                    context.ambient_selectors.remove(name);
                    if name == "HOME" {
                        invalidate_context_paths(context);
                    }
                    continue;
                }
                let value = match assigned {
                    Some(value) if command_word_is_statically_bound(value, ShellType::Posix) => {
                        ShellVariable::Static(normalize_shell_token(value, ShellType::Posix))
                    }
                    Some(_) => ShellVariable::Unresolved,
                    None => shell_variables
                        .get(name)
                        .cloned()
                        .unwrap_or(ShellVariable::Missing),
                };
                update_exported_variable(
                    name,
                    value,
                    shell_variables,
                    context,
                    exported_variables,
                    completeness,
                );
            }
        }
        _ => unreachable!("filtered above"),
    }
    true
}

const MAX_ENVIRONMENT_BODY_DEPTH: usize = 8;

#[derive(Default)]
struct PowerShellMutationSyntax {
    environment_assignment: bool,
    environment_api_call: bool,
}

fn powershell_reference_end(raw: &str, index: usize) -> Option<usize> {
    let tail = raw.get(index..)?;
    if tail
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("$env:"))
    {
        let mut end = index + 5;
        while raw.as_bytes().get(end).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'(' | b')')
        }) {
            end += 1;
        }
        return (end > index + 5).then_some(end);
    }
    if tail
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("${env:"))
    {
        let close = raw.get(index + 6..)?.find('}')? + index + 6;
        return (close > index + 6).then_some(close + 1);
    }
    None
}

fn powershell_assignment_follows(raw: &str, mut index: usize) -> bool {
    while let Some(ch) = raw.get(index..).and_then(|tail| tail.chars().next()) {
        if !ch.is_whitespace() {
            break;
        }
        index += ch.len_utf8();
    }
    let tail = raw.get(index..).unwrap_or_default();
    tail.starts_with('=')
        || ["+=", "-=", "*=", "/=", "%="]
            .iter()
            .any(|operator| tail.starts_with(operator))
}

fn powershell_mutation_syntax(raw: &str) -> PowerShellMutationSyntax {
    let mut syntax = PowerShellMutationSyntax::default();
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    let mut quote = None;
    let mut line_comment = false;
    while index < bytes.len() {
        let ch = match raw.get(index..).and_then(|tail| tail.chars().next()) {
            Some(ch) => ch,
            None => break,
        };
        let char_len = ch.len_utf8();
        if line_comment {
            if matches!(ch, '\r' | '\n') {
                line_comment = false;
            }
            index += char_len;
            continue;
        }
        if let Some(kind) = quote {
            if kind == tokenize::PowerShellQuoteKind::Double && ch == '`' {
                index += char_len;
                if let Some(next) = raw.get(index..).and_then(|tail| tail.chars().next()) {
                    index += next.len_utf8();
                }
                continue;
            }
            if tokenize::powershell_quote_kind(ch) == Some(kind) {
                let next = raw
                    .get(index + char_len..)
                    .and_then(|tail| tail.chars().next());
                if kind == tokenize::PowerShellQuoteKind::Single
                    && next.and_then(tokenize::powershell_quote_kind) == Some(kind)
                {
                    index += char_len + next.map_or(0, char::len_utf8);
                    continue;
                }
                quote = None;
            }
            index += char_len;
            continue;
        }
        if ch == '@' {
            if let Some(here_string) = tokenize::powershell_here_string(raw, index) {
                index = here_string.end;
                continue;
            }
        }
        if ch == '<' && bytes.get(index + 1) == Some(&b'#') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'#' && bytes[index + 1] == b'>') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        if ch == '#' {
            line_comment = true;
            index += 1;
            continue;
        }
        if ch == '`' {
            index += 1;
            if let Some(next) = raw.get(index..).and_then(|tail| tail.chars().next()) {
                index += next.len_utf8();
            }
            continue;
        }
        if let Some(kind) = tokenize::powershell_quote_kind(ch) {
            quote = Some(kind);
            index += char_len;
            continue;
        }
        if ch == '$' {
            if let Some(end) = powershell_reference_end(raw, index) {
                syntax.environment_assignment |= powershell_assignment_follows(raw, end);
                index = end;
                continue;
            }
        }
        const ENVIRONMENT_API: &str = "::setenvironmentvariable";
        if raw
            .get(index..index.saturating_add(ENVIRONMENT_API.len()))
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(ENVIRONMENT_API))
        {
            syntax.environment_api_call = true;
            index += ENVIRONMENT_API.len();
            continue;
        }
        index += char_len;
    }
    syntax
}

fn explicit_environment_provider_arg(argument: &str, shell: ShellType) -> bool {
    let value = normalize_shell_token(argument, shell).to_ascii_lowercase();
    value.starts_with("env:")
        || value.starts_with("env:\\")
        || value.starts_with("${env:")
        || value.starts_with("$env:")
}

fn powershell_command_may_mutate_environment(
    segment: &tokenize::Segment,
    depth: usize,
    remaining_bodies: &mut usize,
) -> bool {
    let base = segment
        .command
        .as_deref()
        .map(|command| normalize_cmd_base(command, ShellType::PowerShell));
    let explicit_environment = segment
        .args
        .iter()
        .any(|argument| explicit_environment_provider_arg(argument, ShellType::PowerShell));
    let environment_item = matches!(
        base.as_deref(),
        Some(
            "set-item"
                | "new-item"
                | "remove-item"
                | "clear-item"
                | "rename-item"
                | "move-item"
                | "copy-item"
                | "set-content"
                | "add-content"
                | "clear-content"
                | "set-itemproperty"
                | "new-itemproperty"
                | "remove-itemproperty"
                | "clear-itemproperty"
                | "si"
                | "ni"
                | "ri"
                | "sc"
                | "ac"
                | "clc"
                | "mi"
                | "move"
                | "mv"
                | "ci"
                | "copy"
                | "cp"
                | "rni"
                | "ren"
                | "sp"
                | "np"
                | "rp"
                | "clp"
                | "rm"
                | "del"
                | "erase"
                | "rd"
                | "rmdir"
                | "cli"
        )
    ) && explicit_environment;
    let explicit_environment_variable = matches!(
        base.as_deref(),
        Some(
            "set-variable"
                | "new-variable"
                | "remove-variable"
                | "clear-variable"
                | "sv"
                | "nv"
                | "rv"
                | "clv"
        )
    ) && explicit_environment;
    let syntax = powershell_mutation_syntax(&segment.raw);
    let direct = environment_item
        || explicit_environment_variable
        || syntax.environment_assignment
        || syntax.environment_api_call;
    if direct {
        return true;
    }
    let scan = match crate::extract::executable_body_scan_bounded(
        &segment.raw,
        ShellType::PowerShell,
        (*remaining_bodies).min(MAX_SHELL_SEGMENTS),
    ) {
        Ok(scan) => scan,
        Err(_) => return true,
    };
    if scan.gap.is_some() {
        return true;
    }
    for body in scan.bodies {
        if *remaining_bodies == 0 {
            return true;
        }
        *remaining_bodies -= 1;
        if environment_body_may_mutate(&body.input, body.shell, depth + 1, remaining_bodies) {
            return true;
        }
    }
    false
}

fn posix_delegated_target(segment: &tokenize::Segment) -> Option<(String, usize)> {
    let base = normalize_cmd_base(segment.command.as_deref()?, ShellType::Posix);
    if !matches!(base.as_str(), "command" | "builtin") {
        return None;
    }
    let mut index = 0usize;
    while let Some(argument) = segment.args.get(index) {
        let argument = normalize_cmd_base(argument, ShellType::Posix);
        if argument == "--" || (base == "command" && argument == "-p") {
            index += 1;
            continue;
        }
        return Some((argument, index + 1));
    }
    None
}

fn posix_trap_may_mutate_environment(
    segment: &tokenize::Segment,
    depth: usize,
    remaining_bodies: &mut usize,
) -> bool {
    let base = segment
        .command
        .as_deref()
        .map(|command| normalize_cmd_base(command, ShellType::Posix));
    let args_start = if base.as_deref() == Some("trap") {
        0
    } else if let Some((target, start)) = posix_delegated_target(segment) {
        if target != "trap" {
            return false;
        }
        start
    } else {
        return false;
    };
    let args = segment.args.get(args_start..).unwrap_or_default();
    if args.is_empty() {
        return false;
    }
    let mut index = 0usize;
    if normalize_shell_token(&args[index], ShellType::Posix) == "-p" {
        return false;
    }
    if normalize_shell_token(&args[index], ShellType::Posix) == "--" {
        index += 1;
    }
    let Some(action) = args.get(index) else {
        return false;
    };
    if !command_word_is_statically_bound(action, ShellType::Posix) {
        return true;
    }
    let action = normalize_shell_token(action, ShellType::Posix);
    if action.is_empty() || action == "-" {
        return false;
    }
    environment_body_may_mutate(&action, ShellType::Posix, depth + 1, remaining_bodies)
}

fn posix_command_may_mutate_environment(
    segment: &tokenize::Segment,
    depth: usize,
    remaining_bodies: &mut usize,
) -> bool {
    if assignment_only_segment(segment, ShellType::Posix).is_some() {
        return true;
    }
    let Some(command) = segment.command.as_deref() else {
        return false;
    };
    let base = normalize_cmd_base(command, ShellType::Posix);
    if base == "trap" || posix_delegated_target(segment).is_some_and(|target| target.0 == "trap") {
        return posix_trap_may_mutate_environment(segment, depth, remaining_bodies);
    }
    if let Some((target, _)) = posix_delegated_target(segment) {
        return matches!(
            target.as_str(),
            "export" | "unset" | "set" | "readonly" | "declare" | "typeset" | "local" | "read"
        );
    }
    matches!(
        base.as_str(),
        "export" | "unset" | "set" | "readonly" | "declare" | "typeset" | "local" | "read"
    ) || (base == "printf"
        && segment.args.iter().any(|argument| {
            let argument = normalize_shell_token(argument, ShellType::Posix);
            argument == "-v"
                || argument
                    .strip_prefix("-v")
                    .is_some_and(|name| !name.is_empty())
        }))
}

fn compound_environment_body(segment: &tokenize::Segment, shell: ShellType) -> bool {
    let base = segment
        .command
        .as_deref()
        .map(|command| normalize_cmd_base(command, shell));
    match shell {
        ShellType::Posix => {
            matches!(
                base.as_deref(),
                Some("{" | "if" | "then" | "elif" | "else" | "while" | "until" | "do" | "for")
            ) || segment.raw.trim_start().starts_with('{')
        }
        ShellType::Cmd => {
            matches!(base.as_deref(), Some("if" | "for" | "do"))
                || segment.raw.trim_start().starts_with('(')
        }
        // Active PowerShell blocks and interpolated subexpressions are handled
        // together by `powershell_command_may_mutate_environment`.
        ShellType::PowerShell => false,
        ShellType::Fish => false,
    }
}

fn environment_body_may_mutate(
    raw: &str,
    shell: ShellType,
    depth: usize,
    remaining_bodies: &mut usize,
) -> bool {
    if depth >= MAX_ENVIRONMENT_BODY_DEPTH || *remaining_bodies == 0 {
        return true;
    }
    let (segments, budget) = tokenize::tokenize_bounded(
        raw,
        shell,
        MAX_SHELL_SEGMENTS,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    );
    if budget.segments_truncated || budget.words_truncated || budget.word_bytes_truncated {
        return true;
    }
    let mut posix_functions = BTreeMap::<String, Option<String>>::new();
    for segment in segments {
        if shell == ShellType::Posix {
            match crate::extract::literal_posix_function_definition(&segment) {
                Ok(Some((name, body))) => {
                    if name.len() > MAX_ARGUMENT_BYTES {
                        return true;
                    }
                    posix_functions
                        .insert(name, (body.len() <= MAX_ARGUMENT_BYTES).then_some(body));
                    continue;
                }
                Err(()) => return true,
                Ok(None) => {}
            }
            let invoked_function = segment
                .command
                .as_deref()
                .filter(|command| command_word_is_statically_bound(command, ShellType::Posix))
                .map(|command| normalize_shell_token(command, ShellType::Posix))
                .and_then(|name| posix_functions.get(&name));
            if let Some(body) = invoked_function {
                if *remaining_bodies == 0 {
                    return true;
                }
                *remaining_bodies -= 1;
                if body.as_ref().is_none_or(|body| {
                    environment_body_may_mutate(body, ShellType::Posix, depth + 1, remaining_bodies)
                }) {
                    return true;
                }
                continue;
            }
        }
        let direct = match shell {
            ShellType::Posix => {
                posix_command_may_mutate_environment(&segment, depth, remaining_bodies)
            }
            ShellType::Cmd => segment
                .command
                .as_deref()
                .is_some_and(|command| normalize_cmd_base(command, ShellType::Cmd) == "set"),
            ShellType::PowerShell => {
                powershell_command_may_mutate_environment(&segment, depth, remaining_bodies)
            }
            ShellType::Fish => segment.command.as_deref().is_some_and(|command| {
                matches!(
                    normalize_cmd_base(command, ShellType::Fish).as_str(),
                    "set" | "read"
                )
            }),
        };
        if direct {
            return true;
        }
        if !compound_environment_body(&segment, shell) {
            continue;
        }
        let scan = match crate::extract::executable_body_scan_bounded(
            &segment.raw,
            shell,
            (*remaining_bodies).min(MAX_SHELL_SEGMENTS),
        ) {
            Ok(scan) => scan,
            Err(_) => return true,
        };
        if scan.gap.is_some() {
            return true;
        }
        for body in scan.bodies {
            if *remaining_bodies == 0 {
                return true;
            }
            *remaining_bodies -= 1;
            if environment_body_may_mutate(&body.input, body.shell, depth + 1, remaining_bodies) {
                return true;
            }
        }
    }
    false
}

fn handle_unmodeled_environment_mutation(
    segment: &tokenize::Segment,
    shell: ShellType,
    shell_variables: &mut BTreeMap<String, ShellVariable>,
    context: &mut Web3ParseContextV2,
    completeness: &mut Completeness,
) -> bool {
    let mutation = match shell {
        ShellType::Fish => segment.command.as_deref().is_some_and(|command| {
            matches!(normalize_cmd_base(command, shell).as_str(), "set" | "read")
        }),
        ShellType::Cmd => {
            let direct_set = segment
                .command
                .as_deref()
                .is_some_and(|command| normalize_cmd_base(command, ShellType::Cmd) == "set");
            let mut remaining_bodies = MAX_SHELL_SEGMENTS;
            direct_set
                || (compound_environment_body(segment, shell)
                    && environment_body_may_mutate(&segment.raw, shell, 0, &mut remaining_bodies))
        }
        ShellType::PowerShell => {
            let mut remaining_bodies = MAX_SHELL_SEGMENTS;
            powershell_command_may_mutate_environment(segment, 0, &mut remaining_bodies)
                || (compound_environment_body(segment, shell)
                    && environment_body_may_mutate(&segment.raw, shell, 0, &mut remaining_bodies))
        }
        ShellType::Posix => {
            let mut remaining_bodies = MAX_SHELL_SEGMENTS;
            posix_trap_may_mutate_environment(segment, 0, &mut remaining_bodies)
                || (compound_environment_body(segment, shell)
                    && environment_body_may_mutate(&segment.raw, shell, 0, &mut remaining_bodies))
        }
    };
    if mutation {
        taint_shell_environment(shell_variables, context, completeness);
    }
    mutation
}

fn cdpath_can_redirect(path: &str, cdpath: ShellVariable) -> bool {
    if Path::new(path).is_absolute()
        || path == "."
        || path == ".."
        || path.starts_with("./")
        || path.starts_with("../")
    {
        return false;
    }
    match cdpath {
        ShellVariable::Missing => false,
        ShellVariable::Static(value) => value
            .split(':')
            .any(|entry| !entry.is_empty() && entry != "."),
        ShellVariable::Unresolved => true,
    }
}

fn segment_controls_cwd(segment: &tokenize::Segment, shell: ShellType) -> bool {
    let Some(command) = segment.command.as_deref() else {
        return false;
    };
    let base = normalize_cmd_base(command, shell);
    matches!(
        base.as_str(),
        "cd" | "pushd" | "popd" | "chdir" | "set-location" | "sl"
    ) || (base == "command"
        && segment
            .args
            .iter()
            .any(|argument| normalize_cmd_base(argument, shell) == "cd"))
}

fn pending_cd(
    segment: &tokenize::Segment,
    shell: ShellType,
    context: &Web3ParseContextV2,
    shell_variables: &BTreeMap<String, ShellVariable>,
) -> Option<PendingCdChange> {
    let command = segment.command.as_deref()?;
    let base = normalize_cmd_base(command, shell);
    if matches!(
        base.as_str(),
        "pushd" | "popd" | "chdir" | "set-location" | "sl"
    ) {
        return Some(PendingCdChange::Unresolved);
    }
    if base != "cd" {
        return None;
    }
    let mut index = 0usize;
    let mut physical = false;
    while let Some(argument) = segment.args.get(index) {
        let option = normalize_shell_token(argument, shell);
        if option == "--" {
            index += 1;
            break;
        }
        let Some(cluster) = option
            .strip_prefix('-')
            .filter(|cluster| !cluster.is_empty())
        else {
            break;
        };
        if option == "-" {
            break;
        }
        if !cluster.chars().all(|flag| matches!(flag, 'L' | 'P')) {
            return Some(PendingCdChange::Unresolved);
        }
        physical = cluster.chars().last().is_some_and(|flag| flag == 'P');
        index += 1;
    }
    if physical || segment.args.len().saturating_sub(index) > 1 {
        return Some(PendingCdChange::Unresolved);
    }
    let value = match segment.args.get(index) {
        Some(path) if command_word_is_statically_bound(path, shell) => {
            normalize_shell_token(path, shell)
        }
        Some(_) => return Some(PendingCdChange::Unresolved),
        None => match shell_variable(segment, shell_variables, "HOME", shell) {
            ShellVariable::Static(home) if Path::new(&home).is_absolute() => home,
            ShellVariable::Missing | ShellVariable::Static(_) | ShellVariable::Unresolved => {
                return Some(PendingCdChange::Unresolved)
            }
        },
    };
    if value == "-"
        || cdpath_can_redirect(
            &value,
            shell_variable(segment, shell_variables, "CDPATH", shell),
        )
    {
        return Some(PendingCdChange::Unresolved);
    }
    Some(
        resolve_cwd(context.cwd.as_deref(), &value)
            .map(PendingCdChange::Static)
            .unwrap_or(PendingCdChange::Unresolved),
    )
}

fn taint_context_cwd(context: &mut Web3ParseContextV2) {
    context.cwd = None;
    invalidate_context_paths(context);
}

fn apply_pending_cd(
    pending: PendingCd,
    separator: Option<&str>,
    shell: ShellType,
    context: &mut Web3ParseContextV2,
    cwd_tainted: &mut bool,
    cwd_conditionally_set: &mut bool,
) {
    if pending.incoming_pipeline
        || matches!(separator, Some("|" | "|&"))
        || (separator == Some("&") && shell != ShellType::Cmd)
    {
        return;
    }
    match (pending.change, separator) {
        (PendingCdChange::Static(path), Some("&&")) => {
            context.cwd = Some(path);
            invalidate_context_paths(context);
            *cwd_tainted = false;
            *cwd_conditionally_set = true;
        }
        (PendingCdChange::Unresolved, Some("&&")) => {
            taint_context_cwd(context);
            *cwd_tainted = true;
            *cwd_conditionally_set = false;
        }
        _ => {
            taint_context_cwd(context);
            *cwd_tainted = true;
            *cwd_conditionally_set = false;
        }
    }
}

fn conditional_cwd_lists(segments: &[tokenize::Segment], shell: ShellType) -> Vec<bool> {
    let mut conditional = vec![false; segments.len()];
    let mut start = 0usize;
    for end in 1..=segments.len() {
        let boundary = end == segments.len()
            || matches!(
                segments[end].preceding_separator.as_deref(),
                Some(";" | "\n" | "&")
            );
        if !boundary {
            continue;
        }
        let list = &segments[start..end];
        let has_conditional_cwd = list
            .iter()
            .any(|segment| segment_controls_cwd(segment, shell))
            && list
                .iter()
                .skip(1)
                .any(|segment| segment.preceding_separator.as_deref() == Some("||"));
        conditional[start..end].fill(has_conditional_cwd);
        start = end;
    }
    conditional
}

fn posix_trailing_background(input: &str, segments: &[tokenize::Segment]) -> bool {
    let Some(last) = segments.last() else {
        return false;
    };
    let suffix = input
        .get(last.byte_range.end..)
        .unwrap_or_default()
        .trim_start_matches([' ', '\t', '\r', '\n']);
    suffix.starts_with('&') && !suffix.starts_with("&&")
}

fn posix_outgoing_separator<'a>(
    input: &'a str,
    segments: &'a [tokenize::Segment],
    index: usize,
) -> Option<&'a str> {
    segments
        .get(index + 1)
        .and_then(|next| next.preceding_separator.as_deref())
        .or_else(|| {
            (index + 1 == segments.len() && posix_trailing_background(input, segments))
                .then_some("&")
        })
}

#[derive(Clone, Copy)]
struct PosixControlRegion {
    end: usize,
    complete: bool,
}

fn strict_posix_control_word(word: &str) -> Option<String> {
    command_word_is_statically_bound(word, ShellType::Posix)
        .then(|| normalize_cmd_base(word, ShellType::Posix))
        .filter(|normalized| normalized == word)
}

fn posix_control_opener(segment: &tokenize::Segment) -> Option<&'static str> {
    let leader = segment
        .command
        .as_deref()
        .and_then(strict_posix_control_word)?;
    let expected_close = match leader.as_str() {
        "if" => Some("fi"),
        "while" | "until" | "for" | "select" => Some("done"),
        "case" => Some("esac"),
        _ => None,
    };
    if expected_close.is_some() {
        return expected_close;
    }

    let introduces_body = matches!(leader.as_str(), "then" | "elif" | "else" | "do" | "!")
        || (leader.ends_with(')') && !leader.ends_with("()"));
    if !introduces_body {
        return None;
    }
    match segment
        .args
        .first()
        .and_then(|argument| strict_posix_control_word(argument))?
        .as_str()
    {
        "if" => Some("fi"),
        "while" | "until" | "for" | "select" => Some("done"),
        "case" => Some("esac"),
        _ => None,
    }
}

fn posix_control_closer(segment: &tokenize::Segment) -> Option<&'static str> {
    match segment
        .command
        .as_deref()
        .and_then(strict_posix_control_word)?
        .as_str()
    {
        "fi" => Some("fi"),
        "done" => Some("done"),
        "esac" => Some("esac"),
        _ => None,
    }
}

/// Assign every tokenizer segment inside a structural POSIX control to the
/// outer control that owns it. Tokenization intentionally splits on `;` and
/// newlines, while Bash ownership continues until `fi`, `done`, or `esac`.
fn posix_control_ownership(
    segments: &[tokenize::Segment],
) -> (Vec<Option<usize>>, Vec<Option<PosixControlRegion>>) {
    let mut owner_for = vec![None; segments.len()];
    let mut regions = vec![None; segments.len()];
    let mut stack = Vec::<(&'static str, usize)>::new();
    let mut malformed = false;

    for (index, segment) in segments.iter().enumerate() {
        if let Some(expected_close) = posix_control_opener(segment) {
            let owner = stack.first().map(|(_, owner)| *owner).unwrap_or(index);
            stack.push((expected_close, owner));
        }
        if let Some((_, owner)) = stack.first() {
            owner_for[index] = Some(*owner);
        }
        if let Some(close) = posix_control_closer(segment) {
            if let Some(position) = stack.iter().rposition(|(expected, _)| *expected == close) {
                malformed |= position + 1 != stack.len();
                stack.truncate(position + 1);
                let (_, owner) = stack.pop().expect("matching control frame");
                if stack.is_empty() {
                    regions[owner] = Some(PosixControlRegion {
                        end: index,
                        complete: !malformed,
                    });
                    malformed = false;
                }
            } else if let Some((_, owner)) = stack.first() {
                owner_for[index] = Some(*owner);
                malformed = true;
            }
        }
    }

    if let Some((_, owner)) = stack.first() {
        regions[*owner] = Some(PosixControlRegion {
            end: segments.len().saturating_sub(1),
            complete: false,
        });
    }
    (owner_for, regions)
}

fn register_posix_function_definition(
    segment: &tokenize::Segment,
    functions: &mut BTreeMap<String, PosixFunctionBinding>,
    budget: &mut PosixFunctionBudget,
    completeness: &mut Completeness,
) -> bool {
    match crate::extract::literal_posix_function_definition_with_body_kind(segment) {
        Ok(Some((name, body, body_kind))) => {
            if name.len() > MAX_ARGUMENT_BYTES {
                completeness.add(IncompleteReason::ArgumentBytesExceeded);
                completeness.add(IncompleteReason::UnresolvedIndirection);
                budget.function_state_unresolved = true;
                return true;
            }
            if functions.get(&name).is_some_and(|binding| binding.readonly) {
                completeness.add(IncompleteReason::UnresolvedIndirection);
                return true;
            }
            if !functions.contains_key(&name) && functions.len() == MAX_SHELL_SEGMENTS {
                completeness.add(IncompleteReason::SegmentBudgetExceeded);
                completeness.add(IncompleteReason::UnresolvedIndirection);
                budget.function_state_unresolved = true;
                return true;
            }
            let body = if body.len() > MAX_ARGUMENT_BYTES {
                completeness.add(IncompleteReason::ArgumentBytesExceeded);
                completeness.add(IncompleteReason::UnresolvedIndirection);
                None
            } else {
                Some(Arc::<str>::from(body))
            };
            functions.insert(
                name,
                PosixFunctionBinding {
                    body,
                    body_kind,
                    readonly: false,
                },
            );
            true
        }
        Err(()) => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            budget.function_state_unresolved = true;
            true
        }
        Ok(None) => false,
    }
}

fn apply_posix_function_table_mutation(
    segment: &tokenize::Segment,
    functions: &mut BTreeMap<String, PosixFunctionBinding>,
    budget: &mut PosixFunctionBudget,
    completeness: &mut Completeness,
) -> bool {
    let Some(command) = segment.command.as_deref() else {
        return false;
    };
    if !command_word_is_statically_bound(command, ShellType::Posix) {
        return false;
    }
    let command = normalize_cmd_base(command, ShellType::Posix);
    if !matches!(command.as_str(), "readonly" | "unset") {
        return false;
    }
    let mut function_mode = false;
    let mut options = true;
    let mut operands = Vec::new();
    for argument in &segment.args {
        if !command_word_is_statically_bound(argument, ShellType::Posix) {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            budget.function_state_unresolved = true;
            return true;
        }
        let argument = normalize_shell_token(argument, ShellType::Posix);
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            let flags = argument.trim_start_matches('-');
            let valid = if command == "readonly" {
                flags
                    .chars()
                    .all(|flag| matches!(flag, 'a' | 'A' | 'f' | 'p'))
            } else {
                flags.chars().all(|flag| matches!(flag, 'f' | 'v' | 'n'))
            };
            if flags.is_empty() || !valid {
                return false;
            }
            function_mode |= flags.contains('f');
            continue;
        }
        options = false;
        operands.push(argument);
    }
    if !function_mode {
        return false;
    }
    for name in operands {
        if command == "readonly" {
            if let Some(binding) = functions.get_mut(&name) {
                binding.readonly = true;
            }
        } else if !functions.get(&name).is_some_and(|binding| binding.readonly) {
            functions.remove(&name);
        }
    }
    true
}

fn taint_posix_function_execution(
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    completeness: &mut Completeness,
) {
    taint_shell_environment(state.shell_variables, state.context, completeness);
    taint_context_cwd(state.context);
    *state.cwd_tainted = true;
    *state.cwd_conditionally_set = false;
    budget.function_state_unresolved = true;
    completeness.add(IncompleteReason::UnresolvedIndirection);
}

fn literal_posix_eval_body(segment: &tokenize::Segment) -> Result<Option<String>, ()> {
    crate::extract::literal_posix_current_shell_eval_body(segment)
}

fn direct_posix_function_name(
    segment: &tokenize::Segment,
    functions: &BTreeMap<String, PosixFunctionBinding>,
) -> Option<String> {
    let command = segment.command.as_deref()?;
    if !command_word_is_statically_bound(command, ShellType::Posix) {
        return None;
    }
    let name = normalize_shell_token(command, ShellType::Posix);
    (matches!(name.as_str(), "command" | "builtin") && functions.contains_key(&name))
        .then_some(name)
}

#[derive(Clone)]
struct TemporaryPosixVariableSnapshot {
    name: String,
    shell_variable: Option<ShellVariable>,
    environment: Option<String>,
    ambient: Option<String>,
    exported: bool,
}

struct TemporaryPosixAssignments {
    variables: Vec<TemporaryPosixVariableSnapshot>,
    cwd: Option<PathBuf>,
    foundry_config_path: Option<PathBuf>,
    solana_config_path: Option<PathBuf>,
    anchor_config_path: Option<PathBuf>,
    changed_home: bool,
}

fn apply_temporary_posix_function_assignments(
    segment: &tokenize::Segment,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    completeness: &mut Completeness,
) -> TemporaryPosixAssignments {
    let (assignments, words_truncated, bytes_truncated) = tokenize::leading_env_assignments_bounded(
        &segment.raw,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    );
    if words_truncated || bytes_truncated {
        completeness.add(if words_truncated {
            IncompleteReason::ArgumentCountExceeded
        } else {
            IncompleteReason::ArgumentBytesExceeded
        });
        taint_posix_function_execution(state, budget, completeness);
    }
    let mut snapshot = TemporaryPosixAssignments {
        variables: Vec::new(),
        cwd: state.context.cwd.clone(),
        foundry_config_path: state.context.foundry_config_path.clone(),
        solana_config_path: state.context.solana_config_path.clone(),
        anchor_config_path: state.context.anchor_config_path.clone(),
        changed_home: false,
    };
    let mut recorded = BTreeSet::new();
    for (name, raw_value) in assignments {
        if recorded.insert(name.clone()) {
            snapshot.variables.push(TemporaryPosixVariableSnapshot {
                shell_variable: state.shell_variables.get(&name).cloned(),
                environment: state.context.environment.get(&name).cloned(),
                ambient: state.context.ambient_selectors.get(&name).cloned(),
                exported: state.exported_variables.contains(&name),
                name: name.clone(),
            });
        }
        let value = if command_word_is_statically_bound(&raw_value, ShellType::Posix) {
            ShellVariable::Static(normalize_shell_token(&raw_value, ShellType::Posix))
        } else {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            ShellVariable::Unresolved
        };
        state.shell_variables.insert(name.clone(), value.clone());
        state.exported_variables.insert(name.clone());
        match value {
            ShellVariable::Static(value) => {
                state
                    .context
                    .environment
                    .insert(name.clone(), value.clone());
                state.context.ambient_selectors.insert(name.clone(), value);
            }
            ShellVariable::Missing | ShellVariable::Unresolved => {
                state.context.environment.remove(&name);
                state.context.ambient_selectors.remove(&name);
            }
        }
        if name == "HOME" {
            snapshot.changed_home = true;
            rederive_default_context_paths(state.context, completeness);
        }
    }
    snapshot
}

fn restore_temporary_posix_function_assignments(
    snapshot: TemporaryPosixAssignments,
    state: &mut PosixShellState<'_>,
) {
    for variable in snapshot.variables {
        match variable.shell_variable {
            Some(value) => {
                state.shell_variables.insert(variable.name.clone(), value);
            }
            None => {
                state.shell_variables.remove(&variable.name);
            }
        }
        match variable.environment {
            Some(value) => {
                state
                    .context
                    .environment
                    .insert(variable.name.clone(), value);
            }
            None => {
                state.context.environment.remove(&variable.name);
            }
        }
        match variable.ambient {
            Some(value) => {
                state
                    .context
                    .ambient_selectors
                    .insert(variable.name.clone(), value);
            }
            None => {
                state.context.ambient_selectors.remove(&variable.name);
            }
        }
        if variable.exported {
            state.exported_variables.insert(variable.name);
        } else {
            state.exported_variables.remove(&variable.name);
        }
    }
    if snapshot.changed_home {
        state.context.solana_config_path = snapshot.solana_config_path;
        if state.context.cwd == snapshot.cwd {
            state.context.foundry_config_path = snapshot.foundry_config_path;
            state.context.anchor_config_path = snapshot.anchor_config_path;
        }
    }
}

fn execute_posix_function(
    name: &str,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Vec<Web3CommandFactsV2> {
    if budget.remaining_calls == 0
        || budget.stack.len() >= MAX_WRAPPER_DEPTH
        || budget.stack.iter().any(|active| active == name)
    {
        completeness.add(IncompleteReason::WrapperDepthExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    }
    let Some(binding) = state.functions.get(name).cloned() else {
        if budget.function_state_unresolved {
            taint_posix_function_execution(state, budget, completeness);
        }
        return Vec::new();
    };
    let Some(body) = binding.body else {
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    };
    budget.remaining_calls -= 1;
    budget.stack.push(name.to_string());
    let commands = match binding.body_kind {
        crate::extract::PosixFunctionBodyKind::CurrentShell => execute_posix_current_shell_body(
            &body,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth,
            completeness,
        ),
        crate::extract::PosixFunctionBodyKind::Subshell => execute_posix_child_shell_body(
            &body,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth,
            completeness,
        ),
    };
    budget.stack.pop();
    commands
}

#[allow(clippy::too_many_arguments)]
fn execute_posix_function_invocation(
    segment: &tokenize::Segment,
    name: &str,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
    separator: Option<&str>,
    outgoing_separator: Option<&str>,
) -> Vec<Web3CommandFactsV2> {
    let state_isolated = matches!(separator, Some("|" | "|&"))
        || matches!(outgoing_separator, Some("|" | "|&" | "&"));
    let conditionally_invoked = matches!(separator, Some("&&" | "||"));
    let state_snapshot = (state_isolated || conditionally_invoked).then(|| {
        (
            (*state.context).clone(),
            (*state.shell_variables).clone(),
            (*state.exported_variables).clone(),
            *state.export_all,
            *state.cwd_tainted,
            *state.cwd_conditionally_set,
            (*state.functions).clone(),
            budget.function_state_unresolved,
        )
    });
    let temporary =
        apply_temporary_posix_function_assignments(segment, state, budget, completeness);
    let commands = execute_posix_function(
        name,
        call_span,
        state,
        budget,
        fact_budget,
        nested_depth,
        completeness,
    );
    restore_temporary_posix_function_assignments(temporary, state);
    if let Some((
        context,
        shell_variables,
        exported_variables,
        export_all,
        cwd_tainted,
        cwd_conditionally_set,
        functions,
        function_state_unresolved,
    )) = state_snapshot
    {
        *state.context = context;
        *state.shell_variables = shell_variables;
        *state.exported_variables = exported_variables;
        *state.export_all = export_all;
        *state.cwd_tainted = cwd_tainted;
        *state.cwd_conditionally_set = cwd_conditionally_set;
        *state.functions = functions;
        budget.function_state_unresolved = function_state_unresolved;
        if conditionally_invoked {
            taint_posix_function_execution(state, budget, completeness);
        }
    }
    commands
}

#[allow(clippy::too_many_arguments)]
fn execute_posix_inline_current_shell_body(
    body: &str,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
    separator: Option<&str>,
    outgoing_separator: Option<&str>,
) -> Vec<Web3CommandFactsV2> {
    if nested_depth >= MAX_WRAPPER_DEPTH {
        completeness.add(IncompleteReason::WrapperDepthExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    }
    let state_isolated = matches!(separator, Some("|" | "|&"))
        || matches!(outgoing_separator, Some("|" | "|&" | "&"));
    let conditionally_executed = matches!(separator, Some("&&" | "||"));
    let state_snapshot = (state_isolated || conditionally_executed).then(|| {
        (
            (*state.context).clone(),
            (*state.shell_variables).clone(),
            (*state.exported_variables).clone(),
            *state.export_all,
            *state.cwd_tainted,
            *state.cwd_conditionally_set,
            (*state.functions).clone(),
            budget.function_state_unresolved,
        )
    });
    let commands = execute_posix_current_shell_body(
        body,
        call_span,
        state,
        budget,
        fact_budget,
        nested_depth + 1,
        completeness,
    );
    if let Some((
        context,
        shell_variables,
        exported_variables,
        export_all,
        cwd_tainted,
        cwd_conditionally_set,
        functions,
        function_state_unresolved,
    )) = state_snapshot
    {
        *state.context = context;
        *state.shell_variables = shell_variables;
        *state.exported_variables = exported_variables;
        *state.export_all = export_all;
        *state.cwd_tainted = cwd_tainted;
        *state.cwd_conditionally_set = cwd_conditionally_set;
        *state.functions = functions;
        budget.function_state_unresolved = function_state_unresolved;
        if conditionally_executed {
            taint_posix_function_execution(state, budget, completeness);
        }
    }
    commands
}

fn execute_posix_child_shell_body(
    body: &str,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Vec<Web3CommandFactsV2> {
    if nested_depth >= MAX_WRAPPER_DEPTH {
        completeness.add(IncompleteReason::WrapperDepthExceeded);
        return Vec::new();
    }
    let snapshot = (
        (*state.context).clone(),
        (*state.shell_variables).clone(),
        (*state.exported_variables).clone(),
        *state.export_all,
        *state.cwd_tainted,
        *state.cwd_conditionally_set,
        (*state.functions).clone(),
        budget.function_state_unresolved,
    );
    let commands = execute_posix_current_shell_body(
        body,
        call_span,
        state,
        budget,
        fact_budget,
        nested_depth + 1,
        completeness,
    );
    let (
        context,
        shell_variables,
        exported_variables,
        export_all,
        cwd_tainted,
        cwd_conditionally_set,
        functions,
        function_state_unresolved,
    ) = snapshot;
    *state.context = context;
    *state.shell_variables = shell_variables;
    *state.exported_variables = exported_variables;
    *state.export_all = export_all;
    *state.cwd_tainted = cwd_tainted;
    *state.cwd_conditionally_set = cwd_conditionally_set;
    *state.functions = functions;
    budget.function_state_unresolved = function_state_unresolved;
    commands
}

struct PosixChildShellExecution {
    commands: Vec<Web3CommandFactsV2>,
    consumes_segment: bool,
}

fn execute_posix_child_shells_for_segment(
    segment: &tokenize::Segment,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> PosixChildShellExecution {
    match crate::extract::literal_posix_subshell_group_body(segment) {
        Ok(Some(body)) => {
            return PosixChildShellExecution {
                commands: execute_posix_child_shell_body(
                    &body,
                    call_span,
                    state,
                    budget,
                    fact_budget,
                    nested_depth,
                    completeness,
                ),
                consumes_segment: true,
            };
        }
        Err(()) => {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return PosixChildShellExecution {
                commands: Vec::new(),
                consumes_segment: true,
            };
        }
        Ok(None) => {}
    }
    let scan =
        match crate::extract::posix_child_shell_scan_bounded(&segment.raw, MAX_SHELL_SEGMENTS) {
            Ok(scan) => scan,
            Err(_) => {
                completeness.add(IncompleteReason::SegmentBudgetExceeded);
                completeness.add(IncompleteReason::UnresolvedIndirection);
                return PosixChildShellExecution {
                    commands: Vec::new(),
                    consumes_segment: false,
                };
            }
        };
    if scan.gap.is_some() {
        completeness.add(IncompleteReason::UnresolvedIndirection);
    }
    let mut commands = Vec::new();
    for body in scan.bodies {
        commands.extend(execute_posix_child_shell_body(
            &body.input,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth,
            completeness,
        ));
    }
    PosixChildShellExecution {
        commands,
        consumes_segment: false,
    }
}

fn posix_control_body_needs_shared_execution(
    body: &str,
    functions: &BTreeMap<String, PosixFunctionBinding>,
) -> bool {
    tokenize::tokenize_bounded(
        body,
        ShellType::Posix,
        MAX_SHELL_SEGMENTS,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    )
    .0
    .iter()
    .any(|segment| {
        !matches!(
            crate::extract::literal_posix_function_definition(segment),
            Ok(None)
        ) || direct_posix_function_name(segment, functions).is_some()
            || crate::extract::literal_posix_current_shell_command(segment)
                .ok()
                .flatten()
                .is_some_and(|(name, bypasses)| !bypasses && functions.contains_key(&name))
            || contains_web3_token(segment, ShellType::Posix)
    })
}

fn execute_posix_conditional_control_body(
    segment: &tokenize::Segment,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Option<Vec<Web3CommandFactsV2>> {
    let scan = crate::extract::posix_current_scope_dispatch_scan(segment)?;
    if scan.bodies.len() > MAX_SHELL_SEGMENTS {
        completeness.add(IncompleteReason::SegmentBudgetExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Some(Vec::new());
    }
    if scan.gap.is_some() {
        taint_posix_function_execution(state, budget, completeness);
    }
    if !scan
        .bodies
        .iter()
        .any(|body| posix_control_body_needs_shared_execution(&body.input, state.functions))
    {
        return None;
    }
    if nested_depth >= MAX_WRAPPER_DEPTH {
        completeness.add(IncompleteReason::WrapperDepthExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Some(Vec::new());
    }

    Some(execute_posix_conditional_candidates(
        scan.bodies.into_iter().map(|body| body.input).collect(),
        false,
        call_span,
        state,
        budget,
        fact_budget,
        nested_depth,
        completeness,
    ))
}

#[allow(clippy::too_many_arguments)]
fn execute_posix_conditional_candidates(
    candidates: Vec<String>,
    retain_proven_function_bodies: bool,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Vec<Web3CommandFactsV2> {
    if nested_depth >= MAX_WRAPPER_DEPTH {
        completeness.add(IncompleteReason::WrapperDepthExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    }

    let baseline_context = (*state.context).clone();
    let baseline_shell_variables = (*state.shell_variables).clone();
    let baseline_exported_variables = (*state.exported_variables).clone();
    let baseline_export_all = *state.export_all;
    let baseline_cwd_tainted = *state.cwd_tainted;
    let baseline_cwd_conditionally_set = *state.cwd_conditionally_set;
    let baseline_functions = (*state.functions).clone();
    let baseline_function_state_unresolved = budget.function_state_unresolved;
    let mut discovered_functions = BTreeMap::<String, PosixFunctionBinding>::new();
    let mut commands = Vec::new();
    for body in candidates {
        *state.context = baseline_context.clone();
        *state.shell_variables = baseline_shell_variables.clone();
        *state.exported_variables = baseline_exported_variables.clone();
        *state.export_all = baseline_export_all;
        *state.cwd_tainted = baseline_cwd_tainted;
        *state.cwd_conditionally_set = baseline_cwd_conditionally_set;
        *state.functions = baseline_functions.clone();
        budget.function_state_unresolved = baseline_function_state_unresolved;
        commands.extend(execute_posix_current_shell_body(
            &body,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth + 1,
            completeness,
        ));
        for (name, binding) in state.functions.iter() {
            if baseline_functions.get(name) == Some(binding) {
                continue;
            }
            discovered_functions
                .entry(name.clone())
                .and_modify(|existing| {
                    if &*existing != binding {
                        existing.body = None;
                    }
                })
                .or_insert_with(|| binding.clone());
        }
        for (name, baseline_binding) in &baseline_functions {
            if state.functions.get(name) == Some(baseline_binding) {
                continue;
            }
            discovered_functions
                .entry(name.clone())
                .or_insert_with(|| baseline_binding.clone())
                .body = None;
        }
    }
    *state.context = baseline_context;
    *state.shell_variables = baseline_shell_variables;
    *state.exported_variables = baseline_exported_variables;
    *state.export_all = baseline_export_all;
    *state.cwd_tainted = baseline_cwd_tainted;
    *state.cwd_conditionally_set = baseline_cwd_conditionally_set;
    *state.functions = baseline_functions;
    budget.function_state_unresolved = baseline_function_state_unresolved;
    for (name, mut binding) in discovered_functions {
        // Unless one branch is proven to execute, keep only the name so a
        // later external command cannot be trusted as the same spelling.
        // A literal `if true; then ...; fi` has exactly one taken branch, so
        // its function definitions do become current-shell bindings.
        if !retain_proven_function_bodies {
            binding.body = None;
        }
        state.functions.insert(name, binding);
    }
    taint_posix_function_execution(state, budget, completeness);
    commands
}

fn owned_posix_if_then_has_proven_true_condition(
    segments: &[tokenize::Segment],
    functions: &BTreeMap<String, PosixFunctionBinding>,
    function_state_unresolved: bool,
) -> bool {
    if function_state_unresolved || functions.contains_key("true") || segments.len() < 3 {
        return false;
    }
    let Some(condition) = segments.first() else {
        return false;
    };
    if posix_control_opener(condition) != Some("fi") || condition.args.len() != 1 {
        return false;
    }
    let condition_word = &condition.args[0];
    if !command_word_is_statically_bound(condition_word, ShellType::Posix)
        || normalize_shell_token(condition_word, ShellType::Posix) != "true"
    {
        return false;
    }
    let then_starts_body = segments
        .get(1)
        .and_then(|segment| segment.command.as_deref())
        .and_then(strict_posix_control_word)
        .is_some_and(|word| word == "then");
    let closes_if = segments
        .last()
        .is_some_and(|segment| posix_control_closer(segment) == Some("fi"));
    let has_alternate_branch = segments.iter().skip(2).any(|segment| {
        segment
            .command
            .as_deref()
            .and_then(strict_posix_control_word)
            .is_some_and(|word| matches!(word.as_str(), "elif" | "else"))
    });
    let body_has_unproven_control = segments
        .iter()
        .skip(1)
        .take(segments.len().saturating_sub(2))
        .any(|segment| {
            matches!(
                segment.preceding_separator.as_deref(),
                Some("&&" | "||" | "|" | "|&" | "&")
            ) || posix_control_opener(segment).is_some()
                || segment
                    .command
                    .as_deref()
                    .filter(|command| command_word_is_statically_bound(command, ShellType::Posix))
                    .map(|command| normalize_cmd_base(command, ShellType::Posix))
                    .is_some_and(|command| {
                        matches!(command.as_str(), "return" | "exit" | "break" | "continue")
                    })
        });
    then_starts_body && closes_if && !has_alternate_branch && !body_has_unproven_control
}

#[allow(clippy::too_many_arguments)]
fn execute_owned_posix_control(
    segments: &[tokenize::Segment],
    complete: bool,
    separator: Option<&str>,
    outgoing_separator: Option<&str>,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Vec<Web3CommandFactsV2> {
    let mut recovered = Vec::<String>::new();
    let mut recovered_bytes = 0usize;
    for segment in segments {
        if let Some(scan) = crate::extract::posix_current_scope_dispatch_scan(segment) {
            if scan.gap.is_some() {
                completeness.add(IncompleteReason::UnresolvedIndirection);
            }
            for body in scan.bodies {
                recovered_bytes = recovered_bytes.saturating_add(body.input.len());
                recovered.push(body.input);
            }
        } else if posix_control_opener(segment).is_none()
            && posix_control_closer(segment).is_none()
            && !segment.raw.trim().is_empty()
        {
            recovered_bytes = recovered_bytes.saturating_add(segment.raw.len());
            recovered.push(segment.raw.clone());
        }
        if recovered.len() > MAX_SHELL_SEGMENTS || recovered_bytes > MAX_INPUT_BYTES {
            completeness.add(IncompleteReason::SegmentBudgetExceeded);
            completeness.add(IncompleteReason::UnresolvedIndirection);
            taint_posix_function_execution(state, budget, completeness);
            return Vec::new();
        }
    }
    if !complete {
        completeness.add(IncompleteReason::UnresolvedIndirection);
    }

    // Execute the recoverable commands as one conservative path. This keeps
    // definitions, assignments, and cwd changes visible to later segments in
    // the same syntactic control while the snapshot/restore below prevents
    // any branch-local state from becoming unconditional caller state.
    let combined = recovered.join(";\n");
    let retain_proven_function_bodies = complete
        && !matches!(separator, Some("&&" | "||" | "|" | "|&"))
        && !matches!(outgoing_separator, Some("|" | "|&" | "&"))
        && owned_posix_if_then_has_proven_true_condition(
            segments,
            state.functions,
            budget.function_state_unresolved,
        );
    execute_posix_conditional_candidates(
        vec![combined],
        retain_proven_function_bodies,
        call_span,
        state,
        budget,
        fact_budget,
        nested_depth,
        completeness,
    )
}

fn execute_posix_current_shell_body(
    input: &str,
    call_span: SourceSpan,
    state: &mut PosixShellState<'_>,
    budget: &mut PosixFunctionBudget,
    fact_budget: &mut CommandFactBudget,
    nested_depth: usize,
    completeness: &mut Completeness,
) -> Vec<Web3CommandFactsV2> {
    if !fact_budget.enter_parse(completeness) {
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    }
    if input.len() > MAX_INPUT_BYTES {
        completeness.add(IncompleteReason::InputBytesExceeded);
        taint_posix_function_execution(state, budget, completeness);
        return Vec::new();
    }
    let (mut segments, token_budget) = tokenize::tokenize_bounded(
        input,
        ShellType::Posix,
        MAX_SHELL_SEGMENTS,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    );
    if token_budget.segments_truncated {
        completeness.add(IncompleteReason::SegmentBudgetExceeded);
    }
    if token_budget.words_truncated {
        completeness.add(IncompleteReason::ArgumentCountExceeded);
    }
    if token_budget.word_bytes_truncated {
        completeness.add(IncompleteReason::ArgumentBytesExceeded);
    }
    let retained_work = fact_budget.retain_work(segments.len(), completeness);
    let work_truncated = retained_work != segments.len();
    segments.truncate(retained_work);
    let execution_truncated = token_budget.segments_truncated
        || token_budget.words_truncated
        || token_budget.word_bytes_truncated
        || work_truncated
        || has_incomplete_quoting(input, ShellType::Posix);
    if execution_truncated {
        taint_posix_function_execution(state, budget, completeness);
    }

    let conditional_cwd_flow = conditional_cwd_lists(&segments, ShellType::Posix);
    let (control_owner, control_regions) = posix_control_ownership(&segments);
    let trailing_background = !work_truncated
        && !token_budget.segments_truncated
        && posix_trailing_background(input, &segments);
    let mut commands = Vec::new();
    let mut pending_cwd = None;
    let mut pending_assignments = None;
    let mut list_context_snapshot = (*state.context).clone();
    let mut list_shell_variables_snapshot = (*state.shell_variables).clone();
    let mut list_exported_variables_snapshot = (*state.exported_variables).clone();
    let mut list_export_all_snapshot = *state.export_all;
    let mut list_cwd_tainted_snapshot = *state.cwd_tainted;
    let mut list_cwd_conditionally_set_snapshot = *state.cwd_conditionally_set;
    let mut list_functions_snapshot = (*state.functions).clone();
    let mut list_function_state_unresolved_snapshot = budget.function_state_unresolved;

    for (segment_index, segment) in segments.iter().enumerate() {
        if control_owner[segment_index].is_some_and(|owner| owner != segment_index) {
            continue;
        }
        let control_region = control_regions[segment_index];
        let separator = segment.preceding_separator.as_deref();
        let outgoing_segment = control_region
            .map(|region| region.end)
            .unwrap_or(segment_index);
        let outgoing_separator = posix_outgoing_separator(input, &segments, outgoing_segment);
        if separator == Some("&") {
            pending_assignments = None;
            pending_cwd = None;
            *state.context = list_context_snapshot.clone();
            *state.shell_variables = list_shell_variables_snapshot.clone();
            *state.exported_variables = list_exported_variables_snapshot.clone();
            *state.export_all = list_export_all_snapshot;
            *state.cwd_tainted = list_cwd_tainted_snapshot;
            *state.cwd_conditionally_set = list_cwd_conditionally_set_snapshot;
            *state.functions = list_functions_snapshot.clone();
            budget.function_state_unresolved = list_function_state_unresolved_snapshot;
        } else {
            if let Some(assignments) = pending_assignments.take() {
                apply_pending_assignments(
                    assignments,
                    separator,
                    ShellType::Posix,
                    state.shell_variables,
                    state.context,
                    state.exported_variables,
                    *state.export_all,
                    completeness,
                );
            }
            if let Some(pending) = pending_cwd.take() {
                apply_pending_cd(
                    pending,
                    separator,
                    ShellType::Posix,
                    state.context,
                    state.cwd_tainted,
                    state.cwd_conditionally_set,
                );
            } else if *state.cwd_conditionally_set && !matches!(separator, Some("&&" | "|" | "|&"))
            {
                taint_context_cwd(state.context);
                *state.cwd_tainted = true;
                *state.cwd_conditionally_set = false;
            }
        }
        if matches!(separator, Some(";" | "\n" | "&")) {
            list_context_snapshot = (*state.context).clone();
            list_shell_variables_snapshot = (*state.shell_variables).clone();
            list_exported_variables_snapshot = (*state.exported_variables).clone();
            list_export_all_snapshot = *state.export_all;
            list_cwd_tainted_snapshot = *state.cwd_tainted;
            list_cwd_conditionally_set_snapshot = *state.cwd_conditionally_set;
            list_functions_snapshot = (*state.functions).clone();
            list_function_state_unresolved_snapshot = budget.function_state_unresolved;
        }

        if let Some(region) = control_region {
            commands.extend(execute_owned_posix_control(
                &segments[segment_index..=region.end],
                region.complete,
                separator,
                outgoing_separator,
                call_span,
                state,
                budget,
                fact_budget,
                nested_depth,
                completeness,
            ));
            continue;
        }

        if register_posix_function_definition(segment, state.functions, budget, completeness) {
            continue;
        }

        let direct_function = direct_posix_function_name(segment, state.functions);
        let current_shell_command = if direct_function.is_some() {
            Ok(None)
        } else {
            crate::extract::literal_posix_current_shell_command(segment)
        };
        let invoked_function = match current_shell_command.as_ref() {
            Ok(Some((name, false))) if state.functions.contains_key(name) => Some(name.clone()),
            Ok(_) => direct_function,
            Err(()) => {
                taint_posix_function_execution(state, budget, completeness);
                continue;
            }
        };
        if let Some(name) = invoked_function {
            // Bash performs command/process substitutions in arguments before
            // dispatching the function. The normal child-shell pass is below
            // dispatch, so run it explicitly here rather than letting a
            // function call hide executable argument material.
            let argument_shells = execute_posix_child_shells_for_segment(
                segment,
                call_span,
                state,
                budget,
                fact_budget,
                nested_depth,
                completeness,
            );
            commands.extend(argument_shells.commands);
            if argument_shells.consumes_segment {
                continue;
            }
            commands.extend(execute_posix_function_invocation(
                segment,
                &name,
                call_span,
                state,
                budget,
                fact_budget,
                nested_depth,
                completeness,
                separator,
                outgoing_separator,
            ));
            continue;
        }

        if apply_posix_function_table_mutation(segment, state.functions, budget, completeness) {
            continue;
        }

        match literal_posix_eval_body(segment) {
            Ok(Some(body)) => {
                commands.extend(execute_posix_inline_current_shell_body(
                    &body,
                    call_span,
                    state,
                    budget,
                    fact_budget,
                    nested_depth,
                    completeness,
                    separator,
                    outgoing_separator,
                ));
                continue;
            }
            Err(()) => {
                taint_posix_function_execution(state, budget, completeness);
                continue;
            }
            Ok(None) => {}
        }

        match crate::extract::literal_posix_brace_group_body(segment) {
            Ok(Some(body)) => {
                commands.extend(execute_posix_inline_current_shell_body(
                    &body,
                    call_span,
                    state,
                    budget,
                    fact_budget,
                    nested_depth,
                    completeness,
                    separator,
                    outgoing_separator,
                ));
                continue;
            }
            Err(()) => {
                taint_posix_function_execution(state, budget, completeness);
                continue;
            }
            Ok(None) => {}
        }

        if let Some(nested) = execute_posix_conditional_control_body(
            segment,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth,
            completeness,
        ) {
            commands.extend(nested);
            continue;
        }

        let child_shells = execute_posix_child_shells_for_segment(
            segment,
            call_span,
            state,
            budget,
            fact_budget,
            nested_depth,
            completeness,
        );
        commands.extend(child_shells.commands);
        if child_shells.consumes_segment {
            continue;
        }

        if current_shell_command
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|(command, _)| command == "return")
        {
            break;
        }
        if current_shell_command
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|(command, _)| matches!(command.as_str(), "source" | "."))
        {
            taint_posix_function_execution(state, budget, completeness);
            continue;
        }

        if handle_posix_environment_mutation(
            segment,
            separator,
            outgoing_separator,
            state.shell_variables,
            state.context,
            state.exported_variables,
            state.export_all,
            completeness,
        ) || handle_unmodeled_environment_mutation(
            segment,
            ShellType::Posix,
            state.shell_variables,
            state.context,
            completeness,
        ) {
            continue;
        }
        if let Some(assignments) = assignment_only_segment(segment, ShellType::Posix) {
            pending_assignments = Some(PendingAssignments {
                values: assignments,
                conditionally_executed: matches!(separator, Some("&&" | "||")),
                incoming_pipeline: matches!(separator, Some("|" | "|&")),
            });
            continue;
        }
        if let Some(pending) = pending_cd(
            segment,
            ShellType::Posix,
            state.context,
            state.shell_variables,
        ) {
            pending_cwd = Some(PendingCd {
                change: if conditional_cwd_flow[segment_index] {
                    PendingCdChange::Unresolved
                } else {
                    pending
                },
                incoming_pipeline: matches!(separator, Some("|" | "|&")),
            });
            continue;
        }

        let mut nested = parse_web3_commands_depth(
            &segment.raw,
            ShellType::Posix,
            (*state.context).clone(),
            nested_depth,
            Completeness::complete(),
            fact_budget,
            false,
        );
        for facts in &mut nested.commands {
            rebase_nested_fact(facts, call_span);
        }
        completeness.merge(&nested.completeness);
        commands.extend(nested.commands);
    }

    if trailing_background {
        *state.context = list_context_snapshot;
        *state.shell_variables = list_shell_variables_snapshot;
        *state.exported_variables = list_exported_variables_snapshot;
        *state.export_all = list_export_all_snapshot;
        *state.cwd_tainted = list_cwd_tainted_snapshot;
        *state.cwd_conditionally_set = list_cwd_conditionally_set_snapshot;
        *state.functions = list_functions_snapshot;
        budget.function_state_unresolved = list_function_state_unresolved_snapshot;
        return commands;
    }

    if let Some(assignments) = pending_assignments {
        apply_pending_assignments(
            assignments,
            Some(";"),
            ShellType::Posix,
            state.shell_variables,
            state.context,
            state.exported_variables,
            *state.export_all,
            completeness,
        );
    }
    if let Some(pending) = pending_cwd {
        apply_pending_cd(
            pending,
            Some(";"),
            ShellType::Posix,
            state.context,
            state.cwd_tainted,
            state.cwd_conditionally_set,
        );
    }
    if execution_truncated {
        taint_posix_function_execution(state, budget, completeness);
    }
    commands
}

fn input_too_large_result() -> Web3ParseResultV2 {
    let mut completeness = Completeness::complete();
    completeness.add(IncompleteReason::InputBytesExceeded);
    Web3ParseResultV2 {
        commands: Vec::new(),
        effects: CommandEffects::new(Vec::new(), completeness.clone()),
        completeness,
    }
}

fn empty_parse_result(completeness: Completeness) -> Web3ParseResultV2 {
    Web3ParseResultV2 {
        commands: Vec::new(),
        effects: CommandEffects::new(Vec::new(), completeness.clone()),
        completeness,
    }
}

/// Parse bounded top-level shell segments into Web3 semantic facts. This is a
/// pure classifier except for the explicitly enabled, no-follow static config
/// reads in [`Web3ParseContextV2`]; it never executes a command or performs I/O to
/// the network.
pub fn parse_web3_commands_v2(
    input: &str,
    shell: ShellType,
    context: &Web3ParseContextV2,
) -> Web3ParseResultV2 {
    if input.len() > MAX_INPUT_BYTES {
        return input_too_large_result();
    }
    let (context, completeness) = bounded_parse_context(context);
    let mut fact_budget = CommandFactBudget::default();
    parse_web3_commands_depth(
        input,
        shell,
        context,
        0,
        completeness,
        &mut fact_budget,
        true,
    )
}

/// Backwards-compatible schema-v1 entry point. New callers that need trusted
/// RPC path outcomes or role-tagged signer/destination collections should use
/// [`parse_web3_commands_v2`].
pub fn parse_web3_commands(
    input: &str,
    shell: ShellType,
    context: &Web3ParseContext,
) -> Web3ParseResult {
    if input.len() > MAX_INPUT_BYTES {
        return input_too_large_result().into();
    }
    let (context, completeness) = bounded_v1_parse_context(context);
    let mut fact_budget = CommandFactBudget::default();
    parse_web3_commands_depth(
        input,
        shell,
        context,
        0,
        completeness,
        &mut fact_budget,
        true,
    )
    .into()
}

fn parse_web3_commands_depth(
    input: &str,
    shell: ShellType,
    mut context: Web3ParseContextV2,
    nested_depth: usize,
    initial_completeness: Completeness,
    fact_budget: &mut CommandFactBudget,
    scan_posix_child_shells: bool,
) -> Web3ParseResultV2 {
    let mut completeness = initial_completeness;
    if !fact_budget.enter_parse(&mut completeness) {
        return empty_parse_result(completeness);
    }
    if input.len() > MAX_INPUT_BYTES {
        completeness.add(IncompleteReason::InputBytesExceeded);
        return empty_parse_result(completeness);
    }
    let (mut segments, token_budget) = tokenize::tokenize_bounded(
        input,
        shell,
        MAX_SHELL_SEGMENTS,
        MAX_ARGV_ITEMS + 1,
        MAX_ARGUMENT_BYTES,
    );
    if token_budget.segments_truncated {
        completeness.add(IncompleteReason::SegmentBudgetExceeded);
    }
    if token_budget.words_truncated {
        completeness.add(IncompleteReason::ArgumentCountExceeded);
    }
    if token_budget.word_bytes_truncated {
        completeness.add(IncompleteReason::ArgumentBytesExceeded);
    }
    let retained_work = fact_budget.retain_work(segments.len(), &mut completeness);
    segments.truncate(retained_work);
    if has_incomplete_quoting(input, shell) {
        completeness.add(IncompleteReason::IncompleteQuoting);
    }
    let conditional_cwd_flow = conditional_cwd_lists(&segments, shell);
    let (posix_control_owner, posix_control_regions) = if shell == ShellType::Posix {
        posix_control_ownership(&segments)
    } else {
        (vec![None; segments.len()], vec![None; segments.len()])
    };
    let mut commands = Vec::new();
    let mut pending_cwd = None;
    let mut pending_assignments = None;
    let mut exported_variables = context.environment.keys().cloned().collect::<BTreeSet<_>>();
    let mut export_all = false;
    let mut shell_variables: BTreeMap<String, ShellVariable> = context
        .environment
        .iter()
        .map(|(name, value)| {
            let value = if command_word_is_statically_bound(value, shell) {
                ShellVariable::Static(value.clone())
            } else {
                ShellVariable::Unresolved
            };
            (name.clone(), value)
        })
        .collect();
    let mut cwd_tainted = false;
    let mut cwd_conditionally_set = false;
    let mut list_context_snapshot = context.clone();
    let mut list_shell_variables_snapshot = shell_variables.clone();
    let mut list_exported_variables_snapshot = exported_variables.clone();
    let mut list_export_all_snapshot = export_all;
    let mut list_cwd_tainted_snapshot = cwd_tainted;
    let mut list_cwd_conditionally_set_snapshot = cwd_conditionally_set;
    let mut posix_functions = BTreeMap::<String, PosixFunctionBinding>::new();
    let mut list_posix_functions_snapshot = posix_functions.clone();
    let mut posix_function_budget = PosixFunctionBudget::default();
    let mut list_posix_function_state_unresolved_snapshot =
        posix_function_budget.function_state_unresolved;
    for (segment_index, segment) in segments.iter().take(MAX_SHELL_SEGMENTS).enumerate() {
        if posix_control_owner[segment_index].is_some_and(|owner| owner != segment_index) {
            continue;
        }
        let control_region = posix_control_regions[segment_index];
        let separator = segment.preceding_separator.as_deref();
        let outgoing_segment = control_region
            .map(|region| region.end)
            .unwrap_or(segment_index);
        let outgoing_separator = if shell == ShellType::Posix {
            posix_outgoing_separator(input, &segments, outgoing_segment)
        } else {
            segments
                .get(outgoing_segment + 1)
                .and_then(|next| next.preceding_separator.as_deref())
        };
        if separator == Some("&") && shell != ShellType::Cmd {
            // A trailing `&` backgrounds the complete preceding AND-list. Its
            // shell assignments and cwd changes occurred in a child context,
            // so restore the state captured before that list.
            pending_assignments = None;
            pending_cwd = None;
            context = list_context_snapshot.clone();
            shell_variables = list_shell_variables_snapshot.clone();
            exported_variables = list_exported_variables_snapshot.clone();
            export_all = list_export_all_snapshot;
            cwd_tainted = list_cwd_tainted_snapshot;
            cwd_conditionally_set = list_cwd_conditionally_set_snapshot;
            posix_functions = list_posix_functions_snapshot.clone();
            posix_function_budget.function_state_unresolved =
                list_posix_function_state_unresolved_snapshot;
        } else {
            if let Some(assignments) = pending_assignments.take() {
                apply_pending_assignments(
                    assignments,
                    separator,
                    shell,
                    &mut shell_variables,
                    &mut context,
                    &exported_variables,
                    export_all,
                    &mut completeness,
                );
            }
            if let Some(pending) = pending_cwd.take() {
                apply_pending_cd(
                    pending,
                    separator,
                    shell,
                    &mut context,
                    &mut cwd_tainted,
                    &mut cwd_conditionally_set,
                );
            } else if cwd_conditionally_set && !matches!(separator, Some("&&" | "|" | "|&")) {
                taint_context_cwd(&mut context);
                cwd_tainted = true;
                cwd_conditionally_set = false;
            }
        }
        if matches!(separator, Some(";" | "\n" | "&")) {
            list_context_snapshot = context.clone();
            list_shell_variables_snapshot = shell_variables.clone();
            list_exported_variables_snapshot = exported_variables.clone();
            list_export_all_snapshot = export_all;
            list_cwd_tainted_snapshot = cwd_tainted;
            list_cwd_conditionally_set_snapshot = cwd_conditionally_set;
            list_posix_functions_snapshot = posix_functions.clone();
            list_posix_function_state_unresolved_snapshot =
                posix_function_budget.function_state_unresolved;
        }
        if shell == ShellType::Posix {
            if let Some(region) = control_region {
                let call_span = SourceSpan::new(
                    segment.byte_range.start,
                    segments[region.end].byte_range.end,
                );
                let mut state = PosixShellState {
                    context: &mut context,
                    shell_variables: &mut shell_variables,
                    exported_variables: &mut exported_variables,
                    export_all: &mut export_all,
                    cwd_tainted: &mut cwd_tainted,
                    cwd_conditionally_set: &mut cwd_conditionally_set,
                    functions: &mut posix_functions,
                };
                commands.extend(execute_owned_posix_control(
                    &segments[segment_index..=region.end],
                    region.complete,
                    separator,
                    outgoing_separator,
                    call_span,
                    &mut state,
                    &mut posix_function_budget,
                    fact_budget,
                    nested_depth,
                    &mut completeness,
                ));
                continue;
            }
            if register_posix_function_definition(
                segment,
                &mut posix_functions,
                &mut posix_function_budget,
                &mut completeness,
            ) {
                continue;
            }
            let direct_function = direct_posix_function_name(segment, &posix_functions);
            let current_shell_command = if direct_function.is_some() {
                Ok(None)
            } else {
                crate::extract::literal_posix_current_shell_command(segment)
            };
            let invoked_function = match current_shell_command.as_ref() {
                Ok(Some((name, false))) if posix_functions.contains_key(name) => Some(name.clone()),
                Ok(_) => direct_function,
                Err(()) => {
                    let mut state = PosixShellState {
                        context: &mut context,
                        shell_variables: &mut shell_variables,
                        exported_variables: &mut exported_variables,
                        export_all: &mut export_all,
                        cwd_tainted: &mut cwd_tainted,
                        cwd_conditionally_set: &mut cwd_conditionally_set,
                        functions: &mut posix_functions,
                    };
                    taint_posix_function_execution(
                        &mut state,
                        &mut posix_function_budget,
                        &mut completeness,
                    );
                    continue;
                }
            };
            if let Some(name) = invoked_function {
                let mut state = PosixShellState {
                    context: &mut context,
                    shell_variables: &mut shell_variables,
                    exported_variables: &mut exported_variables,
                    export_all: &mut export_all,
                    cwd_tainted: &mut cwd_tainted,
                    cwd_conditionally_set: &mut cwd_conditionally_set,
                    functions: &mut posix_functions,
                };
                let argument_shells = execute_posix_child_shells_for_segment(
                    segment,
                    source_span(segment),
                    &mut state,
                    &mut posix_function_budget,
                    fact_budget,
                    nested_depth,
                    &mut completeness,
                );
                commands.extend(argument_shells.commands);
                if argument_shells.consumes_segment {
                    continue;
                }
                commands.extend(execute_posix_function_invocation(
                    segment,
                    &name,
                    source_span(segment),
                    &mut state,
                    &mut posix_function_budget,
                    fact_budget,
                    nested_depth,
                    &mut completeness,
                    separator,
                    outgoing_separator,
                ));
                continue;
            }
            if apply_posix_function_table_mutation(
                segment,
                &mut posix_functions,
                &mut posix_function_budget,
                &mut completeness,
            ) {
                continue;
            }
            match literal_posix_eval_body(segment) {
                Ok(Some(body)) => {
                    let mut state = PosixShellState {
                        context: &mut context,
                        shell_variables: &mut shell_variables,
                        exported_variables: &mut exported_variables,
                        export_all: &mut export_all,
                        cwd_tainted: &mut cwd_tainted,
                        cwd_conditionally_set: &mut cwd_conditionally_set,
                        functions: &mut posix_functions,
                    };
                    commands.extend(execute_posix_inline_current_shell_body(
                        &body,
                        source_span(segment),
                        &mut state,
                        &mut posix_function_budget,
                        fact_budget,
                        nested_depth,
                        &mut completeness,
                        separator,
                        outgoing_separator,
                    ));
                    continue;
                }
                Err(()) => {
                    let mut state = PosixShellState {
                        context: &mut context,
                        shell_variables: &mut shell_variables,
                        exported_variables: &mut exported_variables,
                        export_all: &mut export_all,
                        cwd_tainted: &mut cwd_tainted,
                        cwd_conditionally_set: &mut cwd_conditionally_set,
                        functions: &mut posix_functions,
                    };
                    taint_posix_function_execution(
                        &mut state,
                        &mut posix_function_budget,
                        &mut completeness,
                    );
                    continue;
                }
                Ok(None) => {}
            }
            match crate::extract::literal_posix_brace_group_body(segment) {
                Ok(Some(body)) => {
                    let mut state = PosixShellState {
                        context: &mut context,
                        shell_variables: &mut shell_variables,
                        exported_variables: &mut exported_variables,
                        export_all: &mut export_all,
                        cwd_tainted: &mut cwd_tainted,
                        cwd_conditionally_set: &mut cwd_conditionally_set,
                        functions: &mut posix_functions,
                    };
                    commands.extend(execute_posix_inline_current_shell_body(
                        &body,
                        source_span(segment),
                        &mut state,
                        &mut posix_function_budget,
                        fact_budget,
                        nested_depth,
                        &mut completeness,
                        separator,
                        outgoing_separator,
                    ));
                    continue;
                }
                Err(()) => {
                    let mut state = PosixShellState {
                        context: &mut context,
                        shell_variables: &mut shell_variables,
                        exported_variables: &mut exported_variables,
                        export_all: &mut export_all,
                        cwd_tainted: &mut cwd_tainted,
                        cwd_conditionally_set: &mut cwd_conditionally_set,
                        functions: &mut posix_functions,
                    };
                    taint_posix_function_execution(
                        &mut state,
                        &mut posix_function_budget,
                        &mut completeness,
                    );
                    continue;
                }
                Ok(None) => {}
            }
            let mut state = PosixShellState {
                context: &mut context,
                shell_variables: &mut shell_variables,
                exported_variables: &mut exported_variables,
                export_all: &mut export_all,
                cwd_tainted: &mut cwd_tainted,
                cwd_conditionally_set: &mut cwd_conditionally_set,
                functions: &mut posix_functions,
            };
            if let Some(nested) = execute_posix_conditional_control_body(
                segment,
                source_span(segment),
                &mut state,
                &mut posix_function_budget,
                fact_budget,
                nested_depth,
                &mut completeness,
            ) {
                commands.extend(nested);
                continue;
            }
            if scan_posix_child_shells {
                let child_shells = execute_posix_child_shells_for_segment(
                    segment,
                    source_span(segment),
                    &mut state,
                    &mut posix_function_budget,
                    fact_budget,
                    nested_depth,
                    &mut completeness,
                );
                commands.extend(child_shells.commands);
                if child_shells.consumes_segment {
                    continue;
                }
            }
            if current_shell_command
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .is_some_and(|(command, _)| matches!(command.as_str(), "source" | "."))
            {
                let mut state = PosixShellState {
                    context: &mut context,
                    shell_variables: &mut shell_variables,
                    exported_variables: &mut exported_variables,
                    export_all: &mut export_all,
                    cwd_tainted: &mut cwd_tainted,
                    cwd_conditionally_set: &mut cwd_conditionally_set,
                    functions: &mut posix_functions,
                };
                taint_posix_function_execution(
                    &mut state,
                    &mut posix_function_budget,
                    &mut completeness,
                );
                continue;
            }
        }
        if (shell == ShellType::Posix
            && handle_posix_environment_mutation(
                segment,
                separator,
                outgoing_separator,
                &mut shell_variables,
                &mut context,
                &mut exported_variables,
                &mut export_all,
                &mut completeness,
            ))
            || handle_unmodeled_environment_mutation(
                segment,
                shell,
                &mut shell_variables,
                &mut context,
                &mut completeness,
            )
        {
            continue;
        }
        if shell == ShellType::Posix {
            if let Some(assignments) = assignment_only_segment(segment, shell) {
                pending_assignments = Some(PendingAssignments {
                    values: assignments,
                    conditionally_executed: matches!(separator, Some("&&" | "||")),
                    incoming_pipeline: matches!(separator, Some("|" | "|&")),
                });
                continue;
            }
        }
        if let Some(pending) = pending_cd(segment, shell, &context, &shell_variables) {
            pending_cwd = Some(PendingCd {
                change: if conditional_cwd_flow[segment_index] {
                    PendingCdChange::Unresolved
                } else {
                    pending
                },
                incoming_pipeline: matches!(separator, Some("|" | "|&")),
            });
            continue;
        }
        let effective = match resolve_effective_command_bounded(segment, shell, MAX_WRAPPER_DEPTH) {
            Ok(effective) => effective,
            Err(error) => {
                let dynamic_identity = segment
                    .command
                    .as_deref()
                    .is_some_and(|command| !command_word_is_statically_bound(command, shell));
                if dynamic_identity {
                    completeness.add(IncompleteReason::UnresolvedIndirection);
                }
                if (shell != ShellType::Posix || scan_posix_child_shells)
                    && contains_potential_executable_web3_token(segment, shell)
                {
                    completeness.add(IncompleteReason::DynamicExecutionUnsupported);
                }
                if contains_web3_token(segment, shell)
                    || dynamic_identity
                    || segment.command.is_some()
                {
                    completeness.add(match error {
                        EffectiveCommandError::WrapperChainTooDeep => {
                            IncompleteReason::WrapperDepthExceeded
                        }
                        EffectiveCommandError::MissingOrAmbiguousCommand => {
                            IncompleteReason::AmbiguousSubcommand
                        }
                        // The shared resolver refused to analyze this segment
                        // because it exhausted the bounded command-analysis
                        // budget. Record the existing budget gap rather than
                        // letting an unanalyzed segment read as complete.
                        EffectiveCommandError::WorkBudgetExceeded => {
                            IncompleteReason::SegmentBudgetExceeded
                        }
                    });
                }
                continue;
            }
        };
        let original_base = segment
            .command
            .as_deref()
            .map(|command| normalize_cmd_base(command, shell));
        if original_base.as_deref() == Some("command")
            && effective
                .segment
                .command
                .as_deref()
                .is_some_and(|command| normalize_cmd_base(command, shell) == "cd")
        {
            pending_cwd = Some(PendingCd {
                change: if conditional_cwd_flow[segment_index] {
                    PendingCdChange::Unresolved
                } else {
                    pending_cd(&effective.segment, shell, &context, &shell_variables)
                        .unwrap_or(PendingCdChange::Unresolved)
                },
                incoming_pipeline: matches!(separator, Some("|" | "|&")),
            });
            continue;
        }
        let mut invocation_completeness = Completeness::complete();
        let (mut effective_context, context_completeness) =
            effective_parse_context(&context, &effective);
        let context_selector_overflow = context_completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded);
        invocation_completeness.merge(&context_completeness);
        if effective.segment.args.len() > MAX_ARGV_ITEMS {
            invocation_completeness.add(IncompleteReason::ArgumentCountExceeded);
        }
        let bounded_args: Vec<String> = effective
            .segment
            .args
            .iter()
            .take(MAX_ARGV_ITEMS)
            .filter_map(|arg| {
                if arg.len() > MAX_ARGUMENT_BYTES {
                    invocation_completeness.add(IncompleteReason::ArgumentBytesExceeded);
                    None
                } else {
                    Some(arg.clone())
                }
            })
            .collect();
        let Some(command) = effective.segment.command.clone() else {
            continue;
        };
        let invocation = Invocation {
            command,
            args: spans_for_effective_args(input, segment, &bounded_args, shell),
        };
        let Some(unwrapped) = unwrap_package_runners(
            invocation,
            shell,
            &effective.environment,
            &effective_context,
            &mut invocation_completeness,
        ) else {
            if contains_web3_token(segment, shell) || !invocation_completeness.is_complete() {
                completeness.merge(&invocation_completeness);
            }
            continue;
        };
        let UnwrappedInvocation {
            invocation,
            selected_cwd,
        } = unwrapped;
        if let Some(selected_cwd) = selected_cwd.as_ref() {
            set_context_cwd(
                &mut effective_context,
                selected_cwd,
                &mut invocation_completeness,
            );
        }
        let tool_name = normalize_cmd_base(&invocation.command, shell);
        let nested_execution = nested_execution(&invocation, shell);
        if nested_execution.is_unsupported() {
            invocation_completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            completeness.merge(&invocation_completeness);
            continue;
        }
        if nested_execution.is_not_nested() && !is_web3_tool_name(&tool_name) {
            if (shell != ShellType::Posix || scan_posix_child_shells)
                && contains_potential_executable_web3_token(segment, shell)
            {
                invocation_completeness.add(IncompleteReason::DynamicExecutionUnsupported);
            }
            if !invocation_completeness.is_complete() {
                completeness.merge(&invocation_completeness);
            }
            continue;
        }
        if cwd_tainted && effective_context.cwd.is_none() {
            invocation_completeness.add(IncompleteReason::WorkingDirectoryUnresolved);
        }
        let empty_environment = EffectiveEnvironment::default();
        let selector_environment = if (effective.execution_context_changed
            && effective.privileged_context_changed)
            || effective.environment.values.len() > MAX_CONTEXT_SELECTORS
            || context_selector_overflow
        {
            &empty_environment
        } else {
            &effective.environment
        };
        match nested_execution {
            NestedExecution::StaticShell(body) => {
                if nested_depth >= MAX_WRAPPER_DEPTH {
                    invocation_completeness.add(IncompleteReason::WrapperDepthExceeded);
                    completeness.merge(&invocation_completeness);
                    continue;
                }
                let mut nested = parse_web3_commands_depth(
                    &body,
                    ShellType::Posix,
                    effective_context,
                    nested_depth + 1,
                    Completeness::complete(),
                    fact_budget,
                    true,
                );
                for facts in &mut nested.commands {
                    rebase_nested_fact(facts, source_span(segment));
                    facts.completeness.merge(&invocation_completeness);
                }
                completeness.merge(&invocation_completeness);
                completeness.merge(&nested.completeness);
                commands.extend(nested.commands);
                continue;
            }
            NestedExecution::Unsupported => unreachable!("handled above"),
            NestedExecution::NotNested => {}
        }
        let mut facts = match tool_name.as_str() {
            "cast" => parse_cast(
                &invocation,
                shell,
                segment,
                selector_environment,
                &effective_context,
            ),
            "forge" => parse_forge(
                &invocation,
                shell,
                segment,
                selector_environment,
                &effective_context,
            ),
            "hardhat" => parse_hardhat(&invocation, shell, segment),
            "solana" => parse_solana(
                &invocation,
                shell,
                segment,
                selector_environment,
                &effective_context,
            ),
            "anchor" => parse_anchor(
                &invocation,
                shell,
                segment,
                selector_environment,
                &effective_context,
            ),
            _ => continue,
        };
        redact_public_fact_secret_shapes(&mut facts);
        facts.completeness.merge(&invocation_completeness);
        completeness.merge(&facts.completeness);
        facts.safety_flags.sort();
        facts.safety_flags.dedup();
        if fact_budget.retain(&facts, &mut completeness) {
            commands.push(facts);
        }
    }
    finalize_bounded_parse_result(commands, completeness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;

    fn parse_web3_commands(
        input: &str,
        shell: ShellType,
        context: &Web3ParseContextV2,
    ) -> Web3ParseResultV2 {
        super::parse_web3_commands_v2(input, shell, context)
    }

    fn parse(command: &str) -> Web3ParseResultV2 {
        parse_web3_commands(
            command,
            ShellType::Posix,
            &Web3ParseContextV2::without_filesystem(),
        )
    }

    fn only(command: &str) -> Web3CommandFactsV2 {
        let result = parse(command);
        assert_eq!(result.commands.len(), 1, "{result:?}");
        result.commands.into_iter().next().unwrap()
    }

    #[cfg(unix)]
    fn install_reviewed_runner_package(root: &Path, tool: &str) {
        use std::os::unix::fs::symlink;

        let package = root.join("node_modules").join(tool);
        let bin = package.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::write(
            package.join("package.json"),
            format!(r#"{{"name":"{tool}","bin":{{"{tool}":"bin/cli.js"}}}}"#),
        )
        .unwrap();
        let true_program = if Path::new("/usr/bin/true").is_file() {
            Path::new("/usr/bin/true")
        } else {
            Path::new("/bin/true")
        };
        fs::copy(true_program, bin.join("cli.js")).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(bin.join("cli.js"), fs::Permissions::from_mode(0o755)).unwrap();
        let shim = root.join("node_modules/.bin").join(tool);
        if !shim.exists() {
            symlink(format!("../{tool}/bin/cli.js"), shim).unwrap();
        }
    }

    #[cfg(unix)]
    fn reviewed_runner_context(root: &Path, tool: &str) -> Web3ParseContextV2 {
        install_reviewed_runner_package(root, tool);
        fs::write(root.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        let home = root.join("home");
        let prefix = root.join("npm-prefix");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(prefix.join("etc")).unwrap();
        let mut context = Web3ParseContextV2::for_cwd(root);
        context
            .environment
            .insert("HOME".to_string(), home.to_string_lossy().into_owned());
        context
            .environment
            .insert("PREFIX".to_string(), prefix.to_string_lossy().into_owned());
        context
    }

    #[test]
    fn cast_exact_write_read_and_no_send_modes() {
        assert_eq!(
            only("cast send 0xabc 'mint()'").write_mode,
            Web3WriteMode::StateChanging
        );
        assert_eq!(
            only("cast send --create 0x6000").operation,
            Web3OperationV2::Create
        );
        assert_eq!(
            only("cast send --dry-run 0xabc").write_mode,
            Web3WriteMode::NoChainWrite
        );
        for query in ["call 0xabc", "balance 0xabc", "code 0xabc"] {
            assert_eq!(
                only(&format!("cast {query}")).write_mode,
                Web3WriteMode::ReadOnly
            );
        }
        assert_eq!(
            only("cast mktx 0xabc").write_mode,
            Web3WriteMode::NoChainWrite
        );
    }

    #[test]
    fn cast_offline_and_generate_unsigned_do_not_suppress_the_broadcast() {
        // Only `--no-send` suppresses the broadcast. `--offline` restricts
        // dependency resolution and `--generate-unsigned` is not a Foundry
        // suppression flag, so neither may turn a send into a confident
        // gap-free NoChainWrite and delete its on-chain write effect.
        let offline = only("cast send 0xabc --offline");
        assert_eq!(offline.write_mode, Web3WriteMode::StateChanging);
        assert!(offline.safety_flags.contains(&Web3SafetyFlag::Offline));
        assert!(!offline.safety_flags.contains(&Web3SafetyFlag::NoSend));

        let generated = only("cast send 0xabc --generate-unsigned");
        assert_eq!(generated.write_mode, Web3WriteMode::StateChanging);
        assert!(!generated.safety_flags.contains(&Web3SafetyFlag::NoSend));
        // An unmodelled flag must still fail closed rather than read as clean.
        assert!(!generated.completeness.is_complete());

        let suppressed = only("cast send 0xabc --no-send");
        assert_eq!(suppressed.write_mode, Web3WriteMode::NoChainWrite);
        assert!(suppressed.safety_flags.contains(&Web3SafetyFlag::NoSend));
    }

    #[test]
    fn an_unresolvable_rpc_flag_is_not_reported_as_the_local_tool_default() {
        // The operator named an endpoint that this analysis cannot resolve.
        // Claiming the localhost default would describe a possible mainnet
        // send as local dev traffic.
        let facts = only("cast send 0xvictim --rpc-url $RPC_URL");
        assert!(
            facts
                .rpc
                .as_ref()
                .is_none_or(|rpc| rpc.source != SelectorSource::ToolDefault),
            "unresolved endpoint reported as the tool default: {:?}",
            facts.rpc
        );
        assert!(facts
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        // With no endpoint named at all, the documented default still applies.
        let defaulted = only("cast send 0xvictim");
        assert_eq!(
            defaulted.rpc.as_ref().map(|rpc| rpc.source),
            Some(SelectorSource::ToolDefault)
        );
    }

    #[test]
    fn an_attached_value_on_a_switch_cannot_suppress_the_broadcast() {
        // `--dry-run` and `--no-send` take no value, so `--dry-run=false` is
        // not a modelled spelling. Silently dropping the attached text while
        // still honouring the switch turned a broadcasting send into a
        // confident NoChainWrite with an empty gap set.
        for command in [
            "cast send 0xabc --dry-run=false",
            "cast send 0xabc --no-send=0",
        ] {
            let facts = only(command);
            assert_eq!(
                facts.write_mode,
                Web3WriteMode::StateChanging,
                "switch with attached value suppressed the write: {command}"
            );
            assert!(
                !facts.completeness.is_complete(),
                "unmodelled flag spelling must fail closed: {command}"
            );
        }
    }

    #[test]
    fn forge_broadcast_resume_and_safety_context() {
        assert_eq!(
            only("forge script Deploy.s.sol").write_mode,
            Web3WriteMode::DryRun
        );
        let broadcast =
            only("forge --profile prod script Deploy.s.sol --skip-simulation --broadcast");
        assert_eq!(broadcast.write_mode, Web3WriteMode::StateChanging);
        assert!(broadcast
            .safety_flags
            .contains(&Web3SafetyFlag::SkipSimulation));
        assert_eq!(
            only("forge script Deploy.s.sol --resume").write_mode,
            Web3WriteMode::StateChanging
        );
        assert!(!only("forge script Deploy.s.sol --skip-simulation")
            .safety_flags
            .contains(&Web3SafetyFlag::SkipSimulation));
    }

    #[test]
    fn hardhat_only_exact_deploy_shapes_are_positive() {
        assert_eq!(
            only("hardhat ignition deploy ignition/modules/Lock.ts --network sepolia").write_mode,
            Web3WriteMode::StateChanging
        );
        assert_eq!(
            only("hardhat deploy --network mainnet").write_mode,
            Web3WriteMode::StateChanging
        );
        assert_eq!(
            only("hardhat run scripts/report.ts").write_mode,
            Web3WriteMode::Unknown
        );
        assert_eq!(
            only("hardhat run scripts/upgrade_proxy.ts").write_mode,
            Web3WriteMode::PotentialWrite
        );
    }

    #[test]
    fn solana_and_anchor_exact_grammars() {
        let solana = only("solana --url https://api.devnet.solana.com program deploy program.so --program-id id.json --skip-preflight");
        assert_eq!(solana.operation, Web3OperationV2::ProgramDeploy);
        assert_eq!(solana.write_mode, Web3WriteMode::StateChanging);
        assert!(solana.safety_flags.contains(&Web3SafetyFlag::SkipPreflight));
        assert_eq!(
            only("solana program show 111").write_mode,
            Web3WriteMode::ReadOnly
        );
        assert_eq!(
            only("solana balance 111").write_mode,
            Web3WriteMode::ReadOnly
        );
        assert_eq!(
            only("anchor deploy --provider.cluster devnet --provider.wallet wallet.json")
                .write_mode,
            Web3WriteMode::StateChanging
        );
        assert_eq!(only("anchor build").write_mode, Web3WriteMode::NoChainWrite);
        assert_eq!(
            only("solana program close 111").write_mode,
            Web3WriteMode::Unknown
        );
        assert_eq!(only("anchor upgrade").write_mode, Web3WriteMode::Unknown);
    }

    #[test]
    fn leading_and_wrapper_environment_selectors_are_supported_without_expansion() {
        let solana = only(
            "SOLANA_URL=https://api.devnet.solana.com SOLANA_KEYPAIR=wallet.json solana program deploy p.so",
        );
        assert_eq!(
            solana.rpc.as_ref().unwrap().host.as_deref(),
            Some("api.devnet.solana.com")
        );
        assert_eq!(
            solana.signer(SignerRole::Keypair).unwrap().source(),
            SelectorSource::LeadingEnvironment
        );
        let anchor =
            only("env ANCHOR_PROVIDER_CLUSTER=devnet ANCHOR_WALLET=wallet.json anchor deploy");
        assert_eq!(anchor.network.network.as_ref().unwrap().value, "devnet");
        assert_eq!(
            anchor.signer(SignerRole::Wallet).unwrap().source(),
            SelectorSource::LeadingEnvironment
        );
    }

    #[test]
    fn wrappers_and_shell_forms_resolve_while_unproven_package_runners_fail_closed() {
        assert_eq!(
            only("sudo env FOUNDRY_PROFILE=prod cast send 0xabc").write_mode,
            Web3WriteMode::StateChanging
        );
        for command in [
            "npx cast send 0xabc",
            "npm exec -- cast send 0xabc",
            "pnpm exec cast send 0xabc",
            "yarn run cast send 0xabc",
            "./node_modules/.bin/cast send 0xabc",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
        for command in [
            "pnpm dlx cast send 0xabc",
            "yarn dlx cast send 0xabc",
            "bunx cast send 0xabc",
            "bun x cast send 0xabc",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
        let powershell = parse_web3_commands(
            "& 'cast.exe' send 0xabc --rpc-url=https://rpc.example",
            ShellType::PowerShell,
            &Web3ParseContextV2::without_filesystem(),
        );
        assert_eq!(
            powershell.commands[0].write_mode,
            Web3WriteMode::StateChanging
        );
    }

    #[cfg(unix)]
    #[test]
    fn literal_runner_prefix_options_are_bounded_and_cwd_aware() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let nested = root.join("packages/app");
        fs::create_dir_all(&nested).unwrap();
        install_reviewed_runner_package(&nested, "forge");
        fs::write(root.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        let mut context = Web3ParseContextV2::for_cwd(&root);
        context
            .environment
            .insert("HOME".to_string(), home.to_string_lossy().into_owned());

        for command in [
            "pnpm --dir packages/app exec forge script Deploy.s.sol --broadcast",
            "pnpm -Cpackages/app exec forge script Deploy.s.sol --broadcast",
            "yarn --cwd packages/app run forge script Deploy.s.sol --broadcast",
            "yarn --cwd=packages/app run forge script Deploy.s.sol --broadcast",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }

        let filtered = parse_web3_commands(
            "pnpm --filter app exec forge script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert!(filtered.commands.is_empty(), "{filtered:?}");
        assert!(filtered
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));

        let bun = parse_web3_commands(
            "bun --cwd packages/app x forge script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert_eq!(bun.commands.len(), 1, "{bun:?}");
        assert!(bun
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));

        for command in [
            "pnpm --filter '$APP' exec forge script Deploy.s.sol --broadcast",
            "pnpm --plugin ./evil.cjs exec forge script Deploy.s.sol --broadcast",
            "yarn --plugin ./evil.cjs run forge script Deploy.s.sol --broadcast",
            "bun --preload ./evil.js x forge script Deploy.s.sol --broadcast",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}: {result:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_local_bin_paths_are_trusted_beneath_the_observed_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let nested = project.join("packages/app");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(&outside).unwrap();
        install_reviewed_runner_package(&nested, "cast");
        install_reviewed_runner_package(&outside, "cast");
        let context = Web3ParseContextV2::for_cwd(&project);

        for command in [
            "packages/app/node_modules/.bin/cast send 0xabc".to_string(),
            format!(
                "{} send 0xabc",
                nested.join("node_modules/.bin/cast").display()
            ),
        ] {
            let result = parse_web3_commands(&command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }

        for command in [
            format!(
                "{} send 0xabc",
                outside.join("node_modules/.bin/cast").display()
            ),
            "node_modules/.bin/../cast send 0xabc".to_string(),
        ] {
            let result = parse_web3_commands(&command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_local_runners_reject_executable_bootstrap_environment() {
        let dir = tempfile::tempdir().unwrap();
        let context = reviewed_runner_context(dir.path(), "cast");
        for command in [
            "NODE_OPTIONS=--require=./evil.js pnpm exec cast balance 0xabc",
            "NODE_OPTIONS=--require=./evil.js yarn run cast balance 0xabc",
            "NPM_CONFIG_NODE_OPTIONS=--require=./evil.js pnpm exec cast balance 0xabc",
            "NODE_PATH=./evil yarn run cast balance 0xabc",
            "YARN_PATH=./evil.cjs yarn run cast balance 0xabc",
            "YARN_YARN_PATH=./evil.cjs yarn run cast balance 0xabc",
            "YARN_RC_FILENAME=.attacker-yarnrc.yml yarn run cast balance 0xabc",
            "NODE_OPTIONS=--require=./evil.js ./node_modules/.bin/cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }

        for command in [
            "NODE_OPTIONS='' pnpm exec cast balance 0xabc",
            "NODE_OPTIONS='' yarn run cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_local_shims_require_a_proven_shebang_interpreter() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let mut context = reviewed_runner_context(dir.path(), "cast");
        let command = "pnpm exec cast balance 0xabc";
        let native = parse_web3_commands(command, ShellType::Posix, &context);
        assert_eq!(native.commands.len(), 1, "{native:?}");

        let entrypoint = dir.path().join("node_modules/cast/bin/cli.js");
        fs::write(&entrypoint, "#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(&entrypoint, fs::Permissions::from_mode(0o755)).unwrap();
        let shadow = dir.path().join("shadow-bin");
        fs::create_dir(&shadow).unwrap();
        let shadow_node = shadow.join("node");
        fs::write(&shadow_node, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&shadow_node, fs::Permissions::from_mode(0o755)).unwrap();
        context.environment.insert(
            "PATH".to_string(),
            std::env::join_paths([shadow.as_path(), Path::new("/usr/bin"), Path::new("/bin")])
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        for command in [
            "pnpm exec cast balance 0xabc",
            "yarn run cast balance 0xabc",
            "./node_modules/.bin/cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }

        let unresolved_path = parse_web3_commands(
            "PATH=$RUNTIME_PATH pnpm exec cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(unresolved_path.commands.is_empty(), "{unresolved_path:?}");
        assert!(unresolved_path
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        fs::write(&entrypoint, "#!/usr/bin/env -S node\n").unwrap();
        let dynamic_shebang = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(dynamic_shebang.commands.is_empty(), "{dynamic_shebang:?}");
        assert!(dynamic_shebang
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
    }

    #[cfg(unix)]
    #[test]
    fn yarn_exact_local_inspects_bounded_no_follow_bootstrap_files() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let mut context = reviewed_runner_context(dir.path(), "cast");
        let command = "yarn run cast balance 0xabc";
        let benign_classic = "--install.check-files true\n--no-progress true\n";
        let benign_modern =
            "nodeLinker: node-modules\nenableColors: true\nenableProgressBars: false\n";
        let xdg = dir.path().join("xdg-config");
        fs::create_dir(&xdg).unwrap();
        let xdg_yarn_config = xdg.join("yarn");
        fs::write(&xdg_yarn_config, benign_classic).unwrap();
        context.environment.insert(
            "XDG_CONFIG_HOME".to_string(),
            xdg.to_string_lossy().into_owned(),
        );
        fs::remove_file(dir.path().join(".yarnrc.yml")).unwrap();
        let implicit_pnp_default = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(
            implicit_pnp_default.commands.is_empty(),
            "{implicit_pnp_default:?}"
        );
        assert!(implicit_pnp_default
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        fs::write(dir.path().join(".yarnrc"), benign_classic).unwrap();
        fs::write(dir.path().join(".yarnrc.yml"), benign_modern).unwrap();
        let benign = parse_web3_commands(command, ShellType::Posix, &context);
        assert_eq!(benign.commands.len(), 1, "{benign:?}");
        let benign_environment = parse_web3_commands(
            "YARN_ENABLE_COLORS=true yarn run cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            benign_environment.commands.len(),
            1,
            "{benign_environment:?}"
        );

        let home_config = dir.path().join("home/.config/yarn/config");
        let home_yarn_config = dir.path().join("home/.yarn/config");
        fs::create_dir_all(home_config.parent().unwrap()).unwrap();
        fs::create_dir_all(home_yarn_config.parent().unwrap()).unwrap();
        fs::write(&home_config, benign_classic).unwrap();
        fs::write(&home_yarn_config, benign_classic).unwrap();
        let benign_additional_locations = parse_web3_commands(command, ShellType::Posix, &context);
        assert_eq!(
            benign_additional_locations.commands.len(),
            1,
            "{benign_additional_locations:?}"
        );

        for (path, configured) in [
            (&xdg_yarn_config, "--modules-folder ./xdg-modules\n"),
            (&xdg_yarn_config, "yarn-path ./xdg-yarn.cjs\n"),
            (&home_config, "--modules-folder ./home-modules\n"),
            (&home_yarn_config, "yarn-path ./home-yarn.cjs\n"),
        ] {
            fs::write(path, configured).unwrap();
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{}: {result:?}", path.display());
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
            fs::write(path, benign_classic).unwrap();
        }

        let outside_xdg = dir.path().join("outside-xdg-yarnrc");
        fs::write(&outside_xdg, benign_classic).unwrap();
        fs::remove_file(&xdg_yarn_config).unwrap();
        symlink(&outside_xdg, &xdg_yarn_config).unwrap();
        let linked_xdg = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(linked_xdg.commands.is_empty(), "{linked_xdg:?}");
        assert!(linked_xdg
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));
        fs::remove_file(&xdg_yarn_config).unwrap();
        fs::write(&xdg_yarn_config, "x".repeat(MAX_CONFIG_BYTES as usize + 1)).unwrap();
        let oversized_xdg = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(oversized_xdg.commands.is_empty(), "{oversized_xdg:?}");
        assert!(oversized_xdg
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigBytesExceeded));
        fs::write(&xdg_yarn_config, benign_classic).unwrap();

        let dynamic_xdg = parse_web3_commands(
            "XDG_CONFIG_HOME=$RUNTIME_XDG yarn run cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(dynamic_xdg.commands.is_empty(), "{dynamic_xdg:?}");
        assert!(dynamic_xdg
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        let mut relative_xdg_context = context.clone();
        relative_xdg_context
            .environment
            .insert("XDG_CONFIG_HOME".to_string(), "relative-xdg".to_string());
        let relative_xdg = parse_web3_commands(command, ShellType::Posix, &relative_xdg_context);
        assert!(relative_xdg.commands.is_empty(), "{relative_xdg:?}");
        assert!(relative_xdg
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));

        for environment_override in [
            "YARN_NODE_LINKER=pnp",
            "YARN_PLUGINS=.yarn/plugins/attacker.cjs",
            "YARN_NPM_REGISTRY_SERVER=https://registry.attacker.example",
            "COREPACK_HOME=.corepack",
        ] {
            let result = parse_web3_commands(
                &format!("{environment_override} yarn run cast balance 0xabc"),
                ShellType::Posix,
                &context,
            );
            assert!(
                result.commands.is_empty(),
                "{environment_override}: {result:?}"
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }

        for manifest in [
            r#"{"packageManager":"yarn@4.5.0"}"#,
            r#"{"workspaces":["packages/*"]}"#,
            r#"{"installConfig":{"pnp":true}}"#,
            r#"{"scripts":{"precast":"./attacker.js"}}"#,
            r#"{"bin":{"cast":"./attacker.js"}}"#,
        ] {
            fs::write(dir.path().join("package.json"), manifest).unwrap();
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{manifest}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
        fs::remove_file(dir.path().join("package.json")).unwrap();

        for classic_override in [
            "--modules-folder ./vendor\n",
            "--registry https://registry.attacker.example\n",
            "--scripts-prepend-node-path true\n",
        ] {
            fs::write(dir.path().join(".yarnrc"), classic_override).unwrap();
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{classic_override}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
        fs::write(dir.path().join(".yarnrc"), benign_classic).unwrap();

        fs::write(
            dir.path().join(".yarnrc"),
            "yarn-path .yarn/releases/yarn.cjs\n",
        )
        .unwrap();
        let classic = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(classic.commands.is_empty(), "{classic:?}");
        assert!(classic
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));

        fs::write(dir.path().join(".yarnrc"), benign_classic).unwrap();
        fs::write(
            dir.path().join("home/.yarnrc"),
            "yarn-path .yarn/releases/home-yarn.cjs\n",
        )
        .unwrap();
        let home_bootstrap = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(home_bootstrap.commands.is_empty(), "{home_bootstrap:?}");
        assert!(home_bootstrap
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        fs::remove_file(dir.path().join("home/.yarnrc")).unwrap();

        for modern_override in [
            "nodeLinker: pnp\n",
            "nodeLinker: node-modules\npnpMode: loose\n",
            "plugins:\n  - path: .yarn/plugins/attacker.cjs\n    spec: attacker\n",
            "npmRegistryServer: https://registry.attacker.example\n",
        ] {
            fs::write(dir.path().join(".yarnrc.yml"), modern_override).unwrap();
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{modern_override}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
        fs::write(dir.path().join(".yarnrc.yml"), benign_modern).unwrap();

        for pnp_path in [
            dir.path().join(".pnp.js"),
            dir.path().join(".pnp.cjs"),
            dir.path().join(".pnp.loader.mjs"),
            dir.path().join("home/.pnp.cjs"),
        ] {
            fs::write(&pnp_path, "module.exports = {};\n").unwrap();
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(
                result.commands.is_empty(),
                "{}: {result:?}",
                pnp_path.display()
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
            fs::remove_file(pnp_path).unwrap();
        }

        let outside_pnp = dir.path().join("outside-pnp.cjs");
        fs::write(&outside_pnp, "module.exports = {};\n").unwrap();
        symlink(&outside_pnp, dir.path().join(".pnp.cjs")).unwrap();
        let linked_pnp = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(linked_pnp.commands.is_empty(), "{linked_pnp:?}");
        assert!(linked_pnp
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));
        fs::remove_file(dir.path().join(".pnp.cjs")).unwrap();

        fs::write(
            dir.path().join(".yarnrc.yml"),
            "yarnPath: ${RUNTIME_YARN}\n",
        )
        .unwrap();
        let modern_dynamic = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(modern_dynamic.commands.is_empty(), "{modern_dynamic:?}");
        assert!(modern_dynamic
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let outside = dir.path().join("outside-yarnrc.yml");
        fs::write(&outside, "nodeLinker: node-modules\n").unwrap();
        fs::remove_file(dir.path().join(".yarnrc.yml")).unwrap();
        symlink(&outside, dir.path().join(".yarnrc.yml")).unwrap();
        let linked = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(linked.commands.is_empty(), "{linked:?}");
        assert!(linked
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));

        fs::remove_file(dir.path().join(".yarnrc.yml")).unwrap();
        fs::write(
            dir.path().join(".yarnrc.yml"),
            "x".repeat(MAX_CONFIG_BYTES as usize + 1),
        )
        .unwrap();
        let oversized = parse_web3_commands(command, ShellType::Posix, &context);
        assert!(oversized.commands.is_empty(), "{oversized:?}");
        assert!(oversized
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigBytesExceeded));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_project_root_cannot_establish_runner_provenance() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-project");
        fs::create_dir(&real).unwrap();
        install_reviewed_runner_package(&real, "cast");
        let linked = dir.path().join("linked-project");
        symlink(&real, &linked).unwrap();
        for linked_root in [linked.clone(), linked.join(".")] {
            let linked_context = Web3ParseContextV2::for_cwd(linked_root);
            for command in [
                "pnpm exec cast balance 0xabc",
                "yarn run cast balance 0xabc",
                "./node_modules/.bin/cast balance 0xabc",
            ] {
                let result = parse_web3_commands(command, ShellType::Posix, &linked_context);
                assert!(result.commands.is_empty(), "{command}: {result:?}");
                assert!(result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
            }
        }

        let real_context = Web3ParseContextV2::for_cwd(&real);
        let benign = parse_web3_commands(
            "pnpm exec cast balance 0xabc",
            ShellType::Posix,
            &real_context,
        );
        assert_eq!(benign.commands.len(), 1, "{benign:?}");
    }

    #[test]
    fn duplicate_selectors_are_idempotent_but_conflicts_are_incomplete() {
        let same = only("cast send 0xabc --chain 1 --chain=1");
        assert!(!same
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConflictingSelector));
        let conflict = only("cast send 0xabc --chain 1 --chain=5");
        assert!(conflict
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConflictingSelector));
        assert_eq!(conflict.write_mode, Web3WriteMode::StateChanging);
        let missing = only("cast send 0xabc --private-key");
        assert!(missing
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::MissingFlagValue));
        let empty = only("cast send 0xabc --private-key=");
        assert!(empty
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::MissingFlagValue));
        let unresolved = only("cast send $DESTINATION --rpc-url $RPC_URL");
        assert_eq!(unresolved.write_mode, Web3WriteMode::StateChanging);
        assert!(unresolved
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn budgets_and_incomplete_quotes_never_produce_a_clean_result() {
        let many = std::iter::repeat_n("echo ok", MAX_SHELL_SEGMENTS + 1)
            .collect::<Vec<_>>()
            .join(";");
        assert!(parse(&many)
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));
        let huge = format!("cast send {}", "x".repeat(MAX_ARGUMENT_BYTES + 1));
        let result = parse(&huge);
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ArgumentBytesExceeded));
        assert!(parse("cast send '0xabc")
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::IncompleteQuoting));
        let argv = format!(
            "cast send 0xabc {}",
            std::iter::repeat_n("arg", MAX_ARGV_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(parse(&argv)
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ArgumentCountExceeded));
    }

    #[test]
    fn generic_wrapper_ceiling_is_exact_and_nested_package_runners_fail_closed() {
        let below_generic_limit =
            format!("{}cast send 0xabc", "env ".repeat(MAX_WRAPPER_DEPTH - 1));
        assert_eq!(
            only(&below_generic_limit).write_mode,
            Web3WriteMode::StateChanging
        );
        let at_generic_limit = format!("{}cast send 0xabc", "env ".repeat(MAX_WRAPPER_DEPTH));
        let over = parse(&at_generic_limit);
        assert!(over.commands.is_empty());
        assert!(over
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::WrapperDepthExceeded));

        for command in ["npx npx cast send 0xabc", "npm exec -- npx cast send 0xabc"] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
    }

    #[test]
    fn raw_signers_never_serialize_or_debug_the_secret() {
        let secret = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = parse(&format!("cast send 0xabc --private-key {secret}"));
        let json = serde_json::to_string(&result).unwrap();
        let debug = format!("{result:?}");
        assert!(!json.contains(secret));
        assert!(!debug.contains(secret));
        assert_eq!(
            result.commands[0]
                .signer(SignerRole::Default)
                .unwrap()
                .kind(),
            SignerKindV2::RawPrivateKey
        );
        assert!(result.commands[0]
            .signer(SignerRole::Default)
            .unwrap()
            .span()
            .is_some());

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic_result = parse(&format!(
            "forge script X --broadcast --mnemonic '{mnemonic}'"
        ));
        let mnemonic_json = serde_json::to_string(&mnemonic_result).unwrap();
        let mnemonic_debug = format!("{mnemonic_result:?}");
        assert!(!mnemonic_json.contains(mnemonic));
        assert!(!mnemonic_debug.contains(mnemonic));
        assert_eq!(
            mnemonic_result.commands[0]
                .signer(SignerRole::Default)
                .unwrap()
                .kind(),
            SignerKindV2::Mnemonic
        );

        let keypair = format!(
            "[{}]",
            std::iter::repeat_n("7", 64).collect::<Vec<_>>().join(",")
        );
        let keypair_result = parse(&format!(
            "solana --url https://api.devnet.solana.com --keypair '{keypair}' program deploy p.so"
        ));
        let keypair_json = serde_json::to_string(&keypair_result).unwrap();
        let keypair_debug = format!("{keypair_result:?}");
        assert!(!keypair_json.contains(&keypair));
        assert!(!keypair_debug.contains(&keypair));

        // Base58 is the textual form wallets export and users paste, so it must
        // reach the same firewall as the hex and numeric-array shapes. Decoding
        // to 64 bytes is what marks it secret; a 32-byte public key is
        // unaffected and stays readable.
        let base58_secret =
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy1T4gdvhCkFoxYNBTLHnJ4KYqPqYLPUZ6BdrMEfLQnKrHVFXiL5NxvW";
        // Guard the guard: if this stopped classifying as secret material the
        // loop below would pass vacuously, because nothing would be retained.
        assert!(
            super::super::model::retained_value_is_secret(base58_secret),
            "base58 secret key must reach the raw-secret firewall"
        );
        for command in [
            format!("solana --url https://api.devnet.solana.com --keypair {base58_secret} program deploy p.so"),
            format!("forge script X --broadcast --keystore {base58_secret}"),
            format!("cast send 0xabc --account {base58_secret}"),
        ] {
            let parsed = parse(&command);
            let json = serde_json::to_string(&parsed).unwrap();
            let debug = format!("{parsed:?}");
            assert!(!json.contains(base58_secret), "base58 secret in JSON: {json}");
            assert!(
                !debug.contains(base58_secret),
                "base58 secret in Debug: {debug}"
            );
        }

        // A 32-byte base58 public key is not secret material and must survive.
        let pubkey = "11111111111111111111111111111111";
        assert!(!super::super::model::retained_value_is_secret(pubkey));
        assert_eq!(
            keypair_result.commands[0]
                .signer(SignerRole::Keypair)
                .unwrap()
                .kind(),
            SignerKindV2::RawKeypair
        );
    }

    #[test]
    fn every_public_retained_reference_rejects_uppercase_hex_secret_shapes() {
        let secret = "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let parser_candidate = format!("  \"{secret}\"  ");
        let nested_candidate = format!("  '  \"{secret}\"  '  ");
        assert!(retained_value_is_secret(&parser_candidate));
        assert!(retained_value_is_secret(&nested_candidate));

        let destination = parse(&format!("cast send '{parser_candidate}'"));
        let retained = destination.commands[0].destination.as_ref().unwrap();
        assert!(retained.value.is_none(), "{destination:?}");
        assert_eq!(retained.source, SelectorSource::Unresolved);
        assert!(!serde_json::to_string(&destination)
            .unwrap()
            .contains(secret));
        assert!(!format!("{destination:?}").contains(secret));

        let rpc = parse(&format!(
            "cast balance 0xabc --rpc-url '{parser_candidate}'"
        ));
        let retained = rpc.commands[0].rpc.as_ref().unwrap();
        assert!(retained.alias.is_none(), "{rpc:?}");
        assert_eq!(retained.source, SelectorSource::Unresolved);
        assert!(!serde_json::to_string(&rpc).unwrap().contains(secret));
        assert!(!format!("{rpc:?}").contains(secret));

        let selector = parse(&format!("cast balance 0xabc --chain '{parser_candidate}'"));
        let retained = selector.commands[0].network.chain.as_ref().unwrap();
        assert_eq!(retained.value, "<redacted>", "{selector:?}");
        assert_eq!(retained.source, SelectorSource::Unresolved);
        assert!(!serde_json::to_string(&selector).unwrap().contains(secret));
        assert!(!format!("{selector:?}").contains(secret));

        let artifact = parse(&format!("forge script '{parser_candidate}'"));
        let retained = artifact.commands[0].artifact.as_ref().unwrap();
        assert!(retained.value.is_none(), "{artifact:?}");
        assert_eq!(retained.source, SelectorSource::Unresolved);
        assert!(!serde_json::to_string(&artifact).unwrap().contains(secret));
        assert!(!format!("{artifact:?}").contains(secret));

        let manual_destination = DestinationReference {
            kind: DestinationKind::Address,
            value: Some(nested_candidate.clone()),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_destination)
            .unwrap()
            .contains(secret));
        assert!(!format!("{manual_destination:?}").contains(secret));
        let decoded: DestinationReference = serde_json::from_value(serde_json::json!({
            "kind": "address",
            "value": nested_candidate.clone(),
            "source": "explicit_flag",
            "span": null
        }))
        .unwrap();
        assert!(decoded.value.is_none());
        assert_eq!(decoded.source, SelectorSource::Unresolved);

        let manual_selector = SelectorReference {
            value: nested_candidate.clone(),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_selector)
            .unwrap()
            .contains(secret));
        assert!(!format!("{manual_selector:?}").contains(secret));
        let decoded: SelectorReference = serde_json::from_value(serde_json::json!({
            "value": nested_candidate.clone(),
            "source": "explicit_flag",
            "span": null
        }))
        .unwrap();
        assert_eq!(decoded.value, "<redacted>");
        assert_eq!(decoded.source, SelectorSource::Unresolved);

        let manual_artifact = ArtifactReference {
            kind: ArtifactKind::Script,
            value: Some(nested_candidate.clone()),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_artifact)
            .unwrap()
            .contains(secret));
        assert!(!format!("{manual_artifact:?}").contains(secret));
        let decoded: ArtifactReference = serde_json::from_value(serde_json::json!({
            "kind": "script",
            "value": nested_candidate.clone(),
            "source": "explicit_flag",
            "span": null
        }))
        .unwrap();
        assert!(decoded.value.is_none());
        assert_eq!(decoded.source, SelectorSource::Unresolved);

        let manual_rpc = RpcReferenceV2 {
            scheme: None,
            host: None,
            port: None,
            path: None,
            path_class: RpcPathClass::Unknown,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias: Some(nested_candidate.clone()),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_rpc).unwrap().contains(secret));
        assert!(!format!("{manual_rpc:?}").contains(secret));
        let decoded: RpcReferenceV2 = serde_json::from_value(serde_json::json!({
            "scheme": null,
            "host": null,
            "port": null,
            "path": null,
            "path_class": "unknown",
            "path_match_outcomes": [],
            "alias": nested_candidate.clone(),
            "source": "explicit_flag",
            "span": null
        }))
        .unwrap();
        assert!(decoded.alias.is_none());
        assert_eq!(decoded.source, SelectorSource::Unresolved);

        let manual_rpc_v1 = RpcReference {
            scheme: None,
            host: None,
            port: None,
            path: None,
            alias: Some(nested_candidate.clone()),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_rpc_v1)
            .unwrap()
            .contains(secret));
        assert!(!format!("{manual_rpc_v1:?}").contains(secret));
        let decoded: RpcReference = serde_json::from_value(serde_json::json!({
            "scheme": null,
            "host": null,
            "port": null,
            "path": null,
            "alias": nested_candidate.clone(),
            "source": "explicit_flag",
            "span": null
        }))
        .unwrap();
        assert!(decoded.alias.is_none());
        assert_eq!(decoded.source, SelectorSource::Unresolved);

        let over_nested = format!("{}{}{}", "\"".repeat(17), secret, "\"".repeat(17));
        let manual_over_nested = SelectorReference {
            value: over_nested,
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&manual_over_nested)
            .unwrap()
            .contains(secret));
        assert!(!format!("{manual_over_nested:?}").contains(secret));
    }

    #[test]
    fn property_parser_is_deterministic_across_all_safe_flag_permutations() {
        let flags = ["--broadcast", "--slow", "--verify"];
        let baseline = only("forge script Deploy.s.sol --broadcast --slow --verify");
        for first in 0..flags.len() {
            for second in 0..flags.len() {
                for third in 0..flags.len() {
                    if first == second || first == third || second == third {
                        continue;
                    }
                    let command = format!(
                        "forge {} script Deploy.s.sol {} {}",
                        flags[first], flags[second], flags[third]
                    );
                    let one = only(&command);
                    let two = only(&command);
                    assert_eq!(one, two);
                    assert_eq!(one.operation, baseline.operation);
                    assert_eq!(one.write_mode, baseline.write_mode);
                    assert_eq!(one.safety_flags, baseline.safety_flags);
                }
            }
        }
    }

    #[test]
    fn foundry_solana_anchor_config_readers_are_static_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.prod]\neth_rpc_url = 'mainnet'\n[rpc_endpoints]\nmainnet = '${RPC_URL}'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("solana.yml"),
            "json_rpc_url: https://api.devnet.solana.com\nkeypair_path: wallet.json\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("Anchor.toml"),
            "[provider]\ncluster = 'devnet'\nwallet = 'wallet.json'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.environment.insert(
            "RPC_URL".into(),
            "https://rpc.example/private?token=secret".into(),
        );
        context.solana_config_path = Some(dir.path().join("solana.yml"));
        let forge = parse_web3_commands(
            "forge --profile prod script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            forge.commands[0].rpc.as_ref().unwrap().host.as_deref(),
            Some("rpc.example")
        );
        assert!(!serde_json::to_string(&forge)
            .unwrap()
            .contains("token=secret"));
        let leading = parse_web3_commands(
            "ETH_RPC_URL=https://leading.example forge --profile prod script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            leading.commands[0].rpc.as_ref().unwrap().host.as_deref(),
            Some("leading.example")
        );
        let explicit = parse_web3_commands(
            "ETH_RPC_URL=https://leading.example forge --rpc-url https://explicit.example script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            explicit.commands[0].rpc.as_ref().unwrap().host.as_deref(),
            Some("explicit.example")
        );
        let solana = parse_web3_commands("solana program deploy p.so", ShellType::Posix, &context);
        assert_eq!(
            solana.commands[0]
                .signer(SignerRole::Keypair)
                .unwrap()
                .kind(),
            SignerKindV2::KeypairFile
        );
        let anchor = parse_web3_commands("anchor deploy", ShellType::Posix, &context);
        assert_eq!(
            anchor.commands[0].network.network.as_ref().unwrap().value,
            "devnet"
        );

        context.environment.remove("RPC_URL");
        let unresolved = parse_web3_commands(
            "forge --profile prod script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert!(unresolved
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn foundry_alias_resolution_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let aliases = (0..=super::super::config::MAX_ALIAS_RESOLUTIONS)
            .map(|index| format!("alias{index} = 'https://rpc{index}.example'"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            dir.path().join("foundry.toml"),
            format!("[rpc_endpoints]\n{aliases}\n"),
        )
        .unwrap();
        let context = Web3ParseContextV2::for_cwd(dir.path());
        let result = parse_web3_commands(
            "cast send 0xabc --rpc-url alias0",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            result.commands[0].rpc.as_ref().unwrap().host.as_deref(),
            Some("rpc0.example")
        );
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::AliasResolutionBudgetExceeded));
    }

    #[test]
    fn malformed_explicit_rpc_stays_unresolved_ahead_of_static_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[rpc_endpoints]\n\"https://%\"='https://lower-precedence.example'\n\"%\"='https://lower-precedence.example'\n\"bad alias\"='https://lower-precedence.example'\n",
        )
        .unwrap();
        for selector in ["https://%", "%", "bad alias"] {
            let result = parse_web3_commands(
                &format!("cast balance 0xabc --rpc-url '{selector}'"),
                ShellType::Posix,
                &Web3ParseContextV2::for_cwd(dir.path()),
            );
            let rpc = result.commands[0].rpc.as_ref().unwrap();
            assert_eq!(rpc.source, SelectorSource::Unresolved, "{result:?}");
            assert!(rpc.host.is_none(), "{result:?}");
            assert!(rpc.alias.is_none(), "{result:?}");
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::UnresolvedIndirection),
                "{selector}: {result:?}"
            );
            assert!(!serde_json::to_string(&result)
                .unwrap()
                .contains("lower-precedence.example"));
        }
    }

    #[test]
    fn injected_selector_maps_and_values_are_bounded_and_secret_safe() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.prod]\neth_rpc_url='mainnet'\n[rpc_endpoints]\nmainnet='${RPC_URL}'\n",
        )
        .unwrap();
        let oversized = "s".repeat(MAX_SELECTOR_BYTES + 1);
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context
            .environment
            .insert("RPC_URL".into(), oversized.clone());
        context
            .ambient_selectors
            .insert("FOUNDRY_CHAIN".into(), oversized.clone());
        let result = parse_web3_commands(
            "forge --profile prod script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SelectorBytesExceeded));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains(&oversized));
        let context_debug = format!("{context:?}");
        assert!(!context_debug.contains("RPC_URL"));
        assert!(!context_debug.contains(&oversized));

        let mut many = Web3ParseContextV2::without_filesystem();
        for index in 0..=MAX_CONTEXT_SELECTORS {
            many.ambient_selectors
                .insert(format!("UNUSED_{index}"), "value".to_string());
        }
        let capped = parse_web3_commands(
            "cast send 0xabc --rpc-url https://rpc.example",
            ShellType::Posix,
            &many,
        );
        assert!(capped
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded));
    }

    #[test]
    fn foundry_profiles_inherit_the_default_profile_rpc() {
        // Foundry layers every profile over `[profile.default]`, so a profile
        // that does not restate `eth_rpc_url` still resolves to the default
        // endpoint. Reporting the localhost tool-default instead would call a
        // live-network send a clean local one.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://mainnet-default.example'\n\
             [profile.prod]\nsolc='0.8.20'\n",
        )
        .unwrap();
        let context = Web3ParseContextV2::for_cwd(dir.path());

        for command in [
            "cast --profile prod send 0xabc --private-key 0xaa",
            "FOUNDRY_PROFILE=prod cast send 0xabc --private-key 0xaa",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(
                result.commands[0].rpc.as_ref().unwrap().host.as_deref(),
                Some("mainnet-default.example"),
                "profile did not inherit the default RPC: {command}"
            );
        }

        // A profile the file does not describe at all is an analysis gap, not
        // a silently inherited value.
        let missing = parse_web3_commands(
            "cast --profile typo send 0xabc --private-key 0xaa",
            ShellType::Posix,
            &context,
        );
        assert!(missing
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigMissing));
    }

    #[cfg(unix)]
    #[test]
    fn config_symlink_fifo_oversize_and_malformed_are_typed_gaps() {
        use std::os::unix::fs::{symlink, FileTypeExt as _};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.toml");
        fs::write(
            &target,
            "[profile.default]\neth_rpc_url='https://rpc.example'\n",
        )
        .unwrap();
        let link = dir.path().join("link.toml");
        symlink(&target, &link).unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(link);
        let linked = parse_web3_commands("forge script X --broadcast", ShellType::Posix, &context);
        assert!(linked
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));

        let fifo = dir.path().join("fifo.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        context.foundry_config_path = Some(fifo);
        let fifo_result =
            parse_web3_commands("forge script X --broadcast", ShellType::Posix, &context);
        assert!(fifo_result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));

        let oversized = dir.path().join("large.toml");
        fs::write(
            &oversized,
            vec![b'x'; super::super::config::MAX_CONFIG_BYTES as usize + 1],
        )
        .unwrap();
        context.foundry_config_path = Some(oversized);
        let large = parse_web3_commands("forge script X --broadcast", ShellType::Posix, &context);
        assert!(large
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigBytesExceeded));

        let malformed = dir.path().join("bad.toml");
        fs::write(&malformed, "[profile.default\n").unwrap();
        context.foundry_config_path = Some(malformed);
        let bad = parse_web3_commands("forge script X --broadcast", ShellType::Posix, &context);
        assert!(bad
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigMalformed));
    }

    #[test]
    fn non_web3_and_fully_explicit_commands_do_not_need_config_io() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(missing);
        let non_web3 = parse_web3_commands(
            "echo cast send is documentation",
            ShellType::Posix,
            &context,
        );
        assert!(non_web3.commands.is_empty());
        assert!(non_web3.completeness.is_complete());
        let explicit = parse_web3_commands(
            "cast send 0xabc --rpc-url https://rpc.example",
            ShellType::Posix,
            &context,
        );
        assert!(!explicit.completeness.gaps().any(|gap| matches!(
            gap,
            IncompleteReason::ConfigMissing | IncompleteReason::ConfigIo
        )));
    }

    #[test]
    fn non_web3_runner_children_never_trigger_provenance_filesystem_reads() {
        let dir = tempfile::tempdir().unwrap();
        // Any runner provenance walk would reject this non-file manifest.
        // Benign children must be discarded before reaching that seam.
        fs::create_dir(dir.path().join("package.json")).unwrap();
        let context = Web3ParseContextV2::for_cwd(dir.path());
        for command in [
            "npx eslint",
            "npm exec -- eslint",
            "pnpm exec eslint",
            "pnpm dlx eslint",
            "yarn dlx eslint",
            "bunx eslint",
            "bun x eslint",
            "./node_modules/.bin/eslint",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result.completeness.is_complete(), "{command}: {result:?}");
        }

        let yarn_script = parse_web3_commands("yarn run eslint", ShellType::Posix, &context);
        assert!(yarn_script.commands.is_empty());
        assert!(yarn_script
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        assert!(!yarn_script.completeness.gaps().any(|gap| matches!(
            gap,
            IncompleteReason::ConfigMalformed
                | IncompleteReason::ConfigNotRegular
                | IncompleteReason::ConfigIo
        )));

        let disguised =
            parse_web3_commands("npx eslint cast send 0xabc", ShellType::Posix, &context);
        assert!(disguised.commands.is_empty());
        assert!(disguised
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        assert!(!disguised.completeness.gaps().any(|gap| matches!(
            gap,
            IncompleteReason::ConfigMalformed
                | IncompleteReason::ConfigNotRegular
                | IncompleteReason::ConfigIo
        )));
    }

    #[cfg(unix)]
    #[test]
    fn package_runner_child_flags_are_preserved_after_exact_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let context = reviewed_runner_context(dir.path(), "forge");
        for command in [
            "npx forge script Deploy.s.sol --broadcast --rpc-url https://rpc.example --ledger",
            "npm exec -- forge script Deploy.s.sol --broadcast --rpc-url https://rpc.example --ledger",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            let facts = &result.commands[0];
            assert_eq!(facts.write_mode, Web3WriteMode::StateChanging, "{command}");
            assert!(facts.safety_flags.contains(&Web3SafetyFlag::Broadcast));
            assert_eq!(
                facts.rpc.as_ref().and_then(|rpc| rpc.host.as_deref()),
                Some("rpc.example")
            );
            assert_eq!(
                facts.signer(SignerRole::Default).unwrap().kind(),
                SignerKindV2::Ledger
            );
        }
        for command in [
            "pnpm exec forge script Deploy.s.sol --broadcast",
            "yarn run forge script Deploy.s.sol --broadcast",
            "./node_modules/.bin/forge script Deploy.s.sol --broadcast",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }
        for command in [
            "pnpm dlx forge script Deploy.s.sol --broadcast",
            "yarn dlx forge script Deploy.s.sol --broadcast",
            "bunx forge script Deploy.s.sol --broadcast",
            "bun x forge script Deploy.s.sol --broadcast",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }

        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"forge":"echo shadowed"}}"#,
        )
        .unwrap();
        let shadowed = parse_web3_commands(
            "yarn run forge script Deploy.s.sol --broadcast",
            ShellType::Posix,
            &context,
        );
        assert!(shadowed.commands.is_empty(), "{shadowed:?}");
        assert!(shadowed
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
    }

    #[test]
    fn reviewed_delegators_and_package_specs_never_complete_empty() {
        for command in [
            "stdbuf -oL cast send 0xabc --rpc-url https://rpc.example",
            "stdbuf --output=L cast send 0xabc --rpc-url https://rpc.example",
        ] {
            assert_eq!(
                only(command).write_mode,
                Web3WriteMode::StateChanging,
                "{command}"
            );
        }
        for (command, expected) in [
            (
                "npx hardhat@3 test --network localhost",
                IncompleteReason::UnresolvedIndirection,
            ),
            ("yarn run deploy", IncompleteReason::UnresolvedIndirection),
            (
                "npx hardhat@npm:unreviewed test",
                IncompleteReason::UnresolvedIndirection,
            ),
            (
                "nice cast send 0xabc --rpc-url https://rpc.example",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "stdbuf --unknown cast send 0xabc",
                IncompleteReason::AmbiguousSubcommand,
            ),
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(
                result.completeness.gaps().any(|gap| gap == expected),
                "{command}: {result:?}"
            );
        }
    }

    #[test]
    fn untrusted_package_specs_and_runner_provenance_never_resolve_as_web3_tools() {
        for command in [
            "npx @evil/cast send 0xabc",
            "npx ./cast send 0xabc",
            "npx --package @evil/cast cast send 0xabc",
            "npm --userconfig \"$NPM_CONFIG\" exec -- cast send 0xabc",
            "pnpm exec @evil/cast send 0xabc",
            "pnpm dlx cast@npm:unreviewed send 0xabc",
            "yarn dlx ./cast send 0xabc",
            "bunx cast@npm:unreviewed send 0xabc",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for command in [
            "npm --workspaces exec -- cast send 0xabc",
            "npm --workspace app exec -- cast send 0xabc",
            "npm --registry https://packages.example exec -- cast send 0xabc",
            "npm --userconfig ./npmrc exec -- cast send 0xabc",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for command in [
            "NPM_CONFIG_REGISTRY=https://packages.example npx cast balance 0xabc",
            "npm_config_registry=https://packages.example npm exec -- cast balance 0xabc",
            "NPM_CONFIG_USERCONFIG=./custom.npmrc npx cast balance 0xabc",
            "npm_config_userconfig=\"$NPMRC\" npx cast balance 0xabc",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| matches!(gap, IncompleteReason::UnresolvedIndirection)));
        }

        let default_registry =
            parse("NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ npx cast balance 0xabc");
        assert!(default_registry.commands.is_empty(), "{default_registry:?}");
        assert!(default_registry
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let mut exported_registry = Web3ParseContextV2::without_filesystem();
        exported_registry.environment.insert(
            "NPM_CONFIG_REGISTRY".to_string(),
            "https://registry.npmjs.org/".to_string(),
        );
        let reassigned_registry = parse_web3_commands(
            "NPM_CONFIG_REGISTRY=https://packages.example; npx cast balance 0xabc",
            ShellType::Posix,
            &exported_registry,
        );
        assert!(
            reassigned_registry.commands.is_empty(),
            "{reassigned_registry:?}"
        );
        assert!(reassigned_registry
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[cfg(unix)]
    #[test]
    fn package_runner_npmrc_provenance_is_bounded_and_no_follow() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://trusted.example'\n",
        )
        .unwrap();
        let home = dir.path().join("home");
        let context = reviewed_runner_context(dir.path(), "cast");

        fs::write(
            dir.path().join(".npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let project = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(project.commands.is_empty(), "{project:?}");
        assert!(
            project
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
            "{project:?}"
        );

        fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(home.join(".npmrc"), "userconfig=./custom.npmrc\n").unwrap();
        let user =
            parse_web3_commands("npm exec -- cast balance 0xabc", ShellType::Posix, &context);
        assert!(user.commands.is_empty(), "{user:?}");
        assert!(
            user.completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
            "{user:?}"
        );

        fs::write(
            home.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".npmrc"),
            vec![b'x'; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        let oversized = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(oversized.commands.is_empty(), "{oversized:?}");
        assert!(oversized
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigBytesExceeded));

        fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        let reviewed = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(reviewed.commands.len(), 1, "{reviewed:?}");
    }

    #[cfg(unix)]
    #[test]
    fn package_runner_npmrc_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.npmrc");
        fs::write(&target, "registry=https://registry.npmjs.org/\n").unwrap();
        symlink(&target, dir.path().join(".npmrc")).unwrap();
        let result = parse_web3_commands(
            "npx cast balance 0xabc",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigNotRegular));
    }

    #[test]
    fn package_runner_provenance_cannot_cross_a_nested_shell() {
        for command in [
            "npx sh -c 'cast send 0xabc'",
            "npm exec -- bash -c 'cast send 0xabc'",
            "NPM_CONFIG_REGISTRY=https://packages.example npx sh -c 'cast send 0xabc'",
            "npm --userconfig ./custom.npmrc exec -- sh -c 'cast send 0xabc'",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
                "{command}: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_effective_config_layers_are_bounded_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let runner_root = project.join("nested");
        let nested = runner_root.join("deeper");
        let home = runner_root.join("home");
        let prefix = dir.path().join("prefix");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(prefix.join("etc")).unwrap();
        fs::write(
            project.join(".npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let runner_context = reviewed_runner_context(&runner_root, "cast");
        let mut context = Web3ParseContextV2::for_cwd(&nested);
        context.environment = runner_context.environment;
        context
            .environment
            .insert("PREFIX".to_string(), prefix.to_string_lossy().into_owned());

        let unrelated_parent =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(unrelated_parent.commands.len(), 1, "{unrelated_parent:?}");

        fs::write(
            runner_root.join(".npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let local_prefix =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(local_prefix.commands.is_empty(), "{local_prefix:?}");
        assert!(
            local_prefix
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
            "{local_prefix:?}"
        );

        fs::write(
            runner_root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            home.join(".npmrc"),
            "globalconfig=../missing-global.npmrc\n",
        )
        .unwrap();
        let chained =
            parse_web3_commands("npm exec -- cast balance 0xabc", ShellType::Posix, &context);
        assert!(chained.commands.is_empty(), "{chained:?}");
        assert!(chained
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigMissing));

        fs::write(
            home.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            prefix.join("etc/npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let global_default =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(global_default.commands.len(), 1, "{global_default:?}");

        for command in [
            "npm --globalconfig ./global.npmrc exec -- cast balance 0xabc",
            "NPM_CONFIG_GLOBALCONFIG=./global.npmrc npx cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result.completeness.gaps().any(|gap| matches!(
                gap,
                IncompleteReason::ConfigMissing | IncompleteReason::UnresolvedIndirection
            )));
        }
    }

    #[test]
    fn npm_missing_home_and_filesystem_free_defaults_are_not_complete() {
        let dir = tempfile::tempdir().unwrap();
        let missing_home = parse_web3_commands(
            "npx cast balance 0xabc",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert!(missing_home.commands.is_empty(), "{missing_home:?}");
        assert!(missing_home
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let mut relative_home = Web3ParseContextV2::for_cwd(dir.path());
        relative_home
            .environment
            .insert("HOME".to_string(), "relative-home".to_string());
        let relative =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &relative_home);
        assert!(relative.commands.is_empty(), "{relative:?}");

        let public_default = parse("npx cast balance 0xabc");
        assert!(public_default.commands.is_empty(), "{public_default:?}");
        assert!(public_default
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[cfg(unix)]
    #[test]
    fn npm_precedence_trust_settings_and_local_bins_are_sound() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let home = dir.path().join("home");
        let user_prefix = dir.path().join("user-prefix");
        let fallback_prefix = dir.path().join("fallback-prefix");
        fs::create_dir_all(&project).unwrap();
        install_reviewed_runner_package(&project, "cast");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(user_prefix.join("etc")).unwrap();
        fs::create_dir_all(fallback_prefix.join("etc")).unwrap();
        fs::write(project.join("package.json"), "{}\n").unwrap();
        let mut context = Web3ParseContextV2::for_cwd(&project);
        context
            .environment
            .insert("HOME".to_string(), home.to_string_lossy().into_owned());
        context.environment.insert(
            "PREFIX".to_string(),
            fallback_prefix.to_string_lossy().into_owned(),
        );

        fs::write(
            user_prefix.join("etc/npmrc"),
            "registry=https://registry.npmjs.org/\nstrict-ssl=true\n",
        )
        .unwrap();
        fs::write(
            fallback_prefix.join("etc/npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        fs::write(
            home.join(".npmrc"),
            format!("prefix={}\n", user_prefix.display()),
        )
        .unwrap();
        let safe_user_override =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(
            safe_user_override.commands.len(),
            1,
            "{safe_user_override:?}"
        );

        fs::write(
            project.join(".npmrc"),
            "registry=https://packages.example\nproxy=https://proxy.example\n",
        )
        .unwrap();
        let safe_cli_override = parse_web3_commands(
            "npm --registry https://registry.npmjs.org --proxy null exec -- cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(safe_cli_override.commands.len(), 1, "{safe_cli_override:?}");

        let inherited_proxy = parse_web3_commands(
            "NPM_CONFIG_REGISTRY=https://registry.npmjs.org NPM_CONFIG_STRICT_SSL=true NPM_CONFIG_PROXY=null HTTP_PROXY=https://fallback-proxy.example npx cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(inherited_proxy.commands.is_empty(), "{inherited_proxy:?}");
        assert!(!inherited_proxy.completeness.is_complete());

        for command in [
            "HTTP_PROXY=https://fallback-proxy.example npm --proxy null exec -- cast balance 0xabc",
            "HTTPS_PROXY=https://fallback-proxy.example npm --https-proxy=false exec -- cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}: {result:?}");
        }

        let mixed_case_script_shell = parse_web3_commands(
            "NpM_CoNfIg_ScRiPt_ShElL=./runner-shell npx cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(
            mixed_case_script_shell.commands.is_empty(),
            "{mixed_case_script_shell:?}"
        );
        assert!(!mixed_case_script_shell.completeness.is_complete());

        for config in [
            "strict-ssl=false\n",
            "ca[]=certificate-one\nca[]=\n",
            "cafile=custom-ca.pem\n",
            "cafile=false\n",
            "cache=.npm-cache\n",
            "script-shell=./runner-shell\n",
            "node-options=--require=./bootstrap.js\n",
            "prefix=../relocated-prefix\n",
            "https-proxy=https://proxy.example\n",
            "@private:registry=https://packages.example\n",
        ] {
            fs::write(project.join(".npmrc"), config).unwrap();
            let result = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{config:?}: {result:?}");
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
                "{config:?}: {result:?}"
            );
        }

        fs::write(
            project.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        let alias = parse_web3_commands(
            "env -u NPM_CONFIG_REGISTRY npm_config_registry=https://registry.npmjs.org npx cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(alias.commands.len(), 1, "{alias:?}");

        fs::remove_file(project.join("node_modules/.bin/cast")).unwrap();
        fs::write(project.join("node_modules/.bin/cast"), "local shim\n").unwrap();
        let local = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(local.commands.is_empty(), "{local:?}");
    }

    #[cfg(unix)]
    #[test]
    fn npm_project_bins_and_explicit_package_selectors_precede_direct_bin_trust() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let context = reviewed_runner_context(&project, "cast");
        fs::write(
            project.join("package.json"),
            r#"{"name":"malicious-project","bin":{"cast":"evil.js"}}"#,
        )
        .unwrap();
        fs::write(project.join("evil.js"), "#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(project.join("evil.js"), fs::Permissions::from_mode(0o755)).unwrap();

        for command in ["npx cast balance 0xabc", "npm exec -- cast balance 0xabc"] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}: {result:?}");
        }

        fs::remove_file(project.join("package.json")).unwrap();
        for command in [
            "npx --package cast cast balance 0xabc",
            "npx -p cast cast balance 0xabc",
            "npm exec --package=cast -- cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}: {result:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_workspace_root_and_first_ancestor_bin_are_both_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let leaf = root.join("packages/app");
        fs::create_dir_all(&leaf).unwrap();
        let mut context = reviewed_runner_context(&leaf, "cast");
        fs::write(
            root.join("package.json"),
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        fs::write(root.join(".npmrc"), "registry=https://packages.example\n").unwrap();

        let root_config = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(root_config.commands.is_empty(), "{root_config:?}");
        assert!(
            root_config
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
            "{root_config:?}"
        );

        fs::write(
            root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        let reviewed =
            parse_web3_commands("npm exec -- cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(reviewed.commands.len(), 1, "{reviewed:?}");

        let ancestor = root.join("ancestor-bin-check");
        let nested = ancestor.join("nested");
        let work = nested.join("work");
        fs::create_dir_all(nested.join("node_modules/.bin")).unwrap();
        fs::create_dir_all(&work).unwrap();
        install_reviewed_runner_package(&ancestor, "cast");
        fs::write(nested.join("node_modules/.bin/cast"), "unreviewed shim\n").unwrap();
        context.cwd = Some(work);
        context.environment.insert(
            "HOME".to_string(),
            ancestor.join("home").to_string_lossy().into_owned(),
        );
        context.environment.insert(
            "PREFIX".to_string(),
            ancestor.join("npm-prefix").to_string_lossy().into_owned(),
        );
        fs::create_dir_all(ancestor.join("home")).unwrap();
        fs::create_dir_all(ancestor.join("npm-prefix/etc")).unwrap();
        let first_ancestor =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(first_ancestor.commands.is_empty(), "{first_ancestor:?}");
    }

    #[cfg(unix)]
    #[test]
    fn npm_bin_declaration_global_fallback_and_custom_runtime_knobs_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let context = reviewed_runner_context(&project, "cast");

        fs::write(
            project.join("node_modules/cast/package.json"),
            r#"{"name":"cast","bin":{"other":"bin/cli.js"}}"#,
        )
        .unwrap();
        let wrong_declaration =
            parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(
            wrong_declaration.commands.is_empty(),
            "{wrong_declaration:?}"
        );
        assert!(!wrong_declaration.completeness.is_complete());

        let global = dir.path().join("global-only");
        let home = global.join("home");
        let prefix = global.join("prefix");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(prefix.join("etc")).unwrap();
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::write(prefix.join("bin/cast"), "global shim\n").unwrap();
        let mut global_context = Web3ParseContextV2::for_cwd(&global);
        global_context
            .environment
            .insert("HOME".to_string(), home.to_string_lossy().into_owned());
        global_context
            .environment
            .insert("PREFIX".to_string(), prefix.to_string_lossy().into_owned());
        let global_only = parse_web3_commands(
            "npm exec -- cast balance 0xabc",
            ShellType::Posix,
            &global_context,
        );
        assert!(global_only.commands.is_empty(), "{global_only:?}");
        assert!(!global_only.completeness.is_complete());

        let runtime_project = dir.path().join("runtime-knobs");
        fs::create_dir_all(&runtime_project).unwrap();
        let runtime_context = reviewed_runner_context(&runtime_project, "cast");
        for command in [
            "NPM_CONFIG_CACHE=.cache npx cast balance 0xabc",
            "NPM_CONFIG_NPX_CACHE=.npx-cache npx cast balance 0xabc",
            "NPM_CONFIG_SCRIPT_SHELL=./shell npx cast balance 0xabc",
            "NPM_CONFIG_NODE_OPTIONS=--require=./bootstrap.js npx cast balance 0xabc",
            "NPM_CONFIG_CALL='cast balance 0xdef' npx cast balance 0xabc",
            "NPM_CONFIG_PACKAGE=@evil/cast npx cast balance 0xabc",
            "NPM_CONFIG_IGNORE_EXISTING=true npx cast balance 0xabc",
            "NPM_CONFIG_NO_INSTALL=true npx cast balance 0xabc",
            "NPM_CONFIG_ALWAYS_SPAWN=true npx cast balance 0xabc",
            "NPM_CONFIG_NODE_ARG=--inspect npx cast balance 0xabc",
            "NPM_CONFIG_NPM=./npm-cli.js npx cast balance 0xabc",
            "NPM_CONFIG_SHELL=./shell npx cast balance 0xabc",
            "NPM_CONFIG_GLOBAL=true npx cast balance 0xabc",
            "NPM_CONFIG_LOCATION=global npx cast balance 0xabc",
            "NPM_CONFIG_WORKSPACE=app npx cast balance 0xabc",
            "NPM_CONFIG_WORKSPACES=true npx cast balance 0xabc",
            "NPM_CONFIG_INCLUDE_WORKSPACE_ROOT=true npx cast balance 0xabc",
            "NODE_OPTIONS=--require=./bootstrap.js npx cast balance 0xabc",
            "NODE_EXTRA_CA_CERTS=./ca.pem npx cast balance 0xabc",
            "NODE_TLS_REJECT_UNAUTHORIZED=0 npx cast balance 0xabc",
            "npm --cache .cache exec -- cast balance 0xabc",
            "npm --script-shell ./shell exec -- cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &runtime_context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
                "{command}: {result:?}"
            );
        }
        let standard_tls = parse_web3_commands(
            "NODE_TLS_REJECT_UNAUTHORIZED=1 npx cast balance 0xabc",
            ShellType::Posix,
            &runtime_context,
        );
        assert_eq!(standard_tls.commands.len(), 1, "{standard_tls:?}");
    }

    #[cfg(unix)]
    #[test]
    fn npm_prefix_coercion_and_empty_environment_values_preserve_typed_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        install_reviewed_runner_package(&project, "cast");
        let home = project.join("home");
        let relative_prefix = project.join("relative-prefix");
        let fallback_prefix = project.join("fallback-prefix");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(relative_prefix.join("etc")).unwrap();
        fs::create_dir_all(fallback_prefix.join("etc")).unwrap();
        fs::write(home.join(".npmrc"), "prefix=relative-prefix\n").unwrap();
        fs::write(
            relative_prefix.join("etc/npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            fallback_prefix.join("etc/npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(&project);
        context
            .environment
            .insert("HOME".to_string(), home.to_string_lossy().into_owned());
        context.environment.insert(
            "PREFIX".to_string(),
            fallback_prefix.to_string_lossy().into_owned(),
        );

        let coerced = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(coerced.commands.len(), 1, "{coerced:?}");

        fs::remove_file(home.join(".npmrc")).unwrap();
        let fallback = parse_web3_commands("npx cast balance 0xabc", ShellType::Posix, &context);
        assert!(fallback.commands.is_empty(), "{fallback:?}");
        fs::write(home.join(".npmrc"), "prefix=relative-prefix\n").unwrap();

        fs::write(
            project.join(".npmrc"),
            "registry=https://packages.example\n",
        )
        .unwrap();
        let empty_registry = parse_web3_commands(
            "NPM_CONFIG_REGISTRY= npx cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(empty_registry.commands.is_empty(), "{empty_registry:?}");

        fs::write(
            project.join(".npmrc"),
            "registry=https://registry.npmjs.org/\ncafile=custom-ca.pem\n",
        )
        .unwrap();
        let empty_cafile = parse_web3_commands(
            "NPM_CONFIG_CAFILE= npx cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(empty_cafile.commands.is_empty(), "{empty_cafile:?}");
        for result in [&empty_registry, &empty_cafile] {
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported),
                "{result:?}"
            );
        }
    }

    #[test]
    fn package_runners_reject_intermediate_runners_and_empty_packages() {
        for command in [
            "npm exec -- npx cast balance 0xabc",
            "npx npm exec -- cast balance 0xabc",
            "npx --package '' cast balance 0xabc",
            "npm exec --package= -- cast balance 0xabc",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}: {result:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_prefix_keeps_process_cwd_while_tool_cwd_flags_override_stale_context() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let deeper = nested.join("deeper");
        fs::create_dir(&deeper).unwrap();
        let mut context = reviewed_runner_context(dir.path(), "cast");
        install_reviewed_runner_package(&nested, "cast");
        fs::create_dir_all(nested.join("etc")).unwrap();
        fs::write(
            nested.join("etc/npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            nested.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".npmrc"),
            "registry=https://packages.example/\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"root-project","bin":{"cast":"evil.js"}}"#,
        )
        .unwrap();
        let root_foundry = dir.path().join("foundry.toml");
        fs::write(
            &root_foundry,
            "[profile.default]\neth_rpc_url='https://root.example'\n",
        )
        .unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://nested.example'\n",
        )
        .unwrap();
        fs::write(
            deeper.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://deeper.example'\n",
        )
        .unwrap();
        context.foundry_config_path = Some(root_foundry);

        for command in [
            "npx --prefix nested cast balance 0xabc",
            "npm --prefix nested exec -- cast balance 0xabc",
            "npm --prefix ignored exec --prefix nested -- cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("root.example"),
                "{command}: {result:?}"
            );
        }
        fs::write(
            nested.join("package.json"),
            r#"{"name":"nested-project","bin":{"cast":"evil.js"}}"#,
        )
        .unwrap();
        let nested_project_bin = parse_web3_commands(
            "npx --prefix nested cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(
            nested_project_bin.commands.is_empty(),
            "{nested_project_bin:?}"
        );
        assert!(!nested_project_bin.completeness.is_complete());
        fs::remove_file(nested.join("package.json")).unwrap();
        let tool_root = parse_web3_commands(
            "cast --root nested balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            tool_root.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested.example"),
            "{tool_root:?}"
        );
        let nested_env = parse_web3_commands(
            "env -C nested env -C deeper cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            nested_env.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("deeper.example")
        );

        fs::create_dir(dir.path().join("missing-root")).unwrap();
        let missing = parse_web3_commands(
            "cast --root missing-root balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            missing.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("localhost")
        );
        assert!(missing
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigMissing));

        let root_solana = dir.path().join("root-solana.yml");
        let nested_solana = dir.path().join("nested-solana.yml");
        fs::write(
            &root_solana,
            "json_rpc_url: https://root-solana.example\nkeypair_path: root.json\n",
        )
        .unwrap();
        fs::write(
            &nested_solana,
            "json_rpc_url: https://nested-solana.example\nkeypair_path: nested.json\n",
        )
        .unwrap();
        context.solana_config_path = Some(root_solana);
        let selected = parse_web3_commands(
            "solana --config nested-solana.yml balance 111",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            selected.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested-solana.example")
        );
        assert!(selected.commands[0].signers.is_empty());

        let dynamic = parse_web3_commands(
            "solana --config \"$SOLANA_CONFIG\" balance 111",
            ShellType::Posix,
            &context,
        );
        assert_ne!(
            dynamic.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("root-solana.example")
        );
        assert!(dynamic
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn privilege_wrappers_taint_ambient_environment_cwd_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("foundry.toml");
        fs::write(
            &config,
            "[profile.default]\neth_rpc_url='https://config.example'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(config);
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://ambient.example".to_string(),
        );
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://ambient.example".to_string(),
        );
        for wrapper in ["sudo", "doas"] {
            let result = parse_web3_commands(
                &format!("{wrapper} cast balance 0xabc"),
                ShellType::Posix,
                &context,
            );
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("localhost"),
                "{wrapper}: {result:?}"
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::ExecutionContextChanged));
        }
    }

    #[test]
    fn static_cd_flows_across_and_and_uncertain_cd_taints_following_facts() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let root_config = dir.path().join("foundry.toml");
        fs::write(
            &root_config,
            "[profile.default]\neth_rpc_url='https://root.example'\n",
        )
        .unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://nested.example'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(root_config);

        for command in [
            "cd nested && cast balance 0xabc",
            "command cd nested && cast balance 0xabc",
        ] {
            let static_cd = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(
                static_cd.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("nested.example"),
                "{command}: {static_cd:?}"
            );
            assert!(!static_cd
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::WorkingDirectoryUnresolved));
        }

        for command in [
            "cd \"$PROJECT\" && cast balance 0xabc",
            "cd nested; cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_ne!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("root.example"),
                "{command}: {result:?}"
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::WorkingDirectoryUnresolved));
        }
    }

    #[test]
    fn reviewed_shell_command_strings_and_platform_shims_are_resolved() {
        for command in [
            "bash -c 'cast send 0xabc --rpc-url https://rpc.example'",
            "sh -lc 'cast send 0xabc --rpc-url https://rpc.example'",
            "zsh -c 'cast send 0xabc --rpc-url https://rpc.example'",
            "dash -c 'cast send 0xabc --rpc-url https://rpc.example'",
            "cast.cmd send 0xabc --rpc-url https://rpc.example",
            "cast.bat send 0xabc --rpc-url https://rpc.example",
        ] {
            assert_eq!(
                only(command).write_mode,
                Web3WriteMode::StateChanging,
                "{command}"
            );
        }

        for (command, expected) in [
            ("$TOOL send 0xabc", IncompleteReason::UnresolvedIndirection),
            (
                "bash -c \"$COMMAND\"",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "bash deploy.sh",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "python -c 'cast send 0xabc'",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "fish -c 'cast send 0xabc'",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "deno eval 'cast send 0xabc'",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(!result.completeness.is_complete(), "{command}");
            assert!(
                result.completeness.gaps().any(|gap| gap == expected),
                "{command}: {result:?}"
            );
        }
    }

    #[test]
    fn effective_environment_clear_unset_set_and_chdir_precede_lower_sources() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://root.example'\n",
        )
        .unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://nested.example'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://ambient.example".to_string(),
        );
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://ambient.example".to_string(),
        );

        let unset = parse_web3_commands(
            "env -u ETH_RPC_URL cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_ne!(
            unset.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("ambient.example")
        );
        let cleared = parse_web3_commands("env -i cast balance 0xabc", ShellType::Posix, &context);
        assert_ne!(
            cleared.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("ambient.example")
        );
        let set = parse_web3_commands(
            "env ETH_RPC_URL=https://wrapper.example cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            set.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("wrapper.example")
        );
        let changed = parse_web3_commands(
            "env -C nested cast balance 0xabc",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert_eq!(
            changed.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested.example")
        );
    }

    #[test]
    fn leading_foundry_rpc_alias_beats_profile_rpc() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='profile'\n[rpc_endpoints]\nprofile='https://profile.example'\nleading='https://leading.example'\n",
        )
        .unwrap();
        let result = parse_web3_commands(
            "env ETH_RPC_URL=leading cast balance 0xabc",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        let rpc = result.commands[0].rpc.as_ref().unwrap();
        assert_eq!(rpc.host.as_deref(), Some("leading.example"));
        assert_eq!(rpc.source, SelectorSource::LeadingEnvironment);
    }

    #[test]
    fn executable_test_tasks_are_not_claimed_no_chain_write() {
        let hardhat = only("hardhat test --network localhost");
        assert_eq!(hardhat.write_mode, Web3WriteMode::PotentialWrite);
        assert!(hardhat
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicConfigUnsupported));
        let anchor = only("anchor test --provider.cluster localnet --provider.wallet wallet.json");
        assert_eq!(anchor.write_mode, Web3WriteMode::PotentialWrite);
        assert!(anchor
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn solana_preserves_every_role_tagged_signer_deterministically() {
        let result = parse(
            "solana --url devnet --keypair keypair.json --upgrade-authority authority.json --fee-payer fee.json program deploy p.so",
        );
        let facts = &result.commands[0];
        assert_eq!(
            facts
                .signers
                .iter()
                .map(|signer| signer.role)
                .collect::<Vec<_>>(),
            vec![
                SignerRole::Keypair,
                SignerRole::Authority,
                SignerRole::FeePayer,
            ]
        );
        assert_eq!(
            facts
                .signer(SignerRole::Authority)
                .unwrap()
                .nonsecret_reference(),
            Some("authority.json")
        );
        assert_eq!(
            result
                .effects
                .effects()
                .iter()
                .filter(|effect| effect.kind == CommandEffectKind::Web3SignerUse)
                .count(),
            3
        );
        assert_eq!(
            result
                .effects
                .effects()
                .iter()
                .filter(|effect| effect.kind == CommandEffectKind::SecretRead)
                .count(),
            3
        );
    }

    #[test]
    fn solana_state_change_requires_resolved_default_keypair() {
        let missing = parse("solana --url devnet program deploy p.so");
        assert!(missing.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SignerMissing));

        let dynamic = parse("solana --url devnet --keypair \"$KEYPAIR\" program deploy p.so");
        assert!(dynamic.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SignerMissing));

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("solana.yml");
        fs::write(
            &config,
            "json_rpc_url: https://config.example\nkeypair_path: wallet.json\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.solana_config_path = Some(config);
        let resolved =
            parse_web3_commands("solana program deploy p.so", ShellType::Posix, &context);
        assert_eq!(
            resolved.commands[0]
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("wallet.json")
        );
        assert!(!resolved.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SignerMissing));
    }

    #[test]
    fn potential_write_always_implies_network_egress() {
        for command in [
            "hardhat test --network localhost",
            "hardhat run scripts/deploy.ts --network localhost",
            "anchor test --provider.cluster localnet --provider.wallet wallet.json",
        ] {
            let result = parse(command);
            assert_eq!(
                result.commands[0].write_mode,
                Web3WriteMode::PotentialWrite,
                "{command}"
            );
            assert!(result
                .effects
                .effects()
                .iter()
                .any(|effect| effect.kind == CommandEffectKind::NetworkEgress));
        }
    }

    #[test]
    fn parser_produced_effects_obey_the_reader_budget_and_round_trip() {
        let command = "solana --url https://rpc.example --keypair wallet.json \
                       program deploy program.so --program-id program.json \
                       --upgrade-authority authority.json --fee-payer fee-payer.json";
        let input = std::iter::repeat_n(command, MAX_SHELL_SEGMENTS)
            .collect::<Vec<_>>()
            .join("; ");
        let result = parse(&input);
        assert_eq!(result.commands.len(), MAX_SHELL_SEGMENTS, "{result:?}");
        assert_eq!(result.effects.effects().len(), MAX_COMMAND_EFFECTS);
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::EffectBudgetExceeded));
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded = Web3ParseResultV2::from_json_slice_bounded(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.effects.effects().len(), MAX_COMMAND_EFFECTS);
        assert!(decoded
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::EffectBudgetExceeded));
    }

    #[test]
    fn build_and_query_operations_project_only_selectors_they_use() {
        let dir = tempfile::tempdir().unwrap();
        let malformed = dir.path().join("malformed.toml");
        fs::write(&malformed, "[broken\n").unwrap();
        let solana = dir.path().join("solana.yml");
        fs::write(
            &solana,
            "json_rpc_url: https://query.example\nkeypair_path: should-not-project.json\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(malformed.clone());
        context.anchor_config_path = Some(malformed);
        context.solana_config_path = Some(solana);
        let private_key = format!("0x{}", "7".repeat(64));

        for command in [
            format!("forge build --private-key {private_key}"),
            "anchor build --provider.wallet should-not-project.json".to_string(),
            "hardhat compile --network should-not-project".to_string(),
        ] {
            let result = parse_web3_commands(&command, ShellType::Posix, &context);
            assert!(result.commands[0].rpc.is_none(), "{command}: {result:?}");
            assert!(
                result.commands[0].signers.is_empty(),
                "{command}: {result:?}"
            );
            assert!(result.commands[0].network.network.is_none());
            assert!(!result.completeness.gaps().any(|gap| matches!(
                gap,
                IncompleteReason::ConfigMalformed | IncompleteReason::ConfigMissing
            )));
            assert!(result.effects.effects().iter().all(|effect| !matches!(
                effect.kind,
                CommandEffectKind::NetworkEgress
                    | CommandEffectKind::SecretRead
                    | CommandEffectKind::Web3SignerUse
            )));
            assert!(!serde_json::to_string(&result)
                .unwrap()
                .contains(&private_key));
        }

        let query = parse_web3_commands("solana balance 111", ShellType::Posix, &context);
        assert_eq!(
            query.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("query.example")
        );
        assert!(query.commands[0].signers.is_empty());
        assert!(!query
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
    }

    #[test]
    fn reviewed_signer_uris_precede_file_classification_and_remain_private() {
        let signer_uri = "usb://ledger?account=do-not-serialize";
        let result = parse(&format!(
            "solana --url devnet --keypair '{signer_uri}' program deploy p.so"
        ));
        assert_eq!(
            result.commands[0]
                .signer(SignerRole::Keypair)
                .unwrap()
                .kind(),
            SignerKindV2::Ledger
        );
        assert!(!result.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        assert!(result
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::Web3SignerUse));
        assert!(!result
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("do-not-serialize"));
        assert!(!format!("{result:?}").contains("do-not-serialize"));
    }

    #[test]
    fn selector_caps_are_applied_before_context_projection() {
        let mut context = Web3ParseContextV2::without_filesystem();
        for index in 0..=MAX_CONTEXT_SELECTORS {
            context.environment.insert(
                format!("SELECTOR_{index}"),
                format!("never-serialize-{index}"),
            );
        }
        let result = parse_web3_commands(
            "echo ok; echo still-ok; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded));
        assert!(result.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("never-serialize"));

        let oversized = format!("cast balance 0xabc {}", "x".repeat(MAX_INPUT_BYTES));
        let before_context = parse_web3_commands(&oversized, ShellType::Posix, &context);
        assert_eq!(before_context.completeness.gaps().count(), 1);
        assert!(before_context
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::InputBytesExceeded));
    }

    #[test]
    fn pretty_multiline_solana_keypair_is_structurally_redacted() {
        let keypair = format!(
            "[\n  {}\n]",
            (0..64)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",\n  ")
        );
        let result = parse(&format!(
            "solana --url devnet --keypair '{keypair}' program deploy p.so"
        ));
        assert_eq!(
            result.commands[0]
                .signer(SignerRole::Keypair)
                .unwrap()
                .kind(),
            SignerKindV2::RawKeypair
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(&keypair));
        assert!(!format!("{result:?}").contains(&keypair));
    }

    #[test]
    fn global_gaps_taint_every_fact_and_effect() {
        let result = parse("cast send 0xabc --rpc-url https://rpc.example; echo 'unterminated");
        assert_eq!(result.commands.len(), 1);
        assert!(result.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::IncompleteQuoting));
        assert!(!result.effects.effects().is_empty());
        assert!(result.effects.effects().iter().all(|effect| effect
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::IncompleteQuoting)));
    }

    #[test]
    fn input_byte_cap_precedes_tokenization() {
        let oversized = format!("cast send 0xabc {}", "x".repeat(MAX_INPUT_BYTES));
        let result = parse(&oversized);
        assert!(result.commands.is_empty());
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::InputBytesExceeded));
    }

    #[test]
    fn argv_and_nested_tokenizer_budgets_fail_closed_before_fact_retention() {
        let too_many = format!("cast {}", vec!["x"; MAX_ARGV_ITEMS + 1].join(" "));
        let result = parse(&too_many);
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ArgumentCountExceeded));

        let too_long = format!("cast {}", "x".repeat(MAX_ARGUMENT_BYTES + 1));
        let result = parse(&too_long);
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ArgumentBytesExceeded));

        let nested_argv = format!("bash -c 'cast {}'", vec!["x"; MAX_ARGV_ITEMS + 1].join(" "));
        let result = parse(&nested_argv);
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ArgumentCountExceeded));

        let nested_segments = format!(
            "bash -c '{}; cast balance 0xabc'",
            vec!["true"; MAX_SHELL_SEGMENTS].join("; ")
        );
        let result = parse(&nested_segments);
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));

        let many_substitutions =
            format!("echo {}", vec!["$(true)"; MAX_SHELL_SEGMENTS + 1].join(" "));
        assert!(many_substitutions.len() < MAX_INPUT_BYTES);
        let result = parse(&many_substitutions);
        assert!(result.commands.is_empty(), "{result:?}");
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let ordinary_arguments = format!(
            "echo {}",
            vec!["ordinary"; MAX_SHELL_SEGMENTS + 1].join(" ")
        );
        let ordinary = parse(&ordinary_arguments);
        assert!(ordinary.commands.is_empty(), "{ordinary:?}");
        assert!(!ordinary
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn solana_queries_have_network_effect_and_require_endpoint_evidence() {
        let result = parse("solana balance 11111111111111111111111111111111");
        assert_eq!(result.commands[0].write_mode, Web3WriteMode::ReadOnly);
        assert!(result.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConfigMissing));
        assert!(result
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::NetworkEgress));
    }

    #[cfg(unix)]
    #[test]
    fn package_selectors_and_scripts_remain_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let context = reviewed_runner_context(dir.path(), "hardhat");
        for command in [
            "npx --package hardhat hardhat test --network localhost",
            "npm exec --package hardhat -- hardhat test --network localhost",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for (command, expected) in [
            (
                "npx --package hardhat@3 hardhat test --network localhost",
                IncompleteReason::UnresolvedIndirection,
            ),
            (
                "npx --package forge hardhat test --network localhost",
                IncompleteReason::UnresolvedIndirection,
            ),
            (
                "npx --package=$WEB3_PACKAGE hardhat test --network localhost",
                IncompleteReason::UnresolvedIndirection,
            ),
            (
                "npm --workspace app exec -- hardhat test --network localhost",
                IncompleteReason::UnresolvedIndirection,
            ),
            (
                "npm run hardhat -- --network localhost",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
            (
                "yarn run hardhat --network localhost",
                IncompleteReason::DynamicExecutionUnsupported,
            ),
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(
                result.completeness.gaps().any(|gap| gap == expected),
                "{command}: {result:?}"
            );
        }
    }

    #[test]
    fn anchor_deploy_forwards_bounded_solana_deploy_arguments_with_precedence() {
        let result = parse(
            "anchor deploy --provider.cluster mainnet --provider.wallet outer.json -- \
             --url devnet --keypair forwarded.json --upgrade-authority authority.json \
             --fee-payer fee.json --program-id program.json --skip-preflight",
        );
        let facts = &result.commands[0];
        assert_eq!(facts.operation, Web3OperationV2::AnchorDeploy);
        assert_eq!(
            facts.rpc.as_ref().and_then(|rpc| rpc.alias.as_deref()),
            Some("devnet")
        );
        assert_eq!(facts.network.network.as_ref().unwrap().value, "devnet");
        assert_eq!(
            facts
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("forwarded.json")
        );
        assert!(facts.signer(SignerRole::Wallet).is_none());
        assert_eq!(
            facts
                .signer(SignerRole::ProgramId)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("program.json")
        );
        assert_eq!(
            facts
                .destination
                .as_ref()
                .map(|destination| destination.kind),
            Some(DestinationKind::ProgramIdFile)
        );
        assert!(facts.safety_flags.contains(&Web3SafetyFlag::SkipPreflight));

        let hardware = parse(
            "anchor deploy --provider.cluster devnet --provider.wallet wallet.json -- \
             --program-id 'usb://ledger/private-path?account=do-not-serialize'",
        );
        assert_eq!(
            hardware.commands[0]
                .signer(SignerRole::ProgramId)
                .unwrap()
                .kind(),
            SignerKindV2::Ledger
        );
        let serialized = serde_json::to_string(&hardware).unwrap();
        assert!(!serialized.contains("private-path"));
        assert!(!serialized.contains("do-not-serialize"));

        for command in [
            "anchor deploy -- --url devnet unexpected-positional",
            "anchor build -- --url devnet",
            "anchor deploy --",
        ] {
            let facts = only(command);
            assert!(facts
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::AmbiguousSubcommand));
        }
    }

    #[test]
    fn anchor_deploy_explicit_and_forwarded_config_precedence_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Anchor.toml"),
            "[provider]\ncluster='static-anchor'\nwallet='static-anchor.json'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("forwarded.yml"),
            "json_rpc_url: https://forwarded-config.example\nkeypair_path: forwarded-config.json\n",
        )
        .unwrap();
        let context = Web3ParseContextV2::for_cwd(dir.path());

        let anchor_explicit = parse_web3_commands(
            "anchor deploy --provider.cluster anchor-explicit --provider.wallet anchor-explicit.json -- --config forwarded.yml",
            ShellType::Posix,
            &context,
        );
        let facts = &anchor_explicit.commands[0];
        assert_eq!(
            facts
                .network
                .network
                .as_ref()
                .map(|value| value.value.as_str()),
            Some("anchor-explicit")
        );
        assert_eq!(
            facts.rpc.as_ref().and_then(|rpc| rpc.alias.as_deref()),
            Some("anchor-explicit")
        );
        assert_eq!(
            facts
                .signer(SignerRole::Wallet)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("anchor-explicit.json")
        );
        assert!(facts.signer(SignerRole::Keypair).is_none());

        let forwarded_explicit = parse_web3_commands(
            "anchor deploy --provider.cluster anchor-explicit --provider.wallet anchor-explicit.json -- --url forwarded-explicit --keypair forwarded-explicit.json --config forwarded.yml",
            ShellType::Posix,
            &context,
        );
        let facts = &forwarded_explicit.commands[0];
        assert_eq!(
            facts.rpc.as_ref().and_then(|rpc| rpc.alias.as_deref()),
            Some("forwarded-explicit")
        );
        assert_eq!(
            facts
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("forwarded-explicit.json")
        );
        assert!(facts.signer(SignerRole::Wallet).is_none());
        assert!(facts
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::ConflictingSelector));

        let forwarded_config = parse_web3_commands(
            "anchor deploy -- --config forwarded.yml",
            ShellType::Posix,
            &context,
        );
        let facts = &forwarded_config.commands[0];
        assert_eq!(
            facts
                .network
                .network
                .as_ref()
                .map(|network| network.value.as_str()),
            Some("static-anchor")
        );
        assert_eq!(
            facts
                .signer(SignerRole::Wallet)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("static-anchor.json")
        );
        assert!(facts.signer(SignerRole::Keypair).is_none());
        assert_ne!(
            facts.rpc.as_ref().and_then(|rpc| rpc.host.as_deref()),
            Some("forwarded-config.example")
        );

        let fallback_dir = tempfile::tempdir().unwrap();
        fs::write(
            fallback_dir.path().join("forwarded.yml"),
            "json_rpc_url: https://forwarded-config.example\nkeypair_path: forwarded-config.json\n",
        )
        .unwrap();
        let forwarded_fallback = parse_web3_commands(
            "anchor deploy -- --config forwarded.yml",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(fallback_dir.path()),
        );
        let facts = &forwarded_fallback.commands[0];
        assert_eq!(
            facts.rpc.as_ref().and_then(|rpc| rpc.host.as_deref()),
            Some("forwarded-config.example")
        );
        assert_eq!(
            facts
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("forwarded-config.json")
        );
    }

    #[test]
    fn anchor_native_program_keypair_is_role_tagged_and_secret_safe() {
        let file = parse(
            "anchor deploy --provider.cluster devnet --provider.wallet usb://ledger --program-name demo --program-keypair program.json",
        );
        let facts = &file.commands[0];
        assert_eq!(
            facts.signer(SignerRole::ProgramId).unwrap().kind(),
            SignerKindV2::KeypairFile
        );
        assert_eq!(
            facts
                .signer(SignerRole::ProgramId)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("program.json")
        );
        assert_eq!(
            facts
                .destination
                .as_ref()
                .map(|destination| (destination.kind, destination.value.as_deref())),
            Some((DestinationKind::Program, Some("demo")))
        );
        assert!(facts.destinations.iter().any(|destination| {
            destination.kind == DestinationKind::Program
                && destination.value.as_deref() == Some("demo")
        }));
        assert!(facts.destinations.iter().any(|destination| {
            destination.kind == DestinationKind::ProgramIdFile
                && destination.value.as_deref() == Some("program.json")
        }));
        assert_eq!(facts.destinations.len(), 2);
        assert!(file
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
        let wire = serde_json::to_value(&file).unwrap();
        let command = &wire["commands"][0];
        assert!(command.get("signer").is_some());
        assert!(command.get("signers").is_some());
        assert!(command.get("destination").is_some());
        assert!(command.get("destinations").is_some());
        let wallet = command["signers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|signer| signer["role"].as_str() == Some("wallet"))
            .unwrap();
        assert_eq!(command["signer"], wallet["signer"]);
        assert_eq!(command["destination"], command["destinations"][0]);

        for value in ["-", "ASK"] {
            let result = parse(&format!(
                "anchor deploy --provider.cluster devnet --provider.wallet usb://ledger --program-name demo --program-keypair {value}"
            ));
            assert_eq!(
                result.commands[0]
                    .signer(SignerRole::ProgramId)
                    .unwrap()
                    .kind(),
                SignerKindV2::KeypairFile
            );
            assert!(result
                .effects
                .effects()
                .iter()
                .any(|effect| effect.kind == CommandEffectKind::SecretRead));
        }

        let hardware = parse(
            "anchor deploy --provider.cluster devnet --provider.wallet usb://ledger \
             --program-name demo --program-keypair 'usb://ledger/private-path?account=do-not-serialize'",
        );
        assert_eq!(
            hardware.commands[0]
                .signer(SignerRole::ProgramId)
                .unwrap()
                .kind(),
            SignerKindV2::KeypairFile
        );
        assert!(hardware
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
        let json = serde_json::to_string(&hardware).unwrap();
        assert!(!json.contains("private-path"));
        assert!(!json.contains("do-not-serialize"));

        for command in [
            "anchor deploy --provider.cluster devnet --provider.wallet wallet.json --program-keypair program.json",
            "anchor deploy --provider.cluster devnet --provider.wallet wallet.json --program-name $PROGRAM --program-keypair program.json",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert!(result.completeness.gaps().any(|gap| matches!(
                gap,
                IncompleteReason::AmbiguousSubcommand | IncompleteReason::UnresolvedIndirection
            )));
        }
    }

    #[test]
    fn exec_clear_and_home_xdg_changes_rederive_config_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let stale_foundry = dir.path().join("stale-foundry.toml");
        fs::write(
            &stale_foundry,
            "[profile.default]\neth_rpc_url='https://stale-foundry.example'\n",
        )
        .unwrap();
        let stale_solana = dir.path().join("stale-solana.yml");
        fs::write(
            &stale_solana,
            "json_rpc_url: https://stale-solana.example\nkeypair_path: stale.json\n",
        )
        .unwrap();
        let stale_anchor = dir.path().join("stale-Anchor.toml");
        fs::write(
            &stale_anchor,
            "[provider]\ncluster='stale-anchor'\nwallet='stale-anchor.json'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(&cwd);
        context.foundry_config_path = Some(stale_foundry);
        context.solana_config_path = Some(stale_solana);
        context.anchor_config_path = Some(stale_anchor);

        let cleared = parse_web3_commands("exec -c cast balance 0xabc", ShellType::Posix, &context);
        assert_eq!(
            cleared.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("localhost")
        );
        let cleared_anchor =
            parse_web3_commands("exec -c anchor deploy", ShellType::Posix, &context);
        assert!(cleared_anchor.commands[0].network.network.is_none());
        assert!(cleared_anchor.commands[0]
            .signer(SignerRole::Wallet)
            .is_none());

        let new_home = dir.path().join("new-home");
        let solana_dir = new_home.join(".config/solana/cli");
        fs::create_dir_all(&solana_dir).unwrap();
        fs::write(
            solana_dir.join("config.yml"),
            "json_rpc_url: https://new-home.example\nkeypair_path: new-home.json\n",
        )
        .unwrap();
        let rehomed = parse_web3_commands(
            &format!("exec -c env HOME={} solana balance 111", new_home.display()),
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            rehomed.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("new-home.example")
        );

        let xdg = dir.path().join("xdg");
        fs::create_dir_all(xdg.join("solana/cli")).unwrap();
        fs::write(
            xdg.join("solana/cli/config.yml"),
            "json_rpc_url: https://xdg.example\nkeypair_path: xdg.json\n",
        )
        .unwrap();
        context
            .environment
            .insert("HOME".to_string(), new_home.to_string_lossy().into_owned());
        context.solana_config_path = Some(solana_dir.join("config.yml"));
        let xdg_ignored = parse_web3_commands(
            &format!("env XDG_CONFIG_HOME={} solana balance 111", xdg.display()),
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            xdg_ignored.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("new-home.example")
        );
        assert_ne!(
            xdg_ignored.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("xdg.example")
        );

        let mut default_keypair_context = Web3ParseContextV2::without_filesystem();
        default_keypair_context
            .environment
            .insert("HOME".to_string(), new_home.to_string_lossy().into_owned());
        default_keypair_context.environment.insert(
            "XDG_CONFIG_HOME".to_string(),
            xdg.to_string_lossy().into_owned(),
        );
        let default_keypair =
            parse_web3_commands("solana address", ShellType::Posix, &default_keypair_context);
        let expected_default_keypair = new_home
            .join(".config/solana/id.json")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            default_keypair.commands[0]
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some(expected_default_keypair.as_str())
        );
        assert!(!default_keypair.commands[0]
            .signer(SignerRole::Keypair)
            .and_then(SignerReferenceV2::nonsecret_reference)
            .is_some_and(|value| value.contains(xdg.to_string_lossy().as_ref())));
    }

    #[test]
    fn reviewed_privileged_delegates_never_produce_complete_empty_results() {
        for command in [
            "pkexec cast send 0xabc --rpc-url https://rpc.example",
            "runuser -u root -- cast send 0xabc --rpc-url https://rpc.example",
            "su root -c 'cast send 0xabc --rpc-url https://rpc.example'",
            "chroot /mnt cast send 0xabc --rpc-url https://rpc.example",
            "setpriv --reuid 0 cast send 0xabc --rpc-url https://rpc.example",
            "nsenter --mount cast send 0xabc --rpc-url https://rpc.example",
            "unshare --mount cast send 0xabc --rpc-url https://rpc.example",
            "systemd-run cast send 0xabc --rpc-url https://rpc.example",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }
    }

    #[test]
    fn grouped_subshell_brace_and_unknown_executors_fail_closed() {
        for command in [
            "(cast send 0xabc --rpc-url https://rpc.example)",
            "{ cast send 0xabc --rpc-url https://rpc.example; }",
            "echo \"$(cast send 0xabc --rpc-url https://rpc.example)\"",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }

        for command in [
            "osascript -e 'do shell script \"cast send 0xabc\"'",
            "osascript script.scpt",
            "osascript -e \"$DYNAMIC_APPLESCRIPT\"",
            "printf 'display dialog ok' | osascript",
            "bwrap cast send 0xabc --rpc-url https://rpc.example",
            "unknown-wrapper cast send 0xabc --rpc-url https://rpc.example",
            "unknown-wrapper 'embedded interpreter says cast send 0xabc'",
            "rg cast README.md",
            "rg --pre ./decoder cast README.md",
            "rg --no-config --hostname-bin ./decoder cast README.md",
            "./rg --no-config cast README.md",
            "git grep cast README.md",
            "git --paginate grep cast README.md",
            "git -c pager.grep=decoder grep cast README.md",
            "git --no-pager grep --textconv cast README.md",
            "git --no-pager grep --no-textconv --ext-grep cast README.md",
            "./git --no-pager grep --no-textconv cast README.md",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::DynamicExecutionUnsupported));
        }

        for command in [
            "rg --no-config cast README.md",
            "git --no-pager grep --no-textconv cast -- README.md",
        ] {
            let result = parse(command);
            assert!(result.commands.is_empty(), "{command}: {result:?}");
            assert!(result.completeness.is_complete(), "{command}: {result:?}");
        }
    }

    #[test]
    fn pipeline_background_and_assignment_only_cwd_flow_is_shell_correct() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://root.example'\n",
        )
        .unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://nested.example'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.environment.insert(
            "HOME".to_string(),
            dir.path().to_string_lossy().into_owned(),
        );
        context
            .environment
            .insert("CDPATH".to_string(), ".".to_string());

        for command in [
            "cd nested | cast balance 0xabc",
            "cd nested & cast balance 0xabc",
            "true | cd nested; cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("root.example"),
                "{command}: {result:?}"
            );
            assert!(!result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        let home_assignment = parse_web3_commands(
            &format!("HOME={}; cd && cast balance 0xabc", nested.display()),
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            home_assignment.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested.example")
        );

        let background_home = parse_web3_commands(
            &format!(
                "HOME={} && true & cd && cast balance 0xabc",
                nested.display()
            ),
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            background_home.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("root.example"),
            "{background_home:?}"
        );
        assert!(!background_home
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let cdpath_assignment = parse_web3_commands(
            "CDPATH=/tmp; cd nested && cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_ne!(
            cdpath_assignment.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("root.example")
        );
        assert!(
            cdpath_assignment
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::WorkingDirectoryUnresolved),
            "{cdpath_assignment:?}"
        );

        let conditional_home = parse_web3_commands(
            &format!(
                "false && HOME={}; cd && cast balance 0xabc",
                nested.display()
            ),
            ShellType::Posix,
            &context,
        );
        assert_ne!(
            conditional_home.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("root.example")
        );
        assert!(conditional_home
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let mut selector_context = context.clone();
        selector_context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://root.example".to_string(),
        );
        selector_context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://root.example".to_string(),
        );
        let updated_selector = parse_web3_commands(
            "ETH_RPC_URL=https://updated.example; cast balance 0xabc",
            ShellType::Posix,
            &selector_context,
        );
        assert_eq!(
            updated_selector.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("updated.example")
        );
        let background_selector = parse_web3_commands(
            "ETH_RPC_URL=https://background.example && true & cast balance 0xabc",
            ShellType::Posix,
            &selector_context,
        );
        assert_eq!(
            background_selector.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("root.example")
        );
        let conditional_selector = parse_web3_commands(
            "false && ETH_RPC_URL=https://branch.example; cast balance 0xabc",
            ShellType::Posix,
            &selector_context,
        );
        assert!(conditional_selector
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let root_solana = dir.path().join(".config/solana/cli");
        let nested_solana = nested.join(".config/solana/cli");
        fs::create_dir_all(&root_solana).unwrap();
        fs::create_dir_all(&nested_solana).unwrap();
        fs::write(
            root_solana.join("config.yml"),
            "json_rpc_url: https://root-solana.example\n",
        )
        .unwrap();
        fs::write(
            nested_solana.join("config.yml"),
            "json_rpc_url: https://nested-solana.example\n",
        )
        .unwrap();
        context.solana_config_path = Some(root_solana.join("config.yml"));
        let reassigned_home = parse_web3_commands(
            &format!("HOME={}; solana balance 111", nested.display()),
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            reassigned_home.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested-solana.example")
        );
    }

    #[test]
    fn persistent_environment_mutations_are_modeled_or_gap_explicitly() {
        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );

        for (command, host) in [
            (
                "export ETH_RPC_URL=https://exported.example; cast balance 0xabc",
                "exported.example",
            ),
            (
                "set -a; ETH_RPC_URL=https://allexport.example; cast balance 0xabc",
                "allexport.example",
            ),
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some(host),
                "{command}: {result:?}"
            );
        }

        let unset = parse_web3_commands(
            "unset ETH_RPC_URL; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_ne!(
            unset.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("original.example")
        );

        let unexport_assignment = parse_web3_commands(
            "export -n ETH_RPC_URL=https://assigned.example; export ETH_RPC_URL; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            unexport_assignment.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("assigned.example"),
            "{unexport_assignment:?}"
        );

        let brace_group = parse_web3_commands(
            "{ export ETH_RPC_URL=https://group.example; }; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            brace_group.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("group.example"),
            "{brace_group:?}"
        );
        assert!(brace_group.completeness.is_complete(), "{brace_group:?}");

        for command in [
            "readonly ETH_RPC_URL=https://readonly.example; cast balance 0xabc",
            "declare -x ETH_RPC_URL=https://declare.example; cast balance 0xabc",
            "typeset -x ETH_RPC_URL=https://typeset.example; cast balance 0xabc",
            "command export ETH_RPC_URL=https://command.example; cast balance 0xabc",
            "command -p -- export ETH_RPC_URL=https://command-option.example; cast balance 0xabc",
            "builtin export ETH_RPC_URL=https://builtin.example; cast balance 0xabc",
            "printf -v ETH_RPC_URL %s https://printf.example; cast balance 0xabc",
            "read ETH_RPC_URL; cast balance 0xabc",
            "trap 'export ETH_RPC_URL=https://trap.example' DEBUG; cast balance 0xabc",
            "builtin trap 'export ETH_RPC_URL=https://builtin-trap.example' DEBUG; cast balance 0xabc",
            "if true; then export ETH_RPC_URL=https://if.example; fi; cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_ne!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("original.example"),
                "{command}: {result:?}"
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection),
                "{command}: {result:?}");
        }

        for (shell, command) in [
            (
                ShellType::Fish,
                "set -gx ETH_RPC_URL https://fish.example; cast balance 0xabc",
            ),
            (ShellType::Fish, "read ETH_RPC_URL; cast balance 0xabc"),
            (
                ShellType::Cmd,
                "set ETH_RPC_URL=https://cmd.example & cast balance 0xabc",
            ),
            (ShellType::Cmd, "set /p ETH_RPC_URL= & cast balance 0xabc"),
            (
                ShellType::Cmd,
                "for %A in (1) do set ETH_RPC_URL=https://loop.example & cast balance 0xabc",
            ),
            (
                ShellType::Cmd,
                "if exist marker set ETH_RPC_URL=https://if.example & cast balance 0xabc",
            ),
            (
                ShellType::Cmd,
                "(set ETH_RPC_URL=https://group.example) & cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "$env:ETH_RPC_URL='https://ps.example'; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "if ($true) { Set-Item Env:ETH_RPC_URL https://if.example }; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output \"before $(Set-Item Env:ETH_RPC_URL https://interpolated.example) after\"; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output @\"\nbefore $(Set-Item Env:ETH_RPC_URL https://here-string.example) after\n\"@; cast balance 0xabc",
            ),
        ] {
            let result = parse_web3_commands(command, shell, &context);
            assert_eq!(result.commands.len(), 1, "{shell:?}: {result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection),
                "{command}: {result:?}");
        }

        let inert_cmd_do = parse_web3_commands(
            "do set ETH_RPC_URL=https://do.example & cast balance 0xabc",
            ShellType::Cmd,
            &context,
        );
        assert_eq!(inert_cmd_do.commands.len(), 1, "{inert_cmd_do:?}");
        assert_eq!(
            inert_cmd_do.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("original.example"),
            "{inert_cmd_do:?}"
        );
        assert!(inert_cmd_do.completeness.is_complete(), "{inert_cmd_do:?}");

        for command in [
            "Set-Item Env:ETH_RPC_URL https://set-item.example; cast balance 0xabc",
            "si Env:ETH_RPC_URL https://alias.example; cast balance 0xabc",
            "New-Item -Path Env:ETH_RPC_URL -Value https://new-item.example; cast balance 0xabc",
            "Remove-Item Env:ETH_RPC_URL; cast balance 0xabc",
            "rm Env:ETH_RPC_URL; cast balance 0xabc",
            "Set-Content Env:ETH_RPC_URL https://set-content.example; cast balance 0xabc",
            "sc Env:ETH_RPC_URL https://sc.example; cast balance 0xabc",
            "Add-Content Env:ETH_RPC_URL https://add-content.example; cast balance 0xabc",
            "ac Env:ETH_RPC_URL https://ac.example; cast balance 0xabc",
            "Clear-Content Env:ETH_RPC_URL; cast balance 0xabc",
            "clc Env:ETH_RPC_URL; cast balance 0xabc",
            "Move-Item Env:ETH_RPC_URL Env:MOVED_RPC_URL; cast balance 0xabc",
            "mi Env:ETH_RPC_URL Env:MOVED_RPC_URL; cast balance 0xabc",
            "mv Env:ETH_RPC_URL Env:MOVED_RPC_URL; cast balance 0xabc",
            "Copy-Item Env:ETH_RPC_URL Env:COPIED_RPC_URL; cast balance 0xabc",
            "ci Env:ETH_RPC_URL Env:COPIED_RPC_URL; cast balance 0xabc",
            "cp Env:ETH_RPC_URL Env:COPIED_RPC_URL; cast balance 0xabc",
            "Rename-Item Env:ETH_RPC_URL RENAMED_RPC_URL; cast balance 0xabc",
            "rni Env:ETH_RPC_URL RENAMED_RPC_URL; cast balance 0xabc",
            "ren Env:ETH_RPC_URL RENAMED_RPC_URL; cast balance 0xabc",
            "sv Env:ETH_RPC_URL https://set-variable.example; cast balance 0xabc",
            "[Environment]::SetEnvironmentVariable('ETH_RPC_URL', 'https://dotnet.example'); cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::PowerShell, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_ne!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("original.example"),
                "{command}: {result:?}"
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for (shell, command) in [
            (
                ShellType::Posix,
                "trap 'echo safe' DEBUG; cast balance 0xabc",
            ),
            (ShellType::Posix, "{ echo safe; }; cast balance 0xabc"),
            (
                ShellType::Cmd,
                "for %A in (1) do echo safe & cast balance 0xabc",
            ),
            (
                ShellType::Cmd,
                "if exist marker echo safe & cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output '$env:ETH_RPC_URL = https://quoted.example'; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output \"$env:ETH_RPC_URL = https://quoted.example\"; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output '$((Set-Item Env:ETH_RPC_URL https://single-quoted.example))'; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output @'\n$(Set-Item Env:ETH_RPC_URL https://single-here-string.example)\n'@; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Write-Output '[Environment]::SetEnvironmentVariable'; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "Set-Variable ETH_RPC_URL https://shell-variable.example; cast balance 0xabc",
            ),
            (
                ShellType::PowerShell,
                "if ($true) { Write-Output safe }; cast balance 0xabc",
            ),
        ] {
            let result = parse_web3_commands(command, shell, &context);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("original.example"),
                "{command}: {result:?}"
            );
            assert!(!result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        let cmd_bare_assignment = parse_web3_commands(
            "ETH_RPC_URL=https://bare.example & cast balance 0xabc",
            ShellType::Cmd,
            &context,
        );
        assert_eq!(cmd_bare_assignment.commands.len(), 1);
        assert_eq!(
            cmd_bare_assignment.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("original.example")
        );
    }

    #[test]
    fn posix_functions_emit_facts_and_share_bounded_current_shell_state() {
        for command in [
            "deploy() { cast send 0xabc --rpc-url https://direct-function.example; }; deploy",
            "deploy() { cast send 0xabc --rpc-url https://transitive-function.example; }; outer() { time -p -- deploy; }; outer",
            "deploy() { cast send 0xabc --rpc-url https://negated-function.example; }; ! deploy",
            "deploy() { cast send 0xabc --rpc-url https://eval-function.example; }; eval 'deploy'",
            "deploy() { cast send 0xabc --rpc-url https://builtin-eval-function.example; }; builtin eval 'deploy'",
            "deploy() { cast send 0xabc --rpc-url https://command-eval-function.example; }; command eval 'deploy'",
            "define() { deploy() { cast send 0xabc --rpc-url https://propagated-function.example; }; }; define; deploy",
            "define() { { deploy() { cast send 0xabc --rpc-url https://brace-function.example; }; }; }; define; deploy",
            "{ deploy() { cast send 0xabc --rpc-url https://top-brace-function.example; }; }; deploy",
            "deploy() { cast send 0xabc --rpc-url https://conditional-call.example; }; if true; then deploy; fi",
            "if true; then deploy() { cast send 0xabc --rpc-url https://conditional-definition.example; }; fi; deploy",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].operation, Web3OperationV2::Send);
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }

        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        let updated = parse_web3_commands(
            "set_rpc() { export ETH_RPC_URL=https://function-state.example; }; set_rpc; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            updated.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("function-state.example"),
            "{updated:?}"
        );
        assert!(!updated
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let defined_inside = parse_web3_commands(
            "outer() { set_rpc() { export ETH_RPC_URL=https://nested-state.example; }; set_rpc; }; outer; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            defined_inside.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested-state.example"),
            "{defined_inside:?}"
        );

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://function-cwd.example'\n",
        )
        .unwrap();
        let cwd = parse_web3_commands(
            "move_and_read() { cd nested && cast balance 0xabc; }; move_and_read",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert_eq!(
            cwd.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("function-cwd.example"),
            "{cwd:?}"
        );

        let cycle = parse_web3_commands(
            "looping() { looping; }; looping; cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(cycle.commands.len(), 1, "{cycle:?}");
        assert!(cycle
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let bypassed = parse("deploy() { cast send 0xabc; }; command deploy");
        assert!(bypassed.commands.is_empty(), "{bypassed:?}");

        let removed = parse("deploy() { cast send 0xabc; }; unset -f deploy; deploy");
        assert!(removed.commands.is_empty(), "{removed:?}");
    }

    #[test]
    fn cwd_options_cdpath_and_branch_merges_are_sound_or_tainted() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://root.example'\n",
        )
        .unwrap();
        fs::write(
            nested.join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https://nested.example'\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.foundry_config_path = Some(dir.path().join("foundry.toml"));
        context
            .environment
            .insert("HOME".to_string(), nested.to_string_lossy().into_owned());

        for command in [
            "cd -L -- nested && cast balance 0xabc",
            "cd -- && cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("nested.example"),
                "{command}: {result:?}"
            );
        }

        for command in [
            "CDPATH=/tmp cd nested && cast balance 0xabc",
            "cd -P nested && cast balance 0xabc",
            "cd nested || true; cast balance 0xabc",
            "cd nested && true; cast balance 0xabc",
            "cd nested && false || cast balance 0xabc",
            "false || cd nested && true; cast balance 0xabc",
        ] {
            let result = parse_web3_commands(command, ShellType::Posix, &context);
            assert_ne!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some("root.example"),
                "{command}: {result:?}"
            );
            assert!(
                result
                    .completeness
                    .gaps()
                    .any(|gap| gap == IncompleteReason::WorkingDirectoryUnresolved),
                "{command}: {result:?}"
            );
        }

        let independent_list = parse_web3_commands(
            "false || true; cd nested && cast balance 0xabc",
            ShellType::Posix,
            &context,
        );
        assert_eq!(
            independent_list.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("nested.example"),
            "{independent_list:?}"
        );

        let cmd = parse_web3_commands("cd nested & cast balance 0xabc", ShellType::Cmd, &context);
        assert_eq!(cmd.commands.len(), 1, "{cmd:?}");
        assert!(cmd
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::WorkingDirectoryUnresolved));
    }

    #[test]
    fn solana_address_is_a_local_default_signer_read_without_implicit_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("solana.yml");
        fs::write(
            &config,
            "json_rpc_url: https://must-not-project.example\nkeypair_path: address.json\n",
        )
        .unwrap();
        let mut context = Web3ParseContextV2::for_cwd(dir.path());
        context.solana_config_path = Some(config);
        let local = parse_web3_commands("solana address", ShellType::Posix, &context);
        let facts = &local.commands[0];
        assert_eq!(facts.operation, Web3OperationV2::Address);
        assert!(facts.rpc.is_none());
        assert_eq!(
            facts
                .signer(SignerRole::Keypair)
                .and_then(SignerReferenceV2::nonsecret_reference),
            Some("address.json")
        );
        assert!(local
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
        assert!(!local
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::NetworkEgress));

        let explicit_rpc = parse("solana --url devnet address --keypair address.json");
        assert!(explicit_rpc.commands[0].rpc.is_none());
        assert!(!explicit_rpc
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::NetworkEgress));

        let use_rpc = parse_web3_commands(
            "solana --use-rpc address --keypair address.json",
            ShellType::Posix,
            &context,
        );
        assert!(use_rpc.commands[0].rpc.is_none());
        assert!(use_rpc
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnknownOption));
        assert!(!use_rpc
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::NetworkEgress));
        assert!(use_rpc
            .effects
            .effects()
            .iter()
            .any(|effect| effect.kind == CommandEffectKind::SecretRead));
    }

    #[test]
    fn solana_program_id_signer_forms_are_role_tagged_and_secret_safe() {
        let file = parse(
            "solana --url devnet --keypair usb://ledger program deploy p.so --program-id id.json",
        );
        assert_eq!(
            file.commands[0]
                .signer(SignerRole::ProgramId)
                .unwrap()
                .kind(),
            SignerKindV2::KeypairFile
        );
        assert_eq!(
            file.effects
                .effects()
                .iter()
                .filter(|effect| effect.kind == CommandEffectKind::SecretRead)
                .count(),
            1
        );

        for (value, expected_kind) in [
            ("-", SignerKindV2::Stdin),
            ("ASK", SignerKindV2::Prompt),
            (
                "usb://ledger/hidden-path?account=do-not-serialize",
                SignerKindV2::Ledger,
            ),
        ] {
            let result = parse(&format!(
                "solana --url devnet --keypair usb://ledger program deploy p.so --program-id '{value}'"
            ));
            assert_eq!(
                result.commands[0]
                    .signer(SignerRole::ProgramId)
                    .unwrap()
                    .kind(),
                expected_kind
            );
            let json = serde_json::to_string(&result).unwrap();
            assert!(!json.contains("hidden-path"));
            assert!(!json.contains("do-not-serialize"));
        }

        let existing = parse(
            "solana --url devnet --keypair usb://ledger program deploy p.so \
             --program-id 11111111111111111111111111111111",
        );
        assert!(existing.commands[0].signer(SignerRole::ProgramId).is_none());
        assert_eq!(
            existing.commands[0].destination.as_ref().unwrap().kind,
            DestinationKind::Address
        );

        let unknown_uri = parse(
            "solana --url devnet --keypair usb://ledger program deploy p.so \
             --program-id 'vault://alice:hunter2@HOST:9443/private-path?token=do-not-serialize#fragment-secret'",
        );
        let signer = unknown_uri.commands[0]
            .signer(SignerRole::ProgramId)
            .unwrap();
        assert_eq!(signer.kind(), SignerKindV2::Unknown);
        assert_eq!(signer.source(), SelectorSource::Unresolved);
        assert_eq!(signer.nonsecret_reference(), Some("vault:"));
        assert!(unknown_uri
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        let json = serde_json::to_string(&unknown_uri).unwrap();
        let debug = format!("{unknown_uri:?}");
        for secret in [
            "alice",
            "hunter2",
            "private-path",
            "do-not-serialize",
            "fragment-secret",
            "host:9443",
        ] {
            assert!(!json.contains(secret), "JSON leaked {secret}: {json}");
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }

        let opaque_uri = parse(
            "solana --url devnet --keypair usb://ledger program deploy p.so \
             --program-id 'pkcs11:token=do-not-serialize;pin-value=hunter2'",
        );
        let signer = opaque_uri.commands[0]
            .signer(SignerRole::ProgramId)
            .unwrap();
        assert_eq!(signer.kind(), SignerKindV2::Unknown);
        assert_eq!(signer.source(), SelectorSource::Unresolved);
        assert_eq!(signer.nonsecret_reference(), Some("pkcs11:"));
        let json = serde_json::to_string(&opaque_uri).unwrap();
        let debug = format!("{opaque_uri:?}");
        for secret in ["do-not-serialize", "pin-value", "hunter2"] {
            assert!(!json.contains(secret), "JSON leaked {secret}: {json}");
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }

        let windows_path = parse(
            "solana --url devnet --keypair 'C:\\wallet.json' program deploy p.so \
             --program-id 11111111111111111111111111111111",
        );
        let signer = windows_path.commands[0]
            .signer(SignerRole::Keypair)
            .unwrap();
        assert_eq!(signer.kind(), SignerKindV2::KeypairFile);
        assert_eq!(signer.nonsecret_reference(), Some("C:\\wallet.json"));
    }

    #[test]
    fn solana_pubkey_decode_rejects_oversized_operands_before_work_or_allocation() {
        assert!(is_solana_pubkey(&"1".repeat(32)));
        let oversized = "1".repeat(16 * 1024);
        for _ in 0..64 {
            assert!(!is_solana_pubkey(&oversized));
        }
    }

    #[test]
    fn anchor_config_unknown_signer_uri_is_unresolved_and_authority_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Anchor.toml"),
            "[provider]\ncluster='devnet'\nwallet='vault://alice:hunter2@HOST:9443/private-wallet?token=do-not-serialize#fragment-secret'\n",
        )
        .unwrap();
        let result = parse_web3_commands(
            "anchor deploy",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert_eq!(result.commands.len(), 1, "{result:?}");
        let signer = result.commands[0].signer(SignerRole::Wallet).unwrap();
        assert_eq!(signer.kind(), SignerKindV2::Unknown);
        assert_eq!(signer.source(), SelectorSource::Unresolved);
        assert_eq!(signer.nonsecret_reference(), Some("vault:"));
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        let json = serde_json::to_string(&result).unwrap();
        let debug = format!("{result:?}");
        for secret in [
            "alice",
            "hunter2",
            "private-wallet",
            "do-not-serialize",
            "fragment-secret",
            "host:9443",
        ] {
            assert!(!json.contains(secret), "JSON leaked {secret}: {json}");
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
    }

    #[test]
    fn anchor_cluster_selector_is_bounded_before_retention_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let oversized = format!("https://rpc.example/{}", "x".repeat(MAX_SELECTOR_BYTES));
        fs::write(
            dir.path().join("Anchor.toml"),
            format!(
                "[provider]\ncluster={}\nwallet='wallet.json'\n",
                toml::Value::String(oversized.clone())
            ),
        )
        .unwrap();
        let result = parse_web3_commands(
            "anchor deploy",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        );
        assert_eq!(result.commands.len(), 1, "{result:?}");
        let facts = &result.commands[0];
        assert!(facts.rpc.is_none(), "{result:?}");
        assert!(facts.network.network.as_ref().is_none_or(|network| {
            network.source == SelectorSource::Unresolved && network.value != "custom_rpc"
        }));
        assert!(facts
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SelectorBytesExceeded));
        assert!(!serde_json::to_string(&result).unwrap().contains(&oversized));
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded = Web3ParseResultV2::from_json_slice_bounded(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.commands.len(), 1);
        assert!(decoded.commands[0].rpc.is_none());
    }

    #[test]
    fn rpc_path_digest_truncation_taints_facts_and_effects() {
        let private_path = "s".repeat(4096);
        let missing_context = parse(&format!(
            "cast call 0xabc --rpc-url https://rpc.example/{private_path}"
        ));
        assert!(missing_context
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherContextMissing));
        assert!(missing_context.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherContextMissing));
        assert!(missing_context.effects.effects().iter().all(|effect| effect
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherContextMissing)));
        assert!(!serde_json::to_string(&missing_context)
            .unwrap()
            .contains(&private_path));

        let mut trusted = Web3ParseContextV2::without_filesystem();
        let trusted_v3 = RpcPathMatcherId::new(3);
        trusted.trusted_rpc_path_prefixes =
            Some(vec![TrustedRpcPathPrefix::new(trusted_v3, "/ssss").unwrap()]);
        let trusted = parse_web3_commands(
            &format!("cast call 0xabc --rpc-url https://rpc.example/{private_path}"),
            ShellType::Posix,
            &trusted,
        );
        assert_eq!(
            trusted.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.trusted_path_outcome(trusted_v3)),
            Some(true)
        );
        assert!(!trusted
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherContextMissing));
        let trusted_json = serde_json::to_string(&trusted).unwrap();
        assert!(trusted_json.contains(r#""matcher_id":3"#));
        assert!(!trusted_json.contains(&private_path));

        let mut over_budget = Web3ParseContextV2::without_filesystem();
        over_budget.trusted_rpc_path_prefixes = Some(
            (0..=MAX_TRUSTED_RPC_PATH_MATCHERS)
                .map(|index| {
                    TrustedRpcPathPrefix::new(
                        RpcPathMatcherId::new(u64::try_from(index).unwrap()),
                        "/trusted",
                    )
                    .unwrap()
                })
                .collect(),
        );
        let over_budget = parse_web3_commands(
            &format!("cast call 0xabc --rpc-url https://rpc.example/{private_path}"),
            ShellType::Posix,
            &over_budget,
        );
        assert!(over_budget
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherBudgetExceeded));
        assert!(!serde_json::to_string(&over_budget)
            .unwrap()
            .contains(&private_path));
    }

    #[cfg(unix)]
    #[test]
    fn hardhat_typescript_config_is_never_opened_or_executed() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("hardhat.config.ts");
        let status = std::process::Command::new("mkfifo")
            .arg(&config)
            .status()
            .unwrap();
        assert!(status.success());
        let context = Web3ParseContextV2::for_cwd(dir.path());
        let result = parse_web3_commands(
            "hardhat ignition deploy ignition/modules/Lock.ts --network sepolia",
            ShellType::Posix,
            &context,
        );
        assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        assert!(result.commands[0]
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::DynamicConfigUnsupported));
    }

    #[test]
    fn one_global_fact_budget_covers_functions_substitutions_and_static_shells() {
        let body = (0..MAX_SHELL_SEGMENTS)
            .map(|index| format!("cast balance 0x{index:x}"))
            .collect::<Vec<_>>()
            .join("; ");
        let calls = std::iter::repeat_n("batch", 5)
            .collect::<Vec<_>>()
            .join("; ");
        let substitutions = std::iter::repeat_n("echo \"$(batch)\"", 5)
            .collect::<Vec<_>>()
            .join("; ");
        let static_shells = (0..5)
            .map(|_| format!("bash -c '{}'", body))
            .collect::<Vec<_>>()
            .join("; ");
        let mixed = format!("batch() {{ {body}; }}; {calls}; {substitutions}; {static_shells}");
        for input in [
            format!("batch() {{ {body}; }}; {calls}"),
            format!("batch() {{ {body}; }}; {substitutions}"),
            static_shells,
            mixed,
        ] {
            let result = parse(&input);
            assert_eq!(result.commands.len(), MAX_WEB3_WIRE_COMMANDS, "{result:?}");
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));
            let encoded = serde_json::to_vec(&result).unwrap();
            let decoded = Web3ParseResultV2::from_json_slice_bounded(&encoded).unwrap();
            assert_eq!(decoded.commands.len(), MAX_WEB3_WIRE_COMMANDS);
        }
    }

    #[test]
    fn shared_fact_free_work_and_expansion_budgets_exhaust_deterministically() {
        let context = Web3ParseContextV2::without_filesystem();

        let leaf = std::iter::repeat_n("true", MAX_SHELL_SEGMENTS)
            .collect::<Vec<_>>()
            .join("; ");
        let static_fan = std::iter::repeat_n(format!("bash -c '{leaf}'"), MAX_SHELL_SEGMENTS)
            .collect::<Vec<_>>()
            .join("; ");
        let fan_result = parse(&static_fan);
        assert!(fan_result.commands.is_empty());
        assert!(fan_result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));

        let mut expansion_budget = CommandFactBudget::default();
        let mut expansion_result = None;
        for _ in 0..=MAX_WEB3_PARSE_EXPANSIONS {
            expansion_result = Some(parse_web3_commands_depth(
                "true",
                ShellType::Posix,
                context.clone(),
                0,
                Completeness::complete(),
                &mut expansion_budget,
                true,
            ));
        }
        let expansion_result = expansion_result.unwrap();
        assert!(expansion_result.commands.is_empty());
        assert!(expansion_result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));

        let breadth = std::iter::repeat_n("true", MAX_SHELL_SEGMENTS)
            .collect::<Vec<_>>()
            .join("; ");
        let mut work_budget = CommandFactBudget::default();
        let mut work_result = None;
        for _ in 0..=MAX_SHELL_SEGMENTS {
            work_result = Some(parse_web3_commands_depth(
                &breadth,
                ShellType::Posix,
                context.clone(),
                0,
                Completeness::complete(),
                &mut work_budget,
                true,
            ));
        }
        let work_result = work_result.unwrap();
        assert!(work_result.commands.is_empty());
        assert!(work_result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));
    }

    #[test]
    fn parser_output_with_max_matchers_stays_inside_bounded_decoder() {
        let mut context = Web3ParseContextV2::without_filesystem();
        context.trusted_rpc_path_prefixes = Some(
            (0..MAX_TRUSTED_RPC_PATH_MATCHERS)
                .map(|index| {
                    TrustedRpcPathPrefix::new(
                        RpcPathMatcherId::new(u64::try_from(index).unwrap()),
                        "/rpc",
                    )
                    .unwrap()
                })
                .collect(),
        );
        let body = (0..MAX_SHELL_SEGMENTS)
            .map(|index| format!("cast balance 0x{index:x} --rpc-url https://rpc.example/rpc"))
            .collect::<Vec<_>>()
            .join("; ");
        let result = parse_web3_commands(
            &format!("batch() {{ {body}; }}; batch; batch; batch; batch"),
            ShellType::Posix,
            &context,
        );
        assert_eq!(result.commands.len(), MAX_WEB3_WIRE_COMMANDS, "{result:?}");
        assert!(result.commands.iter().all(|facts| {
            facts.rpc.as_ref().is_some_and(|rpc| {
                rpc.path_match_outcomes.as_slice().len() == MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES
            })
        }));
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherBudgetExceeded));
        let encoded = serde_json::to_vec(&result).unwrap();
        assert!(encoded.len() <= MAX_WEB3_PARSE_RESULT_JSON_BYTES);
        let decoded = Web3ParseResultV2::from_json_slice_bounded(&encoded).unwrap();
        assert_eq!(decoded.commands.len(), result.commands.len());
    }

    #[test]
    fn shared_serialized_command_budget_truncates_before_decoder_limit() {
        let long_path = format!("wallet-{}.json", "x".repeat(15_900));
        let fact = only(&format!(
            "solana --url devnet --keypair '{long_path}' program deploy program.so"
        ));
        let mut budget = CommandFactBudget::default();
        let mut completeness = Completeness::complete();
        let mut commands = Vec::new();
        for _ in 0..MAX_WEB3_WIRE_COMMANDS {
            if !budget.retain(&fact, &mut completeness) {
                break;
            }
            commands.push(fact.clone());
        }
        assert!(!commands.is_empty());
        assert!(commands.len() < MAX_WEB3_WIRE_COMMANDS);
        let result = finalize_bounded_parse_result(commands, completeness);
        assert!(result
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::SegmentBudgetExceeded));
        let encoded = serde_json::to_vec(&result).unwrap();
        assert!(encoded.len() <= MAX_WEB3_PARSE_RESULT_JSON_BYTES);
        assert_eq!(
            Web3ParseResultV2::from_json_slice_bounded(&encoded)
                .unwrap()
                .commands
                .len(),
            result.commands.len()
        );
    }

    #[test]
    fn solana_numeric_seed_material_never_becomes_a_path() {
        let seed32 = format!(
            "[{}]",
            (0..32)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let keypair64 = format!(
            "[{}]",
            (0..64)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut out_of_range = (0..64).map(|value| value.to_string()).collect::<Vec<_>>();
        out_of_range[63] = "987654321".to_string();
        let out_of_range = format!("[{}]", out_of_range.join(","));
        let mut malformed = (0..32).map(|value| value.to_string()).collect::<Vec<_>>();
        malformed[31] = "not_a_byte".to_string();
        let malformed = format!("[{}", malformed.join(","));

        let near_shaped = [31usize, 33, 63, 65].map(|length| {
            format!(
                "[{}",
                (0..length)
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        });
        let mostly_malformed = format!(
            "[{}]truncated",
            (0..32)
                .map(|index| if index < 8 {
                    index.to_string()
                } else {
                    format!("damaged_{index}")
                })
                .collect::<Vec<_>>()
                .join(",")
        );
        let missing_open = format!(
            "{}]",
            (0..32)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let bare_numeric_list = (0..64)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");

        for secret in [
            seed32,
            keypair64,
            out_of_range,
            malformed,
            mostly_malformed,
            missing_open,
            bare_numeric_list,
        ]
        .into_iter()
        .chain(near_shaped)
        {
            let result = parse(&format!(
                "solana --url devnet --keypair '{secret}' program deploy p.so"
            ));
            let signer = result.commands[0].signer(SignerRole::Keypair).unwrap();
            assert_eq!(signer.kind(), SignerKindV2::RawKeypair, "{result:?}");
            assert!(signer.nonsecret_reference().is_none());
            assert!(!serde_json::to_string(&result).unwrap().contains(&secret));
            assert!(!format!("{result:?}").contains(&secret));
        }

        let program_seed = format!(
            "[{}]",
            (0..32)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let malformed_program_seed = format!(
            "[{}",
            (0..31)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        for material in [program_seed, malformed_program_seed] {
            for command in [
                format!("solana --url devnet program deploy p.so --program-id '{material}'"),
                format!(
                    "anchor deploy --provider.cluster devnet --provider.wallet wallet.json --program-name demo --program-keypair '{material}'"
                ),
            ] {
                let result = parse(&command);
                assert!(result.commands[0].destinations.iter().all(|destination| {
                    destination.value.as_deref() != Some(material.as_str())
                }));
                assert!(result.commands[0].signers.iter().all(|signer| {
                    signer.signer.nonsecret_reference() != Some(material.as_str())
                }));
                assert!(!serde_json::to_string(&result).unwrap().contains(&material));
                assert!(!format!("{result:?}").contains(&material));
            }
        }
    }

    #[test]
    fn rpc_selectors_reject_whatwg_scheme_without_authority_everywhere() {
        fn assert_unresolved(result: &Web3ParseResultV2) {
            let rpc = result.commands[0].rpc.as_ref().unwrap();
            assert!(rpc.host.is_none(), "{result:?}");
            assert!(rpc.alias.is_none(), "{result:?}");
            assert_eq!(rpc.source, SelectorSource::Unresolved);
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for malformed in [
            "https:example.com",
            "https:/example.com",
            "https:///example.com",
            "https:////example.com",
            "https://\\example.com",
            "ftp://example.com",
            "bad alias",
        ] {
            assert_unresolved(&parse(&format!(
                "cast balance 0xabc --rpc-url '{malformed}'"
            )));
            assert_unresolved(&parse(&format!(
                "ETH_RPC_URL='{malformed}' cast balance 0xabc"
            )));
        }

        let mut ambient = Web3ParseContextV2::without_filesystem();
        ambient
            .ambient_selectors
            .insert("ETH_RPC_URL".to_string(), "https:example.com".to_string());
        assert_unresolved(&parse_web3_commands(
            "cast balance 0xabc",
            ShellType::Posix,
            &ambient,
        ));

        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\neth_rpc_url='https:example.com'\n",
        )
        .unwrap();
        assert_unresolved(&parse_web3_commands(
            "cast balance 0xabc",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        ));
    }

    #[test]
    fn every_anchor_cluster_source_uses_the_strict_endpoint_classifier() {
        fn assert_unresolved(result: &Web3ParseResultV2) {
            let facts = &result.commands[0];
            let rpc = facts.rpc.as_ref().unwrap();
            assert!(rpc.host.is_none(), "{result:?}");
            assert!(rpc.alias.is_none(), "{result:?}");
            assert_eq!(rpc.source, SelectorSource::Unresolved);
            assert_eq!(
                facts
                    .network
                    .network
                    .as_ref()
                    .map(|network| (network.value.as_str(), network.source)),
                Some(("unresolved", SelectorSource::Unresolved))
            );
            assert!(result
                .completeness
                .gaps()
                .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        }

        for cluster in [
            "https:example.com",
            "https:/example.com",
            "https:////example.com",
            "ftp://example.com",
            "bad alias",
        ] {
            assert_unresolved(&parse(&format!(
                "anchor deploy --provider.cluster '{cluster}' --provider.wallet wallet.json"
            )));
        }
        assert_unresolved(&parse(
            "ANCHOR_PROVIDER_CLUSTER=https:example.com anchor deploy --provider.wallet wallet.json",
        ));

        let mut ambient = Web3ParseContextV2::without_filesystem();
        ambient.ambient_selectors.insert(
            "ANCHOR_PROVIDER_CLUSTER".to_string(),
            "https:example.com".to_string(),
        );
        assert_unresolved(&parse_web3_commands(
            "anchor deploy --provider.wallet wallet.json",
            ShellType::Posix,
            &ambient,
        ));

        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Anchor.toml"),
            "[provider]\ncluster='https:example.com'\nwallet='wallet.json'\n",
        )
        .unwrap();
        assert_unresolved(&parse_web3_commands(
            "anchor deploy",
            ShellType::Posix,
            &Web3ParseContextV2::for_cwd(dir.path()),
        ));

        let safe = parse("anchor deploy --provider.cluster devnet --provider.wallet wallet.json");
        assert_eq!(
            safe.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.alias.as_deref()),
            Some("devnet")
        );
    }

    #[test]
    fn bash_function_shadowing_and_lookup_bypass_are_distinct() {
        for (name, host) in [
            ("command", "command-shadow.example"),
            ("builtin", "builtin-shadow.example"),
        ] {
            let result = parse(&format!(
                "{name}() {{ cast send 0xabc --rpc-url https://{host}; }}; {name}"
            ));
            assert_eq!(result.commands.len(), 1, "{result:?}");
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some(host)
            );
        }

        for bypass in ["command deploy", "builtin deploy"] {
            let result = parse(&format!(
                "deploy() {{ cast send 0xabc --rpc-url https://bypassed.example; }}; {bypass}"
            ));
            assert!(result.commands.is_empty(), "{result:?}");
        }
    }

    #[test]
    fn temporary_function_assignments_apply_then_restore() {
        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        let result = parse_web3_commands(
            "inspect() { cast balance 0xabc; }; ETH_RPC_URL=https://temporary.example inspect; cast balance 0xdef",
            ShellType::Posix,
            &context,
        );
        assert_eq!(result.commands.len(), 2, "{result:?}");
        assert_eq!(
            result.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("temporary.example")
        );
        assert_eq!(
            result.commands[1]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("original.example")
        );
    }

    #[test]
    fn brace_groups_share_function_state_while_subshells_isolate_it() {
        let brace = parse(
            "{ deploy() { cast send 0xabc --rpc-url https://brace-state.example; }; }; deploy",
        );
        assert_eq!(brace.commands.len(), 1, "{brace:?}");

        let subshell_definition = parse(
            "(deploy() { cast send 0xabc --rpc-url https://subshell-local.example; }); deploy",
        );
        assert!(
            subshell_definition.commands.is_empty(),
            "{subshell_definition:?}"
        );

        let inherited = parse(
            "deploy() { cast send 0xabc --rpc-url https://subshell-inherited.example; }; (deploy)",
        );
        assert_eq!(inherited.commands.len(), 1, "{inherited:?}");

        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://original.example".to_string(),
        );
        for (group, expected) in [
            ("{ set_rpc; }", "brace-mutated.example"),
            ("(set_rpc)", "original.example"),
        ] {
            let result = parse_web3_commands(
                &format!(
                    "set_rpc() {{ export ETH_RPC_URL=https://brace-mutated.example; }}; {group}; cast balance 0xabc"
                ),
                ShellType::Posix,
                &context,
            );
            assert_eq!(
                result.commands[0]
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.host.as_deref()),
                Some(expected),
                "{result:?}"
            );
        }
    }

    #[test]
    fn parenthesized_function_bodies_restore_caller_state() {
        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://caller.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://caller.example".to_string(),
        );
        let result = parse_web3_commands(
            "isolated() ( export ETH_RPC_URL=https://child.example; local_deploy() { cast send 0xabc; }; local_deploy ); isolated; local_deploy; cast balance 0xdef",
            ShellType::Posix,
            &context,
        );
        assert_eq!(result.commands.len(), 2, "{result:?}");
        assert_eq!(
            result.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("child.example")
        );
        assert_eq!(
            result.commands[1]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("caller.example")
        );
    }

    #[test]
    fn trailing_background_inside_functions_never_commits_shell_state() {
        let mut context = Web3ParseContextV2::without_filesystem();
        context.environment.insert(
            "ETH_RPC_URL".to_string(),
            "https://caller.example".to_string(),
        );
        context.ambient_selectors.insert(
            "ETH_RPC_URL".to_string(),
            "https://caller.example".to_string(),
        );
        let result = parse_web3_commands(
            "mutate_env() { export ETH_RPC_URL=https://background.example & }; define_child() { child_only() { cast send 0xabc --rpc-url https://escaped.example; } & }; mutate_env; define_child; child_only; cast balance 0xdef",
            ShellType::Posix,
            &context,
        );
        assert_eq!(result.commands.len(), 1, "{result:?}");
        assert_eq!(
            result.commands[0]
                .rpc
                .as_ref()
                .and_then(|rpc| rpc.host.as_deref()),
            Some("caller.example")
        );
    }

    #[test]
    fn function_arguments_are_scanned_before_dispatch_in_every_scope() {
        for command in [
            "sink() { :; }; sink \"$(cast send 0xabc --rpc-url https://top-arg.example)\"",
            "sink() { :; }; sink <(cast send 0xabc --rpc-url https://top-process-arg.example)",
            "sink() { :; }; outer() { sink \"$(cast send 0xabc --rpc-url https://nested-arg.example)\"; }; outer",
            "sink() { :; }; outer() { sink <(cast send 0xabc --rpc-url https://nested-process-arg.example); }; outer",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }
    }

    #[test]
    fn structural_controls_own_all_tokenizer_segments_and_taint_escape_state() {
        let conditional = parse(
            "if true; then branch_deploy() { cast send 0xabc --rpc-url https://branch.example; }; branch_deploy; fi; branch_deploy",
        );
        assert_eq!(conditional.commands.len(), 2, "{conditional:?}");
        assert!(conditional
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let unknown_definition = parse(
            "if runtime_condition; then maybe_deploy() { cast send 0xabc --rpc-url https://unknown-branch.example; }; fi; maybe_deploy",
        );
        assert!(
            unknown_definition.commands.is_empty(),
            "{unknown_definition:?}"
        );
        assert!(unknown_definition
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));

        let loop_body =
            parse("while false\ndo\ncast send 0xabc --rpc-url https://loop.example\ndone");
        assert_eq!(loop_body.commands.len(), 1, "{loop_body:?}");
        assert!(loop_body
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
    }

    #[test]
    fn functions_flow_through_substitutions_and_current_shell_controls() {
        for command in [
            "deploy() { cast send 0xabc --rpc-url https://command-sub.example; }; echo \"$(deploy)\"",
            "deploy() { cast send 0xabc --rpc-url https://process-sub.example; }; cat <(deploy)",
            "deploy() { cast send 0xabc --rpc-url https://parameter-sub.example; }; : \"${VALUE:=$(deploy)}\"",
            "deploy() { cast send 0xabc --rpc-url https://case-body.example; }; case x in x) deploy;; esac",
            "deploy() { cast send 0xabc --rpc-url https://if-body.example; }; if true; then deploy; fi",
        ] {
            let result = parse(command);
            assert_eq!(result.commands.len(), 1, "{command}: {result:?}");
            assert_eq!(result.commands[0].write_mode, Web3WriteMode::StateChanging);
        }

        let local = parse(
            "echo \"$(local_deploy() { cast send 0xabc --rpc-url https://local-sub.example; }; local_deploy)\"; local_deploy",
        );
        assert_eq!(local.commands.len(), 1, "{local:?}");

        let cycle = parse(
            "looping() { echo \"$(looping)\"; }; looping; cast balance 0xabc --rpc-url https://after-cycle.example",
        );
        assert_eq!(cycle.commands.len(), 1, "{cycle:?}");
        assert!(cycle
            .completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::WrapperDepthExceeded));
    }

    #[test]
    fn web3_effects_are_typed_without_policy_or_rule_ids() {
        let result = parse("cast send 0xabc --ledger --rpc-url https://rpc.example");
        let kinds: BTreeSet<_> = result
            .effects
            .effects()
            .iter()
            .map(|effect| effect.kind)
            .collect();
        assert_eq!(
            kinds,
            BTreeSet::from([
                CommandEffectKind::NetworkEgress,
                CommandEffectKind::Web3SignerUse,
                CommandEffectKind::Web3Write,
            ])
        );
    }
}
