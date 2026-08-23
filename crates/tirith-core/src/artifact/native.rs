//! Native binary triage (PR B7).
//!
//! A4 hands B7 each native member (`.so`/`.dylib`/`.pyd`/`.node`) as a
//! [`crate::artifact::archive::NativeMemberHandoff`]: a [`Buffered`] variant with the
//! whole decompressed body when the member is within the native-parse cap (default
//! 64 MiB), or a [`Streaming`] view (whole-member SHA-256 + a bounded printable
//! string scan + a leading header window) when it is larger. This module turns that
//! handoff into deterministic, policy-independent observations and ONE correlated
//! finding.
//!
//! [`Buffered`]: crate::artifact::archive::NativeMemberHandoff::Buffered
//! [`Streaming`]: crate::artifact::archive::NativeMemberHandoff::Streaming
//!
//! # Why a vetted read-only object library, not hand-rolled parsing
//!
//! Parsing ELF + fat/universal Mach-O + PE/TLS by hand over attacker-controlled
//! bytes is a large malformed-input attack surface (section tables that point past
//! EOF, symbol tables with absurd counts, fat headers that overlap). We use
//! `gimli-rs/object` (pure Rust, READ-ONLY, widely fuzzed), with features minimized
//! to exactly the formats we triage and MSRV pinned under the workspace floor. The
//! ONLY hand-written parsing is a tiny magic/architecture FALLBACK classifier
//! ([`classify_magic`]) used when the principal parser declines a buffer or when we
//! only have a streaming member's header window.
//!
//! # Never panic; partial on malformed
//!
//! [`triage_native`] NEVER panics on any input. Every `object` call is fallible and
//! is matched, never `unwrap`/`expect`/`[]`-indexed past a checked bound; every
//! iteration is bounded by an explicit count cap; a malformed or truncated buffer
//! falls back to the magic classifier and is recorded [`NativeCoverage::Partial`].
//! A persistent fuzz target and a deterministic malformed corpus exercise this.
//!
//! # The buffer A4 hands off IS the principal parser's input
//!
//! For a [`Buffered`] member the WHOLE decompressed body is parsed, giving full
//! random access to section / symbol / import tables and TLS / init data that a
//! 2 MiB prefix would miss. The 2 MiB header window
//! ([`crate::artifact::archive::NATIVE_HEADER_WINDOW_BYTES`]) is consulted ONLY by
//! the fallback magic classifier, never by the principal parser.
//!
//! # Correlation that does not over-fit
//!
//! A native module is reported [`crate::verdict::RuleId::NativeImportExecutionChain`]
//! (Critical) ONLY when all three hold:
//!
//! ```text
//! execution_entry : PyInit_* OR ELF constructor OR Mach-O mod-init OR PE TLS/DllMain
//! AND danger_capability : process spawn OR runtime loader OR downloader/network OR dynamic code loading
//! AND corroboration : external runtime name OR sibling script/payload reference OR sensitive path OR known malicious indicator
//! ```
//!
//! The relationships are GENERIC ("references ANY sibling executable/script",
//! "launches ANY unrelated runtime"); known names like `_index.js`/`bun` only raise
//! confidence, they do not define the rule, so renaming a payload does not evade.
//! Mere [`NativeModulePresent`] yields at most an informational signal, never
//! Critical.
//!
//! [`NativeModulePresent`]: NativeFactKind::NativeModulePresent
//!
//! # Out of single-artifact triage (deferred elsewhere)
//!
//! The prior-release delta (a baseline diff) and the cross-artifact reference
//! finding (where ownership across a wheel set is known) are NOT here. B7 is
//! single-binary triage plus the self-contained correlation; B8 owns the
//! artifact-set / installed cross-distribution correlation.

use std::collections::BTreeSet;

use crate::artifact::archive::NativeMemberHandoff;
use crate::artifact::{
    ArtifactSignal, ArtifactSignalKind, EdgeConfidence, ExecutionEdge, ExecutionTrigger,
};
use crate::location::SubjectLocation;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Caps on the deterministic extraction so a hostile (but structurally valid)
/// binary cannot turn triage into a memory / CPU DoS. Every collection that grows
/// from binary content is bounded by one of these.
mod caps {
    /// Maximum dynamic imports collected.
    pub const MAX_IMPORTS: usize = 4096;
    /// Maximum PE import descriptors traversed before any thunk/name work. This is
    /// separate from the import count because a hostile table can contain many
    /// descriptors whose thunk lists are empty.
    pub const MAX_IMPORT_DESCRIPTORS: usize = 4096;
    /// Maximum bytes accepted from one structured import name before lowercasing or
    /// retaining it. Oversized names make analysis partial instead of allocating.
    pub const MAX_IMPORT_NAME_LENGTH: usize = 4096;
    /// Maximum exported symbols scanned for `PyInit_*` / constructor names.
    pub const MAX_SYMBOLS: usize = 200_000;
    /// Maximum embedded strings examined from the string scan.
    pub const MAX_STRINGS_SCANNED: usize = 100_000;
    /// Maximum distinct embedded URLs retained.
    pub const MAX_URLS: usize = 256;
    /// Maximum characters retained from one embedded URL.
    pub const MAX_URL_LENGTH: usize = 2048;
    /// Maximum distinct sibling executable/script references retained.
    pub const MAX_SIBLING_REFS: usize = 256;
    /// Maximum bytes retained from one sibling reference.
    pub const MAX_SIBLING_REF_LENGTH: usize = 1024;
    /// Maximum attacker-controlled URL/PyInit/sibling token occurrences examined
    /// across all printable strings in one native member.
    pub const MAX_STRING_TOKEN_OCCURRENCES: usize = 100_000;
    /// Maximum characters retained from one `PyInit_*` name discovered in raw
    /// string data.
    pub const MAX_PYINIT_NAME_LENGTH: usize = 256;
    /// Maximum sections enumerated (for the constructor/init-section presence
    /// checks); an absurd section count is itself a malformed-binary tell but must
    /// not be unbounded work.
    pub const MAX_SECTIONS: usize = 65_536;
    /// Maximum bytes retained from one printable run before token analysis. The
    /// buffered member itself is already capped at 64 MiB by the archive reader;
    /// this lower cap prevents one giant run from causing a giant lowercase copy.
    pub const MAX_PRINTABLE_RUN_BYTES: usize = 8 * 1024 * 1024;
    /// Maximum architectures enumerated from a fat/universal Mach-O header.
    pub const MAX_FAT_ARCHES: usize = 64;
}

/// Remaining traversal work for one native member. A fat Mach-O shares this
/// budget across every slice, so per-object helper calls cannot multiply the
/// advertised caps by the architecture count.
struct ExtractionBudget {
    imports_remaining: usize,
    import_descriptors_remaining: usize,
    symbols_remaining: usize,
    dynamic_symbols_remaining: usize,
    sections_remaining: usize,
    strings_remaining: usize,
    string_token_occurrences_remaining: usize,
}

impl Default for ExtractionBudget {
    fn default() -> Self {
        Self {
            imports_remaining: caps::MAX_IMPORTS,
            import_descriptors_remaining: caps::MAX_IMPORT_DESCRIPTORS,
            symbols_remaining: caps::MAX_SYMBOLS,
            dynamic_symbols_remaining: caps::MAX_SYMBOLS,
            sections_remaining: caps::MAX_SECTIONS,
            strings_remaining: caps::MAX_STRINGS_SCANNED,
            string_token_occurrences_remaining: caps::MAX_STRING_TOKEN_OCCURRENCES,
        }
    }
}

impl ExtractionBudget {
    /// Whether every structured table budget has been exhausted. A fat Mach-O with
    /// another slice at this point cannot be proved covered without restarting
    /// attacker-controlled parser work, so slice traversal must stop as Partial.
    fn structured_exhausted(&self) -> bool {
        self.imports_remaining == 0
            && self.import_descriptors_remaining == 0
            && self.symbols_remaining == 0
            && self.dynamic_symbols_remaining == 0
            && self.sections_remaining == 0
    }
}

/// Consume one slot from a member-scoped traversal budget. Returning `false`
/// means the caller has observed a real item beyond the cap; merely reaching zero
/// after the last in-cap item remains complete.
fn take_budget_slot(remaining: &mut usize) -> bool {
    if *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    true
}

/// How completely a native member was triaged. A [`Buffered`] member parses in
/// full; a [`Streaming`] (above-cap) member is magic/arch + string-scan only.
///
/// [`Buffered`]: NativeMemberHandoff::Buffered
/// [`Streaming`]: NativeMemberHandoff::Streaming
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeCoverage {
    /// The whole member was parsed (it was within the native-parse cap and the
    /// object parser accepted it). Set explicitly by every full-parse path; never
    /// the default, so a coverage value cannot silently claim full coverage.
    Full,
    /// Only a partial triage ran: either the member was streamed (above the
    /// native-parse cap, so magic/arch + printable strings only), or the principal
    /// parser declined a buffered member as malformed and we fell back to the magic
    /// classifier. Either way the deep extraction is incomplete. The DEFAULT: a
    /// coverage enum must fail closed (assume incomplete), so a freshly-defaulted
    /// facts value reports partial until a full parse overwrites it.
    #[default]
    Partial,
}

/// Exact reason a native analysis is partial. This is separate from
/// [`NativeCoverage`] so callers can fail closed while still explaining which
/// parser boundary or attacker-controlled cap prevented full coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativePartialReason {
    /// The member was provided only as a bounded streaming view.
    StreamingView,
    /// The buffered object parser rejected the member.
    ObjectParseFailed,
    /// A fat Mach-O header could not be parsed.
    FatHeaderParseFailed,
    /// More imports existed than the import traversal cap permits.
    ImportTableLimit,
    /// More PE import descriptors existed than the descriptor traversal cap permits.
    ImportDescriptorLimit,
    /// A structured import name exceeded its pre-allocation length cap.
    ImportNameLengthLimit,
    /// The object import table itself could not be read.
    ImportTableUnreadable,
    /// An import name was not valid UTF-8 and could not be classified.
    InvalidImportName,
    /// More ordinary symbols existed than the symbol traversal cap permits.
    SymbolTableLimit,
    /// An ordinary symbol name could not be read.
    InvalidSymbolName,
    /// More dynamic symbols existed than the dynamic-symbol traversal cap permits.
    DynamicSymbolTableLimit,
    /// A dynamic symbol name could not be read.
    InvalidDynamicSymbolName,
    /// More sections existed than the section traversal cap permits.
    SectionTableLimit,
    /// A section name could not be read.
    InvalidSectionName,
    /// A fat Mach-O contained more architecture slices than may be traversed.
    FatArchitectureLimit,
    /// A fat Mach-O still had slices after every member-wide structured budget was
    /// exhausted.
    FatTraversalBudgetExhausted,
    /// A fat Mach-O architecture slice could not be read.
    FatSliceUnreadable,
    /// A fat Mach-O architecture slice could not be parsed as an object.
    FatSliceParseFailed,
    /// A printable run exceeded the bounded per-run byte cap.
    PrintableRunByteLimit,
    /// More printable strings existed than the string traversal cap permits.
    PrintableStringCountLimit,
    /// More distinct sibling payload references existed than may be retained.
    SiblingReferenceLimit,
    /// A sibling payload reference exceeded its per-reference length cap.
    SiblingReferenceLengthLimit,
    /// More printable token occurrences existed than may be examined safely.
    PrintableTokenOccurrenceLimit,
    /// More distinct embedded URLs existed than may be retained.
    EmbeddedUrlLimit,
    /// An embedded URL exceeded the bounded per-URL character cap.
    EmbeddedUrlLengthLimit,
    /// More distinct `PyInit_*` names existed than may be retained.
    PyInitExportLimit,
    /// A string-derived `PyInit_*` name exceeded its character cap.
    PyInitNameLengthLimit,
}

impl NativePartialReason {
    /// Stable human-readable evidence token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StreamingView => "streaming_view",
            Self::ObjectParseFailed => "object_parse_failed",
            Self::FatHeaderParseFailed => "fat_header_parse_failed",
            Self::ImportTableLimit => "import_table_limit",
            Self::ImportDescriptorLimit => "import_descriptor_limit",
            Self::ImportNameLengthLimit => "import_name_length_limit",
            Self::ImportTableUnreadable => "import_table_unreadable",
            Self::InvalidImportName => "invalid_import_name",
            Self::SymbolTableLimit => "symbol_table_limit",
            Self::InvalidSymbolName => "invalid_symbol_name",
            Self::DynamicSymbolTableLimit => "dynamic_symbol_table_limit",
            Self::InvalidDynamicSymbolName => "invalid_dynamic_symbol_name",
            Self::SectionTableLimit => "section_table_limit",
            Self::InvalidSectionName => "invalid_section_name",
            Self::FatArchitectureLimit => "fat_architecture_limit",
            Self::FatTraversalBudgetExhausted => "fat_traversal_budget_exhausted",
            Self::FatSliceUnreadable => "fat_slice_unreadable",
            Self::FatSliceParseFailed => "fat_slice_parse_failed",
            Self::PrintableRunByteLimit => "printable_run_byte_limit",
            Self::PrintableStringCountLimit => "printable_string_count_limit",
            Self::SiblingReferenceLimit => "sibling_reference_limit",
            Self::SiblingReferenceLengthLimit => "sibling_reference_length_limit",
            Self::PrintableTokenOccurrenceLimit => "printable_token_occurrence_limit",
            Self::EmbeddedUrlLimit => "embedded_url_limit",
            Self::EmbeddedUrlLengthLimit => "embedded_url_length_limit",
            Self::PyInitExportLimit => "py_init_export_limit",
            Self::PyInitNameLengthLimit => "py_init_name_length_limit",
        }
    }
}

/// The recognized object-file format. `Unknown` covers anything the magic
/// classifier does not recognize (a non-native member, or a truncated/garbled
/// header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFormat {
    /// An ELF object (Linux / BSD `.so`).
    Elf,
    /// A single-architecture Mach-O object (macOS `.dylib`/`.so`).
    MachO,
    /// A fat / universal Mach-O (multiple architecture slices).
    MachOFat,
    /// A PE / COFF object (Windows `.pyd`/`.dll`).
    Pe,
    /// Unrecognized or unparseable.
    Unknown,
}

impl NativeFormat {
    /// A short wire/evidence label.
    fn label(self) -> &'static str {
        match self {
            NativeFormat::Elf => "ELF",
            NativeFormat::MachO => "Mach-O",
            NativeFormat::MachOFat => "Mach-O (fat/universal)",
            NativeFormat::Pe => "PE/COFF",
            NativeFormat::Unknown => "unknown",
        }
    }
}

/// The deterministic facts extracted from one native member. Policy-independent
/// raw observations; correlation ([`correlate_native`]) decides what becomes a
/// finding. Sets are deduplicated and bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeFacts {
    /// The detected object format.
    pub format: Option<NativeFormat>,
    /// A short architecture/ABI label (e.g. `x86-64`, `aarch64`), best-effort.
    pub arch: Option<String>,
    /// How completely the member was triaged.
    pub coverage: NativeCoverage,
    /// Precise reasons [`Self::coverage`] is [`NativeCoverage::Partial`]. Empty for
    /// fully covered extraction and for a freshly defaulted, not-yet-analyzed value.
    pub partial_reasons: BTreeSet<NativePartialReason>,
    /// Dynamic imports (capped, deduplicated, lowercased).
    pub imports: BTreeSet<String>,
    /// Exported `PyInit_*` symbol names (a CPython extension's init entry, which
    /// runs arbitrary module code on import).
    pub py_init_exports: BTreeSet<String>,
    /// An ELF `.init_array`/`.init`/`.ctors` (or `DT_INIT`) constructor is present.
    pub has_elf_constructor: bool,
    /// A Mach-O `__mod_init_func` (or `__init_func`) module-init section is present.
    pub has_macho_mod_init: bool,
    /// A PE TLS directory (callback table) or a `DllMain` export is present.
    pub has_pe_tls_or_dllmain: bool,
    /// Embedded URLs (capped, deduplicated). Includes benign homepage/license URLs,
    /// so this set ALONE is not a danger capability; only a SUSPICIOUS-shaped URL
    /// ([`is_suspicious_url`]) counts toward the danger leg.
    pub embedded_urls: BTreeSet<String>,
    /// At least one embedded URL has a suspicious shape (an IP-literal host, a
    /// non-standard port, or a raw-content host), the only URL form that counts as a
    /// danger capability. A plain `https://docs.example/` does not set this.
    pub has_suspicious_url: bool,
    /// External-runtime names referenced as whole tokens (bun/node/deno/sh/bash/
    /// cmd.exe/...), capped. A bare mention is NOT a danger capability on its own
    /// (the name can appear in help text); see [`has_runtime_launch`].
    pub runtime_names: BTreeSet<String>,
    /// Sensitive filesystem paths referenced (`~/.aws`, `.ssh`, keychain, ...).
    pub sensitive_paths: BTreeSet<String>,
    /// Process-spawn API tokens found as IMPORTED/UNDEFINED symbols (`execve`,
    /// `posix_spawn`, `system`, `fork`, `CreateProcess`, ...). An IMPORT is a strong
    /// signal the module actually calls the API; distinct from a `.rodata` STRING
    /// mention, which is weak (libc symbol strings are ubiquitous).
    pub spawn_imports: BTreeSet<String>,
    /// Dynamic-code-loading API tokens found as IMPORTED symbols (`dlopen`, `dlsym`,
    /// `LoadLibrary`, `GetProcAddress`, ...). Strong, like [`Self::spawn_imports`].
    pub dlopen_imports: BTreeSet<String>,
    /// A single embedded string contains BOTH a spawn/exec verb AND an external
    /// runtime name (e.g. `posix_spawn ... bun` or `system("node ...")`): the
    /// campaign's actual pattern, a native module LAUNCHING a foreign runtime. This
    /// is the strongest danger+corroboration signal and is filename-independent.
    pub has_runtime_launch: bool,
    /// A single embedded string contains BOTH a spawn/exec verb AND a sibling
    /// script/executable reference (`system("./loader/x.js")`): a native module
    /// spawning a bundled sibling payload.
    pub has_spawn_with_sibling: bool,
    /// Sibling executable/script references (`_index.js`, `*.node`, `*.sh`,
    /// `*.py`), capped. GENERIC: any sibling script/executable, not a known name.
    /// A bare `.py` reference ALONE does not corroborate; it must co-occur with a
    /// spawn/runtime ([`Self::has_spawn_with_sibling`]).
    pub sibling_refs: BTreeSet<String>,
}

impl NativeFacts {
    /// Downgrade coverage and retain the precise reason without duplicate noise.
    fn mark_partial(&mut self, reason: NativePartialReason) {
        self.coverage = NativeCoverage::Partial;
        self.partial_reasons.insert(reason);
    }

    /// Whether the member exposes a direct EXECUTION ENTRY: a `PyInit_*` export, an
    /// ELF constructor, a Mach-O module-init, or a PE TLS callback / `DllMain`.
    /// A Python extension can act directly from `PyInit_*` (no separate constructor
    /// needed), so any one of these qualifies.
    pub fn has_execution_entry(&self) -> bool {
        !self.py_init_exports.is_empty()
            || self.has_elf_constructor
            || self.has_macho_mod_init
            || self.has_pe_tls_or_dllmain
    }

    /// Whether the member exhibits a DANGER CAPABILITY. Deliberately STRICT to keep
    /// ordinary CPython extensions (which embed libc symbol strings and homepage
    /// URLs and ship `.py` files beside the `.so`) from tripping a Critical: a bare
    /// `socket`/`dlopen` STRING or a benign homepage URL does NOT qualify. A danger
    /// capability is one of:
    /// * a process-spawn / dynamic-loader API used as an actual IMPORTED symbol
    ///   (`spawn_imports`/`dlopen_imports` non-empty), OR
    /// * a string that LAUNCHES a foreign runtime (`has_runtime_launch`) or spawns a
    ///   sibling payload (`has_spawn_with_sibling`), OR
    /// * a SUSPICIOUS-shaped embedded URL (IP literal / odd port / raw host).
    ///
    /// A bare network API import (`connect`/`socket`/`getaddrinfo`) is deliberately
    /// NOT a danger leg, because a great many benign extensions legitimately link the
    /// socket API; a network capability contributes only when it shows up as a
    /// runtime launch or a suspicious URL (both of which already qualify above), so
    /// network imports are not collected as their own signal.
    pub fn has_danger_capability(&self) -> bool {
        !self.spawn_imports.is_empty()
            || !self.dlopen_imports.is_empty()
            || self.has_runtime_launch
            || self.has_spawn_with_sibling
            || self.has_suspicious_url
    }

    /// Whether the member actually IMPORTS a process-spawn or dynamic-loader API
    /// (an undefined symbol it calls), the strong "this binary really executes
    /// other code" proof.
    pub fn has_spawn_or_loader_import(&self) -> bool {
        !self.spawn_imports.is_empty() || !self.dlopen_imports.is_empty()
    }

    /// Whether the member carries CORROBORATION for an execution chain. STRICT, for
    /// the same reason as [`Self::has_danger_capability`]: a single `.py` sibling
    /// reference or a bare runtime NAME is NOT enough on its own (both are common in
    /// benign extensions). Corroboration is one of:
    /// * a runtime LAUNCH (a spawn verb co-located with a runtime name), OR
    /// * a spawn co-located with a sibling script/payload, OR
    /// * a sensitive credential path (`~/.aws`, `.ssh`, keychain), OR
    /// * a real spawn/loader IMPORT together with a runtime name OR a sibling
    ///   reference anywhere in the binary. This closes the evasion where a malicious
    ///   `.so` imports `posix_spawn`/`execvp` (so the spawn verb is NOT a string) and
    ///   carries the runtime name and payload path as SEPARATE argv rodata strings:
    ///   the import is the proof it spawns, and the name/ref says what it launches. A
    ///   benign numerical extension imports neither, so its bare `.py` references stay
    ///   non-corroborating.
    /// * a known-malicious indicator (folded in by [`correlate_native`], not here).
    pub fn has_corroboration(&self) -> bool {
        self.has_runtime_launch
            || self.has_spawn_with_sibling
            || !self.sensitive_paths.is_empty()
            || (self.has_spawn_or_loader_import()
                && (!self.runtime_names.is_empty() || !self.sibling_refs.is_empty()))
    }
}

/// The full result of triaging one native member: the extracted facts, the
/// granular signals, the execution edges, and AT MOST ONE correlated finding.
#[derive(Debug, Clone, Default)]
pub struct NativeTriage {
    /// The deterministic extracted facts.
    pub facts: NativeFacts,
    /// Granular [`ArtifactSignal`]s (a native module is present; an execution
    /// entry; a danger capability; corroboration). Evidence for correlation.
    pub signals: Vec<ArtifactSignal>,
    /// Execution edges discovered (the native module's init triggers a sibling
    /// payload / launches a runtime).
    pub edges: Vec<ExecutionEdge>,
    /// The correlated finding, present ONLY when the full conjunction holds (a
    /// Critical [`RuleId::NativeImportExecutionChain`]).
    pub finding: Option<Finding>,
}

/// Triage one native member handed off by the A4 archive reader. NEVER panics:
/// every parse path is fallible and malformed input yields
/// [`NativeCoverage::Partial`] facts, not a panic.
///
/// `known_malicious_indicator` is `true` when the CALLER has independently matched the
/// member's SHA-256 against a known-malicious set; pass `false` when no such lookup is
/// wired (the lookups are DB-gated in B8/DB-D). `unowned` is `true` when the module's path
/// is in NO installed RECORD - a DISTINCT corroborator with its own evidence text (it is
/// not a hash match, and must not be reported as one).
pub fn triage_native(
    handoff: &NativeMemberHandoff,
    known_malicious_indicator: bool,
    unowned: bool,
) -> NativeTriage {
    let facts = extract_facts(handoff);
    correlate_native(
        facts,
        handoff.location(),
        known_malicious_indicator,
        unowned,
    )
}

/// Extract the deterministic facts from a handoff. A buffered member is parsed in
/// full (falling back to the magic classifier on any parse failure); a streaming
/// member is magic/arch + printable-string scan only.
fn extract_facts(handoff: &NativeMemberHandoff) -> NativeFacts {
    match handoff {
        NativeMemberHandoff::Buffered { bytes, .. } => extract_from_buffer(bytes),
        NativeMemberHandoff::Streaming {
            header_window,
            printable_strings,
            ..
        } => extract_from_streaming(header_window, printable_strings),
    }
}

/// Full extraction from a buffered member. Parses with `object`; on ANY parse
/// failure falls back to the magic classifier and records [`NativeCoverage::Partial`].
fn extract_from_buffer(bytes: &[u8]) -> NativeFacts {
    let mut facts = NativeFacts {
        coverage: NativeCoverage::Full,
        ..NativeFacts::default()
    };
    let mut budget = ExtractionBudget::default();

    // A fat/universal Mach-O is parsed slice by slice (it has no single object
    // view). Detect it first via the magic classifier; if it is fat, parse arches.
    let magic = classify_magic(bytes);
    if magic == NativeFormat::MachOFat {
        facts.format = Some(NativeFormat::MachOFat);
        // Parse each architecture slice as its own object, accumulating facts. If
        // the fat header itself is malformed we degrade to Partial.
        if !parse_fat_macho(bytes, &mut facts, &mut budget) {
            facts.mark_partial(NativePartialReason::FatHeaderParseFailed);
        }
        // The string scan over the WHOLE buffer still runs below regardless of slice
        // parse success (strings live in the slices but a whole-buffer scan is a safe
        // superset for the bounded capability/URL/path detection).
        scan_buffer_strings(bytes, &mut facts, &mut budget);
        return facts;
    }

    // Single-object parse (ELF / Mach-O / PE).
    use object::read::Object;
    match object::read::File::parse(bytes) {
        Ok(obj) => {
            facts.format = Some(object_format(&obj));
            facts.arch = architecture_label(obj.architecture());
            extract_from_object(&obj, &mut facts, &mut budget);
        }
        Err(_) => {
            // The principal parser declined: fall back to magic/arch only, Partial.
            facts.format = Some(magic);
            facts.mark_partial(NativePartialReason::ObjectParseFailed);
        }
    }

    // Bounded string scan over the whole buffer for capability / URL / path /
    // runtime / sibling evidence (a superset of symbol/import names; cheap and
    // format-independent). Runs whether or not the structured parse succeeded.
    scan_buffer_strings(bytes, &mut facts, &mut budget);
    facts
}

/// Partial extraction for an above-cap streaming member: magic/arch from the
/// header window, plus the capability/URL/path/runtime/sibling scan over the
/// PRINTABLE STRINGS A4 already collected while streaming (we never buffered the
/// whole body). Always [`NativeCoverage::Partial`].
fn extract_from_streaming(header_window: &[u8], printable_strings: &[String]) -> NativeFacts {
    let mut facts = NativeFacts {
        coverage: NativeCoverage::Partial,
        format: Some(classify_magic(header_window)),
        ..NativeFacts::default()
    };
    facts.mark_partial(NativePartialReason::StreamingView);
    let mut budget = ExtractionBudget::default();
    // Arch from the header window only, best-effort (parse just the prefix; a real
    // header is far under 2 MiB, so a prefix parse usually yields the architecture).
    use object::read::Object;
    if let Ok(obj) = object::read::File::parse(header_window) {
        facts.arch = architecture_label(obj.architecture());
    }
    // The streaming view never gives us symbol/import/section tables, so an
    // execution-entry can only be inferred from a `PyInit_*` STRING in the
    // printable scan (a weaker signal than an actual export, but correlation treats
    // it as Partial anyway). The capability scan runs over the collected strings.
    scan_strings(
        printable_strings.iter().map(|s| s.as_str()),
        &mut facts,
        &mut budget,
    );
    facts
}

/// Map an `object` parsed file to our coarse [`NativeFormat`].
fn object_format(obj: &object::read::File) -> NativeFormat {
    match obj.format() {
        object::BinaryFormat::Elf => NativeFormat::Elf,
        object::BinaryFormat::MachO => NativeFormat::MachO,
        object::BinaryFormat::Pe | object::BinaryFormat::Coff => NativeFormat::Pe,
        _ => NativeFormat::Unknown,
    }
}

/// Retain and classify one structured import name only after its byte length has
/// passed the allocation cap.
fn record_structured_import_name(name: &str, facts: &mut NativeFacts) {
    if name.len() > caps::MAX_IMPORT_NAME_LENGTH {
        facts.mark_partial(NativePartialReason::ImportNameLengthLimit);
        return;
    }
    let lower = name.to_ascii_lowercase();
    classify_capability_import(&lower, facts);
    facts.imports.insert(lower);
}

/// Decode one structured import name without allocating attacker-sized storage.
fn record_structured_import_bytes(name: &[u8], facts: &mut NativeFacts) {
    if name.len() > caps::MAX_IMPORT_NAME_LENGTH {
        facts.mark_partial(NativePartialReason::ImportNameLengthLimit);
        return;
    }
    match std::str::from_utf8(name) {
        Ok(name) => record_structured_import_name(name, facts),
        Err(_) => facts.mark_partial(NativePartialReason::InvalidImportName),
    }
}

/// Walk a PE import table lazily. The generic [`object::read::Object::imports`]
/// API first constructs a complete `Vec<Import>` and therefore applies Tirith's
/// cap only after attacker-controlled allocation. This mirrors the same public
/// low-level parser while consuming descriptor/thunk budgets before reading or
/// allocating each name.
fn extract_pe_imports<Pe>(
    file: &object::read::pe::PeFile<'_, Pe>,
    facts: &mut NativeFacts,
    budget: &mut ExtractionBudget,
) where
    Pe: object::read::pe::ImageNtHeaders,
{
    use object::endian::LittleEndian as LE;
    use object::read::pe::ImageThunkData as _;

    let table = match file.import_table() {
        Ok(Some(table)) => table,
        Ok(None) => return,
        Err(_) => {
            facts.mark_partial(NativePartialReason::ImportTableUnreadable);
            return;
        }
    };
    let mut descriptors = match table.descriptors() {
        Ok(descriptors) => descriptors,
        Err(_) => {
            facts.mark_partial(NativePartialReason::ImportTableUnreadable);
            return;
        }
    };

    loop {
        let descriptor = match descriptors.next() {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => return,
            Err(_) => {
                facts.mark_partial(NativePartialReason::ImportTableUnreadable);
                return;
            }
        };
        if !take_budget_slot(&mut budget.import_descriptors_remaining) {
            facts.mark_partial(NativePartialReason::ImportDescriptorLimit);
            return;
        }

        let mut first_thunk = descriptor.original_first_thunk.get(LE);
        if first_thunk == 0 {
            first_thunk = descriptor.first_thunk.get(LE);
        }
        let mut thunks = match table.thunks(first_thunk) {
            Ok(thunks) => thunks,
            Err(_) => {
                facts.mark_partial(NativePartialReason::ImportTableUnreadable);
                return;
            }
        };
        loop {
            let thunk = match thunks.next::<Pe>() {
                Ok(Some(thunk)) => thunk,
                Ok(None) => break,
                Err(_) => {
                    facts.mark_partial(NativePartialReason::ImportTableUnreadable);
                    return;
                }
            };
            // Count ordinal imports too: they are attacker-controlled traversal
            // work even though they have no name to classify.
            if !take_budget_slot(&mut budget.imports_remaining) {
                facts.mark_partial(NativePartialReason::ImportTableLimit);
                return;
            }
            if thunk.is_ordinal() {
                continue;
            }
            match table.hint_name(thunk.address()) {
                Ok((_hint, name)) => record_structured_import_bytes(name, facts),
                Err(_) => facts.mark_partial(NativePartialReason::ImportTableUnreadable),
            }
        }
    }
}

/// Extract format-specific facts from a parsed single-object file: imports,
/// `PyInit_*` exports, constructor/init-section presence, and TLS/DllMain. Every
/// iteration is bounded before attacker-derived allocation.
fn extract_from_object(
    obj: &object::read::File,
    facts: &mut NativeFacts,
    budget: &mut ExtractionBudget,
) {
    use object::read::{Object, ObjectSection, ObjectSymbol};

    // Derive the format from THIS parsed object, not from `facts.format`. For a
    // fat/universal Mach-O, `facts.format` is `MachOFat` while each slice parsed
    // here is a thin Mach-O; keying the section-presence match on the slice's own
    // format is what lets a fat Mach-O whose only constructor is `__mod_init_func`
    // set `has_macho_mod_init` (otherwise the Mach-O arm never matches a fat slice).
    let format = object_format(obj);

    // PE imports live in a separate descriptor/thunk table, so walk it through the
    // bounded lazy helper. ELF and Mach-O imports are undefined symbols and are
    // folded into their already-bounded symbol loops below. Avoid Object::imports()
    // entirely: it eagerly materializes an unbounded Vec before the caller sees it.
    match obj {
        object::read::File::Pe32(file) => extract_pe_imports(file, facts, budget),
        object::read::File::Pe64(file) => extract_pe_imports(file, facts, budget),
        _ => {}
    }

    // Exported symbols: collect `PyInit_*` and detect a `DllMain` export (PE) /
    // constructor-shaped names. Bounded by MAX_SYMBOLS.
    for sym in obj.symbols() {
        if !take_budget_slot(&mut budget.symbols_remaining) {
            facts.mark_partial(NativePartialReason::SymbolTableLimit);
            break;
        }
        let Ok(name) = sym.name() else {
            facts.mark_partial(NativePartialReason::InvalidSymbolName);
            continue;
        };
        let is_import = format == NativeFormat::MachO && sym.is_undefined() && !name.is_empty();
        if is_import && !take_budget_slot(&mut budget.imports_remaining) {
            facts.mark_partial(NativePartialReason::ImportTableLimit);
            break;
        }
        if name.starts_with("PyInit_") || name.starts_with("_PyInit_") {
            if name.len() > caps::MAX_PYINIT_NAME_LENGTH {
                facts.mark_partial(NativePartialReason::PyInitNameLengthLimit);
            } else {
                record_py_init_export(facts, name.to_string(), caps::MAX_SYMBOLS);
            }
        }
        if is_import {
            record_structured_import_name(name, facts);
        }
        if format == NativeFormat::Pe && name.eq_ignore_ascii_case("DllMain") {
            facts.has_pe_tls_or_dllmain = true;
        }
    }
    // Also scan dynamic symbols (ELF puts exported `PyInit_*` in `.dynsym`, and its
    // UNDEFINED dynamic symbols are the imports an ELF references). Handling them
    // in this bounded loop avoids the eager allocation performed by `obj.imports()`.
    for sym in obj.dynamic_symbols() {
        if !take_budget_slot(&mut budget.dynamic_symbols_remaining) {
            facts.mark_partial(NativePartialReason::DynamicSymbolTableLimit);
            break;
        }
        let Ok(name) = sym.name() else {
            facts.mark_partial(NativePartialReason::InvalidDynamicSymbolName);
            continue;
        };
        let is_import = format == NativeFormat::Elf && sym.is_undefined() && !name.is_empty();
        if is_import && !take_budget_slot(&mut budget.imports_remaining) {
            facts.mark_partial(NativePartialReason::ImportTableLimit);
            break;
        }
        if name.starts_with("PyInit_") || name.starts_with("_PyInit_") {
            if name.len() > caps::MAX_PYINIT_NAME_LENGTH {
                facts.mark_partial(NativePartialReason::PyInitNameLengthLimit);
            } else {
                record_py_init_export(facts, name.to_string(), caps::MAX_SYMBOLS);
            }
        }
        // An UNDEFINED symbol is an import: the module calls it but does not define
        // it. This is the strong spawn/loader/network signal for ELF.
        if is_import {
            record_structured_import_name(name, facts);
        }
    }

    // Section-presence checks for constructors / module-init / TLS, format-aware.
    for sec in obj.sections() {
        if !take_budget_slot(&mut budget.sections_remaining) {
            facts.mark_partial(NativePartialReason::SectionTableLimit);
            break;
        }
        let name = match sec.name() {
            Ok(name) => name,
            Err(_) => {
                facts.mark_partial(NativePartialReason::InvalidSectionName);
                continue;
            }
        };
        // A constructor/init/TLS section only RUNS code when it is non-empty: an
        // empty `.init_array` (which honest toolchains do emit) holds zero function
        // pointers and triggers nothing, so an empty section is not an execution
        // entry. `.init` (code, not a pointer array) is treated the same: an empty
        // section is inert. Mach-O module-init sections live in `__DATA`/
        // `__DATA_CONST` as `__mod_init_func` (and the legacy `__init_func`);
        // `object` reports the section name without the segment. A PE `.tls` section
        // indicates a TLS directory whose callbacks run on load/thread start (a
        // `DllMain` export is caught above).
        if sec.size() == 0 {
            continue;
        }
        match format {
            NativeFormat::Elf
                if matches!(name, ".init_array" | ".ctors" | ".init" | ".preinit_array") =>
            {
                facts.has_elf_constructor = true;
            }
            NativeFormat::MachO if matches!(name, "__mod_init_func" | "__init_func") => {
                facts.has_macho_mod_init = true;
            }
            NativeFormat::Pe if name == ".tls" => {
                facts.has_pe_tls_or_dllmain = true;
            }
            _ => {}
        }
    }

    // ELF dynamic-section `DT_INIT`/`DT_INIT_ARRAY` is also a constructor; the
    // `.init_array` section check above is the common case, so we do not additionally
    // walk the dynamic table here (kept simple; section presence is sufficient and
    // cheaper, and a stripped binary that hides `.init_array` is rare and still
    // caught by the string scan's capability evidence).

    // Raw strings are scanned once over the complete bounded member buffer by
    // `extract_from_buffer`. Re-scanning each section here duplicated attacker work
    // and reset the string-count cap per section/slice; one whole-buffer pass is a
    // strict superset and gives the cap honest per-member semantics.
}

/// Parse a fat/universal Mach-O header and each architecture slice. Returns `true`
/// if the fat header parsed (slices are best-effort); `false` if the fat header
/// itself was malformed. Bounded by [`caps::MAX_FAT_ARCHES`].
fn parse_fat_macho(bytes: &[u8], facts: &mut NativeFacts, budget: &mut ExtractionBudget) -> bool {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};

    // Try 64-bit fat first, then 32-bit. (`FileKind` distinguishes them, but trying
    // both is simplest and each parse is bounded.)
    if let Ok(fat) = MachOFatFile64::parse(bytes) {
        let arches = fat.arches();
        if arches.len() > caps::MAX_FAT_ARCHES {
            facts.mark_partial(NativePartialReason::FatArchitectureLimit);
        }
        for (i, arch) in arches.iter().enumerate() {
            if i >= caps::MAX_FAT_ARCHES {
                break;
            }
            if budget.structured_exhausted() {
                facts.mark_partial(NativePartialReason::FatTraversalBudgetExhausted);
                break;
            }
            if facts.arch.is_none() {
                facts.arch = architecture_label(arch.architecture());
            }
            match arch.data(bytes) {
                Ok(slice) => match object::read::File::parse(slice) {
                    Ok(obj) => extract_from_object(&obj, facts, budget),
                    Err(_) => facts.mark_partial(NativePartialReason::FatSliceParseFailed),
                },
                Err(_) => facts.mark_partial(NativePartialReason::FatSliceUnreadable),
            }
        }
        return true;
    }
    if let Ok(fat) = MachOFatFile32::parse(bytes) {
        let arches = fat.arches();
        if arches.len() > caps::MAX_FAT_ARCHES {
            facts.mark_partial(NativePartialReason::FatArchitectureLimit);
        }
        for (i, arch) in arches.iter().enumerate() {
            if i >= caps::MAX_FAT_ARCHES {
                break;
            }
            if budget.structured_exhausted() {
                facts.mark_partial(NativePartialReason::FatTraversalBudgetExhausted);
                break;
            }
            if facts.arch.is_none() {
                facts.arch = architecture_label(arch.architecture());
            }
            match arch.data(bytes) {
                Ok(slice) => match object::read::File::parse(slice) {
                    Ok(obj) => extract_from_object(&obj, facts, budget),
                    Err(_) => facts.mark_partial(NativePartialReason::FatSliceParseFailed),
                },
                Err(_) => facts.mark_partial(NativePartialReason::FatSliceUnreadable),
            }
        }
        return true;
    }
    false
}

/// A short architecture/ABI label from `object`'s [`object::Architecture`].
fn architecture_label(arch: object::Architecture) -> Option<String> {
    use object::Architecture as A;
    let s = match arch {
        A::X86_64 | A::X86_64_X32 => "x86-64",
        A::I386 => "x86",
        A::Aarch64 | A::Aarch64_Ilp32 => "aarch64",
        A::Arm => "arm",
        A::Riscv64 => "riscv64",
        A::Riscv32 => "riscv32",
        A::PowerPc64 => "ppc64",
        A::PowerPc => "ppc",
        A::Mips64 => "mips64",
        A::Mips => "mips",
        A::S390x => "s390x",
        A::LoongArch64 => "loongarch64",
        A::Wasm32 | A::Wasm64 => "wasm",
        A::Unknown => return None,
        _ => "other",
    };
    Some(s.to_string())
}

/// The tiny hand-written magic/architecture FALLBACK classifier: recognize the
/// object format from the leading bytes ONLY. Used when the principal parser
/// declines a buffer or when only a streaming header window is available. Never
/// reads past the bytes it is given.
fn classify_magic(bytes: &[u8]) -> NativeFormat {
    match crate::content_kind::classify_native_prefix(bytes) {
        crate::content_kind::NativeMagic::Elf => NativeFormat::Elf,
        crate::content_kind::NativeMagic::MachO => NativeFormat::MachO,
        crate::content_kind::NativeMagic::MachOFat => NativeFormat::MachOFat,
        crate::content_kind::NativeMagic::Pe => NativeFormat::Pe,
        crate::content_kind::NativeMagic::Unknown => NativeFormat::Unknown,
    }
}

// ----------------------------------------------------------------------------
// String / capability scanning
// ----------------------------------------------------------------------------

/// Process-spawn API names, matched as IMPORTED symbols (an import means the module
/// calls the API; a `.rodata` string mention does not). Cross-platform: POSIX
/// `exec*`/`system`/`fork`/`posix_spawn` and Windows `CreateProcess`/`ShellExecute`/
/// `WinExec`. Also used as the spawn-VERB set when detecting a spawn co-located with
/// a runtime/sibling in a single string (the campaign's launch pattern).
const SPAWN_TOKENS: &[&str] = &[
    "execve",
    "execl",
    "execlp",
    "execvp",
    "execvpe",
    "posix_spawn",
    "posix_spawnp",
    "system",
    "popen",
    "fork",
    "vfork",
    "createprocessa",
    "createprocessw",
    "createprocess",
    "shellexecutea",
    "shellexecutew",
    "shellexecute",
    "winexec",
];

/// Spawn tokens safe to match as a co-occurring WORD inside a rodata string. This
/// excludes the plain English words "system" and "fork" from [`SPAWN_TOKENS`]: as
/// bare words they appear in benign error strings ("system error: cannot find x.py",
/// "fork the repo"), so matching them that way co-located with a `.py` sibling
/// produced false-positive Critical findings. The caller still matches `system(` /
/// `fork(` (the CALL form) separately, so a real `system("bun run x")` fires; and
/// both remain in [`SPAWN_TOKENS`] for IMPORT classification, where an imported
/// `system`/`fork` symbol is a real signal.
const SPAWN_VERB_TOKENS: &[&str] = &[
    "execve",
    "execl",
    "execlp",
    "execvp",
    "execvpe",
    "posix_spawn",
    "posix_spawnp",
    "popen",
    "vfork",
    "createprocessa",
    "createprocessw",
    "createprocess",
    "shellexecutea",
    "shellexecutew",
    "shellexecute",
    "winexec",
];

/// Dynamic-code-loading API names, matched as IMPORTED symbols. `dlopen`/`dlsym` on
/// POSIX, `LoadLibrary`/`GetProcAddress` on Windows. (`mprotect`/`VirtualProtect`
/// are deliberately EXCLUDED: many benign extensions legitimately use them, so they
/// are too noisy for a Critical-conjunction leg.)
const DLOPEN_TOKENS: &[&str] = &[
    "dlopen",
    "dlsym",
    "loadlibrarya",
    "loadlibraryw",
    "loadlibraryexa",
    "loadlibraryexw",
    "loadlibrary",
    "getprocaddress",
];

/// External-runtime names (whole-word). GENERIC: any of these LAUNCHED from the
/// native module (co-located with a spawn verb in one string) is the runtime-loader
/// signal. A known name only raises confidence; renaming a payload script cannot
/// evade because the rule keys on the RUNTIME name, not the script. The 2-char `sh`
/// is excluded from the bare-name set (too many false hits inside paths) but its
/// longer shells are kept; a real `sh` launch is still caught via `bash`/`/bin/sh`
/// shaped strings co-located with a spawn verb.
const RUNTIME_TOKENS: &[&str] = &[
    "bun",
    "node",
    "nodejs",
    "deno",
    "npx",
    "bash",
    "zsh",
    "cmd.exe",
    "powershell",
    "pwsh",
    "wscript",
    "cscript",
];

/// Sensitive filesystem-path needles (substring; these are path FRAGMENTS, matched
/// as substrings rather than whole tokens because they appear inside longer paths).
const SENSITIVE_PATH_NEEDLES: &[&str] = &[
    ".aws/credentials",
    ".aws/config",
    "/.aws",
    "/.ssh",
    "id_rsa",
    "id_ed25519",
    ".ssh/authorized_keys",
    "login.keychain",
    "/library/keychains",
    ".config/gcloud",
    ".docker/config.json",
    ".npmrc",
    ".netrc",
    ".gnupg",
    "/etc/shadow",
    ".kube/config",
];

/// Sibling-script/executable extensions (a reference to a file with one of these
/// extensions, GENERIC: any sibling script/payload, not a known filename).
const SIBLING_EXTENSIONS: &[&str] = &[
    ".js", ".mjs", ".cjs", ".node", ".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".rb", ".pl",
];

/// Scan a buffer for printable-ASCII strings (runs >= 4) and feed each to the
/// capability scanner. Bounded by the number of strings examined.
fn scan_buffer_strings(bytes: &[u8], facts: &mut NativeFacts, budget: &mut ExtractionBudget) {
    scan_bytes_strings(bytes, facts, budget);
}

/// Extract printable-ASCII runs (>= 4 chars) from raw bytes and scan them. Bounded
/// by [`caps::MAX_STRINGS_SCANNED`] (count) AND by capping each accumulated run at
/// [`caps::MAX_PRINTABLE_RUN_BYTES`] (so one giant all-printable run cannot force a
/// multi-gigabyte `to_ascii_lowercase` + token sweep — the run is truncated and
/// records [`NativePartialReason::PrintableRunByteLimit`]).
fn scan_bytes_strings(bytes: &[u8], facts: &mut NativeFacts, budget: &mut ExtractionBudget) {
    let mut current: Vec<u8> = Vec::new();
    let mut run_truncated = false;
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            // Cap the run length: once at the cap, stop appending (the prefix is
            // enough for token detection; an unbounded run is a DoS lever).
            if current.len() < caps::MAX_PRINTABLE_RUN_BYTES {
                current.push(b);
            } else if !run_truncated {
                // Prefix-only treatment of a giant run can hide tokens after the
                // cap. Keep memory bounded but make the result explicitly Partial.
                facts.mark_partial(NativePartialReason::PrintableRunByteLimit);
                run_truncated = true;
            }
        } else {
            if current.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    if !take_budget_slot(&mut budget.strings_remaining) {
                        facts.mark_partial(NativePartialReason::PrintableStringCountLimit);
                        return;
                    }
                    scan_one_string(s, facts, budget);
                }
            }
            current.clear();
            run_truncated = false;
        }
    }
    if current.len() >= 4 {
        if let Ok(s) = std::str::from_utf8(&current) {
            if !take_budget_slot(&mut budget.strings_remaining) {
                facts.mark_partial(NativePartialReason::PrintableStringCountLimit);
            } else {
                scan_one_string(s, facts, budget);
            }
        }
    }
}

/// Scan an iterator of already-extracted strings (the streaming-view path).
fn scan_strings<'a, I: Iterator<Item = &'a str>>(
    strings: I,
    facts: &mut NativeFacts,
    budget: &mut ExtractionBudget,
) {
    for s in strings {
        // The loop only reaches this branch after observing an actual next item.
        // Thus exactly-at-cap input stays complete, while cap + 1 is explicit.
        if !take_budget_slot(&mut budget.strings_remaining) {
            facts.mark_partial(NativePartialReason::PrintableStringCountLimit);
            break;
        }
        scan_one_string(s, facts, budget);
    }
}

/// Insert one attacker-derived string into a bounded fact set. An at-cap duplicate
/// is harmless; only a distinct (cap + 1)th value reports exhaustion.
fn insert_bounded(set: &mut BTreeSet<String>, value: String, limit: usize) -> bool {
    if set.contains(&value) {
        return true;
    }
    if set.len() >= limit {
        return false;
    }
    set.insert(value);
    true
}

fn record_sibling_reference(facts: &mut NativeFacts, reference: String, limit: usize) {
    if !insert_bounded(&mut facts.sibling_refs, reference, limit) {
        facts.mark_partial(NativePartialReason::SiblingReferenceLimit);
    }
}

fn record_embedded_url(facts: &mut NativeFacts, url: String, limit: usize) {
    if !insert_bounded(&mut facts.embedded_urls, url, limit) {
        facts.mark_partial(NativePartialReason::EmbeddedUrlLimit);
    }
}

fn record_py_init_export(facts: &mut NativeFacts, name: String, limit: usize) {
    if !insert_bounded(&mut facts.py_init_exports, name, limit) {
        facts.mark_partial(NativePartialReason::PyInitExportLimit);
    }
}

/// Collect at most `limit` characters and report whether one more character was
/// present. The single-item peek makes exact-at-cap input complete.
fn collect_chars_capped<I: Iterator<Item = char>>(mut chars: I, limit: usize) -> (String, bool) {
    let value = chars.by_ref().take(limit).collect();
    let exceeded = chars.next().is_some();
    (value, exceeded)
}

/// Classify an IMPORTED symbol name (already lowercase) into the strong capability
/// sets. An import is a strong signal because the module actually references the API
/// (unlike a `.rodata` string mention, which is libc-ubiquitous). Bounded by the
/// tiny token lists.
fn classify_capability_import(name: &str, facts: &mut NativeFacts) {
    // Imported symbol names are exact (a relocation target), so an exact / word
    // match against the token list is right; we still use `contains_word` so a
    // decorated name (`_execve`, `execve@GLIBC_2.2.5`) matches.
    for t in SPAWN_TOKENS {
        if contains_word(name, t) {
            facts.spawn_imports.insert((*t).to_string());
        }
    }
    for t in DLOPEN_TOKENS {
        if contains_word(name, t) {
            facts.dlopen_imports.insert((*t).to_string());
        }
    }
}

/// Scan one extracted string for the co-occurrence tells (a spawn verb with a
/// runtime / a sibling), the runtime names, the suspicious-URL shape, the sensitive
/// paths, the sibling references, and a `PyInit_*` string (the streaming-view path).
/// Case-insensitive. The co-occurrence checks are what keep ordinary extensions
/// (which embed libc symbol strings and homepage URLs) from satisfying a Critical
/// leg: a danger/corroboration leg needs the spawn verb and the runtime/sibling in
/// the SAME string, not merely both present somewhere in the binary.
fn scan_one_string(s: &str, facts: &mut NativeFacts, budget: &mut ExtractionBudget) {
    let lower = s.to_ascii_lowercase();

    // Does THIS string contain a spawn/exec verb? (used for the co-occurrence legs.)
    // Distinctive spawn tokens match as a word; the plain English words "system" and
    // "fork" match ONLY as a call (`system(`/`fork(`), so a real `system("bun run x")`
    // fires but benign prose ("system error: cannot find x.py") does not.
    let has_spawn_verb = SPAWN_VERB_TOKENS.iter().any(|t| contains_word(&lower, t))
        || lower.contains("system(")
        || lower.contains("fork(");

    // Runtime names present in this string.
    let mut runtimes_here: Vec<&str> = Vec::new();
    for t in RUNTIME_TOKENS {
        if contains_word(&lower, t) {
            runtimes_here.push(t);
        }
    }
    // A `/bin/sh`- or `/bin/bash`-shaped shell path also counts as a runtime here
    // (covers the 2-char `sh` we excluded from the bare-name set).
    let shell_path_here =
        lower.contains("/bin/sh") || lower.contains("/bin/bash") || lower.contains("/system32/cmd");
    for r in &runtimes_here {
        // This set's universe is the fixed `RUNTIME_TOKENS` table, so it is
        // inherently bounded without a second, silently truncating storage cap.
        facts.runtime_names.insert((*r).to_string());
    }

    // Sibling script/executable references in this string. `sibling_here` is computed
    // UNCONDITIONALLY (mirroring `runtimes_here` above) so the spawn+sibling
    // co-occurrence check still fires after the storage cap is hit; only the STORAGE is
    // capped. Otherwise a crafted binary could pad 256 benign sibling names early to
    // silently disable the spawn+sibling leg for every later string (e.g. a later
    // `execvp("./payload.js", ...)`).
    let mut sibling_here = false;
    for ext in SIBLING_EXTENSIONS {
        if collect_sibling_references(s, &lower, ext, facts, budget) {
            sibling_here = true;
        }
    }

    // The campaign's launch pattern: a spawn verb AND a runtime (or a shell path) in
    // ONE string -> a native module launching a foreign runtime. The strongest
    // danger+corroboration signal, filename-independent.
    if has_spawn_verb && (!runtimes_here.is_empty() || shell_path_here) {
        facts.has_runtime_launch = true;
    }
    // A spawn verb co-located with a sibling script/payload reference.
    if has_spawn_verb && sibling_here {
        facts.has_spawn_with_sibling = true;
    }

    // Embedded URL. A benign homepage/license URL does NOT count as danger; only a
    // SUSPICIOUS shape (IP literal host / non-standard port / raw-content host) sets
    // `has_suspicious_url`. The full URL is still recorded for evidence.
    // Scan ALL scheme occurrences, not just the first: a benign leading URL must not
    // mask a suspicious one later in the same string.
    // The scan runs UNCONDITIONALLY (mirroring the sibling/runtime caps) so
    // `has_suspicious_url` is still set after the storage cap is hit; only the STORAGE is
    // capped. Otherwise a crafted binary could pad 256 benign URLs early to disable the
    // suspicious-URL danger leg for every later string.
    'schemes: for scheme in ["http://", "https://", "ftp://"] {
        for (pos, _) in lower.match_indices(scheme) {
            if !take_budget_slot(&mut budget.string_token_occurrences_remaining) {
                facts.mark_partial(NativePartialReason::PrintableTokenOccurrenceLimit);
                break 'schemes;
            }
            let tail = &s[pos.min(s.len())..];
            let (url, url_truncated) = collect_chars_capped(
                tail.chars()
                    .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != '`'),
                caps::MAX_URL_LENGTH,
            );
            if url_truncated {
                facts.mark_partial(NativePartialReason::EmbeddedUrlLengthLimit);
            }
            if url.len() >= scheme.len() {
                if is_suspicious_url(&url) {
                    facts.has_suspicious_url = true;
                }
                record_embedded_url(facts, url, caps::MAX_URLS);
            }
        }
    }

    // A `PyInit_*` substring (the streaming-view path has no symbol table; harmless
    // on the buffered path where the real export is already recorded).
    for (pos, _) in s.match_indices("PyInit_") {
        if !take_budget_slot(&mut budget.string_token_occurrences_remaining) {
            facts.mark_partial(NativePartialReason::PrintableTokenOccurrenceLimit);
            break;
        }
        let (name, name_truncated) = collect_chars_capped(
            s[pos..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_'),
            caps::MAX_PYINIT_NAME_LENGTH,
        );
        if name_truncated {
            facts.mark_partial(NativePartialReason::PyInitNameLengthLimit);
        }
        if name.len() > "PyInit_".len() {
            record_py_init_export(facts, name, caps::MAX_SYMBOLS);
        }
    }

    // Sensitive-path substrings (a credential path is a corroborator on its own).
    // Like runtime names, this set's universe is a fixed table and needs no second
    // attacker-reachable storage cap.
    for needle in SENSITIVE_PATH_NEEDLES {
        if lower.contains(needle) {
            facts.sensitive_paths.insert((*needle).to_string());
        }
    }
}

/// Whether an embedded URL has a SUSPICIOUS shape: an IP-literal host, an explicit
/// non-standard port, or a raw-content host. A plain `https://docs.example/path` is
/// NOT suspicious (benign homepage/docs URLs are common in extensions). Best-effort
/// host parsing on the already-extracted URL string.
fn is_suspicious_url(url: &str) -> bool {
    // Strip the scheme and isolate the authority (host[:port]) up to the first `/`.
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Drop any userinfo.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Split host and port (IPv6 in brackets is treated as a host literal -> suspicious).
    if host_port.starts_with('[') {
        return true; // IPv6 literal host
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    // Non-standard explicit port (anything other than 80/443/21 for the schemes).
    if let Some(p) = port {
        if !p.is_empty() && !matches!(p, "80" | "443" | "21") {
            return true;
        }
    }
    // IPv4-literal host (all dot-separated components numeric).
    let is_ipv4 = !host.is_empty()
        && host.split('.').count() == 4
        && host
            .split('.')
            .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
    if is_ipv4 {
        return true;
    }
    // Raw-content / paste hosts often used for second-stage payloads.
    const RAW_HOSTS: &[&str] = &[
        "raw.githubusercontent.com",
        "pastebin.com",
        "paste.ee",
        "transfer.sh",
        "0x0.st",
        "ngrok.io",
        "ngrok-free.app",
    ];
    let host_l = host.to_ascii_lowercase();
    RAW_HOSTS
        .iter()
        .any(|h| host_l == *h || host_l.ends_with(&format!(".{h}")))
}

/// Retain every filename-like token in `s` ending in `ext`, and return whether at
/// least one valid reference existed. `lower` is `s` lowercased for the
/// case-insensitive extension match. Collection stays globally bounded through
/// [`record_sibling_reference`], while enumeration continues so a full set cannot
/// hide the co-located spawn signal.
fn collect_sibling_references(
    s: &str,
    lower: &str,
    ext: &str,
    facts: &mut NativeFacts,
    budget: &mut ExtractionBudget,
) -> bool {
    // `.js` is a PREFIX of `.json` (likewise `.py`/`.pyc`, `.sh`/`.sha256`,
    // `.bash`/`.bashrc`), so the FIRST occurrence of `ext` may sit inside a longer
    // extension whose boundary check fails - yet a LATER occurrence can be a real sibling.
    // Iterate EVERY occurrence; stopping after the first silently loses later
    // same-extension references in the same string.
    let mut found = false;
    for (pos, _) in lower.match_indices(ext) {
        if !take_budget_slot(&mut budget.string_token_occurrences_remaining) {
            facts.mark_partial(NativePartialReason::PrintableTokenOccurrenceLimit);
            break;
        }
        let end = pos + ext.len();
        // The character after the extension must be a path/word boundary (not another
        // identifier char), so `.js` does not fire inside `.jsonp`. `_` counts as a
        // continuation too: `addon.node_v8` is a `.node_v8` token, NOT a `.node` reference.
        let after_ok = end >= s.len()
            || !s
                .as_bytes()
                .get(end)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
        if !after_ok {
            continue;
        }
        // Walk backwards from `pos` to the start of the basename (a separator or quote).
        let bytes = s.as_bytes();
        let mut start = pos;
        while start > 0 {
            let b = bytes[start - 1];
            if b == b'/'
                || b == b'\\'
                || b == b'"'
                || b == b'\''
                || b == b'`'
                || b == b' '
                || b == b'='
            {
                break;
            }
            start -= 1;
        }
        let candidate = &s[start..end];
        // A bare extension with no stem (`.js`) is not a sibling reference.
        if candidate.len() <= ext.len() {
            continue;
        }
        found = true;
        if candidate.len() > caps::MAX_SIBLING_REF_LENGTH {
            facts.mark_partial(NativePartialReason::SiblingReferenceLengthLimit);
            continue;
        }
        record_sibling_reference(facts, candidate.to_string(), caps::MAX_SIBLING_REFS);
    }
    found
}

/// `true` if `haystack` contains `word` bounded on both sides by a non-identifier
/// character (mirrors `pth::contains_word`). `word` must be lowercase; `haystack`
/// is already lowercase. A `word` containing a `.` (e.g. `cmd.exe`) treats the `.`
/// as part of the token, with identifier-boundary checks at the ends only.
fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let wbytes = word.as_bytes();
    if wbytes.is_empty() || wbytes.len() > bytes.len() {
        return false;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while i + wbytes.len() <= bytes.len() {
        if &bytes[i..i + wbytes.len()] == wbytes {
            let before_ok = i == 0 || !is_ident(bytes[i - 1]);
            let after_idx = i + wbytes.len();
            let after_ok = after_idx >= bytes.len() || !is_ident(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ----------------------------------------------------------------------------
// Correlation
// ----------------------------------------------------------------------------

/// Correlate native facts into signals, edges, and AT MOST ONE finding.
///
/// A native module's mere presence yields at most an informational
/// [`ArtifactSignalKind::NativeExecutionEntry`]/etc signal; the Critical
/// [`RuleId::NativeImportExecutionChain`] fires ONLY on the full conjunction:
/// execution_entry AND danger_capability AND corroboration. `known_malicious`
/// satisfies the corroboration leg directly (the fourth corroborator).
fn correlate_native(
    facts: NativeFacts,
    location: &SubjectLocation,
    known_malicious: bool,
    unowned: bool,
) -> NativeTriage {
    let mut signals: Vec<ArtifactSignal> = Vec::new();
    let mut edges: Vec<ExecutionEdge> = Vec::new();

    let has_entry = facts.has_execution_entry();
    let has_capability = facts.has_danger_capability();
    let has_corroboration = facts.has_corroboration() || known_malicious || unowned;

    // Execution-entry signal (PyInit_* / constructor / mod-init / TLS-DllMain).
    // When there IS a real entry we emit the High-confidence entry signal; when
    // there is not, we still record a Low-confidence presence marker so a consumer
    // sees that a native module was inspected (mere presence is informational and
    // never, on its own, a finding). The two are mutually exclusive so the same
    // kind is never double-counted.
    if has_entry {
        signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::NativeExecutionEntry,
            location: location.clone(),
            evidence: execution_entry_evidence(&facts),
            confidence: EdgeConfidence::High,
        });
    } else {
        let fmt_label = facts.format.map(|f| f.label()).unwrap_or("unknown");
        let coverage_suffix = if facts.coverage == NativeCoverage::Partial {
            format!(", partial triage: {}", partial_reason_summary(&facts))
        } else {
            String::new()
        };
        signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::NativeExecutionEntry,
            location: location.clone(),
            evidence: format!(
                "native module present, no execution entry ({}{}{})",
                fmt_label,
                facts
                    .arch
                    .as_deref()
                    .map(|a| format!(", {a}"))
                    .unwrap_or_default(),
                coverage_suffix,
            ),
            // Presence alone is Low: it becomes meaningful only in the conjunction.
            confidence: EdgeConfidence::Low,
        });
    }

    // Danger-capability signal.
    if has_capability {
        signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::NativeDangerCapability,
            location: location.clone(),
            evidence: danger_capability_evidence(&facts),
            confidence: EdgeConfidence::Medium,
        });
    }

    // Corroboration signal.
    if has_corroboration {
        signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::NativeCorroboration,
            location: location.clone(),
            evidence: corroboration_evidence(&facts, known_malicious, unowned),
            confidence: EdgeConfidence::Medium,
        });
    }

    // The full conjunction trips the Critical finding plus an execution edge.
    let finding = if has_entry && has_capability && has_corroboration {
        edges.push(ExecutionEdge {
            from: location.clone(),
            trigger: ExecutionTrigger::NativeModuleInit,
            // The payload site: a named sibling reference when we have one, else the
            // module itself (the chain is internal: init -> capability).
            to: facts
                .sibling_refs
                .iter()
                .next()
                .map(|r| SubjectLocation::from_path(r.clone()))
                .unwrap_or_else(|| location.clone()),
            mechanism: edge_mechanism(&facts),
            confidence: EdgeConfidence::High,
        });
        Some(build_finding(&facts, location, known_malicious, unowned))
    } else {
        None
    };

    NativeTriage {
        facts,
        signals,
        edges,
        finding,
    }
}

/// Evidence text for the execution-entry signal.
fn execution_entry_evidence(facts: &NativeFacts) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !facts.py_init_exports.is_empty() {
        parts.push(format!(
            "Python init export(s): {}",
            joined(&facts.py_init_exports, 4)
        ));
    }
    if facts.has_elf_constructor {
        parts.push("ELF constructor (.init_array/.ctors)".to_string());
    }
    if facts.has_macho_mod_init {
        parts.push("Mach-O __mod_init_func".to_string());
    }
    if facts.has_pe_tls_or_dllmain {
        parts.push("PE TLS callback / DllMain".to_string());
    }
    format!("native execution entry: {}", parts.join("; "))
}

/// Evidence text for the danger-capability signal.
fn danger_capability_evidence(facts: &NativeFacts) -> String {
    let mut parts: Vec<String> = Vec::new();
    if facts.has_runtime_launch {
        parts.push(format!(
            "launches an external runtime ({})",
            joined(&facts.runtime_names, 4)
        ));
    }
    if facts.has_spawn_with_sibling {
        parts.push(format!(
            "spawns a sibling script/payload ({})",
            joined(&facts.sibling_refs, 4)
        ));
    }
    if !facts.spawn_imports.is_empty() {
        parts.push(format!(
            "process-spawn import(s) ({})",
            joined(&facts.spawn_imports, 4)
        ));
    }
    if !facts.dlopen_imports.is_empty() {
        parts.push(format!(
            "dynamic-loader import(s) ({})",
            joined(&facts.dlopen_imports, 4)
        ));
    }
    if facts.has_suspicious_url {
        parts.push(format!(
            "suspicious embedded URL ({})",
            joined(&facts.embedded_urls, 2)
        ));
    }
    format!("native danger capability: {}", parts.join("; "))
}

/// Evidence text for the corroboration signal. Lists only the corroborators that
/// actually fired (a co-located runtime launch, a co-located sibling spawn, a
/// sensitive path, or a known-malicious indicator), not bare mentions.
fn corroboration_evidence(facts: &NativeFacts, known_malicious: bool, unowned: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    if known_malicious {
        parts.push("known malicious indicator (hash match)".to_string());
    }
    // The unowned-module corroborator is NOT a hash match: its evidence must say so, or a
    // responder would search for a threat-DB hash lookup that never happened.
    if unowned {
        parts.push("native module not listed in any installed RECORD".to_string());
    }
    if facts.has_runtime_launch {
        parts.push(format!(
            "launches an external runtime ({})",
            joined(&facts.runtime_names, 4)
        ));
    }
    if facts.has_spawn_with_sibling {
        parts.push(format!(
            "spawns a sibling script/payload ({})",
            joined(&facts.sibling_refs, 4)
        ));
    }
    if !facts.sensitive_paths.is_empty() {
        parts.push(format!(
            "sensitive path ({})",
            joined(&facts.sensitive_paths, 4)
        ));
    }
    // The fourth has_corroboration path: a spawn/loader-import symbol alongside a runtime
    // name or sibling-payload reference carried as SEPARATE rodata strings (paths 1-2 cover
    // the co-located-in-one-string case). Without this branch that path yields an empty
    // evidence body, leaving a responder (or triage tooling) with "native chain
    // corroboration: " and nothing after the colon.
    if facts.has_spawn_or_loader_import()
        && !facts.has_runtime_launch
        && !facts.has_spawn_with_sibling
        && (!facts.runtime_names.is_empty() || !facts.sibling_refs.is_empty())
    {
        let mut bits: Vec<String> = Vec::new();
        if !facts.runtime_names.is_empty() {
            bits.push(format!("runtime {}", joined(&facts.runtime_names, 4)));
        }
        if !facts.sibling_refs.is_empty() {
            bits.push(format!(
                "sibling/payload {}",
                joined(&facts.sibling_refs, 4)
            ));
        }
        parts.push(format!(
            "spawn/loader import co-occurs with a {} string",
            bits.join(" and a ")
        ));
    }
    format!("native chain corroboration: {}", parts.join("; "))
}

/// The execution-edge mechanism description.
fn edge_mechanism(facts: &NativeFacts) -> String {
    let runtime = facts
        .runtime_names
        .iter()
        .next()
        .map(|r| format!("launches runtime '{r}'"))
        .unwrap_or_else(|| "executes capability".to_string());
    format!(
        "native module init {} on load (entry: {})",
        runtime,
        if !facts.py_init_exports.is_empty() {
            "PyInit_*"
        } else if facts.has_elf_constructor {
            ".init_array"
        } else if facts.has_macho_mod_init {
            "__mod_init_func"
        } else {
            "TLS/DllMain"
        }
    )
}

/// Build the Critical [`RuleId::NativeImportExecutionChain`] finding from the full
/// conjunction of facts.
fn build_finding(
    facts: &NativeFacts,
    location: &SubjectLocation,
    known_malicious: bool,
    unowned: bool,
) -> Finding {
    let mut evidence: Vec<Evidence> = Vec::new();
    evidence.push(Evidence::Text {
        detail: format!("native member: {location}"),
    });
    evidence.push(Evidence::Text {
        detail: execution_entry_evidence(facts),
    });
    evidence.push(Evidence::Text {
        detail: danger_capability_evidence(facts),
    });
    evidence.push(Evidence::Text {
        detail: corroboration_evidence(facts, known_malicious, unowned),
    });
    if facts.coverage == NativeCoverage::Partial {
        evidence.push(Evidence::Text {
            detail: format!(
                "triage was PARTIAL ({}); the chain was established from the available evidence",
                partial_reason_summary(facts)
            ),
        });
    }

    Finding {
        rule_id: RuleId::NativeImportExecutionChain,
        severity: Severity::Critical,
        title: "Native module import-execution chain".to_string(),
        description:
            "A bundled native module exposes a direct execution entry (a PyInit_* export, an \
             ELF constructor, a Mach-O module-init section, or a PE TLS callback / DllMain) AND a \
             danger capability (a process spawn, an external-runtime loader, a downloader/network \
             call, or dynamic code loading) AND corroboration (an external runtime name, a sibling \
             script/payload reference, a sensitive credential path, or a known-malicious \
             indicator). This is the native-import trigger the live supply-chain campaign uses to \
             hand execution from a compiled extension to a bundled payload at import time. The \
             rule keys on GENERIC relationships (any sibling script, any unrelated runtime), so \
             renaming the payload does not evade it. Inspect the module and reinstall the \
             distribution from a trusted source."
                .to_string(),
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: Some("T1129".to_string()),
        custom_rule_id: None,
    }
}

/// Render every retained partial-coverage reason for responder-facing evidence.
/// Manually constructed/default facts may have no reason; keep that state explicit
/// instead of inventing a parser failure.
fn partial_reason_summary(facts: &NativeFacts) -> String {
    if facts.partial_reasons.is_empty() {
        return "unspecified_incomplete_analysis".to_string();
    }
    facts
        .partial_reasons
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Join up to `n` items of a set with `, `, appending `…` if truncated.
fn joined(set: &BTreeSet<String>, n: usize) -> String {
    let mut out: Vec<&str> = set.iter().take(n).map(|s| s.as_str()).collect();
    if set.len() > n {
        out.push("…");
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::archive::NativeMemberHandoff;

    /// Build a buffered handoff over `bytes` at a synthetic member location.
    fn buffered(bytes: Vec<u8>) -> NativeMemberHandoff {
        let sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        NativeMemberHandoff::Buffered {
            location: SubjectLocation::member(
                "demo-1.0-cp311-cp311-linux_x86_64.whl",
                "demo/_core.so",
            ),
            bytes,
            sha256,
        }
    }

    /// Scan one standalone test string under a fresh member budget. Tests that
    /// exercise cross-string exhaustion use `scan_strings` directly with a shared
    /// budget instead.
    fn scan_test_string(s: &str, facts: &mut NativeFacts) {
        scan_one_string(s, facts, &mut ExtractionBudget::default());
    }

    // ------------------------------------------------------------------
    // Minimal ELF64 builder (hand-rolled so the tests pull NO write-side
    // dependency; `object`'s read parser accepts these and our extraction sees the
    // PyInit_* dynamic symbol, the .init_array constructor section, and the planted
    // .rodata capability strings).
    // ------------------------------------------------------------------

    /// A minimal ELF64 little-endian shared object (`ET_DYN`, `EM_X86_64`) with:
    /// a `.dynstr`/`.dynsym` exporting each name in `exports`; an `.init_array`
    /// section IFF `with_init_array`; and a `.rodata` holding `rodata` verbatim
    /// (where the capability strings live). Section-header driven (no program
    /// headers needed for `object`'s section/symbol reads).
    fn build_elf(exports: &[&str], with_init_array: bool, rodata: &[u8]) -> Vec<u8> {
        let symbols = exports.iter().map(|name| (*name, true)).collect::<Vec<_>>();
        build_elf_symbols(&symbols, with_init_array, rodata)
    }

    /// Variant of [`build_elf`] whose symbols can be defined exports (`true`) or
    /// undefined imports (`false`).
    fn build_elf_symbols(
        symbols: &[(&str, bool)],
        with_init_array: bool,
        rodata: &[u8],
    ) -> Vec<u8> {
        // ---- .dynstr: a NUL byte, then each symbol name NUL-terminated ----
        let mut dynstr: Vec<u8> = vec![0];
        let mut name_offsets: Vec<u32> = Vec::new();
        for (name, _) in symbols {
            name_offsets.push(dynstr.len() as u32);
            dynstr.extend_from_slice(name.as_bytes());
            dynstr.push(0);
        }

        // ---- .dynsym: a null symbol, then one GLOBAL FUNC per symbol ----
        // Elf64_Sym = { st_name u32, st_info u8, st_other u8, st_shndx u16,
        //               st_value u64, st_size u64 } = 24 bytes.
        let mut dynsym: Vec<u8> = vec![0u8; 24]; // index 0: null symbol
        for ((_, defined), off) in symbols.iter().zip(&name_offsets) {
            let mut sym = Vec::new();
            sym.extend_from_slice(&off.to_le_bytes()); // st_name
            sym.push(0x12); // st_info: STB_GLOBAL<<4 | STT_FUNC (1) = 0x12
            sym.push(0); // st_other
            let section = if *defined { 1u16 } else { 0u16 };
            sym.extend_from_slice(&section.to_le_bytes()); // SHN_UNDEF or a defined section
            let value = if *defined { 0x1000u64 } else { 0u64 };
            sym.extend_from_slice(&value.to_le_bytes()); // st_value
            sym.extend_from_slice(&0u64.to_le_bytes()); // st_size
            dynsym.extend_from_slice(&sym);
        }

        // ---- .init_array (8 bytes of a single relative pointer slot) ----
        let init_array: Vec<u8> = if with_init_array {
            0x1234u64.to_le_bytes().to_vec()
        } else {
            Vec::new()
        };

        // ---- .shstrtab: section-name string table ----
        // Order of sections (and their name offsets) is fixed below.
        let mut shstrtab: Vec<u8> = vec![0];
        let sh_name = |s: &str, tab: &mut Vec<u8>| -> u32 {
            let off = tab.len() as u32;
            tab.extend_from_slice(s.as_bytes());
            tab.push(0);
            off
        };
        let n_dynsym = sh_name(".dynsym", &mut shstrtab);
        let n_dynstr = sh_name(".dynstr", &mut shstrtab);
        let n_init = sh_name(".init_array", &mut shstrtab);
        let n_rodata = sh_name(".rodata", &mut shstrtab);
        let n_shstrtab = sh_name(".shstrtab", &mut shstrtab);

        // ---- Lay out section DATA after the 64-byte ELF header ----
        // Sections: [0]=NULL, [1]=.dynsym, [2]=.dynstr, [3]=.init_array (opt),
        //           [4]=.rodata, [5]=.shstrtab. We always emit .rodata + .shstrtab;
        //           .init_array is conditional but we keep a fixed index scheme by
        //           always reserving it (empty when absent) for simpler offsets.
        let ehsize = 64u64;
        let mut cursor = ehsize;
        let off_dynsym = cursor;
        cursor += dynsym.len() as u64;
        let off_dynstr = cursor;
        cursor += dynstr.len() as u64;
        let off_init = cursor;
        cursor += init_array.len() as u64;
        let off_rodata = cursor;
        cursor += rodata.len() as u64;
        let off_shstrtab = cursor;
        cursor += shstrtab.len() as u64;
        // Section header table starts here (align to 8).
        let shoff = (cursor + 7) & !7;

        // Number of sections: NULL + dynsym + dynstr + rodata + shstrtab (+ init).
        let mut sections: Vec<[u64; 8]> = Vec::new();
        // Each entry: [name, type, flags, addr, offset, size, link, entsize-or-info].
        // We pack into a helper-friendly tuple and serialize precisely below.
        // SHT_NULL
        sections.push([0, 0, 0, 0, 0, 0, 0, 0]);
        // .dynsym (SHT_DYNSYM = 11). link = index of .dynstr; info = first non-local
        // symbol index (1). entsize = 24.
        let dynstr_index_placeholder = 2u64;
        sections.push([
            n_dynsym as u64,
            11,
            0,
            0,
            off_dynsym,
            dynsym.len() as u64,
            dynstr_index_placeholder,
            24,
        ]);
        // .dynstr (SHT_STRTAB = 3).
        sections.push([
            n_dynstr as u64,
            3,
            0,
            0,
            off_dynstr,
            dynstr.len() as u64,
            0,
            0,
        ]);
        // .init_array (SHT_INIT_ARRAY = 14). Always present as a section; size 0
        // when the constructor is absent.
        sections.push([
            n_init as u64,
            14,
            0,
            0,
            off_init,
            init_array.len() as u64,
            0,
            8,
        ]);
        // .rodata (SHT_PROGBITS = 1).
        sections.push([
            n_rodata as u64,
            1,
            0,
            0,
            off_rodata,
            rodata.len() as u64,
            0,
            0,
        ]);
        // .shstrtab (SHT_STRTAB = 3).
        sections.push([
            n_shstrtab as u64,
            3,
            0,
            0,
            off_shstrtab,
            shstrtab.len() as u64,
            0,
            0,
        ]);
        let shstrndx = (sections.len() - 1) as u16;
        let shnum = sections.len() as u16;

        // ---- Assemble the file ----
        let mut buf: Vec<u8> = Vec::new();
        // e_ident
        buf.extend_from_slice(b"\x7fELF");
        buf.push(2); // EI_CLASS = ELFCLASS64
        buf.push(1); // EI_DATA = ELFDATA2LSB
        buf.push(1); // EI_VERSION
        buf.push(0); // EI_OSABI
        buf.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding
        buf.extend_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        buf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
        buf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff (none)
        buf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        buf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        buf.extend_from_slice(&(ehsize as u16).to_le_bytes()); // e_ehsize
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        buf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf.extend_from_slice(&shnum.to_le_bytes()); // e_shnum
        buf.extend_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx

        // Section data (in the order their offsets were assigned).
        debug_assert_eq!(buf.len() as u64, ehsize);
        buf.extend_from_slice(&dynsym);
        buf.extend_from_slice(&dynstr);
        buf.extend_from_slice(&init_array);
        buf.extend_from_slice(rodata);
        buf.extend_from_slice(&shstrtab);
        // Pad to shoff.
        while (buf.len() as u64) < shoff {
            buf.push(0);
        }
        // Section header table.
        for s in &sections {
            buf.extend_from_slice(&(s[0] as u32).to_le_bytes()); // sh_name
            buf.extend_from_slice(&(s[1] as u32).to_le_bytes()); // sh_type
            buf.extend_from_slice(&s[2].to_le_bytes()); // sh_flags
            buf.extend_from_slice(&s[3].to_le_bytes()); // sh_addr
            buf.extend_from_slice(&s[4].to_le_bytes()); // sh_offset
            buf.extend_from_slice(&s[5].to_le_bytes()); // sh_size
            buf.extend_from_slice(&(s[6] as u32).to_le_bytes()); // sh_link
            buf.extend_from_slice(&(s[7] as u32).to_le_bytes()); // sh_info (we reuse)
            buf.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
            buf.extend_from_slice(&s[7].to_le_bytes()); // sh_entsize
        }
        buf
    }

    // ------------------------------------------------------------------
    // Minimal thin Mach-O 64 + fat/universal wrapper builders (hand-rolled,
    // no write-side dependency). `object`'s read parser accepts these and our
    // extraction sees the `__DATA,__mod_init_func` module-init section.
    // ------------------------------------------------------------------

    /// A minimal little-endian 64-bit `MH_DYLIB` Mach-O carrying ONE
    /// `LC_SEGMENT_64` with a single non-empty `__DATA,__mod_init_func` section
    /// (the module-init pointer table). No symbol table and no `PyInit_*`, so the
    /// ONLY execution entry is the Mach-O module-init. Layout: the 32-byte header,
    /// one segment load command (72 bytes) + one section_64 (80 bytes), then the
    /// section's data appended after the load commands.
    fn build_macho_mod_init() -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xFEED_FACF;
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;
        const CPU_SUBTYPE_X86_64_ALL: u32 = 0x0000_0003;
        const MH_DYLIB: u32 = 0x6; // filetype
        const LC_SEGMENT_64: u32 = 0x19;

        // The init-pointer table data (one 8-byte pointer slot, non-empty so the
        // section RUNS code and counts as a constructor).
        let initdata: Vec<u8> = 0x1234u64.to_le_bytes().to_vec();

        let header_size = 32u32;
        let seg_cmd_size = 72u32; // segment_command_64 sans sections
        let sect_size = 80u32; // one section_64
        let sizeofcmds = seg_cmd_size + sect_size;
        // The section data lives immediately after the load commands.
        let data_off = header_size + sizeofcmds;

        let mut buf: Vec<u8> = Vec::new();
        // ---- mach_header_64 ----
        buf.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        buf.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        buf.extend_from_slice(&CPU_SUBTYPE_X86_64_ALL.to_le_bytes());
        buf.extend_from_slice(&MH_DYLIB.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        buf.extend_from_slice(&sizeofcmds.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // ---- LC_SEGMENT_64 ("__DATA") ----
        buf.extend_from_slice(&LC_SEGMENT_64.to_le_bytes()); // cmd
        buf.extend_from_slice(&sizeofcmds.to_le_bytes()); // cmdsize (seg + its sections)
        let mut segname = [0u8; 16];
        segname[.."__DATA".len()].copy_from_slice(b"__DATA");
        buf.extend_from_slice(&segname);
        buf.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        buf.extend_from_slice(&(initdata.len() as u64).to_le_bytes()); // vmsize
        buf.extend_from_slice(&(data_off as u64).to_le_bytes()); // fileoff
        buf.extend_from_slice(&(initdata.len() as u64).to_le_bytes()); // filesize
        buf.extend_from_slice(&7u32.to_le_bytes()); // maxprot (rwx)
        buf.extend_from_slice(&3u32.to_le_bytes()); // initprot (rw)
        buf.extend_from_slice(&1u32.to_le_bytes()); // nsects
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags

        // ---- section_64 ("__mod_init_func" in "__DATA") ----
        let mut sectname = [0u8; 16];
        sectname[.."__mod_init_func".len()].copy_from_slice(b"__mod_init_func");
        buf.extend_from_slice(&sectname);
        buf.extend_from_slice(&segname); // segname (same 16-byte field)
        buf.extend_from_slice(&0u64.to_le_bytes()); // addr
        buf.extend_from_slice(&(initdata.len() as u64).to_le_bytes()); // size
        buf.extend_from_slice(&data_off.to_le_bytes()); // offset (file)
        buf.extend_from_slice(&3u32.to_le_bytes()); // align (2^3)
        buf.extend_from_slice(&0u32.to_le_bytes()); // reloff
        buf.extend_from_slice(&0u32.to_le_bytes()); // nreloc
                                                    // S_MOD_INIT_FUNC_POINTERS = 0x9 (section type/attributes flags).
        buf.extend_from_slice(&0x9u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved3

        debug_assert_eq!(buf.len() as u32, data_off);
        // ---- section data ----
        buf.extend_from_slice(&initdata);
        buf
    }

    /// Wrap `slices` into a big-endian fat/universal Mach-O (`FAT_MAGIC`,
    /// `0xCAFEBABE`). The 8-byte fat header is followed by one `fat_arch` (20 bytes
    /// each) per slice, then each slice's bytes at its declared offset (page-aligned).
    fn build_fat_macho(slices: &[Vec<u8>]) -> Vec<u8> {
        const FAT_MAGIC: u32 = 0xCAFE_BABE;
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;
        const CPU_TYPE_ARM64: u32 = 0x0100_000C;
        const CPU_SUBTYPE_ALL: u32 = 0x0000_0003;
        let align: u32 = 0x4000; // 16 KiB, 2^14

        let header_len = 8u32 + 20u32 * slices.len() as u32;
        // Lay out each slice at a page-aligned offset after the header.
        let mut offsets: Vec<u32> = Vec::new();
        let mut cursor = (header_len + align - 1) & !(align - 1);
        for s in slices {
            offsets.push(cursor);
            cursor = (cursor + s.len() as u32 + align - 1) & !(align - 1);
        }
        let total = cursor as usize;

        let mut buf: Vec<u8> = Vec::with_capacity(total);
        // ---- fat_header (BIG-ENDIAN) ----
        buf.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        buf.extend_from_slice(&(slices.len() as u32).to_be_bytes());
        // ---- fat_arch[] (BIG-ENDIAN) ----
        let cputypes = [CPU_TYPE_X86_64, CPU_TYPE_ARM64];
        for (i, s) in slices.iter().enumerate() {
            buf.extend_from_slice(&cputypes[i % cputypes.len()].to_be_bytes()); // cputype
            buf.extend_from_slice(&CPU_SUBTYPE_ALL.to_be_bytes()); // cpusubtype
            buf.extend_from_slice(&offsets[i].to_be_bytes()); // offset
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes()); // size
            buf.extend_from_slice(&14u32.to_be_bytes()); // align (2^14)
        }
        // ---- slice payloads at their offsets ----
        buf.resize(total, 0);
        for (i, s) in slices.iter().enumerate() {
            let off = offsets[i] as usize;
            buf[off..off + s.len()].copy_from_slice(s);
        }
        buf
    }

    // ------------------------------------------------------------------
    // Extraction tests
    // ------------------------------------------------------------------

    #[test]
    fn elf_parses_and_extracts_pyinit_and_constructor() {
        let elf = build_elf(&["PyInit__core"], true, b"just some benign rodata\0");
        let facts = extract_from_buffer(&elf);
        assert_eq!(
            facts.format,
            Some(NativeFormat::Elf),
            "ELF magic recognized"
        );
        assert_eq!(
            facts.coverage,
            NativeCoverage::Full,
            "in-cap ELF parses fully"
        );
        assert_eq!(facts.arch.as_deref(), Some("x86-64"));
        assert!(
            facts.py_init_exports.iter().any(|s| s == "PyInit__core"),
            "PyInit_ export extracted from .dynsym, got {:?}",
            facts.py_init_exports
        );
        assert!(
            facts.has_elf_constructor,
            ".init_array constructor detected"
        );
        assert!(facts.has_execution_entry());
    }

    #[test]
    fn elf_import_cap_is_applied_before_name_allocation() {
        let names = (0..=caps::MAX_IMPORTS)
            .map(|index| format!("import_{index}"))
            .collect::<Vec<_>>();
        let symbols = names
            .iter()
            .map(|name| (name.as_str(), false))
            .collect::<Vec<_>>();
        let elf = build_elf_symbols(&symbols, false, b"benign\0");
        let facts = extract_from_buffer(&elf);

        assert_eq!(facts.imports.len(), caps::MAX_IMPORTS);
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::ImportTableLimit));
    }

    #[test]
    fn structured_import_and_pyinit_names_are_bounded_before_copy() {
        let oversized_import = "i".repeat(caps::MAX_IMPORT_NAME_LENGTH + 1);
        let oversized_pyinit = format!(
            "PyInit_{}",
            "p".repeat(caps::MAX_PYINIT_NAME_LENGTH + 1 - "PyInit_".len())
        );
        let symbols = [
            (oversized_import.as_str(), false),
            (oversized_pyinit.as_str(), true),
        ];
        let elf = build_elf_symbols(&symbols, false, b"benign\0");
        let facts = extract_from_buffer(&elf);

        assert!(facts.imports.is_empty());
        assert!(facts
            .py_init_exports
            .iter()
            .all(|name| name.len() <= caps::MAX_PYINIT_NAME_LENGTH));
        assert!(!facts.py_init_exports.contains(&oversized_pyinit));
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::ImportNameLengthLimit));
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::PyInitNameLengthLimit));
    }

    #[test]
    fn elf_without_init_array_has_no_constructor() {
        let elf = build_elf(&["PyInit__core"], false, b"\0");
        let facts = extract_from_buffer(&elf);
        // .init_array section present but EMPTY -> not a constructor.
        assert!(
            !facts.has_elf_constructor,
            "an empty .init_array must not count as a constructor"
        );
        // PyInit alone is still an execution entry.
        assert!(facts.has_execution_entry());
    }

    #[test]
    fn elf_rodata_capability_strings_are_extracted() {
        // The campaign pattern as it appears on disk: a SINGLE argv/command string
        // co-locating the spawn verb, the runtime, and the sibling payload
        // (`system("bun run ./payload/_index.js")`), plus a separate credential path
        // and a suspicious (IP-literal) URL. The co-occurrence is what makes the
        // danger/corroboration legs fire; bare separate tokens would not.
        let rodata = b"system(\"bun run ./payload/_index.js\")\0http://203.0.113.5:8080/c2\0/root/.aws/credentials\0";
        let elf = build_elf(&["PyInit_mod"], true, rodata);
        let facts = extract_from_buffer(&elf);
        assert!(
            facts.runtime_names.contains("bun"),
            "runtime token extracted"
        );
        assert!(
            facts.has_runtime_launch,
            "a spawn verb co-located with a runtime is a runtime launch"
        );
        assert!(
            facts.has_spawn_with_sibling,
            "a spawn verb co-located with a sibling script"
        );
        assert!(
            facts.has_suspicious_url,
            "an IP-literal host with a non-standard port is a suspicious URL"
        );
        assert!(
            facts.sensitive_paths.iter().any(|p| p.contains(".aws")),
            "sensitive path, got {:?}",
            facts.sensitive_paths
        );
        assert!(
            facts.sibling_refs.iter().any(|r| r.ends_with("_index.js")),
            "sibling script ref, got {:?}",
            facts.sibling_refs
        );
    }

    #[test]
    fn benign_libc_strings_and_homepage_url_are_not_danger() {
        // The false-positive case the review caught: an ordinary extension whose
        // rodata contains libc symbol STRINGS (socket/connect/dlopen) and a benign
        // homepage URL and a `.py` sibling, but with NO co-located spawn+runtime.
        // It must NOT register a danger capability or corroboration.
        let rodata =
            b"socket\0connect\0dlopen\0https://numpy.org/doc\0from . import _core  # _core.py\0";
        let elf = build_elf(&["PyInit__core"], true, rodata);
        let facts = extract_from_buffer(&elf);
        assert!(
            !facts.has_danger_capability(),
            "bare libc strings + a homepage URL are not a danger capability; got {facts:?}"
        );
        assert!(
            !facts.has_corroboration(),
            "a bare .py reference is not corroboration"
        );
        // And the full triage produces no Critical finding.
        let triage = triage_native(&buffered(elf), false, false);
        assert!(triage.finding.is_none());
    }

    #[test]
    fn spawn_and_dlopen_imports_are_danger() {
        // When the spawn/loader APIs are real IMPORTS (undefined symbols), that IS a
        // danger capability (the module actually calls them), distinct from a string.
        let mut facts = NativeFacts::default();
        classify_capability_import("posix_spawn", &mut facts);
        classify_capability_import("dlopen", &mut facts);
        classify_capability_import("execve@glibc_2.2.5", &mut facts);
        assert!(facts.spawn_imports.contains("posix_spawn"));
        assert!(
            facts.spawn_imports.contains("execve"),
            "decorated import matches"
        );
        assert!(facts.dlopen_imports.contains("dlopen"));
        assert!(facts.has_danger_capability());
    }

    #[test]
    fn spawn_import_with_separate_argv_strings_corroborates() {
        // EVASION CLOSURE: a malicious .so that IMPORTS posix_spawn (so the spawn
        // verb is NOT a rodata string) and carries the runtime name and payload path
        // as SEPARATE argv strings (`"bun"`, `"run"`, `"./_x.js"`) must still
        // correlate: the import is the proof it spawns, the bare name/ref says what.
        let mut facts = NativeFacts {
            format: Some(NativeFormat::Elf),
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        facts.py_init_exports.insert("PyInit_evil".to_string());
        classify_capability_import("posix_spawn", &mut facts); // a real import
        facts.runtime_names.insert("bun".to_string()); // a SEPARATE rodata string
        facts.sibling_refs.insert("_x.js".to_string()); // another separate string
                                                        // No co-located runtime-launch string, no sensitive path.
        assert!(!facts.has_runtime_launch);
        assert!(!facts.has_spawn_with_sibling);
        assert!(facts.has_spawn_or_loader_import());
        assert!(
            facts.has_corroboration(),
            "a real spawn import + a bare runtime/sibling is corroboration"
        );
        // The corroboration evidence must NOT be empty for this 4th-path-only scenario
        // (regression: it produced "native chain corroboration: " with nothing after).
        let evidence = corroboration_evidence(&facts, false, false);
        assert!(
            evidence.len() > "native chain corroboration: ".len(),
            "the spawn-import + separate-string path must produce non-empty evidence, got {evidence:?}"
        );
        let triage = correlate_native(
            facts,
            &SubjectLocation::member("a.whl", "m.so"),
            false,
            false,
        );
        assert!(
            triage.finding.is_some(),
            "the import-based chain must trip Critical"
        );
    }

    #[test]
    fn benign_extension_with_py_siblings_and_no_spawn_import_is_clean() {
        // The contrast: the SAME bare runtime/sibling strings but WITHOUT a spawn or
        // loader import (an ordinary extension) must NOT corroborate.
        let mut facts = NativeFacts {
            format: Some(NativeFormat::Elf),
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        facts.py_init_exports.insert("PyInit__core".to_string());
        facts.sibling_refs.insert("helper.py".to_string());
        facts.runtime_names.insert("node".to_string()); // e.g. a comment mentioning node
        assert!(!facts.has_spawn_or_loader_import());
        assert!(
            !facts.has_corroboration(),
            "bare runtime/sibling without a spawn import is not corroboration"
        );
        assert!(!facts.has_danger_capability());
        let triage = correlate_native(
            facts,
            &SubjectLocation::member("a.whl", "m.so"),
            false,
            false,
        );
        assert!(triage.finding.is_none());
    }

    /// The English word "system" co-located with a `.py` sibling in one benign error
    /// string must NOT fire the spawn-with-sibling leg ("system" is only a spawn
    /// signal as an IMPORTED symbol, not as a string word).
    #[test]
    fn benign_extension_system_error_string_with_py_sibling_is_clean() {
        let mut facts = NativeFacts::default();
        scan_test_string("system error: cannot find helper.py", &mut facts);
        assert!(
            !facts.has_spawn_with_sibling,
            "the English word 'system' must not count as a string spawn verb"
        );
    }

    /// A benign leading URL must not mask a suspicious URL later in the SAME string:
    /// every scheme occurrence is scanned, not just the first.
    #[test]
    fn second_suspicious_url_in_one_string_sets_flag() {
        let mut facts = NativeFacts::default();
        scan_test_string(
            "http://docs.example.org/ https://198.51.100.1:4444/stage2",
            &mut facts,
        );
        assert!(
            facts.has_suspicious_url,
            "the suspicious second URL must be detected"
        );
    }

    #[test]
    fn suspicious_url_shapes() {
        assert!(
            is_suspicious_url("http://203.0.113.5/x"),
            "IPv4 literal host"
        );
        assert!(is_suspicious_url("https://evil.example:8443/x"), "odd port");
        assert!(
            is_suspicious_url("https://raw.githubusercontent.com/a/b/c"),
            "raw-content host"
        );
        assert!(
            is_suspicious_url("http://[2001:db8::1]/x"),
            "IPv6 literal host"
        );
        // Benign shapes are NOT suspicious.
        assert!(!is_suspicious_url("https://numpy.org/doc"));
        assert!(
            !is_suspicious_url("https://example.com:443/x"),
            "standard port"
        );
        assert!(!is_suspicious_url("http://docs.python.org/3/"));
    }

    #[test]
    fn magic_classifier_recognizes_each_format() {
        let mut pe = vec![0u8; 0x58];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x40u32).to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");

        assert_eq!(classify_magic(b"\x7fELFrest"), NativeFormat::Elf);
        assert_eq!(
            classify_magic(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0]),
            NativeFormat::MachOFat
        );
        assert_eq!(
            classify_magic(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0]),
            NativeFormat::MachO
        );
        assert_eq!(
            classify_magic(&[0xFE, 0xED, 0xFA, 0xCE, 0, 0]),
            NativeFormat::MachO
        );
        assert_eq!(classify_magic(&pe), NativeFormat::Pe);
        assert_eq!(classify_magic(b"MZ\x90\x00"), NativeFormat::Unknown);

        let mut malformed_signature = pe.clone();
        malformed_signature[0x40..0x44].copy_from_slice(b"PX\0\0");
        assert_eq!(classify_magic(&malformed_signature), NativeFormat::Unknown);

        let mut out_of_bounds = vec![0u8; 0x40];
        out_of_bounds[..2].copy_from_slice(b"MZ");
        out_of_bounds[0x3c..0x40].copy_from_slice(&(0x100u32).to_le_bytes());
        assert_eq!(classify_magic(&out_of_bounds), NativeFormat::Unknown);
        assert_eq!(classify_magic(b"not-an-object"), NativeFormat::Unknown);
        assert_eq!(classify_magic(b""), NativeFormat::Unknown);
        assert_eq!(classify_magic(b"M"), NativeFormat::Unknown);
    }

    // ------------------------------------------------------------------
    // Never-panic / malformed corpus
    // ------------------------------------------------------------------

    #[test]
    fn triage_never_panics_on_malformed_corpus() {
        // A deterministic corpus of adversarial inputs: truncated headers, claimed
        // ELF/Mach-O/PE magics over garbage, all-zero, and a truncation of a real
        // ELF at every length.
        let real = build_elf(&["PyInit_x"], true, b"execve\0bun\0https://x.example/\0");
        let mut corpus: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0u8; 1],
            vec![0u8; 64],
            b"\x7fELF".to_vec(),
            b"\x7fELF\x02\x01\x01".to_vec(),
            [0xCA, 0xFE, 0xBA, 0xBE].to_vec(),
            [0xCA, 0xFE, 0xBA, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF].to_vec(),
            b"MZ".to_vec(),
            b"MZ\x90\x00\x03\x00\x00\x00".to_vec(),
            vec![0xFFu8; 4096],
        ];
        // Truncate the real ELF at every length (header/section-table boundaries).
        for len in 0..real.len() {
            corpus.push(real[..len].to_vec());
        }
        // A pseudo-random byte sweep (deterministic LCG, no rng dependency).
        let mut state: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..2000 {
            let n = (state % 8192) as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                v.push((state >> 33) as u8);
            }
            corpus.push(v);
        }

        for (i, bytes) in corpus.iter().enumerate() {
            // The whole pipeline (extract + correlate) must not panic. We also flip
            // the known-malicious corroborator to exercise both correlation branches.
            let h = buffered(bytes.clone());
            let _ = triage_native(&h, false, false);
            let _ = triage_native(&h, true, true);
            // Exercise the streaming path too (header window + arbitrary strings).
            let stream = NativeMemberHandoff::Streaming {
                location: SubjectLocation::member("a.whl", "m.so"),
                sha256: "0".repeat(64),
                size: bytes.len() as u64,
                header_window: bytes.clone(),
                printable_strings: vec!["bun".into(), "execve".into(), format!("blob{i}")],
            };
            let _ = triage_native(&stream, false, false);
        }
    }

    // ------------------------------------------------------------------
    // Correlation matrix
    // ------------------------------------------------------------------

    /// Helper: triage an ELF with the given exports / constructor / rodata and
    /// return whether a Critical chain finding fired.
    fn fires_chain(
        exports: &[&str],
        init_array: bool,
        rodata: &[u8],
        known_malicious: bool,
    ) -> bool {
        let elf = build_elf(exports, init_array, rodata);
        let triage = triage_native(&buffered(elf), known_malicious, false);
        triage
            .finding
            .as_ref()
            .map(|f| {
                f.rule_id == RuleId::NativeImportExecutionChain && f.severity == Severity::Critical
            })
            .unwrap_or(false)
    }

    #[test]
    fn full_conjunction_trips_critical() {
        // execution_entry (PyInit_) + a single string that LAUNCHES a runtime against
        // a sibling payload (danger AND corroboration in one co-located string).
        assert!(
            fires_chain(
                &["PyInit_mod"],
                true,
                b"system(\"bun run ./loader/_index.js\")\0",
                false
            ),
            "PyInit + a co-located runtime launch must trip Critical"
        );
    }

    #[test]
    fn near_miss_no_execution_entry_stays_informational() {
        // Danger + corroboration (a runtime launch) but NO execution entry.
        let elf = build_elf(&[], false, b"system(\"bun run ./loader/_index.js\")\0");
        let triage = triage_native(&buffered(elf), false, false);
        assert!(
            triage.finding.is_none(),
            "no execution entry -> no Critical (stays informational signals)"
        );
        // The presence signal is still recorded (informational, never a finding).
        assert!(triage
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::NativeExecutionEntry));
    }

    #[test]
    fn near_miss_no_danger_capability_stays_informational() {
        // PyInit + constructor but NO danger capability and NO corroboration: a
        // NumPy/SciPy-shaped extension. MUST NOT trip Critical.
        assert!(
            !fires_chain(
                &["PyInit__core"],
                true,
                b"numpy.core.multiarray\0_ARRAY_API\0",
                false
            ),
            "a NumPy-shaped .so (PyInit + constructor, no danger) must not trip Critical"
        );
    }

    #[test]
    fn near_miss_no_corroboration_stays_informational() {
        // PyInit + a danger capability (a SUSPICIOUS url, which is danger but NOT
        // corroboration) and nothing else. MUST NOT trip Critical.
        let rodata = b"https://203.0.113.9:9000/beacon\0";
        let elf = build_elf(&["PyInit_mod"], true, rodata);
        let facts = extract_from_buffer(&elf);
        assert!(facts.has_danger_capability(), "a suspicious URL is danger");
        assert!(!facts.has_corroboration(), "but it is not corroboration");
        let triage = triage_native(&buffered(elf), false, false);
        assert!(
            triage.finding.is_none(),
            "execution entry + danger but no corroboration must not trip Critical"
        );
    }

    #[test]
    fn known_malicious_indicator_satisfies_corroboration() {
        // PyInit + danger (suspicious URL) + NO string corroboration, but the caller
        // passes known_malicious=true (a hash match). That satisfies corroboration.
        let rodata = b"https://203.0.113.9:9000/beacon\0";
        assert!(
            fires_chain(&["PyInit_mod"], true, rodata, true),
            "a known-malicious hash satisfies the corroboration leg"
        );
        // And without it, the same binary does NOT fire (proving the leg is real).
        assert!(!fires_chain(&["PyInit_mod"], true, rodata, false));
    }

    #[test]
    fn numpy_shaped_so_is_clean() {
        // A more complete NumPy-shaped control: PyInit, constructor, BLAS-ish
        // imports/strings, but nothing dangerous.
        let rodata = b"PyInit__multiarray_umath\0cblas_dgemm\0numpy.linalg\0_ARRAY_API\0";
        let elf = build_elf(&["PyInit__multiarray_umath"], true, rodata);
        let triage = triage_native(&buffered(elf), false, false);
        assert!(
            triage.finding.is_none(),
            "NumPy-shaped .so must produce no Critical finding, signals only"
        );
        assert!(
            !triage.facts.has_danger_capability(),
            "no danger capability in a numerical extension"
        );
    }

    #[test]
    fn renaming_payload_does_not_evade() {
        // The relationship is generic: ANY runtime launched against ANY sibling
        // script qualifies, so renaming the payload (or swapping bun->node) does not
        // evade. The rule keys on the spawn+runtime co-occurrence, not the filename.
        assert!(
            fires_chain(
                &["PyInit_mod"],
                true,
                b"execvp(\"node\", \"./assets/totally-innocent-name.js\")\0",
                false
            ),
            "a renamed sibling script launched via a runtime must still trip"
        );
    }

    // ------------------------------------------------------------------
    // Above-cap streaming path
    // ------------------------------------------------------------------

    #[test]
    fn streaming_path_is_partial() {
        // The above-cap streaming handoff: header window (ELF magic) + collected
        // strings. Triage must be Partial and still extract capability strings.
        let header = build_elf(&["PyInit_x"], true, b"\0"); // a real ELF prefix
        let stream = NativeMemberHandoff::Streaming {
            location: SubjectLocation::member("big.whl", "huge/_ext.so"),
            sha256: "a".repeat(64),
            size: 200 * 1024 * 1024,
            header_window: header,
            printable_strings: vec![
                "PyInit_x".into(),
                // The campaign launch string as one collected run (spawn + runtime +
                // sibling co-located), so the chain reconstructs even on the
                // streaming path.
                "system(\"bun run ./loader/_index.js\")".into(),
            ],
        };
        let triage = triage_native(&stream, false, false);
        assert_eq!(triage.facts.coverage, NativeCoverage::Partial);
        assert!(triage
            .facts
            .partial_reasons
            .contains(&NativePartialReason::StreamingView));
        assert_eq!(
            triage.facts.format,
            Some(NativeFormat::Elf),
            "magic from header window"
        );
        // The PyInit string + the co-located runtime launch reconstruct the chain
        // even on the streaming path (a weaker but still-present inference).
        assert!(triage.facts.py_init_exports.iter().any(|s| s == "PyInit_x"));
        assert!(triage.facts.has_runtime_launch);
        assert!(triage.facts.runtime_names.contains("bun"));
        assert!(
            triage.finding.is_some(),
            "the streaming chain still correlates"
        );
    }

    #[test]
    fn presence_only_yields_no_finding() {
        // A bare module with no entry, no capability, no corroboration: only the
        // informational presence signal, never a finding.
        let elf = build_elf(&[], false, b"plain data section\0");
        let triage = triage_native(&buffered(elf), false, false);
        assert!(triage.finding.is_none());
        assert!(
            triage
                .signals
                .iter()
                .all(|s| s.confidence == EdgeConfidence::Low
                    || s.kind == ArtifactSignalKind::NativeExecutionEntry),
            "presence-only emits low-confidence informational signals"
        );
    }

    #[test]
    fn word_boundary_avoids_substring_false_positive() {
        // `node` must not fire inside `nodeenv`; `bun` must not fire inside `bunny`.
        let elf = build_elf(&["PyInit_x"], true, b"posix_spawn\0nodeenv\0bunny_data\0");
        let facts = extract_from_buffer(&elf);
        assert!(
            !facts.runtime_names.contains("node"),
            "'node' must not match inside 'nodeenv'"
        );
        assert!(
            !facts.runtime_names.contains("bun"),
            "'bun' must not match inside 'bunny_data'"
        );
    }

    #[test]
    fn sibling_extension_word_boundary() {
        // `.js` must not fire inside `.jsonp`; a real `.js` reference must.
        let mut facts = NativeFacts::default();
        scan_test_string("config.jsonp", &mut facts);
        assert!(
            facts.sibling_refs.is_empty(),
            "'.js' must not match in '.jsonp'"
        );
        let mut facts2 = NativeFacts::default();
        scan_test_string("./a/run.js", &mut facts2);
        assert!(facts2.sibling_refs.iter().any(|r| r.ends_with("run.js")));
        // `_` is a token continuation: `addon.node_v8` is a `.node_v8` name, NOT a `.node`
        // sibling reference, so it must not fire.
        let mut facts3 = NativeFacts::default();
        scan_test_string("dlopen(\"addon.node_v8\")", &mut facts3);
        assert!(
            facts3.sibling_refs.is_empty(),
            "'.node' must not match in '.node_v8': {:?}",
            facts3.sibling_refs
        );
    }

    #[test]
    fn sibling_reference_skips_prefix_extension_to_later_match() {
        // `.js` is a PREFIX of `.json`: a string with `.json` BEFORE a real `.js` must still
        // detect the later `.js` sibling. The old `find` stopped at the `.json` occurrence
        // (its boundary check failed) and silently dropped the real reference, leaving the
        // spawn+sibling chain undetected.
        let mut facts = NativeFacts::default();
        scan_test_string("system(\"./config.json ./payload.js\")", &mut facts);
        assert!(
            facts.sibling_refs.iter().any(|r| r.ends_with("payload.js")),
            "the real ./payload.js sibling must be found past the .json occurrence; got {:?}",
            facts.sibling_refs
        );
    }

    #[test]
    fn every_same_extension_sibling_in_one_string_is_retained() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string("execve(\"first.js second.js\")", &mut facts);

        assert_eq!(
            facts.sibling_refs,
            BTreeSet::from(["first.js".to_string(), "second.js".to_string()]),
            "same-extension references must not be silently limited to the first match"
        );
        assert!(facts.has_spawn_with_sibling);
        assert_eq!(facts.coverage, NativeCoverage::Full);
    }

    // ------------------------------------------------------------------
    // A4 -> B7 wheel native-handoff contract
    // ------------------------------------------------------------------

    #[test]
    fn wheel_native_handoff_triages_to_chain() {
        // The full A4 -> B7 contract: a wheel carries a malicious native member;
        // the archive reader streams it into a Buffered handoff; B7 triages that
        // handoff and the chain fires. This exercises the contract B8 will drive
        // from the CLI without B7 owning the wheel-open path.
        use crate::artifact::archive::{read_wheel, ArchiveLimits, CollectingVisitor};
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        // A malicious .so (PyInit + constructor + a co-located runtime-launch string).
        let so = build_elf(
            &["PyInit_evil"],
            true,
            b"system(\"bun run ./loader/_index.js\")\0",
        );

        // Pack it into a minimal wheel.
        let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
        zw.start_file("evil/_ext.so", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(&so).unwrap();
        zw.start_file("evil-1.0.dist-info/METADATA", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n\n")
            .unwrap();
        let wheel = zw.finish().unwrap().into_inner();

        // Read the wheel, collecting native handoffs.
        let sha: String = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&wheel))
        };
        let mut visitor = CollectingVisitor::default();
        let _ = read_wheel(
            Cursor::new(wheel),
            "evil-1.0-cp311-cp311-linux_x86_64.whl",
            &sha,
            &ArchiveLimits::default(),
            &mut visitor,
        );

        assert_eq!(visitor.native.len(), 1, "the .so member is handed off");
        let handoff = &visitor.native[0];
        // It is buffered (well under the native-parse cap) with full bytes.
        assert!(
            matches!(handoff, NativeMemberHandoff::Buffered { .. }),
            "an in-cap native member is buffered"
        );

        // Triage the handoff: the chain must fire.
        let triage = triage_native(handoff, false, false);
        assert_eq!(triage.facts.coverage, NativeCoverage::Full);
        assert!(
            triage
                .facts
                .py_init_exports
                .iter()
                .any(|s| s == "PyInit_evil"),
            "PyInit export survived the wheel round-trip"
        );
        let finding = triage
            .finding
            .as_ref()
            .expect("the wheel's malicious .so must trip the chain");
        assert_eq!(finding.rule_id, RuleId::NativeImportExecutionChain);
        assert_eq!(finding.severity, Severity::Critical);
        // The member location renders as `foo.whl!/member`.
        assert!(
            handoff.location().to_string().contains(".whl!/"),
            "the handoff carries the archive-member location: {}",
            handoff.location()
        );
    }

    // ------------------------------------------------------------------
    // Fat/universal Mach-O slice extraction (T2.5)
    // ------------------------------------------------------------------

    #[test]
    fn thin_macho_mod_init_func_sets_execution_entry() {
        // A single thin Mach-O whose only constructor is `__mod_init_func` (no
        // PyInit_*) sets has_macho_mod_init: the per-object format keys the section
        // match, so the Mach-O arm fires.
        let macho = build_macho_mod_init();
        let facts = extract_from_buffer(&macho);
        assert_eq!(
            facts.format,
            Some(NativeFormat::MachO),
            "thin Mach-O recognized"
        );
        assert!(
            facts.has_macho_mod_init,
            "__mod_init_func detected on a thin Mach-O, got {facts:?}"
        );
        assert!(facts.has_execution_entry());
    }

    #[test]
    fn fat_macho_mod_init_func_slice_sets_execution_entry() {
        // A 2-slice fat/universal Mach-O whose only constructor is `__mod_init_func`
        // (no PyInit_*). Before the fix the section-presence match keyed on
        // `facts.format` (which is MachOFat for the container), so the MachO arm
        // never matched a slice and has_execution_entry stayed false. Deriving the
        // format from each parsed SLICE fixes it.
        let slice = build_macho_mod_init();
        let fat = build_fat_macho(&[slice.clone(), slice]);
        assert_eq!(
            classify_magic(&fat),
            NativeFormat::MachOFat,
            "fat magic recognized"
        );
        let facts = extract_from_buffer(&fat);
        assert_eq!(
            facts.format,
            Some(NativeFormat::MachOFat),
            "the container is fat Mach-O"
        );
        assert!(
            facts.has_macho_mod_init,
            "__mod_init_func inside a fat slice must set the Mach-O module-init entry; got {facts:?}"
        );
        assert!(
            facts.has_execution_entry(),
            "a fat Mach-O whose only constructor is __mod_init_func has an execution entry"
        );
    }

    #[test]
    fn fat_macho_stops_when_member_wide_structured_budgets_are_exhausted() {
        let slice = build_macho_mod_init();
        let fat = build_fat_macho(&[slice.clone(), slice]);
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            format: Some(NativeFormat::MachOFat),
            ..NativeFacts::default()
        };
        let mut budget = ExtractionBudget {
            imports_remaining: 0,
            import_descriptors_remaining: 0,
            symbols_remaining: 0,
            dynamic_symbols_remaining: 0,
            sections_remaining: 0,
            ..ExtractionBudget::default()
        };

        assert!(parse_fat_macho(&fat, &mut facts, &mut budget));
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::FatTraversalBudgetExhausted));
    }

    // ------------------------------------------------------------------
    // Coverage fails closed (T3.19)
    // ------------------------------------------------------------------

    #[test]
    fn native_facts_default_is_partial_not_full() {
        // A coverage enum must fail closed: a freshly-defaulted facts value reports
        // PARTIAL coverage, never Full, so a value that skips the full-parse path
        // cannot silently claim it was completely triaged.
        assert_eq!(NativeCoverage::default(), NativeCoverage::Partial);
        assert_eq!(NativeFacts::default().coverage, NativeCoverage::Partial);
    }

    #[test]
    fn printable_run_cap_edge_marks_only_truncated_run_partial() {
        let mut at_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut at_cap_budget = ExtractionBudget::default();
        scan_bytes_strings(
            &vec![b'A'; caps::MAX_PRINTABLE_RUN_BYTES],
            &mut at_cap,
            &mut at_cap_budget,
        );
        assert_eq!(
            at_cap.coverage,
            NativeCoverage::Full,
            "a run exactly at the cap was fully inspected"
        );
        assert!(at_cap.partial_reasons.is_empty());

        let mut over_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut over_cap_budget = ExtractionBudget::default();
        scan_bytes_strings(
            &vec![b'A'; caps::MAX_PRINTABLE_RUN_BYTES + 1],
            &mut over_cap,
            &mut over_cap_budget,
        );
        assert_eq!(
            over_cap.coverage,
            NativeCoverage::Partial,
            "a single hidden byte beyond the retained run must downgrade coverage"
        );
        assert!(over_cap
            .partial_reasons
            .contains(&NativePartialReason::PrintableRunByteLimit));
    }

    #[test]
    fn printable_string_count_cap_edge_is_reported() {
        fn strings(count: usize) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(count * 5);
            for _ in 0..count {
                bytes.extend_from_slice(b"ABCD\0");
            }
            bytes
        }

        let mut at_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut at_cap_budget = ExtractionBudget::default();
        scan_bytes_strings(
            &strings(caps::MAX_STRINGS_SCANNED),
            &mut at_cap,
            &mut at_cap_budget,
        );
        assert_eq!(at_cap.coverage, NativeCoverage::Full);
        assert!(at_cap.partial_reasons.is_empty());

        let mut over_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut over_cap_budget = ExtractionBudget::default();
        scan_bytes_strings(
            &strings(caps::MAX_STRINGS_SCANNED + 1),
            &mut over_cap,
            &mut over_cap_budget,
        );
        assert_eq!(over_cap.coverage, NativeCoverage::Partial);
        assert!(over_cap
            .partial_reasons
            .contains(&NativePartialReason::PrintableStringCountLimit));
    }

    #[test]
    fn extracted_string_cap_peeks_and_is_member_scoped() {
        let mut at_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut at_cap_budget = ExtractionBudget::default();
        scan_strings(
            std::iter::repeat_n("ABCD", caps::MAX_STRINGS_SCANNED),
            &mut at_cap,
            &mut at_cap_budget,
        );
        assert_eq!(at_cap.coverage, NativeCoverage::Full);
        assert!(at_cap.partial_reasons.is_empty());

        let mut over_cap = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut over_cap_budget = ExtractionBudget::default();
        scan_strings(
            std::iter::repeat_n("ABCD", caps::MAX_STRINGS_SCANNED + 1),
            &mut over_cap,
            &mut over_cap_budget,
        );
        assert_eq!(over_cap.coverage, NativeCoverage::Partial);
        assert!(over_cap
            .partial_reasons
            .contains(&NativePartialReason::PrintableStringCountLimit));

        // Reusing the same extraction budget across calls models multiple fat
        // slices/helpers: exact aggregate exhaustion is complete, but one actual
        // item in a later call proves the member-wide cap was exceeded.
        let mut split = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        let mut split_budget = ExtractionBudget::default();
        let first = caps::MAX_STRINGS_SCANNED / 2;
        scan_strings(
            std::iter::repeat_n("ABCD", first),
            &mut split,
            &mut split_budget,
        );
        scan_strings(
            std::iter::repeat_n("EFGH", caps::MAX_STRINGS_SCANNED - first),
            &mut split,
            &mut split_budget,
        );
        assert_eq!(split.coverage, NativeCoverage::Full);
        scan_strings(std::iter::once("IJKL"), &mut split, &mut split_budget);
        assert_eq!(split.coverage, NativeCoverage::Partial);
        assert!(split
            .partial_reasons
            .contains(&NativePartialReason::PrintableStringCountLimit));
    }

    #[test]
    fn sibling_reference_cap_marks_only_distinct_cap_plus_one() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        for i in 0..caps::MAX_SIBLING_REFS {
            record_sibling_reference(&mut facts, format!("payload{i}.js"), caps::MAX_SIBLING_REFS);
        }
        assert_eq!(facts.sibling_refs.len(), caps::MAX_SIBLING_REFS);
        assert_eq!(facts.coverage, NativeCoverage::Full);

        // A duplicate at capacity does not mean any evidence was lost.
        record_sibling_reference(
            &mut facts,
            "payload0.js".to_string(),
            caps::MAX_SIBLING_REFS,
        );
        assert_eq!(facts.coverage, NativeCoverage::Full);

        // A distinct overflow is omitted, explained, and cannot suppress the
        // co-located spawn boolean for a late malicious reference.
        scan_test_string("execve(\"late-stage.js\")", &mut facts);
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::SiblingReferenceLimit));
        assert!(facts.has_spawn_with_sibling);
    }

    #[test]
    fn embedded_url_cap_marks_only_distinct_cap_plus_one() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        for i in 0..caps::MAX_URLS {
            record_embedded_url(
                &mut facts,
                format!("https://example.com/{i}"),
                caps::MAX_URLS,
            );
        }
        assert_eq!(facts.embedded_urls.len(), caps::MAX_URLS);
        assert_eq!(facts.coverage, NativeCoverage::Full);

        record_embedded_url(
            &mut facts,
            "https://example.com/0".to_string(),
            caps::MAX_URLS,
        );
        assert_eq!(facts.coverage, NativeCoverage::Full);

        scan_test_string("https://198.51.100.1:4444/stage", &mut facts);
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::EmbeddedUrlLimit));
        assert!(
            facts.has_suspicious_url,
            "a URL beyond the retention cap must still set derived danger facts"
        );
    }

    #[test]
    fn py_init_export_cap_marks_only_distinct_cap_plus_one() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        for i in 0..caps::MAX_SYMBOLS {
            record_py_init_export(&mut facts, format!("PyInit_mod{i}"), caps::MAX_SYMBOLS);
        }
        assert_eq!(facts.py_init_exports.len(), caps::MAX_SYMBOLS);
        assert_eq!(facts.coverage, NativeCoverage::Full);

        record_py_init_export(&mut facts, "PyInit_mod0".to_string(), caps::MAX_SYMBOLS);
        assert_eq!(facts.coverage, NativeCoverage::Full);

        record_py_init_export(
            &mut facts,
            "PyInit_actual_overflow".to_string(),
            caps::MAX_SYMBOLS,
        );
        assert_eq!(facts.coverage, NativeCoverage::Partial);
        assert!(facts
            .partial_reasons
            .contains(&NativePartialReason::PyInitExportLimit));
    }

    #[test]
    fn url_and_py_init_length_caps_distinguish_exact_from_plus_one() {
        let exact_url = format!(
            "https://{}",
            "a".repeat(caps::MAX_URL_LENGTH - "https://".len())
        );
        let mut exact_url_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&exact_url, &mut exact_url_facts);
        assert_eq!(exact_url.chars().count(), caps::MAX_URL_LENGTH);
        assert_eq!(exact_url_facts.coverage, NativeCoverage::Full);

        let overlong_url = format!("{exact_url}a");
        let mut overlong_url_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&overlong_url, &mut overlong_url_facts);
        assert_eq!(overlong_url_facts.coverage, NativeCoverage::Partial);
        assert!(overlong_url_facts
            .partial_reasons
            .contains(&NativePartialReason::EmbeddedUrlLengthLimit));

        let exact_py_init = format!(
            "PyInit_{}",
            "x".repeat(caps::MAX_PYINIT_NAME_LENGTH - "PyInit_".len())
        );
        let mut exact_py_init_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&exact_py_init, &mut exact_py_init_facts);
        assert_eq!(exact_py_init.chars().count(), caps::MAX_PYINIT_NAME_LENGTH);
        assert_eq!(exact_py_init_facts.coverage, NativeCoverage::Full);

        let overlong_py_init = format!("{exact_py_init}x");
        let mut overlong_py_init_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&overlong_py_init, &mut overlong_py_init_facts);
        assert_eq!(overlong_py_init_facts.coverage, NativeCoverage::Partial);
        assert!(overlong_py_init_facts
            .partial_reasons
            .contains(&NativePartialReason::PyInitNameLengthLimit));
    }

    #[test]
    fn printable_token_occurrences_and_sibling_names_are_bounded() {
        let exact = ".js ".repeat(caps::MAX_STRING_TOKEN_OCCURRENCES);
        let mut exact_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&exact, &mut exact_facts);
        assert_eq!(exact_facts.coverage, NativeCoverage::Full);

        let overflow = format!("{exact}.js ");
        let mut overflow_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&overflow, &mut overflow_facts);
        assert_eq!(overflow_facts.coverage, NativeCoverage::Partial);
        assert!(overflow_facts
            .partial_reasons
            .contains(&NativePartialReason::PrintableTokenOccurrenceLimit));

        let oversized_sibling = format!("{}.js", "s".repeat(caps::MAX_SIBLING_REF_LENGTH + 1));
        let mut sibling_facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        scan_test_string(&oversized_sibling, &mut sibling_facts);
        assert!(sibling_facts.sibling_refs.is_empty());
        assert!(sibling_facts
            .partial_reasons
            .contains(&NativePartialReason::SiblingReferenceLengthLimit));
    }

    #[test]
    fn fixed_runtime_and_sensitive_path_universes_are_fully_retained() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        for token in RUNTIME_TOKENS {
            scan_test_string(token, &mut facts);
        }
        for needle in SENSITIVE_PATH_NEEDLES {
            scan_test_string(needle, &mut facts);
        }

        let expected_runtimes = RUNTIME_TOKENS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<BTreeSet<_>>();
        let expected_paths = SENSITIVE_PATH_NEEDLES
            .iter()
            .map(|value| (*value).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(facts.runtime_names, expected_runtimes);
        assert_eq!(facts.sensitive_paths, expected_paths);
        assert_eq!(facts.coverage, NativeCoverage::Full);
        assert!(facts.partial_reasons.is_empty());
    }

    #[test]
    fn traversal_budget_marks_only_an_observed_extra_item() {
        for cap in [
            caps::MAX_IMPORTS,
            caps::MAX_SYMBOLS,
            caps::MAX_SECTIONS,
            caps::MAX_STRINGS_SCANNED,
        ] {
            let mut remaining = cap;
            for _ in 0..cap {
                assert!(take_budget_slot(&mut remaining));
            }
            assert_eq!(remaining, 0, "exact exhaustion is not overflow");
            assert!(!take_budget_slot(&mut remaining), "cap + 1 is observable");
        }
    }

    #[test]
    fn partial_reason_and_truncated_pyinit_evidence_are_explicit() {
        let mut facts = NativeFacts {
            coverage: NativeCoverage::Full,
            ..NativeFacts::default()
        };
        for i in 0..5 {
            facts.py_init_exports.insert(format!("PyInit_mod{i}"));
        }
        facts.mark_partial(NativePartialReason::EmbeddedUrlLimit);
        facts.mark_partial(NativePartialReason::PrintableStringCountLimit);

        assert_eq!(
            partial_reason_summary(&facts),
            "printable_string_count_limit, embedded_url_limit"
        );
        assert!(
            execution_entry_evidence(&facts).contains('…'),
            "five exports must be distinguishable from four in evidence"
        );
    }

    #[test]
    fn whole_buffer_string_scan_retains_in_cap_section_evidence() {
        // Native section data is a subset of the bounded member buffer. The scanner
        // now makes one member-wide pass instead of resetting its string budget for
        // every section and fat slice; ordinary section evidence remains visible.
        let elf = build_elf(&["PyInit_x"], true, b"./loader/run.js\0");
        let facts = extract_from_buffer(&elf);
        assert!(
            facts.sibling_refs.iter().any(|r| r.ends_with("run.js")),
            "an in-cap .rodata sibling ref is still found via the whole-buffer scan"
        );
        assert_eq!(facts.coverage, NativeCoverage::Full);
    }

    // ------------------------------------------------------------------
    // network_imports removed, not dead (T3.21)
    // ------------------------------------------------------------------

    #[test]
    fn network_imports_either_wired_or_removed() {
        // The dead `network_imports` field was REMOVED (it was never read and was
        // redundant with the runtime-launch / suspicious-URL legs). A network API
        // imported on its own must NOT, by itself, register a danger capability,
        // exactly as the (now-trimmed) doc promises. This is the behavioral proof
        // that removing the field changed no detection.
        let mut facts = NativeFacts::default();
        classify_capability_import("getaddrinfo", &mut facts);
        classify_capability_import("curl_easy_perform", &mut facts);
        classify_capability_import("wsaconnect", &mut facts);
        assert!(
            facts.spawn_imports.is_empty() && facts.dlopen_imports.is_empty(),
            "network imports are not classified as spawn/loader imports"
        );
        assert!(
            !facts.has_danger_capability(),
            "a bare network import is not a danger capability on its own; got {facts:?}"
        );
    }
}
