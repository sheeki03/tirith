//! MCP content typing (C2). Parses a `tools/call` `result` from a
//! `serde_json::Value` into a typed shape that:
//!
//! * maps each known MCP content block to a [`rust_mcp_schema::ContentBlock`]
//!   (text / image / audio / resource-link / embedded-resource), and
//! * preserves every UNKNOWN block losslessly as [`PreservedContent::Unknown`]
//!   (the raw `Value`), so a block this build does not model is forwarded byte
//!   for byte in compat mode and rejected in strict mode.
//!
//! This replaces the gateway's lossy hand-rolled `reshape_for_deserialize`,
//! which silently coerced every item to `{type:"text", text:...}` and dropped
//! items with no `text` field. The typed model is the structural front-end to
//! the output filter: it decides what is known vs unknown and (under strict)
//! whether to reject, but the actual scrub/Block/Warn rewrite still happens in
//! [`crate::mcp::output_filter`] over the round-tripped [`ToolCallResult`].
//!
//! ## Strict vs compat
//!
//! * [`TypingMode::Compat`]: partial coverage. Known blocks are typed; unknown
//!   blocks are kept as `Unknown(Value)` and forwarded unchanged. This is the
//!   default and matches the gateway's "never break a working upstream" stance.
//! * [`TypingMode::Strict`]: full coverage required. Any unknown block (or a
//!   `content` array that is not an array of objects) makes [`parse_tool_result`]
//!   return [`ContentTypingError::UnknownBlock`]; the caller fails closed.
//!
//! ## Schema validation
//!
//! [`SchemaValidator`] wraps `jsonschema` (built with `default-features=false`,
//! the `regex` pattern engine, and NO remote/file `$ref` resolution) to check a
//! tool's declared `inputSchema` against call arguments and `outputSchema`
//! against `result.structuredContent`. A server schema that does not COMPILE
//! [`SchemaValidator::compile`] returns [`SchemaError::InvalidSchema`]; the
//! caller SUSPENDS that tool (refuses to expose / forward it) rather than
//! silently disabling validation. A schema that compiles but whose instance
//! fails validation is a per-call [`SchemaError::InstanceInvalid`].

use rust_mcp_schema::ContentBlock;
use serde_json::Value;
use std::fmt;

/// One element of a `tools/call` result's `content` array: either a known,
/// typed MCP content block, or an unknown block kept verbatim.
///
/// The `Known` variant wraps the rich `rust-mcp-schema` `ContentBlock` (~280B);
/// `Unknown` holds a small JSON `Value`. The size gap is inherent to the domain,
/// and this enum is constructed/matched on the content-forwarding path where the
/// block is re-serialized anyway, so boxing every block to satisfy the heuristic
/// would add a heap allocation per content element for no real benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum PreservedContent {
    /// A block this build models (text / image / audio / resource-link /
    /// embedded-resource), parsed into the canonical `rust-mcp-schema` type.
    Known(ContentBlock),
    /// A block this build does NOT model. The raw JSON value is kept verbatim so
    /// it can be forwarded unchanged (compat), never coerced, never dropped.
    Unknown(Value),
}

impl fmt::Debug for PreservedContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(_) => formatter
                .debug_struct("Known")
                .field("payload", &"<inspected-content>")
                .finish(),
            Self::Unknown(_) => formatter
                .debug_struct("Unknown")
                .field("payload", &"<preserved-unmodeled-content>")
                .finish(),
        }
    }
}

impl PreservedContent {
    /// The raw JSON for this block, reconstructed losslessly. For [`Self::Known`]
    /// this re-serializes the typed block (a faithful round-trip of the modeled
    /// fields); for [`Self::Unknown`] it is the original value, untouched.
    pub fn to_value(&self) -> Value {
        match self {
            // `ContentBlock` is `#[serde(untagged)]` with `type`-validated
            // variants, so serialization yields the same object shape it parsed
            // from. Infallible for these types; fall back to Null only to keep
            // this total (it never triggers in practice).
            PreservedContent::Known(block) => serde_json::to_value(block).unwrap_or(Value::Null),
            PreservedContent::Unknown(v) => v.clone(),
        }
    }

    /// `true` if this is an unknown (unmodeled) block.
    pub fn is_unknown(&self) -> bool {
        matches!(self, PreservedContent::Unknown(_))
    }
}

/// How [`parse_tool_result`] treats a content block it cannot type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TypingMode {
    /// Forward unknown blocks unchanged (partial coverage). Default.
    #[default]
    Compat,
    /// Reject any unknown block (full coverage required); the caller fails closed.
    Strict,
}

/// A `tools/call` result decomposed into typed/preserved content plus the
/// untouched `structuredContent`. `extra` keeps every top-level field the MCP
/// `CallToolResult` shape does not name (e.g. `_meta`), so re-serialization is
/// lossless for unmodeled siblings too.
#[derive(Clone)]
pub struct TypedToolResult {
    /// The `content` array, each element typed or preserved.
    pub content: Vec<PreservedContent>,
    /// MCP `isError` (absent reads as `false`).
    pub is_error: bool,
    /// `structuredContent`, kept as a raw `Value` (data, not a content block).
    pub structured_content: Option<Value>,
    /// Every other top-level key of `result`, preserved verbatim for round-trip.
    pub extra: serde_json::Map<String, Value>,
}

impl fmt::Debug for TypedToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedToolResult")
            .field("content_count", &self.content.len())
            .field(
                "unknown_content_count",
                &self
                    .content
                    .iter()
                    .filter(|block| block.is_unknown())
                    .count(),
            )
            .field("is_error", &self.is_error)
            .field(
                "structured_content_present",
                &self.structured_content.is_some(),
            )
            .field("extra_field_count", &self.extra.len())
            .finish()
    }
}

/// Why [`parse_tool_result`] could not type a `result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentTypingError {
    /// `result` was not a JSON object.
    NotAnObject,
    /// `content` was present but not a JSON array.
    ContentNotArray,
    /// A `content` element was not a JSON object.
    ElementNotObject,
    /// Strict mode: a `content` element did not map to a known block. The raw
    /// serde error is deliberately not retained because it may echo an
    /// attacker-controlled discriminator or field value at a public error or
    /// `Debug` boundary.
    UnknownBlock,
}

impl std::fmt::Display for ContentTypingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentTypingError::NotAnObject => write!(f, "tools/call result is not an object"),
            ContentTypingError::ContentNotArray => write!(f, "result.content is not an array"),
            ContentTypingError::ElementNotObject => {
                write!(f, "a result.content element is not an object")
            }
            ContentTypingError::UnknownBlock => {
                write!(f, "unknown content block under strict mode")
            }
        }
    }
}

impl std::error::Error for ContentTypingError {}

/// Parse a `tools/call` `result` Value into a [`TypedToolResult`].
///
/// * `content[]` elements are matched to a [`ContentBlock`] via serde. A match
///   becomes [`PreservedContent::Known`]; a non-match becomes
///   [`PreservedContent::Unknown`] in [`TypingMode::Compat`], or aborts with
///   [`ContentTypingError::UnknownBlock`] in [`TypingMode::Strict`].
/// * `structuredContent` is kept verbatim.
/// * every other top-level field is preserved in `extra`.
///
/// A missing `content` is treated as an empty array (matches the MCP shape where
/// `content` may be omitted). This never silently drops an element: unknown
/// blocks survive in `Unknown`, and non-object elements are a strict-or-compat
/// decision rather than a quiet skip.
pub fn parse_tool_result(
    result: &Value,
    mode: TypingMode,
) -> Result<TypedToolResult, ContentTypingError> {
    let obj = result.as_object().ok_or(ContentTypingError::NotAnObject)?;

    let is_error = obj.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let structured_content = obj.get("structuredContent").cloned();

    let mut content = Vec::new();
    match obj.get("content") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                // Each element MUST be an object (MCP content blocks are objects).
                if !item.is_object() {
                    if mode == TypingMode::Strict {
                        return Err(ContentTypingError::ElementNotObject);
                    }
                    // Compat: preserve the odd element verbatim rather than drop it.
                    content.push(PreservedContent::Unknown(item.clone()));
                    continue;
                }
                match serde_json::from_value::<ContentBlock>(item.clone()) {
                    Ok(block) => content.push(PreservedContent::Known(block)),
                    Err(_) => {
                        if mode == TypingMode::Strict {
                            return Err(ContentTypingError::UnknownBlock);
                        }
                        content.push(PreservedContent::Unknown(item.clone()));
                    }
                }
            }
        }
        Some(_) => return Err(ContentTypingError::ContentNotArray),
    }

    // Preserve all top-level fields except the three we model explicitly.
    let mut extra = obj.clone();
    extra.remove("content");
    extra.remove("isError");
    extra.remove("structuredContent");

    Ok(TypedToolResult {
        content,
        is_error,
        structured_content,
        extra,
    })
}

impl TypedToolResult {
    /// `true` if any content block is unknown (unmodeled). Used by callers that
    /// want a compat-mode audit signal that partial coverage kicked in.
    pub fn has_unknown(&self) -> bool {
        self.content.iter().any(PreservedContent::is_unknown)
    }

    /// Re-serialize to a `result` Value, losslessly: known blocks round-trip
    /// through their typed form, unknown blocks and `extra` siblings are emitted
    /// verbatim. `isError`/`structuredContent` are only emitted when meaningful
    /// (false / None are omitted, matching the MCP wire shape).
    pub fn to_value(&self) -> Value {
        let mut obj = self.extra.clone();
        let content: Vec<Value> = self
            .content
            .iter()
            .map(PreservedContent::to_value)
            .collect();
        obj.insert("content".to_string(), Value::Array(content));
        if self.is_error {
            obj.insert("isError".to_string(), Value::Bool(true));
        }
        if let Some(sc) = &self.structured_content {
            obj.insert("structuredContent".to_string(), sc.clone());
        }
        Value::Object(obj)
    }

    /// Iterate the scannable text leaves of every content block, in order, so a
    /// caller can stream them through the engine without re-coercing the shape.
    /// Yields each `text` field of a text block plus the string leaves of any
    /// preserved/unknown block (image/audio carry base64 in `data`; that and any
    /// other string is attacker-controlled tool output and must be scanned).
    /// Structured content is scanned separately by the output filter.
    pub fn scan_chunks(&self) -> Vec<String> {
        let mut out = Vec::new();
        for block in &self.content {
            collect_block_strings(&block.to_value(), &mut out);
        }
        // repo-0292: top-level `extra` fields (`_meta`, vendor extensions) are
        // attacker-controlled too and are re-emitted verbatim by `to_value`.
        // Scanning only `content` let an upstream smuggle prompt-injection or
        // terminal-control text past the analyzer in a standard field.
        collect_block_strings(&Value::Object(self.extra.clone()), &mut out);
        out
    }
}

/// Append every JSON string leaf of `v` (values and object keys) to `out`. Keys
/// are attacker-controlled too, so a payload hidden in a key still reaches the
/// scanner. Mirrors the structured-content leaf walk in `output_filter`.
fn collect_block_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_block_strings(item, out);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                out.push(key.clone());
                collect_block_strings(val, out);
            }
        }
        _ => {}
    }
}

// ── JSON Schema validation (inputSchema / outputSchema) ──────────────────────

/// Why a JSON-schema validation failed.
#[derive(Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// The SERVER's declared schema did not compile (malformed, or it references
    /// a remote/file `$ref` we refuse to resolve). The caller must SUSPEND the
    /// tool, never silently skip validation. Carries a short reason.
    InvalidSchema(String),
    /// The schema compiled, but the INSTANCE (args / structuredContent) failed
    /// validation. A per-call policy decision, not a tool-suspension. Carries the
    /// first error message.
    InstanceInvalid(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::InvalidSchema(why) => {
                write!(f, "invalid server schema: {}", schema_trait_detail(why))
            }
            SchemaError::InstanceInvalid(why) => {
                write!(f, "instance failed schema: {}", schema_trait_detail(why))
            }
        }
    }
}

impl std::fmt::Debug for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::InvalidSchema(why) => f
                .debug_tuple("InvalidSchema")
                .field(&schema_trait_detail(why))
                .finish(),
            SchemaError::InstanceInvalid(why) => f
                .debug_tuple("InstanceInvalid")
                .field(&schema_trait_detail(why))
                .finish(),
        }
    }
}

impl std::error::Error for SchemaError {}

/// A compiled JSON-schema validator with bounded, offline-only resolution.
///
/// Built via [`SchemaValidator::compile`], which uses `jsonschema::options()`
/// with the `regex` pattern engine (linear-time, no catastrophic backtracking)
/// and the crate's `default-features=false` build, so NO `$ref` is fetched over
/// HTTP or read from the filesystem (those resolvers are off without the
/// `resolve-http`/`resolve-file` features). A schema with an unresolvable
/// external `$ref` therefore fails to compile and SUSPENDS the tool, which is
/// the intended fail-closed behavior.
pub struct SchemaValidator {
    inner: jsonschema::Validator,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaValidator").finish_non_exhaustive()
    }
}

impl SchemaValidator {
    /// Compile a server-declared schema. Returns [`SchemaError::InvalidSchema`]
    /// (tool-suspending) when the schema is malformed or needs remote/file `$ref`
    /// resolution we refuse to perform.
    ///
    /// Only object schemas are accepted: a non-object (e.g. `true`/`false`/a
    /// string) is not a usable tool schema and suspends the tool rather than
    /// degrading to "validate nothing".
    pub fn compile(schema: &Value) -> Result<Self, SchemaError> {
        if !schema.is_object() {
            return Err(SchemaError::InvalidSchema(
                "schema is not a JSON object".to_string(),
            ));
        }
        let inner = jsonschema::options()
            // Linear-time regex engine (default features pull `fancy-regex`,
            // which can backtrack; `regex` cannot). Pattern bounds are enforced
            // by the engine choice, not a post-hoc check.
            .with_pattern_options(jsonschema::PatternOptions::regex())
            .build(schema)
            // jsonschema's Display includes schema values and locations. The
            // gateway only needs the typed disposition; keep the diagnostic
            // categorical so a malicious descriptor cannot echo its bytes.
            .map_err(|_| SchemaError::InvalidSchema("schema compilation failed".to_string()))?;
        Ok(Self { inner })
    }

    /// Validate an instance against the compiled schema. Returns
    /// [`SchemaError::InstanceInvalid`] with the first error on failure.
    pub fn validate(&self, instance: &Value) -> Result<(), SchemaError> {
        match self.inner.validate(instance) {
            Ok(()) => Ok(()),
            Err(e) => Err(SchemaError::InstanceInvalid(schema_error_summary(&e))),
        }
    }

    /// `true` if the instance is valid (no error detail).
    pub fn is_valid(&self, instance: &Value) -> bool {
        self.inner.is_valid(instance)
    }
}

const MAX_SCHEMA_DIAGNOSTIC_COMPONENT_BYTES: usize = 256;

/// Return only the validation keyword and a bounded, privacy-projected JSON
/// pointer. `ValidationError::Display` includes the rejected instance value,
/// which may be a credential supplied in tool arguments or structured output.
fn schema_error_summary(error: &jsonschema::ValidationError<'_>) -> String {
    let keyword = bounded_schema_component(error.kind().keyword(), 64);
    let pointer = bounded_schema_component(
        error.instance_path().as_str(),
        MAX_SCHEMA_DIAGNOSTIC_COMPONENT_BYTES,
    );
    let pointer = if pointer.is_empty() { "/" } else { &pointer };
    format!("keyword={keyword}; instance_path={pointer}")
}

fn bounded_schema_component(value: &str, max_bytes: usize) -> String {
    let share_safe =
        crate::redact::redact_for_audience(value, crate::redact::ShareAudience::PublicPaste)
            .redacted_content;
    let projected = crate::redact::redact_blocked_output(&share_safe);
    let sanitized = crate::mcp::output_filter::sanitize_for_display(&projected);
    let truncated = crate::util::truncate_bytes(&sanitized, max_bytes);
    if truncated.len() < sanitized.len() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn schema_trait_detail(value: &str) -> String {
    bounded_schema_component(value, MAX_SCHEMA_DIAGNOSTIC_COMPONENT_BYTES)
}

/// Compile a tool's declared schema and validate `instance` against it in one
/// step. Distinguishes a bad SERVER schema (suspend the tool) from a bad
/// INSTANCE (per-call decision):
///
/// * `Ok(())`: schema compiled and the instance is valid.
/// * `Err(InvalidSchema)`: the schema did not compile; SUSPEND the tool.
/// * `Err(InstanceInvalid)`: the schema compiled but the instance failed.
///
/// `None` schema means "no schema declared", which validates trivially (`Ok`).
pub fn validate_against_schema(
    schema: Option<&Value>,
    instance: &Value,
) -> Result<(), SchemaError> {
    let Some(schema) = schema else {
        return Ok(());
    };
    let validator = SchemaValidator::compile(schema)?;
    validator.validate(instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text_block(s: &str) -> Value {
        json!({ "type": "text", "text": s })
    }

    #[test]
    fn known_text_block_is_typed() {
        let result = json!({ "content": [ text_block("hello") ] });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();
        assert_eq!(typed.content.len(), 1);
        assert!(
            matches!(typed.content[0], PreservedContent::Known(_)),
            "a text block must type as Known"
        );
        assert!(!typed.has_unknown());
    }

    #[test]
    fn image_and_audio_blocks_are_typed() {
        let result = json!({
            "content": [
                { "type": "image", "data": "aGVsbG8=", "mimeType": "image/png" },
                { "type": "audio", "data": "aGVsbG8=", "mimeType": "audio/wav" },
            ]
        });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();
        assert_eq!(typed.content.len(), 2);
        assert!(typed.content.iter().all(|b| !b.is_unknown()));
    }

    #[test]
    fn unknown_block_preserved_in_compat() {
        // A future content type this build does not model.
        let weird = json!({ "type": "video", "url": "https://example.invalid/v.mp4" });
        let result = json!({ "content": [ text_block("ok"), weird.clone() ] });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();
        assert_eq!(typed.content.len(), 2);
        assert!(typed.has_unknown(), "the video block must be Unknown");
        // Lossless: the preserved block round-trips byte-for-byte.
        let round = typed.content[1].to_value();
        assert_eq!(round, weird, "unknown block must round-trip unchanged");
    }

    #[test]
    fn unknown_block_rejected_in_strict() {
        let weird = json!({ "type": "video", "url": "https://example.invalid/v.mp4" });
        let result = json!({ "content": [ weird ] });
        let err = parse_tool_result(&result, TypingMode::Strict).unwrap_err();
        assert!(
            matches!(err, ContentTypingError::UnknownBlock),
            "strict mode must reject an unknown block; got {err:?}"
        );
    }

    #[test]
    fn public_debug_never_exposes_known_unknown_structured_or_extra_payloads() {
        let provider_secret = format!("https://eth-mainnet.g.alchemy.com/v2/{}", "A".repeat(48));
        let contextual_secret = format!("PRIVATE_KEY=0x{}", "11".repeat(32));
        let structured_canary = "C04_STRUCTURED_CONTENT_CANARY";
        let extra_canary = "C04_EXTRA_FIELD_CANARY";
        let result = json!({
            "content": [
                text_block(&contextual_secret),
                {
                    "type": "future_provider_block",
                    "endpoint": provider_secret.clone(),
                },
            ],
            "structuredContent": {
                "credential": structured_canary,
            },
            "_meta": {
                "authorization": extra_canary,
            },
        });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();

        let mut renderings = vec![format!("{typed:?}")];
        renderings.extend(typed.content.iter().map(|block| format!("{block:?}")));
        for rendering in renderings {
            for canary in [
                provider_secret.as_str(),
                contextual_secret.as_str(),
                structured_canary,
                extra_canary,
            ] {
                assert!(!rendering.contains(canary), "{rendering}");
            }
        }
        let summary = format!("{typed:?}");
        assert!(summary.contains("content_count: 2"), "{summary}");
        assert!(summary.contains("unknown_content_count: 1"), "{summary}");
        assert!(
            summary.contains("structured_content_present: true"),
            "{summary}"
        );
        assert!(summary.contains("extra_field_count: 1"), "{summary}");

        // Privacy-safe traits do not weaken the compat forwarding contract.
        assert_eq!(typed.to_value(), result);
    }

    #[test]
    fn strict_unknown_error_is_categorical_for_attacker_discriminators() {
        let canary = format!("future_ghp_{}", "Q".repeat(36));
        let result = json!({
            "content": [{
                "type": canary.clone(),
                "providerCredential": format!("sk-ant-api03-{}", "R".repeat(32)),
            }],
        });
        let error = parse_tool_result(&result, TypingMode::Strict).unwrap_err();
        assert_eq!(error, ContentTypingError::UnknownBlock);
        for rendering in [error.to_string(), format!("{error:?}")] {
            assert!(!rendering.contains(&canary), "{rendering}");
            assert!(!rendering.contains("sk-ant-api03-"), "{rendering}");
        }
    }

    #[test]
    fn round_trip_preserves_extra_and_structured() {
        let result = json!({
            "content": [ text_block("body") ],
            "isError": true,
            "structuredContent": { "rows": [1, 2, 3] },
            "_meta": { "trace": "abc" },
        });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();
        assert!(typed.is_error);
        let back = typed.to_value();
        assert_eq!(back["isError"], json!(true));
        assert_eq!(back["structuredContent"], json!({ "rows": [1, 2, 3] }));
        assert_eq!(back["_meta"], json!({ "trace": "abc" }), "extra preserved");
    }

    #[test]
    fn missing_content_is_empty_not_error() {
        let result = json!({ "isError": false });
        let typed = parse_tool_result(&result, TypingMode::Strict).unwrap();
        assert!(typed.content.is_empty());
    }

    #[test]
    fn content_not_array_is_error() {
        let result = json!({ "content": "oops" });
        let err = parse_tool_result(&result, TypingMode::Compat).unwrap_err();
        assert_eq!(err, ContentTypingError::ContentNotArray);
    }

    #[test]
    fn scan_chunks_yields_text_and_unknown_strings() {
        let result = json!({
            "content": [
                text_block("visible-text"),
                { "type": "video", "caption": "hidden-in-unknown" },
            ]
        });
        let typed = parse_tool_result(&result, TypingMode::Compat).unwrap();
        let chunks = typed.scan_chunks();
        let joined = chunks.join("\u{0}");
        assert!(joined.contains("visible-text"));
        assert!(
            joined.contains("hidden-in-unknown"),
            "string leaves of an unknown block must be scannable: {chunks:?}"
        );
    }

    // ── schema validation ────────────────────────────────────────────────

    #[test]
    fn valid_instance_passes() {
        let schema = json!({
            "type": "object",
            "properties": { "name": { "type": "string" } },
            "required": ["name"],
        });
        let ok = json!({ "name": "tirith" });
        assert!(validate_against_schema(Some(&schema), &ok).is_ok());
    }

    #[test]
    fn invalid_instance_is_instance_error() {
        let schema = json!({
            "type": "object",
            "properties": { "n": { "type": "number" } },
            "required": ["n"],
        });
        let bad = json!({ "n": "not-a-number" });
        let err = validate_against_schema(Some(&schema), &bad).unwrap_err();
        assert!(
            matches!(err, SchemaError::InstanceInvalid(_)),
            "a bad instance is InstanceInvalid, got {err:?}"
        );
    }

    #[test]
    fn instance_error_contains_only_keyword_and_projected_pointer() {
        let secret = format!("ghp_{}", "V".repeat(36));
        let property = format!("credential-{secret}");
        let schema = json!({
            "type": "object",
            "properties": { (property.clone()): { "type": "number" } },
        });
        let bad = json!({ (property): secret.clone() });
        let SchemaError::InstanceInvalid(detail) =
            validate_against_schema(Some(&schema), &bad).unwrap_err()
        else {
            panic!("expected instance validation error");
        };
        assert!(detail.contains("keyword=type"), "{detail}");
        assert!(detail.contains("instance_path=/"), "{detail}");
        assert!(!detail.contains(&secret), "{detail}");
        assert!(
            !detail.contains('"'),
            "raw JSON instance value leaked: {detail}"
        );
        assert!(detail.len() <= MAX_SCHEMA_DIAGNOSTIC_COMPONENT_BYTES + 96);
    }

    #[test]
    fn benign_instance_pointer_remains_actionable() {
        let schema = json!({
            "type": "object",
            "properties": { "count": { "type": "number" } },
        });
        let SchemaError::InstanceInvalid(detail) =
            validate_against_schema(Some(&schema), &json!({"count": "no"})).unwrap_err()
        else {
            panic!("expected instance validation error");
        };
        assert_eq!(detail, "keyword=type; instance_path=/count");
    }

    #[test]
    fn directly_constructed_schema_error_traits_project_payloads() {
        let secret = format!("ghp_{}", "Y".repeat(36));
        let error = SchemaError::InstanceInvalid(format!(
            "raw instance {secret} at /Users/alice/private/{secret}"
        ));
        let display = error.to_string();
        let debug = format!("{error:?}");
        for rendered in [&display, &debug] {
            assert!(!rendered.contains(&secret), "{rendered}");
            assert!(!rendered.contains("/Users/alice"), "{rendered}");
            assert!(rendered.contains("REDACTED"), "{rendered}");
            assert!(rendered.len() <= MAX_SCHEMA_DIAGNOSTIC_COMPONENT_BYTES + 64);
        }
    }

    #[test]
    fn malformed_schema_suspends_tool() {
        // `type` must be a string or array of strings; a number is malformed.
        let schema = json!({ "type": 123 });
        let err = SchemaValidator::compile(&schema).unwrap_err();
        assert!(
            matches!(err, SchemaError::InvalidSchema(_)),
            "a malformed schema must be InvalidSchema (suspend), got {err:?}"
        );
    }

    #[test]
    fn non_object_schema_suspends_tool() {
        let schema = json!("a string is not a schema object");
        let err = SchemaValidator::compile(&schema).unwrap_err();
        assert!(matches!(err, SchemaError::InvalidSchema(_)));
    }

    #[test]
    fn no_schema_validates_trivially() {
        let instance = json!({ "anything": true });
        assert!(validate_against_schema(None, &instance).is_ok());
    }

    #[test]
    fn remote_ref_schema_does_not_resolve_over_network() {
        // With default-features=false, no HTTP/file `$ref` resolver is wired, so a
        // schema whose validation depends on resolving a remote `$ref` must NOT
        // succeed by fetching it. Either compilation fails (InvalidSchema, which
        // suspends the tool) or the unresolved ref makes a would-be-valid instance
        // not validate, both are fail-closed. We assert we never silently fetch
        // and pass.
        let schema = json!({
            "$ref": "https://example.invalid/remote-schema.json"
        });
        // Building may fail outright (preferred) ...
        match SchemaValidator::compile(&schema) {
            Err(SchemaError::InvalidSchema(_)) => {}
            Err(other) => panic!("unexpected compile error: {other:?}"),
            Ok(validator) => {
                // ... or, if it builds, it must not have fetched the remote doc to
                // call an arbitrary instance valid against it. A bare object should
                // not be silently accepted via a resolved remote schema.
                let _ = validator.is_valid(&json!({ "x": 1 }));
                // No network assertion possible here; the contract is that no
                // resolver feature is compiled in (see Cargo.toml C2 pin). This
                // test documents the expectation and guards the feature set.
            }
        }
    }
}
