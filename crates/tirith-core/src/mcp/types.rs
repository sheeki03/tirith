use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    #[allow(dead_code)]
    pub capabilities: Value,
    /// MCP `initialize.clientInfo`, read by the dispatcher to populate
    /// [`AgentOrigin::Mcp`](crate::agent_origin::AgentOrigin::Mcp).
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientInfo {
    /// Caller-claimed client name (`"Claude Code"`, `"cursor"`, …). Not
    /// verified; sanitized before it lands in
    /// [`AgentOrigin::Mcp`](crate::agent_origin::AgentOrigin::Mcp).
    pub name: String,
    /// Caller-claimed client version. Optional and sanitized.
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
    pub resources: ResourcesCapability,
}

#[derive(Debug, Serialize)]
pub struct ToolsCapability {}

#[derive(Debug, Serialize)]
pub struct ResourcesCapability {}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ContentItem>,
    // M7 ch4: deserialized for the output-filter path; default false so an
    // upstream that omits `isError` reads as "no error".
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub is_error: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub structured_content: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContentItem {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ResourceReadParams {
    pub uri: String,
}

#[derive(Debug, Serialize)]
pub struct ResourceContent {
    pub uri: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: String,
}

/// Supported MCP protocol versions, newest first.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    "2025-11-25", // Current
    "2025-06-18", // Structured tool outputs, enhanced OAuth
    "2025-03-26", // OAuth 2.1, Streamable HTTP
    "2024-11-05", // Initial release (Claude Code, Codex, Cursor, etc.)
];

pub fn negotiate_version(requested: &str) -> String {
    if SUPPORTED_VERSIONS.contains(&requested) {
        requested.to_string()
    } else {
        // Unknown version — respond with our preferred and let the client decide.
        SUPPORTED_VERSIONS[0].to_string()
    }
}
