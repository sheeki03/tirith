/// Structural recursion ceiling shared by the MCP output scanners.
///
/// The leaf sanitizer in [`output_filter`] and the URI/blob walkers in
/// [`response_inspect`] must refuse at the same depth: a value the sanitizer
/// declined as too deep must not then be walked by the inspector. The gateway's
/// JSON parser already caps nesting, but a public caller can hand either path a
/// `serde_json::Value` built in memory, so both enforce this independently.
pub(crate) const MAX_STRUCTURED_DEPTH: usize = 128;

pub mod content;
pub mod dispatcher;
pub mod origin;
pub mod output_filter;
pub mod resources;
pub mod response_inspect;
pub mod tools;
pub mod types;
