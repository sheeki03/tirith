//! Provenance composition over already-computed signals (plan Stack F).
//!
//! This module holds read models that COMPOSE existing inspection / lock outputs
//! into provenance answers, introducing no new detection and no new
//! [`crate::verdict::RuleId`]. F1 ships the execution/ownership/MCP graph; later
//! units (release differential, attestation binding) attach here.

/// The composed provenance graph (PR F1): a typed read model over an
/// [`crate::artifact::ArtifactInspection`]'s execution edges, the
/// [`crate::artifact::record::OwnershipIndex`], and the
/// [`crate::mcp_lock::McpInventory`], rendered as JSON or Graphviz DOT.
pub mod graph;
