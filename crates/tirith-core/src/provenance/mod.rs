//! Provenance composition over already-computed signals (plan Stack F).
//!
//! This module holds read models that COMPOSE existing inspection / lock outputs
//! into provenance answers, introducing no new detection and no new
//! [`crate::verdict::RuleId`]. F1 ships the execution/ownership/MCP graph; F3 adds
//! the PyPI attestation provenance TYPES and the subject-digest binding (the
//! network fetch + Sigstore verification live in the CLI crate).

/// The composed provenance graph (PR F1): a typed read model over an
/// [`crate::artifact::ArtifactInspection`]'s execution edges, the
/// [`crate::artifact::record::OwnershipIndex`], and the
/// [`crate::mcp_lock::McpInventory`], rendered as JSON or Graphviz DOT.
pub mod graph;

/// PyPI attestation provenance (PR F3): the portable, async-free TYPES
/// ([`pypi_integrity::AttestationOutcome`], [`pypi_integrity::PublisherIdentity`],
/// [`pypi_integrity::PublisherPolicy`]) and the subject-digest BINDING
/// ([`pypi_integrity::bind_subject_digest`]) that ties a verified attestation to
/// the quarantined artifact's SHA-256. The Integrity API fetch and the Sigstore
/// cryptographic verification (the `sigstore-*` / `tuf` / `tokio` closure) live in
/// the `tirith` CLI crate; this module is the pure half. Provenance evidence only:
/// it emits no [`crate::verdict::RuleId`] and is never an auto-allow.
pub mod pypi_integrity;

/// npm registry package identity and provenance FACTS (C13): the parsed
/// `dist.integrity` SRI, the legacy shasum status, the registry signature and
/// attestation states, and the origin-validated tarball URL. Facts only. No
/// state here can reach `Verified`: npm signs with ECDSA P-256 and this
/// workspace has no P-256 backend, and the Sigstore closure the attestations
/// need is off on the workspace MSRV. Tirith also does not download npm
/// tarballs, so the SRI is never bound to bytes.
pub mod npm_facts;
