# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tirith, please report it responsibly.

**Preferred:** [GitHub Security Advisory](../../security/advisories/new) — creates a private channel between you and the maintainers.

**Alternative:** Email security@tirith.sh

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response expectations

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 1 week |
| Fix or mitigation | Within 2 weeks for critical issues |

We will coordinate disclosure timing with you. We won't publish details until a fix is available.

## Scope

**In scope** — these are security vulnerabilities:

- **Detection bypass**: A command or URL that should trigger a rule but doesn't (false negative in a security-critical path)
- **Shell injection via hooks**: Tirith's shell hooks introducing command injection vectors
- **Audit log tampering**: Ability to suppress or forge audit log entries
- **Policy bypass**: Circumventing blocklist/allowlist enforcement
- **Information disclosure**: Tirith leaking sensitive data beyond the local audit log

**Not in scope**:

- False positives (non-malicious commands flagged) — file a regular bug report
- Detection of novel attack techniques not covered by existing rules — file a feature request
- Issues requiring local root/admin access — tirith does not defend against privileged local attackers

## Data handling

Tirith's command parser, local rules, and `paste` analysis run locally. A
normal `check` may enrich package-install candidates through the enabled OSV,
deps.dev, ecosyste.ms, Safe Browsing, or KEV providers; those requests can
disclose the parsed package name and version or constraint to the provider.
Use `tirith check --offline` (or disable the corresponding policy providers) to
guarantee that runtime enrichment makes no network request. Offline mode is
enforced in both the direct and daemon-backed check paths; an unavailable local
answer is reported as incomplete rather than silently going online.

- `paste` makes no network calls.
- Tirith sends no telemetry, analytics, or crash reports.
- Analysis results are written to a local JSONL audit log only.
- Full command text is redacted in logs (first 80 chars, truncated).

The audit log lives at `$XDG_DATA_HOME/tirith/log.jsonl` (normally
`~/.local/share/tirith/log.jsonl`, or the platform equivalent). Disable it with
`TIRITH_LOG=0`.

There is no unrelated phone-home behavior.

## Reproducible builds

Release artifacts are built via GitHub Actions with:
- [Sigstore cosign](https://github.com/sigstore/cosign) signatures using GitHub OIDC
- [SLSA provenance](https://slsa.dev) generation
- SHA-256 checksums for all archives

Verify a release:
```bash
TAG=vX.Y.Z  # replace with the exact immutable release tag you downloaded
cosign verify-blob \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity "https://github.com/sheeki03/tirith/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum --check --strict checksums.txt
```

## Supported versions

The latest published minor release line receives security fixes. Older minor
lines receive best-effort support only; upgrade before reporting a result as a
current-version vulnerability. Code on an unreleased branch or integration
stack is not a supported release until its protected tag and artifacts exist.

Beginning with v0.4.0, 0.4.x is the supported release line, and v0.4.2 is the
current published patch. The 0.3.x line now receives best-effort support only.
