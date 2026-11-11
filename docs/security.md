# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tirith, please report it responsibly:

1. **GitHub Security Advisory** (preferred): Use the [Security tab](https://github.com/sheeki03/tirith/security/advisories/new) to create a private advisory
2. **Email**: security@tirith.sh

The repository-level [security policy](../SECURITY.md) is the authoritative
copy. It also covers data handling and release verification.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, targeting 2 weeks for critical issues

## Scope

The following are considered security vulnerabilities in tirith:

- **Bypass of detection**: A command or URL that should trigger a rule but doesn't (false negative)
- **Shell injection via hooks**: tirith's shell hooks introducing command injection vectors
- **Audit log tampering**: Ability to suppress or forge audit log entries
- **Policy bypass**: Circumventing blocklist/allowlist enforcement
- **Information disclosure**: tirith leaking sensitive data (command contents, file paths) beyond the audit log

The following are **not** in scope:

- False positives (non-malicious commands being flagged) — these are bugs, not vulnerabilities
- Detection of novel attack techniques not covered by existing rules — these are feature requests
- Issues requiring local root/admin access (tirith does not defend against privileged attackers)

## Supported Versions

The latest published minor release line receives security fixes. Older minor
lines receive best-effort support only. An integration branch is not a
supported release until the protected tag and public artifacts exist. See the
repository-level [security policy](../SECURITY.md) for the current release-line
status and verification instructions.
