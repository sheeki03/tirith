# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tirith, please report it responsibly:

1. **GitHub Security Advisory** (preferred): Use the [Security tab](../../security/advisories/new) to create a private advisory
2. **Email**: Send details to the maintainers listed in the repository

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

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |
