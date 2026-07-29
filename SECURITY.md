# Security Policy

SecretVault is security-critical software: it stores and injects credentials for
AI agents and applications. We welcome responsible disclosure of vulnerabilities
and commit to a fast, coordinated response.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security
report.** Public disclosure before a fix is ready puts every SecretVault
deployment at risk.

Report privately through **one** of these channels, in order of preference:

1. **GitHub Private Security Advisory (preferred).**
   Open
   [github.com/itsaygea/secretvault/security/advisories/new](https://github.com/itsaygea/secretvault/security/advisories/new)
   and use the provided template. This keeps the report visible only to
   repository maintainers and lets us collaborate on a fix in private. It does
   not require any public disclosure.

2. **Email.** Send details to **security@itsaygea.com** with the subject
   `SecretVault vulnerability report`. This inbox is monitored. If you do not
   receive an acknowledgment within the SLA below, use channel 1 as a fallback.

### What to include

To help us reproduce and triage quickly, please include:

- A clear description of the vulnerability and its security impact.
- The affected component (proxy, MCP server, REST API, SDK, web UI, crypto,
  database schema, container image, CI, installer) and version.
- Step-by-step reproduction, including environment details (OS, Node.js,
  browser, Supabase/PostgreSQL version).
- A minimal proof of concept. If the PoC contains real credentials or secrets,
  redact them and describe them symbolically instead.

### What NOT to include

Please **do not** include any of the following in a report:

- Real, live credentials, API keys, master keys, linking keys, or any plaintext
  secret — SecretVault is a credential store, so substituting a clearly-fake
  value (e.g. `TEST_KEY_DO_NOT_USE`) is always sufficient.
- Personal data about other people.
- Exploitation of third-party systems you do not own or have authorization to
  test. Stay within a SecretVault instance you control.
- Automated mass-scanner output without a confirmed, reproducible finding.

## Response expectations

| Stage | Target |
| --- | --- |
| Initial acknowledgment | Within 2 business days |
| Triage and severity rating | Within 5 business days |
| Patch strategy communicated | Within 10 business days |
| Security patch release | Severity-dependent (see below) |

Severity and timeline follow the
[CVSS v3.1](https://www.first.org/cvss/calculator/3.1) base score:

| Severity | CVSS | Patch target |
| --- | --- | --- |
| Critical | 9.0 – 10.0 | Emergency release, days |
| High | 7.0 – 8.9 | Next release, ≤ 2 weeks |
| Medium | 4.0 – 6.9 | Next scheduled release |
| Low | 0.1 – 3.9 | Best effort, backlog |

These are targets, not guarantees. We will keep reporters informed of progress.

## Disclosure

- We practice **coordinated disclosure**. Public advisories are published
  concurrently with (or shortly after) a patched release, once deployers have
  had a reasonable window to update.
- Reporters are credited by name/handle only with their explicit consent.
- We request a **90-day disclosure window** from initial report before any
  public disclosure; we will honor a reporter's wish to disclose earlier if a
  patch is available and deployed.

## Supported versions

Only the latest released version of SecretVault receives security fixes.

| Version | Supported |
| --- | --- |
| latest `main` / most recent release | ✅ |
| older releases | ❌ (upgrade advised) |

The runtime is a container image. Run the image pinned to a specific digest
(see `docs/install.md`) and subscribe to releases to receive security updates.

## Acknowledgments

We are grateful to researchers who report vulnerabilities responsibly.
Coordinated disclosures may be acknowledged here with the reporter's consent.

## Hardening reference

For the product's security architecture, threat model, and the bounded-egress /
no-plaintext invariants, see [`docs/security.md`](docs/security.md).
