# Security Policy

## ⚠️ Authorized use only

SecretNode is a **passive attack-surface scanner** built for defenders, bug-bounty
researchers, and security teams to find **their own** exposed credentials before an
attacker does. It is intended **exclusively** for:

- infrastructure you own, or
- targets you have **explicit, written authorization** to assess (a signed engagement,
  or a bug-bounty program whose scope includes the target).

Scanning systems without authorization may be illegal in your jurisdiction. You are
solely responsible for how you use this tool.

### Safety controls built in
- **Passive only.** SecretNode performs read-only reconnaissance. It never exploits a
  finding, never uses a discovered credential, and never performs write operations
  against a target.
- **SSRF guard.** Scans against private/loopback/link-local/reserved addresses (e.g.
  cloud metadata endpoints) are refused unless `ALLOW_PRIVATE_TARGETS=true` is set for
  authorized internal-lab testing.
- **Scope restriction.** Asset discovery stays on the target's own domain by default
  (`SCOPE_SAME_DOMAIN=true`).
- **Authentication required.** The API/WebSocket/dashboard refuse to start without a
  `SECRETNODE_API_KEY`, and every request is gated by it.
- **Redaction.** Matched secrets are partially redacted before being written to
  reports, logs, or Discord alerts.

## Reporting a vulnerability

If you discover a security issue **in SecretNode itself**, please report it privately:

- Open a [GitHub Security Advisory](https://github.com/azmolhaque/secretnode/security/advisories/new), or
- Email the maintainer (see the profile at <https://github.com/azmolhaque>).

Please do **not** open a public issue for a security vulnerability. We aim to
acknowledge reports within a few days and will credit reporters who wish to be named.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.2.x   | ✅ |
| < 2.2   | ❌ |
