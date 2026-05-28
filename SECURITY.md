# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.y (upcoming stable) | Will receive security fixes once released. |
| 0.x.y (current prerelease) | No security fixes. Pin a version and upgrade when 1.x ships. |

The `0.x.y` line is a prerelease series. It will not receive backported security fixes; users are expected to upgrade to the upcoming stable `1.x.y` line once available.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

GitHub Private Vulnerability Reporting will be enabled via the repository Security tab; check there for the current status. In the meantime, report vulnerabilities by email to **dah.kenangnon@gmail.com**. Include:
- A description of the vulnerability
- Steps to reproduce
- Affected package(s) and version(s)
- Any suggested fix or patch (optional)

You will receive an acknowledgement within 72 hours. Fixes target the upcoming stable line; expect a release within 14 days of confirmation once `1.x.y` is generally available.

## Scope

Security reports are accepted for all `@oidfed/*` packages:
- `@oidfed/core` — trust chain resolution and validation
- `@oidfed/authority` — federation endpoint handlers
- `@oidfed/leaf` — entity configuration serving
- `@oidfed/oidc` — registration protocol handling
- `@oidfed/cli` — command-line interface

The following applications are included in scope for security reports. All are read-only, client-side only tools; reports are welcome but will be treated as lower severity:

- **Home** (`oidfed/home`): The project home page.
- **Explorer** (`oidfed/explorer`): The `@oidfed/explorer` browser app.
- **Learn** (`oidfed/learn`): The practical guide to learning OpenID Federation.

## Out of Scope

- Vulnerabilities in upstream dependencies (report to: `jose`, `zod`, `commander`, etc.)
- Issues requiring physical access to a host
- Social engineering attacks
