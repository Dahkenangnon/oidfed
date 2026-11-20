# Security Policy

## Supported Versions

When version 3 is published, security fixes will target the release lines below. Use the latest patch in the supported line for your package.

| Packages | Supported versions after the v3 release |
| --- | --- |
| `@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/wallet`, and `@oidfed/cli` | `3.x` |
| `@oidfed/crypto` | `1.x` |

Earlier release lines of those packages and prereleases will stop receiving security fixes when v3 is published.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

GitHub Private Vulnerability Reporting will be enabled via the repository Security tab; check there for the current status. In the meantime, report vulnerabilities by email to **dah.kenangnon@gmail.com**. Include:
- A description of the vulnerability
- Steps to reproduce
- Affected package(s) and version(s)
- Any suggested fix or patch (optional)

You will receive an acknowledgement within 72 hours. Confirmed vulnerabilities are triaged for a fix release within 14 days whenever a coordinated disclosure timeline allows it.

## Scope

Security reports are accepted for all `@oidfed/*` packages:
- `@oidfed/core` — trust chain resolution and validation
- `@oidfed/crypto` — crypto adapters, signing, and keyrings
- `@oidfed/authority` — federation endpoint handlers
- `@oidfed/leaf` — entity configuration serving
- `@oidfed/oidc` — registration protocol handling
- `@oidfed/wallet` — wallet federation roles, attestations, and request validation
- `@oidfed/cli` — command-line interface

The following applications are included in scope for security reports. All are read-only, client-side only tools; reports are welcome but will be treated as lower severity:

- **Home** (`oidfed/home`): The project home page.
- **Explorer** (`oidfed/explorer`): The `@oidfed/explorer` browser app.
- **Learn** (`oidfed/learn`): The practical guide to learning OpenID Federation.

## Out of Scope

- Vulnerabilities in upstream dependencies (report to: `jose`, `zod`, `commander`, etc.)
- Issues requiring physical access to a host
- Social engineering attacks
