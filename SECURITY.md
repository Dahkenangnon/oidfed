# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (pre-release) | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by email to **dah.kenangnon@gmail.com**. Include:
- A description of the vulnerability
- Steps to reproduce
- Affected package(s) and version(s)
- Any suggested fix or patch (optional)

You will receive an acknowledgement within 72 hours. We aim to release a fix within 14 days of confirmation.

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
- **Learn** (`oidfed/learn`): The practical guide to learning OID Federation.


## Out of Scope

- Vulnerabilities in upstream dependencies (report to: `jose`, `zod`, `commander`, etc.)
- Issues requiring physical access to a host
- Social engineering attacks
