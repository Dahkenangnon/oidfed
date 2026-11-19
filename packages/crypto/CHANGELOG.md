# Changelog

## [Unreleased]

## [1.0.0] - 2026-11-18

- Add portable engine, signer and keyring contracts with independent Web Crypto and optional JOSE entrypoints.
- Add bounded inspection and strict parsing for compact JSON JWS, plus JWK, base64url and ECDSA representation utilities.
- Use portable UTF-8 and detached JWK copies without host encoding or cloning globals.
- Make signing-input and signature bytes authoritative across verification backends.
- Add immutable signing snapshots and in-memory key publication, activation, retirement and revocation history, including recorded publication times.
