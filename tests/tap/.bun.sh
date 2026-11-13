#!/usr/bin/env bash
set -e
bun run --tsconfig-override "$(pwd)/tests/tap/tsconfig.json" tests/tap/run-bun.ts
