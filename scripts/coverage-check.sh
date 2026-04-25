#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Run the TAP Node suite under c8 to produce per-package coverage data.
npx c8 tsx tests/tap/run-node.ts

# Enforce per-package thresholds against the collected data.
# core, authority, leaf: 90 statements / 85 branches / 90 functions / 90 lines
# oidc: 85 statements / 75 branches / 85 functions / 85 lines (initial floor)
npx c8 check-coverage --include 'packages/core/src/**' \
	--statements 90 --branches 85 --functions 90 --lines 90

npx c8 check-coverage --include 'packages/authority/src/**' \
	--statements 90 --branches 85 --functions 90 --lines 90

npx c8 check-coverage --include 'packages/leaf/src/**' \
	--statements 90 --branches 85 --functions 90 --lines 90

npx c8 check-coverage --include 'packages/oidc/src/**' \
	--statements 85 --branches 75 --functions 85 --lines 85
