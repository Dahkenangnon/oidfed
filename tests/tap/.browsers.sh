#!/usr/bin/env bash
set -e
./node_modules/.bin/esbuild \
  --log-level=warning \
  --tsconfig=tests/tap/tsconfig.json \
  --format=esm \
  --bundle \
  --minify \
  --target=esnext \
  --outfile=tests/tap/.build/run-browser.js \
  tests/tap/run-browser.ts

: "${BROWSER:=chromium}"
npx playwright test --project="$BROWSER"
