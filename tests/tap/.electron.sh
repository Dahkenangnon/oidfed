#!/usr/bin/env bash
set -e
./node_modules/.bin/esbuild \
  --log-level=warning \
  --format=esm \
  --bundle \
  --platform=node \
  --target=esnext \
  --external:electron \
  --outfile=tests/tap/.build/run-electron.js \
  tests/tap/run-electron.ts

./node_modules/.bin/electron --no-sandbox tests/tap/.build/run-electron.js
