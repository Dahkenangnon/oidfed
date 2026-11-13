#!/usr/bin/env bash
set -e
deno run --import-map=tests/tap/.deno-imports.json --allow-read --allow-env --unstable-sloppy-imports tests/tap/run-deno.ts
