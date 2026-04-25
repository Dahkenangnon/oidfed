#!/usr/bin/env bash
set -e
deno run --allow-read --allow-env --unstable-sloppy-imports tests/tap/run-deno.ts
