#!/usr/bin/env bash
set -e

COMPATIBILITY_DATE=2026-11-19
WORKERD_VERSION=1.20261119.1

./node_modules/.bin/esbuild \
  --log-level=warning \
  --tsconfig=tests/tap/tsconfig.json \
  --format=esm \
  --bundle \
  --target=esnext \
  --outfile=tests/tap/.build/run-workerd.js \
  tests/tap/run-workerd.ts

generate_capnp() {
  local flags=$1
  cat > "$(pwd)/tests/tap/.workerd.capnp" <<EOT
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = .tapWorker)],
);
const tapWorker :Workerd.Worker = (
  modules = [(name = "worker", esModule = embed ".build/run-workerd.js")],
  compatibilityDate = "$COMPATIBILITY_DATE",
  compatibilityFlags = $flags
);
EOT
}

run_test() { generate_capnp "$1"; npx --yes "workerd@$WORKERD_VERSION" test --verbose "$(pwd)/tests/tap/.workerd.capnp"; }

run_test "[]"
run_test '["nodejs_compat"]'
