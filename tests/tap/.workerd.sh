#!/usr/bin/env bash
set -e

COMPATIBILITY_DATE=$(node -p "new Date().toISOString().slice(0,10)")

./node_modules/.bin/esbuild \
  --log-level=warning \
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

run_test() { generate_capnp "$1"; npx workerd test --verbose "$(pwd)/tests/tap/.workerd.capnp"; }

run_test "[]"
NO_COMPAT=$?
run_test '["nodejs_compat"]'
COMPAT=$?
test $NO_COMPAT -eq 0 && test $COMPAT -eq 0
