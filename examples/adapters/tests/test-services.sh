#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."
pg="oidfed-storage-contract-$$-postgres"

wait_for_postgres() {
	for ((attempt=0; attempt<45; attempt++)); do
		if docker exec "$pg" pg_isready -h 127.0.0.1 >/dev/null 2>&1; then
			local address
			address="$(docker port "$pg" 5432)"
			export OIDFED_STORAGE_POSTGRES="postgres://postgres@127.0.0.1:${address##*:}/postgres"
			return
		fi
		sleep 1
	done
	echo "PostgreSQL readiness probe failed" >&2
	return 1
}

docker run -d --name "$pg" -p 127.0.0.1::5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18.6-bookworm >/dev/null
trap 'docker rm -fv "$pg" >/dev/null 2>&1 || true' EXIT
wait_for_postgres
pnpm --filter @oidfed/storage-examples test

cursor="$(pnpm --filter @oidfed/storage-examples exec tsx tests/collection-restart.ts seed "$pg")"
docker restart "$pg" >/dev/null
wait_for_postgres
pnpm --filter @oidfed/storage-examples exec tsx tests/collection-restart.ts verify "$pg" "$cursor"
