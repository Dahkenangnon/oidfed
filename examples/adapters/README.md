# PostgreSQL storage adapter example

Copy [postgres.ts](postgres.ts) into your app. Install `pg` and `@oidfed/core`, and add `@types/pg` for TypeScript.

## Local setup

Use a local database for this example. Run provisioning once to create the `oidfed` schema. Use the same stable namespace for all replicas of one federation entity.

```ts
import { composeFederationStorage, MemoryFederationStorage } from "@oidfed/core";
import { Pool } from "pg";
import { postgresStorage, provisionPostgresStorage } from "./postgres.js";

const pool = new Pool({ connectionString: databaseUrl });
await provisionPostgresStorage(pool);
const namespace = "https://anchor.example";
const base = postgresStorage({ pool, namespace });
const cache = new MemoryFederationStorage({ namespace, capabilities: ["cache", "namespace"] });
const storage = composeFederationStorage({ base, cache });
```

Pass `storage` to `TrustAnchor.create`, `Intermediate.create`, or `Leaf.create` with the rest of the host configuration. Attached roles inherit the same handle. The host closes its pool or client on shutdown. Handles returned by `withNamespace` share those connections and isolate stored data by namespace.

The composed handle exposes subordinates, Trust Marks, subordinate events, Collection, replay, and cache.

```ts
import { assertStorageCapabilities } from "@oidfed/core";

assertStorageCapabilities(storage, ["trustMark:read", "entityCollection"]);
const mark = await storage.trustMark.status(trustMarkJwt);
const snapshot = await storage.entityCollection.current(anchorId);
```

Records are addressed by the exact `(namespace, kind, id)` tuple. PostgreSQL indexes fixed-width SHA-256 digests for the namespace and ID so multibyte identifiers fit. Queries compare the original values and reject conflicting writes. PostgreSQL stores `payload` as `jsonb`. The adapter validates each payload against its kind before writing and after reading. Match the host’s `algorithmRegistry`, `customPolicyOperators`, `trustMarkProfiles`, and `maxCompactBytes` when it configures them.

The example uses a process-local cache. For a shared cache, pass a cache handle with the same namespace to `composeFederationStorage`.

## Production setup

Run `provisionPostgresStorage` in your deployment’s migration step with a role that owns the `oidfed` schema. Review and version the schema changes in that migration. Start the application with a separate role. Give it connection rights, schema usage, and table data privileges. The application pool should use a role without schema creation or table ownership privileges.

For an earlier example layout, provision a fresh database and follow the [offline import steps](../../docs/features/11.6.storage-adapters.md#import-records-into-the-postgresql-layout).

For an existing login role named `oidfed_app` and database named `federation`, these are example grants and limits. Set the timeouts for your workload and keep lock waits shorter than the statement timeout.

```sql
GRANT USAGE ON SCHEMA oidfed TO oidfed_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA oidfed TO oidfed_app;

ALTER ROLE oidfed_app IN DATABASE federation SET search_path = pg_catalog, oidfed;
ALTER ROLE oidfed_app IN DATABASE federation SET lock_timeout = '1s';
ALTER ROLE oidfed_app IN DATABASE federation SET statement_timeout = '5s';
ALTER ROLE oidfed_app IN DATABASE federation SET idle_in_transaction_session_timeout = '10s';
```

Connect to the writable database with TLS certificate verification. Supply the deployment's CA and a URL for the application role. Keep TLS policy in the pool configuration and omit conflicting TLS parameters from the URL.

```ts
import { Pool } from "pg";
import { postgresStorage } from "./postgres.js";

const pool = new Pool({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 3000,
  ssl: { ca: postgresCa, rejectUnauthorized: true },
});
const storage = postgresStorage({ pool, namespace: "https://anchor.example" });
```

Namespaces scope queries under the same database credentials. Choose them from trusted host configuration. Use separate roles and databases when the applications need independent database access.

## Queries and limits

The namespace guard serializes writes across clients. Within a scope, the adapter runs each complete repository call in order. Await all calls in the callback. Keep network and other external work outside the scope because a serialization failure or deadlock can rerun the callback. An ambiguous commit outcome requires reconciliation against the database before retrying the operation.

PostgreSQL filters subordinate candidates and scans them in keyset batches. Derived rows index the subjects, types, and issuers of Trust Marks. Core applies mark eligibility before the adapter selects the newest record or returns a page. Store writes go through the adapter to keep the lookup data and payloads consistent.

Replay checks the exact key, expiry, and live capacity under the namespace guard with a bounded SQL query. Outer storage transactions keep their serializable isolation. The adapter backs off between retries after a confirmed serialization failure or deadlock. Replay and Collection expiry use the database clock by default. PostgreSQL stores payloads as `jsonb`, which excludes NUL characters and unpaired UTF-16 surrogates even when a generic JSON encoder accepts them.

Unpaged listing can return all matching records. Event history reads and appends transfer a complete history for one subject. Collection publishes its snapshot and current pointer in one transaction. Publication scans retained snapshots. Cursor saves use an indexed check of live capacity and exact cursor identity. Size the retention window and `maxSnapshots` and `maxCursors` limits for the deployment. An expired cursor or an unavailable historical snapshot produces `page_not_found`.

### Prune expired records

The adapter removes at most 1,000 expired replay claims and cursors per maintenance pass. Writes trigger a pass at most once per 60 seconds per handle by default. Replicas serialize each pass under the same namespace guard. Expired claims can be replaced and expired cursors stop counting toward capacity even before cleanup.

To set your own cadence, set `cleanupIntervalSeconds: 0` and schedule `await storage.pruneExpired()` from an operator job for each active namespace. Use `pruneExpired(batchSize)` to choose a smaller batch. Pruning uses the same clock as the adapter. Hosts should also schedule cleanup for inactive namespaces if physical retention matters.

## Verify the adapter

After `pnpm --filter '@oidfed/core...' build`, run `pnpm test:storage:adapters`. It starts PostgreSQL 18.6 in Docker, runs the contract and regression tests, and checks that a Collection cursor resumes after a restart.

[Storage API](../../docs/api/core/storage.md) · [Migration guide](../../docs/api/migration-v3.md#federation-storage)
