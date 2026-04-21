import {
	compareTrustAnchorKeys,
	decodeEntityStatement,
	err,
	FederationEndpoint,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	type HttpClient,
	type JWKSet,
	ok,
	type Result,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import { extractJwks, parseEntityIdOrError } from "../util/entity-id.js";
import type { Logger } from "../util/logger.js";

export interface HealthDeps {
	readonly httpClient: HttpClient;
	readonly formatter: OutputFormatter;
	readonly logger: Logger;
	readonly readFile: (path: string) => Promise<string>;
}

export interface HealthArgs {
	readonly entityId: string;
	readonly taJwks?: string | undefined;
}

export async function handler(args: HealthArgs, deps: HealthDeps): Promise<Result<string>> {
	const eidResult = parseEntityIdOrError(args.entityId);
	if (!eidResult.ok) return eidResult;
	const eid = eidResult.value;

	const checks: { endpoint: string; status: string; time_ms: number }[] = [];

	// Check well-known endpoint
	const ecStart = Date.now();
	const ecResult = await fetchEntityConfiguration(eid, { httpClient: deps.httpClient });
	checks.push({
		endpoint: WELL_KNOWN_OPENID_FEDERATION,
		status: ecResult.ok ? "ok" : "error",
		time_ms: Date.now() - ecStart,
	});

	// Detect available endpoints from EC metadata
	if (ecResult.ok) {
		const decoded = decodeEntityStatement(ecResult.value);
		if (decoded.ok) {
			const payload = decoded.value.payload as Record<string, unknown>;
			const metadata = payload.metadata as Record<string, Record<string, unknown>> | undefined;
			const fedEntity = metadata?.federation_entity;

			const endpointsToCheck: {
				name: string;
				key: string;
				method?: string | undefined;
				headers?: Record<string, string> | undefined;
				body?: string | undefined;
			}[] = [
				{ name: FederationEndpoint.List, key: "federation_list_endpoint" },
				{ name: FederationEndpoint.Fetch, key: "federation_fetch_endpoint" },
				{ name: FederationEndpoint.Resolve, key: "federation_resolve_endpoint" },
				{
					name: FederationEndpoint.TrustMarkStatus,
					key: "federation_trust_mark_status_endpoint",
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({ trust_mark: "health-check" }).toString(),
				},
			];

			for (const ep of endpointsToCheck) {
				const url = fedEntity?.[ep.key] as string | undefined;
				if (url) {
					const start = Date.now();
					try {
						const init: RequestInit = {};
						if (ep.method) init.method = ep.method;
						if (ep.headers) init.headers = ep.headers;
						if (ep.body) init.body = ep.body;
						const resp = await deps.httpClient(url, init);
						checks.push({
							endpoint: ep.name,
							status: resp.ok || resp.status === 400 ? "ok" : `error (${resp.status})`,
							time_ms: Date.now() - start,
						});
					} catch {
						checks.push({ endpoint: ep.name, status: "unreachable", time_ms: Date.now() - start });
					}
				}
			}
		}
	}

	// TA key comparison if --ta-jwks provided
	let keyComparison: unknown;
	if (args.taJwks && ecResult.ok) {
		let taJwksRaw: string;
		try {
			taJwksRaw = await deps.readFile(args.taJwks);
		} catch {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`Cannot read TA JWKS file: ${args.taJwks}`,
				),
			);
		}

		let fileJwks: JWKSet;
		try {
			fileJwks = JSON.parse(taJwksRaw) as JWKSet;
		} catch {
			return err(
				federationError(FederationErrorCode.InvalidRequest, "TA JWKS file is not valid JSON"),
			);
		}

		const decoded = decodeEntityStatement(ecResult.value);
		if (decoded.ok) {
			const payload = decoded.value.payload as Record<string, unknown>;
			const jwksResult = extractJwks(payload);
			if (!jwksResult.ok) return jwksResult;
			keyComparison = compareTrustAnchorKeys(jwksResult.value, fileJwks, eid);
		}
	}

	const allOk = checks.every((c) => c.status === "ok");
	return ok(
		deps.formatter.format({
			entity_id: args.entityId,
			healthy: allOk,
			checks,
			...(keyComparison ? { key_comparison: keyComparison } : {}),
		}),
	);
}

export function register(program: Command, deps: HealthDeps): void {
	program
		.command("health")
		.description("Check health of federation endpoints for an entity")
		.argument("<entity-id>", "Entity ID to check")
		.option("--ta-jwks <path>", "Path to out-of-band TA JWKS file for key comparison")
		.action(async (entityIdArg: string, opts: { taJwks?: string }) => {
			const result = await handler({ entityId: entityIdArg, taJwks: opts.taJwks }, deps);
			if (result.ok) {
				process.stdout.write(`${result.value}\n`);
			} else {
				deps.logger.error(result.error.description);
				process.exitCode = 1;
			}
		});
}
