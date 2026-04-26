import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
	DEFAULT_MAX_CHAIN_DEPTH,
	err,
	FederationErrorCode,
	federationError,
	JWKSetSchema,
	ok,
	type Result,
} from "@oidfed/core";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const MAX_CHAIN_DEPTH_LIMIT = 100;

export const TrustAnchorConfigSchema = z
	.object({
		entity_id: z.string(),
		jwks: JWKSetSchema.optional(),
	})
	.strict();

export const ConfigSchema = z
	.object({
		trust_anchors: z.array(TrustAnchorConfigSchema).default([]),
		http_timeout_ms: z.number().int().positive().default(10_000),
		max_chain_depth: z
			.number()
			.int()
			.positive()
			.max(MAX_CHAIN_DEPTH_LIMIT)
			.default(DEFAULT_MAX_CHAIN_DEPTH),
	})
	.strict();

export type Config = z.infer<typeof ConfigSchema>;

export const DEFAULT_CONFIG: Config = {
	trust_anchors: [],
	http_timeout_ms: 10_000,
	max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
};

export function configDir(): string {
	return join(homedir(), ".oidfed");
}

export function configPath(): string {
	return join(configDir(), "config.yaml");
}

/**
 * Load the CLI configuration.
 *
 * Path resolution order:
 *   1. The `path` argument if supplied (typically from `--config`).
 *   2. `process.env.OIDFED_CONFIG_PATH` if set.
 *   3. The default `~/.oidfed/config.yaml`.
 *
 * Missing files (ENOENT) silently produce DEFAULT_CONFIG; YAML or schema
 * validation errors are returned as `Result.err`.
 */
export async function loadConfig(path?: string): Promise<Result<Config>> {
	const filePath = path ?? process.env.OIDFED_CONFIG_PATH ?? configPath();
	let raw: string;
	try {
		raw = await readFile(filePath, "utf-8");
	} catch (e: unknown) {
		if (e instanceof Error && "code" in e && e.code === "ENOENT") {
			return ok(DEFAULT_CONFIG);
		}
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Failed to read config: ${e instanceof Error ? e.message : String(e)}`,
			),
		);
	}

	let parsed: unknown;
	try {
		parsed = parseYaml(raw);
	} catch (e: unknown) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Invalid YAML in config: ${e instanceof Error ? e.message : String(e)}`,
			),
		);
	}

	const result = ConfigSchema.safeParse(parsed);
	if (!result.success) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Invalid config: ${result.error.message}`,
			),
		);
	}

	return ok(result.data);
}
