import {
	applyMetadataPolicy,
	type ParsedEntityStatement,
	resolveMetadataPolicy,
} from "@oidfed/core";
import { useMemo } from "react";

export interface PolicyLevel {
	readonly level: number;
	readonly issuer: string | null;
	readonly metadata: Record<string, Record<string, unknown>>;
	readonly error: string | null;
}

export function usePolicyLevelDiff(
	statements: readonly ParsedEntityStatement[] | undefined,
): readonly PolicyLevel[] {
	return useMemo(() => {
		if (!statements || statements.length < 2) return [];

		const ec = statements[0];
		if (!ec) return [];

		const leafMetadata = (ec.payload.metadata ?? {}) as Record<string, Record<string, unknown>>;

		const levels: PolicyLevel[] = [
			{
				level: 0,
				issuer: null,
				metadata: leafMetadata,
				error: null,
			},
		];

		// Subordinate statements are indices 1..N-2 (N-1 is TA EC)
		const subordinates = statements.slice(1, -1);
		if (subordinates.length === 0) return levels;

		let currentMetadata = structuredClone(leafMetadata) as Record<string, Record<string, unknown>>;

		for (let i = 0; i < subordinates.length; i++) {
			const stmt = subordinates[i] as ParsedEntityStatement;
			const issuer = String(stmt.payload.iss ?? "unknown");

			// Build a slice of subordinates up to this level and resolve merged policy
			const slice = subordinates.slice(0, i + 1);
			const mergeResult = resolveMetadataPolicy([...slice]);

			if (!mergeResult.ok) {
				levels.push({
					level: i + 1,
					issuer,
					metadata: currentMetadata,
					error: `Policy merge error: ${mergeResult.error.description}`,
				});
				continue;
			}

			const applyResult = applyMetadataPolicy(leafMetadata, mergeResult.value);

			if (!applyResult.ok) {
				levels.push({
					level: i + 1,
					issuer,
					metadata: currentMetadata,
					error: `Policy apply error: ${applyResult.error.description}`,
				});
				continue;
			}

			currentMetadata = applyResult.value as Record<string, Record<string, unknown>>;
			levels.push({
				level: i + 1,
				issuer,
				metadata: currentMetadata,
				error: null,
			});
		}

		return levels;
	}, [statements]);
}
