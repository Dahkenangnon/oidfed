import {
	applyMetadataPolicy,
	decodeEntityStatement,
	type EntityId,
	fetchEntityConfiguration,
	isOk,
	resolveMetadataPolicy,
	resolveTrustChains,
	type TrustAnchorSet,
	validateEntityId,
} from "@oidfed/core";
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@oidfed/ui";
import { AlertTriangle, GitCompare } from "lucide-react";
import { useCallback, useState } from "react";
import { JsonTree } from "@/components/shared/json-tree";
import { usePageTitle } from "@/hooks/use-page-title";
import { useSettings } from "@/hooks/use-settings";
import { ResolvedMetadataDiff } from "../trust-chain/components/resolved-metadata-diff";
import { DiffForm } from "./components/diff-form";

interface DiffParams {
	readonly entityId: string;
	readonly taA: string;
	readonly taB: string;
}

interface DiffResult {
	readonly resolvedA: Record<string, Record<string, unknown>>;
	readonly resolvedB: Record<string, Record<string, unknown>>;
	readonly policyA: Record<string, unknown>;
	readonly policyB: Record<string, unknown>;
	readonly taA: string;
	readonly taB: string;
}

async function buildTaSet(
	taEntityId: string,
	httpTimeoutMs: number,
	signal: AbortSignal,
): Promise<TrustAnchorSet> {
	const validated = validateEntityId(taEntityId);
	if (!validated.ok) throw new Error(validated.error.description);

	const ecResult = await fetchEntityConfiguration(validated.value, { httpTimeoutMs, signal });
	if (!ecResult.ok) throw new Error(`Failed to fetch TA EC: ${ecResult.error.description}`);

	const decoded = decodeEntityStatement(ecResult.value);
	if (!decoded.ok) throw new Error(`Failed to decode TA EC: ${decoded.error.description}`);

	const payload = decoded.value.payload as Record<string, unknown>;
	const jwks = payload.jwks as { keys: readonly Record<string, unknown>[] } | undefined;
	if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
		throw new Error(`TA has no JWKS: ${taEntityId}`);
	}

	const map = new Map<EntityId, Readonly<{ jwks: { keys: readonly Record<string, unknown>[] } }>>();
	map.set(taEntityId as EntityId, { jwks });
	return map as unknown as TrustAnchorSet;
}

export function MetadataDiffPage() {
	usePageTitle("Metadata Diff — OidFed Explorer");
	const [settings] = useSettings();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<DiffResult | null>(null);

	const handleSubmit = useCallback(
		async (params: DiffParams) => {
			setLoading(true);
			setError(null);
			setResult(null);

			const controller = new AbortController();
			const { httpTimeoutMs, maxChainDepth } = settings;

			try {
				const validated = validateEntityId(params.entityId);
				if (!validated.ok) throw new Error(validated.error.description);

				const [taSetA, taSetB] = await Promise.all([
					buildTaSet(params.taA, httpTimeoutMs, controller.signal),
					buildTaSet(params.taB, httpTimeoutMs, controller.signal),
				]);

				const [resultA, resultB] = await Promise.all([
					resolveTrustChains(validated.value, taSetA, {
						httpTimeoutMs,
						maxChainDepth,
						signal: controller.signal,
					}),
					resolveTrustChains(validated.value, taSetB, {
						httpTimeoutMs,
						maxChainDepth,
						signal: controller.signal,
					}),
				]);

				const chainA = resultA.chains[0];
				const chainB = resultB.chains[0];

				if (!chainA)
					throw new Error(
						`No chain found via TA A. ${resultA.errors[0]?.description ?? "Unknown error"}`,
					);
				if (!chainB)
					throw new Error(
						`No chain found via TA B. ${resultB.errors[0]?.description ?? "Unknown error"}`,
					);

				// Decode raw JWT strings into ParsedEntityStatement
				const decodeAll = (jwts: ReadonlyArray<string>) =>
					jwts.map((jwt) => {
						const r = decodeEntityStatement(jwt);
						if (!r.ok) throw new Error(`Failed to decode chain statement: ${r.error.description}`);
						return r.value;
					});

				const stmtsA = decodeAll(chainA.statements);
				const stmtsB = decodeAll(chainB.statements);

				// Leaf EC metadata (index 0)
				const leafMetadataA = (stmtsA[0]?.payload.metadata ?? {}) as Record<
					string,
					Record<string, unknown>
				>;
				const leafMetadataB = (stmtsB[0]?.payload.metadata ?? {}) as Record<
					string,
					Record<string, unknown>
				>;

				// Subordinate statements for policy (slice 1 to -1)
				const subordinatesA = stmtsA.slice(1, -1);
				const subordinatesB = stmtsB.slice(1, -1);

				const policyResultA =
					subordinatesA.length > 0 ? resolveMetadataPolicy(subordinatesA) : null;
				const policyResultB =
					subordinatesB.length > 0 ? resolveMetadataPolicy(subordinatesB) : null;

				let resolvedA: Record<string, Record<string, unknown>> = leafMetadataA;
				let resolvedB: Record<string, Record<string, unknown>> = leafMetadataB;

				if (policyResultA && isOk(policyResultA)) {
					const applied = applyMetadataPolicy(leafMetadataA, policyResultA.value);
					if (isOk(applied)) resolvedA = applied.value as Record<string, Record<string, unknown>>;
				}

				if (policyResultB && isOk(policyResultB)) {
					const applied = applyMetadataPolicy(leafMetadataB, policyResultB.value);
					if (isOk(applied)) resolvedB = applied.value as Record<string, Record<string, unknown>>;
				}

				setResult({
					resolvedA,
					resolvedB,
					policyA:
						policyResultA && isOk(policyResultA)
							? (policyResultA.value as Record<string, unknown>)
							: {},
					policyB:
						policyResultB && isOk(policyResultB)
							? (policyResultB.value as Record<string, unknown>)
							: {},
					taA: params.taA,
					taB: params.taB,
				});
			} catch (err) {
				setError(err instanceof Error ? err.message : "Unknown error");
			} finally {
				setLoading(false);
			}
		},
		[settings],
	);

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Metadata Diff</h1>
				<p className="text-sm text-muted-foreground">
					Compare resolved metadata for the same entity via two different trust anchors
				</p>
			</div>

			<DiffForm loading={loading} onSubmit={handleSubmit} />

			{!loading && !error && !result && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<GitCompare className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Select an entity and two trust anchors above to compare resolved metadata
						</p>
					</div>
				</div>
			)}

			{loading && (
				<div className="space-y-3">
					<Skeleton className="h-8 w-48" />
					<Skeleton className="h-64 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{error}</p>
				</div>
			)}

			{result && !loading && (
				<Tabs defaultValue="diff">
					<TabsList>
						<TabsTrigger value="diff">Diff</TabsTrigger>
						<TabsTrigger value="policy-a">Policy via TA A</TabsTrigger>
						<TabsTrigger value="policy-b">Policy via TA B</TabsTrigger>
					</TabsList>

					<TabsContent value="diff" className="mt-4">
						<div className="space-y-2">
							<div className="flex flex-wrap gap-4 text-xs text-muted-foreground font-mono">
								<span>Left: {result.taA}</span>
								<span>Right: {result.taB}</span>
							</div>
							<ResolvedMetadataDiff
								originalMetadata={result.resolvedA}
								resolvedMetadata={result.resolvedB}
							/>
						</div>
					</TabsContent>

					<TabsContent value="policy-a" className="mt-4">
						<JsonTree data={result.policyA} collapsed={2} />
					</TabsContent>

					<TabsContent value="policy-b" className="mt-4">
						<JsonTree data={result.policyB} collapsed={2} />
					</TabsContent>
				</Tabs>
			)}
		</div>
	);
}
