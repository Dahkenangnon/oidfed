import type { TrustChain } from "@oidfed/core";
import { Badge, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@oidfed/ui";
import { CheckCircle, Link, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { useParams } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";
import { ChainComparisonView } from "./components/chain-comparison-view";
import { ChainExpirationBar } from "./components/chain-expiration-bar";
import { ChainForm } from "./components/chain-form";
import { ChainHeaderDisplay } from "./components/chain-header-display";
import { ChainSelector } from "./components/chain-selector";
import { ChainTimeline } from "./components/chain-timeline";
import { ConstraintPanel } from "./components/constraint-panel";
import { CriticalOperators } from "./components/critical-operators";
import { NoTrustAnchorsWarning } from "./components/no-trust-anchors-warning";
import { PolicyLevelDiffView } from "./components/policy-level-diff-view";
import { PolicyMergeView } from "./components/policy-merge-view";
import { ResolvedMetadataDiff } from "./components/resolved-metadata-diff";
import { TrustMarkList } from "./components/trust-mark-list";
import { useChainComparison } from "./hooks/use-chain-comparison";
import { useChainResolution } from "./hooks/use-chain-resolution";
import { useChainValidation } from "./hooks/use-chain-validation";
import { usePolicyLevelDiff } from "./hooks/use-policy-level-diff";
import { useTrustAnchorSet } from "./hooks/use-trust-anchor-set";

export function TrustChainPage() {
	usePageTitle("Trust Chain — OidFed Explorer");
	const { entityId: rawEntityId } = useParams<{ entityId?: string }>();
	const entityId = rawEntityId ? decodeURIComponent(rawEntityId) : undefined;

	const {
		trustAnchorSet,
		anchorsWithoutJwks,
		failedAnchors,
		loading: loadingAnchors,
	} = useTrustAnchorSet();
	const {
		chains,
		loading: loadingChains,
		error,
		refetch,
	} = useChainResolution(entityId, trustAnchorSet);
	const loading = loadingAnchors || loadingChains;

	const [selectedIndex, setSelectedIndex] = useState(0);
	const selectedChain: TrustChain | null = chains[selectedIndex] ?? null;

	const { details: validationDetails, loading: validating } = useChainValidation(
		selectedChain,
		trustAnchorSet,
	);

	const { chainAIndex, chainBIndex, selectA, selectB } = useChainComparison();
	const policyLevels = usePolicyLevelDiff(validationDetails?.chain?.statements);

	// Extract critical claims from chain statements
	const criticalClaims = useMemo(() => {
		if (!validationDetails?.chain) return [];
		const claims = new Set<string>();
		for (const stmt of validationDetails.chain.statements) {
			const crit = stmt.payload.metadata_policy_crit;
			if (Array.isArray(crit)) {
				for (const c of crit) {
					if (typeof c === "string") claims.add(c);
				}
			}
		}
		return [...claims];
	}, [validationDetails]);

	const constraintViolations = useMemo(() => {
		if (!validationDetails?.chain) return [];
		const violations: string[] = [];
		const stmts = validationDetails.chain.statements;
		const intermediates = stmts.length - 2;
		for (const stmt of stmts) {
			const c = stmt.payload.constraints as Record<string, unknown> | undefined;
			if (!c) continue;
			const maxPath = c.max_path_length as number | undefined;
			if (maxPath !== undefined && intermediates > maxPath) {
				violations.push(
					`max_path_length violated: ${intermediates} intermediate(s) > max ${maxPath} (from ${String(stmt.payload.iss)})`,
				);
			}
		}
		return violations;
	}, [validationDetails]);

	// Extract original leaf metadata from the EC (first element is always the leaf's own)
	const originalMetadata = useMemo(() => {
		if (!validationDetails?.chain) return {};
		const stmts = validationDetails.chain.statements;
		const ec = stmts[0];
		return (ec?.payload.metadata ?? {}) as Record<string, unknown>;
	}, [validationDetails]);

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Trust Chain Explorer</h1>
				<p className="text-sm text-muted-foreground">
					Resolve and visualize trust chains from any entity to configured trust anchors
				</p>
			</div>

			<ChainForm initialEntityId={entityId} loading={loading} onRefetch={refetch} />

			{!trustAnchorSet && !loadingAnchors && (
				<NoTrustAnchorsWarning
					anchorsWithoutJwks={anchorsWithoutJwks}
					failedAnchors={failedAnchors}
				/>
			)}

			{!loading && !error && chains.length === 0 && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<Link className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Enter an entity identifier above to resolve and visualize its trust chains
						</p>
					</div>
				</div>
			)}

			{loading && (
				<div className="space-y-4">
					<Skeleton className="h-8 w-48" />
					<Skeleton className="h-64 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
					<p className="text-sm text-destructive-foreground font-medium">Error</p>
					<p className="text-sm text-destructive-foreground/80 mt-1">{error}</p>
				</div>
			)}

			{chains.length > 0 && selectedChain && (
				<div className="space-y-6">
					<div className="flex items-center gap-4 flex-wrap">
						<ChainExpirationBar expiresAt={selectedChain.expiresAt} />
					</div>

					<ChainSelector
						chains={chains}
						selectedIndex={selectedIndex}
						onSelect={setSelectedIndex}
					/>

					{validationDetails && !validating && (
						<div className="flex items-center gap-2">
							{validationDetails.valid && constraintViolations.length === 0 ? (
								<Badge className="gap-1.5 bg-success/15 text-success-foreground border border-success/60 hover:bg-success/15">
									<CheckCircle className="size-3.5" />
									Chain Valid
								</Badge>
							) : (
								<Badge className="gap-1.5 bg-destructive/15 text-destructive-foreground border border-destructive/60 hover:bg-destructive/15">
									<XCircle className="size-3.5" />
									Chain Invalid
								</Badge>
							)}
							{constraintViolations.length > 0 && (
								<span className="text-xs text-muted-foreground">— see Constraints tab</span>
							)}
							{!validationDetails.valid && (
								<span className="text-xs text-muted-foreground">— see Timeline tab</span>
							)}
						</div>
					)}

					{validating && (
						<div className="space-y-2">
							<Skeleton className="h-6 w-32" />
							<Skeleton className="h-48 w-full" />
						</div>
					)}

					{validationDetails && (
						<Tabs defaultValue="timeline">
							<TabsList className="flex-wrap">
								<TabsTrigger value="timeline">Timeline</TabsTrigger>
								<TabsTrigger value="policy">Policy</TabsTrigger>
								<TabsTrigger value="metadata">Metadata</TabsTrigger>
								<TabsTrigger value="constraints">Constraints</TabsTrigger>
								<TabsTrigger value="trust-marks">Trust Marks</TabsTrigger>
								<TabsTrigger value="policy-diff">Policy Diff</TabsTrigger>
								<TabsTrigger value="comparison">Comparison</TabsTrigger>
								<TabsTrigger value="raw">Raw</TabsTrigger>
							</TabsList>

							<TabsContent value="timeline" className="mt-4">
								{validationDetails.chain ? (
									<ChainTimeline
										chain={validationDetails.chain}
										errors={validationDetails.errors}
									/>
								) : (
									<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 space-y-2">
										<p className="text-sm font-medium text-destructive-foreground">
											Chain validation failed
										</p>
										{validationDetails.errors.map((e, i) => (
											<p
												// biome-ignore lint/suspicious/noArrayIndexKey: errors lack stable unique ID
												key={`err-${i}-${e.code}`}
												className="text-xs text-destructive-foreground/80"
											>
												[{e.code}] {e.message}
											</p>
										))}
									</div>
								)}
							</TabsContent>

							<TabsContent value="policy" className="mt-4 space-y-4">
								{criticalClaims.length > 0 && <CriticalOperators criticalClaims={criticalClaims} />}
								{validationDetails.chain ? (
									<PolicyMergeView statements={validationDetails.chain.statements} />
								) : (
									<p className="text-sm text-muted-foreground">
										Chain validation required for policy view.
									</p>
								)}
							</TabsContent>

							<TabsContent value="metadata" className="mt-4">
								{validationDetails.chain ? (
									<ResolvedMetadataDiff
										originalMetadata={originalMetadata}
										resolvedMetadata={validationDetails.chain.resolvedMetadata}
									/>
								) : (
									<p className="text-sm text-muted-foreground">
										Chain validation required for metadata view.
									</p>
								)}
							</TabsContent>

							<TabsContent value="constraints" className="mt-4">
								{validationDetails.chain ? (
									<ConstraintPanel
										statements={validationDetails.chain.statements}
										violations={constraintViolations}
									/>
								) : (
									<p className="text-sm text-muted-foreground">
										Chain validation required for constraints view.
									</p>
								)}
							</TabsContent>

							<TabsContent value="trust-marks" className="mt-4">
								{validationDetails.chain ? (
									<TrustMarkList trustMarks={validationDetails.chain.trustMarks} />
								) : (
									<p className="text-sm text-muted-foreground">
										Chain validation required for trust marks view.
									</p>
								)}
							</TabsContent>

							<TabsContent value="policy-diff" className="mt-4">
								{validationDetails.chain ? (
									<PolicyLevelDiffView levels={policyLevels} />
								) : (
									<p className="text-sm text-muted-foreground">
										Chain validation required for policy diff view.
									</p>
								)}
							</TabsContent>

							<TabsContent value="comparison" className="mt-4">
								<ChainComparisonView
									chains={chains}
									chainAIndex={chainAIndex}
									chainBIndex={chainBIndex}
									onSelectA={selectA}
									onSelectB={selectB}
								/>
							</TabsContent>

							<TabsContent value="raw" className="mt-4">
								<ChainHeaderDisplay statements={[...selectedChain.statements]} />
							</TabsContent>
						</Tabs>
					)}
				</div>
			)}
		</div>
	);
}
