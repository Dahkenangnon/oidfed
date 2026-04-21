import { Badge, Button, Input, Skeleton } from "@oidfed/ui";
import { AlertTriangle, Clock, HeartPulse, List, RefreshCw, Search, Square, X } from "lucide-react";
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";
import { NoTrustAnchorsWarning } from "../trust-chain/components/no-trust-anchors-warning";
import { useTrustAnchorSet } from "../trust-chain/hooks/use-trust-anchor-set";
import { BatchExpiryPanel } from "./components/batch-expiry-panel";
import { BatchHealthPanel } from "./components/batch-health-panel";
import { SubordinateFiltersPanel } from "./components/subordinate-filters";
import { SubordinateList } from "./components/subordinate-list";
import { useBatchExpiry } from "./hooks/use-batch-expiry";
import { useBatchHealth } from "./hooks/use-batch-health";
import { useSubordinateEnrichment } from "./hooks/use-subordinate-enrichment";
import type { SubordinateFilters } from "./hooks/use-subordinate-list";
import { useSubordinateList } from "./hooks/use-subordinate-list";

export function SubordinateListingPage() {
	usePageTitle("Subordinates — OidFed Explorer");
	const [searchParams, setSearchParams] = useSearchParams();
	const initialEntity = searchParams.get("entity") ?? "";
	const [authorityId, setAuthorityId] = useState(initialEntity);
	const [submittedId, setSubmittedId] = useState<string | undefined>(initialEntity || undefined);
	const [filters, setFilters] = useState<SubordinateFilters>({});

	const { entityIds, listEndpoint, loading, error, refetch } = useSubordinateList(
		submittedId,
		filters,
	);

	const { enrichment, loading: enrichmentLoading } = useSubordinateEnrichment(entityIds);

	const {
		trustAnchorSet,
		hasTrustAnchors,
		anchorsWithoutJwks,
		failedAnchors,
		loading: loadingAnchors,
	} = useTrustAnchorSet();

	const batchHealth = useBatchHealth();
	const batchExpiry = useBatchExpiry();

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmed = authorityId.trim();
			if (trimmed) {
				setSubmittedId(trimmed);
				setSearchParams({ entity: trimmed });
			}
		},
		[authorityId, setSearchParams],
	);

	const handleFiltersChange = useCallback((newFilters: SubordinateFilters) => {
		setFilters(newFilters);
	}, []);

	const hasEntities = entityIds.length > 0 && !loading;

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Subordinate Listing</h1>
				<p className="text-sm text-muted-foreground">
					Browse subordinates of any authority via the federation list endpoint
				</p>
			</div>

			<form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
				<div className="relative flex-1">
					<Input
						type="url"
						placeholder="https://authority.example.com — Enter authority Entity ID"
						value={authorityId}
						onChange={(e) => setAuthorityId(e.target.value)}
						className="pr-8"
					/>
					{authorityId && (
						<button
							type="button"
							onClick={() => setAuthorityId("")}
							className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
						>
							<X className="size-4" />
						</button>
					)}
				</div>
				<Button type="submit" disabled={!authorityId.trim() || loading}>
					<Search className="mr-2 size-4" />
					List
				</Button>
				{submittedId && (
					<Button type="button" variant="outline" onClick={refetch} disabled={loading}>
						<RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
					</Button>
				)}
			</form>

			{!submittedId && !loading && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<List className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">Enter an authority entity ID above to browse its subordinates</p>
					</div>
				</div>
			)}

			{submittedId && <SubordinateFiltersPanel onChange={handleFiltersChange} />}

			{loading && (
				<div className="space-y-2">
					{Array.from({ length: 5 }).map((_, i) => (
						// biome-ignore lint/suspicious/noArrayIndexKey: skeleton placeholders
						<Skeleton key={i} className="h-10 w-full" />
					))}
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{error}</p>
				</div>
			)}

			{submittedId && !loading && !error && listEndpoint === null && (
				<div className="rounded-lg border border-warning/50 bg-warning/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-warning-foreground shrink-0 mt-0.5" />
					<div>
						<p className="text-sm font-medium text-warning-foreground">
							No federation_list_endpoint declared
						</p>
						<p className="text-sm text-warning-foreground/80">
							This entity does not expose a list endpoint in its federation_entity metadata.
						</p>
					</div>
				</div>
			)}

			{listEndpoint && !loading && (
				<div className="flex items-center gap-2">
					<span className="text-xs text-muted-foreground">List endpoint:</span>
					<Badge variant="outline" className="font-mono text-xs">
						{listEndpoint}
					</Badge>
				</div>
			)}

			{hasEntities && (
				<div className="flex flex-wrap gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => batchHealth.start(entityIds)}
						disabled={batchHealth.running}
					>
						<HeartPulse className="mr-1.5 size-3.5" />
						Health Check
					</Button>
					{batchHealth.running && (
						<Button variant="outline" size="sm" onClick={batchHealth.cancel}>
							<Square className="mr-1.5 size-3.5" />
							Stop
						</Button>
					)}
					<Button
						variant="outline"
						size="sm"
						onClick={() => {
							if (trustAnchorSet) batchExpiry.start(entityIds, trustAnchorSet);
						}}
						disabled={batchExpiry.running || !trustAnchorSet}
					>
						<Clock className="mr-1.5 size-3.5" />
						Expiry Scan
					</Button>
					{batchExpiry.running && (
						<Button variant="outline" size="sm" onClick={batchExpiry.cancel}>
							<Square className="mr-1.5 size-3.5" />
							Stop
						</Button>
					)}
				</div>
			)}

			{!loadingAnchors && !hasTrustAnchors && hasEntities && (
				<NoTrustAnchorsWarning
					anchorsWithoutJwks={anchorsWithoutJwks}
					failedAnchors={failedAnchors}
				/>
			)}

			{(batchHealth.running || batchHealth.results.size > 0) && (
				<BatchHealthPanel
					results={batchHealth.results}
					progress={batchHealth.progress}
					running={batchHealth.running}
				/>
			)}

			{(batchExpiry.running || batchExpiry.entries.length > 0) && (
				<BatchExpiryPanel
					entries={batchExpiry.entries}
					progress={batchExpiry.progress}
					running={batchExpiry.running}
				/>
			)}

			{!loading && (
				<SubordinateList
					entityIds={entityIds}
					enrichment={enrichment}
					enrichmentLoading={enrichmentLoading}
				/>
			)}
		</div>
	);
}
