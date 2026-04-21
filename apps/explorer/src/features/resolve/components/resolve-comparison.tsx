import {
	Badge,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@oidfed/ui";
import { AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { ResolvedMetadataDiff } from "../../trust-chain/components/resolved-metadata-diff";
import type {
	ResolvePerTaError,
	ResolvePerTaOutcome,
	ResolvePerTaResult,
} from "../hooks/use-resolve-query";
import { ResolveResult } from "./resolve-result";

interface ResolveComparisonProps {
	readonly results: readonly ResolvePerTaOutcome[];
}

function extractHostname(entityId: string): string {
	try {
		return new URL(entityId).hostname;
	} catch {
		return entityId;
	}
}

function isSuccess(r: ResolvePerTaOutcome): r is ResolvePerTaResult {
	return r.responsePayload != null;
}

function isFailure(r: ResolvePerTaOutcome): r is ResolvePerTaError {
	return r.error != null;
}

export function ResolveComparison({ results }: ResolveComparisonProps) {
	const successes = useMemo(() => results.filter(isSuccess), [results]);
	const failureCount = useMemo(() => results.filter(isFailure).length, [results]);

	const [compareA, setCompareA] = useState(0);
	const [compareB, setCompareB] = useState(1);

	const canCompare = successes.length >= 2;

	// For single result, show it directly
	const single = results.length === 1 ? results[0] : undefined;
	if (single != null) {
		if (isFailure(single)) {
			return (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<div>
						<p className="text-sm font-medium">{extractHostname(single.trustAnchorId)}</p>
						<p className="text-sm text-destructive-foreground">{single.error}</p>
					</div>
				</div>
			);
		}
		return <ResolveResult payload={single.responsePayload} requestUrl={single.requestUrl} />;
	}

	const firstResult = results[0];
	if (firstResult == null) return null;

	const successA = successes[compareA];
	const successB = successes[compareB];

	return (
		<div className="space-y-4">
			{/* Summary */}
			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-sm">Resolution Summary</CardTitle>
				</CardHeader>
				<CardContent className="flex gap-3 text-sm">
					<Badge variant="secondary" className="gap-1">
						<CheckCircle2 className="size-3" />
						{successes.length} resolved
					</Badge>
					{failureCount > 0 && (
						<Badge variant="destructive" className="gap-1">
							<XCircle className="size-3" />
							{failureCount} failed
						</Badge>
					)}
				</CardContent>
			</Card>

			{/* Per-TA tabs + Compare */}
			<Tabs defaultValue={firstResult.trustAnchorId}>
				<TabsList className="flex-wrap h-auto gap-1">
					{results.map((r) => (
						<TabsTrigger key={r.trustAnchorId} value={r.trustAnchorId} className="gap-1.5">
							{isFailure(r) ? (
								<XCircle className="size-3 text-destructive-foreground" />
							) : (
								<CheckCircle2 className="size-3 text-emerald-500" />
							)}
							{extractHostname(r.trustAnchorId)}
						</TabsTrigger>
					))}
					{canCompare && <TabsTrigger value="__compare__">Compare</TabsTrigger>}
				</TabsList>

				{results.map((r) => (
					<TabsContent key={r.trustAnchorId} value={r.trustAnchorId} className="mt-4">
						{isFailure(r) ? (
							<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
								<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
								<div>
									<p className="text-sm font-mono break-all">{r.trustAnchorId}</p>
									<p className="text-sm text-destructive-foreground mt-1">{r.error}</p>
								</div>
							</div>
						) : (
							<ResolveResult payload={r.responsePayload} requestUrl={r.requestUrl} />
						)}
					</TabsContent>
				))}

				{canCompare && (
					<TabsContent value="__compare__" className="mt-4 space-y-4">
						<div className="flex items-center gap-2 flex-wrap">
							<span className="text-sm text-muted-foreground">Comparing:</span>
							<select
								value={compareA}
								onChange={(e) => setCompareA(Number(e.target.value))}
								className="rounded-md border bg-background px-2 py-1 text-xs font-mono"
							>
								{successes.map((r, i) => (
									<option key={r.trustAnchorId} value={i}>
										{extractHostname(r.trustAnchorId)}
									</option>
								))}
							</select>
							<span className="text-sm text-muted-foreground">vs</span>
							<select
								value={compareB}
								onChange={(e) => setCompareB(Number(e.target.value))}
								className="rounded-md border bg-background px-2 py-1 text-xs font-mono"
							>
								{successes.map((r, i) => (
									<option key={r.trustAnchorId} value={i}>
										{extractHostname(r.trustAnchorId)}
									</option>
								))}
							</select>
						</div>

						{compareA === compareB || successA == null || successB == null ? (
							<p className="text-sm text-muted-foreground">
								Select two different trust anchors to compare.
							</p>
						) : (
							<>
								<p className="text-xs text-muted-foreground">
									Left: {extractHostname(successA.trustAnchorId)} · Right:{" "}
									{extractHostname(successB.trustAnchorId)}
								</p>
								<ResolvedMetadataDiff
									originalMetadata={
										successA.responsePayload.metadata as Record<string, Record<string, unknown>>
									}
									resolvedMetadata={
										successB.responsePayload.metadata as Record<string, Record<string, unknown>>
									}
								/>
							</>
						)}
					</TabsContent>
				)}
			</Tabs>
		</div>
	);
}
