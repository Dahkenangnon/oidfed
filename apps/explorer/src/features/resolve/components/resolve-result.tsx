import type { ResolveResponsePayload } from "@oidfed/core";
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
import { CopyButton } from "@/components/shared/copy-button";
import { EntityLink } from "@/components/shared/entity-link";
import { JsonTree } from "@/components/shared/json-tree";
import { ResolvedMetadataDiff } from "../../trust-chain/components/resolved-metadata-diff";

interface ResolveResultProps {
	readonly payload: ResolveResponsePayload;
	readonly requestUrl: string;
}

function formatTimestamp(unix: number): string {
	return `${new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export function ResolveResult({ payload, requestUrl }: ResolveResultProps) {
	// Original leaf metadata from trust_chain[0] if available
	const firstChainJwt = payload.trust_chain[0];

	let originalMetadata: Record<string, Record<string, unknown>> = {};
	if (firstChainJwt) {
		try {
			const parts = firstChainJwt.split(".");
			if (parts[1]) {
				const raw = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as Record<
					string,
					unknown
				>;
				originalMetadata = (raw.metadata ?? {}) as Record<string, Record<string, unknown>>;
			}
		} catch {
			// ignore decode errors
		}
	}

	const resolvedMetadata = payload.metadata as Record<string, Record<string, unknown>>;
	const hasChain = payload.trust_chain.length > 0;
	const hasTrustMarks = payload.trust_marks && payload.trust_marks.length > 0;

	return (
		<div className="space-y-4">
			{/* Header */}
			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-sm">Response Summary</CardTitle>
				</CardHeader>
				<CardContent className="space-y-2 text-sm">
					<div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
						<span className="text-muted-foreground font-mono text-xs">iss</span>
						<EntityLink entityId={payload.iss} />

						<span className="text-muted-foreground font-mono text-xs">sub</span>
						<EntityLink entityId={payload.sub} />

						<span className="text-muted-foreground font-mono text-xs">iat</span>
						<span className="text-xs">{formatTimestamp(payload.iat)}</span>

						<span className="text-muted-foreground font-mono text-xs">exp</span>
						<span className="text-xs">{formatTimestamp(payload.exp)}</span>

						<span className="text-muted-foreground font-mono text-xs">trust_chain</span>
						<Badge variant="secondary" className="w-fit text-xs">
							{payload.trust_chain.length} statement{payload.trust_chain.length !== 1 ? "s" : ""}
						</Badge>
					</div>

					<div className="flex items-center gap-2 pt-1">
						<span className="text-xs text-muted-foreground font-mono">Request:</span>
						<span className="text-xs font-mono text-brand-500 break-all">{requestUrl}</span>
						<CopyButton value={requestUrl} />
					</div>
				</CardContent>
			</Card>

			{/* Tabs */}
			<Tabs defaultValue="metadata">
				<TabsList>
					<TabsTrigger value="metadata">Resolved Metadata</TabsTrigger>
					{hasChain && <TabsTrigger value="diff">Diff (original vs resolved)</TabsTrigger>}
					{hasChain && (
						<TabsTrigger value="chain">Trust Chain ({payload.trust_chain.length})</TabsTrigger>
					)}
					{hasTrustMarks && (
						<TabsTrigger value="trust-marks">
							Trust Marks ({payload.trust_marks?.length ?? 0})
						</TabsTrigger>
					)}
				</TabsList>

				<TabsContent value="metadata" className="mt-4">
					<JsonTree data={resolvedMetadata} collapsed={2} />
				</TabsContent>

				{hasChain && (
					<TabsContent value="diff" className="mt-4">
						<p className="text-xs text-muted-foreground mb-2">
							Left: original leaf EC metadata · Right: resolver-resolved metadata
						</p>
						<ResolvedMetadataDiff
							originalMetadata={originalMetadata}
							resolvedMetadata={resolvedMetadata}
						/>
					</TabsContent>
				)}

				{hasChain && (
					<TabsContent value="chain" className="mt-4 space-y-3">
						{payload.trust_chain.map((jwt, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: chain is ordered
							<div key={i} className="space-y-1">
								<p className="text-xs text-muted-foreground font-mono">Statement {i}</p>
								<div className="rounded-lg border bg-code p-3 font-mono text-xs break-all">
									{jwt}
									<CopyButton value={jwt} className="ml-2" />
								</div>
							</div>
						))}
					</TabsContent>
				)}

				{hasTrustMarks && (
					<TabsContent value="trust-marks" className="mt-4">
						<JsonTree data={payload.trust_marks} collapsed={2} />
					</TabsContent>
				)}
			</Tabs>
		</div>
	);
}
