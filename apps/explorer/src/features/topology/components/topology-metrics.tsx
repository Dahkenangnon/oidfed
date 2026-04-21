import type { TopologyMetrics } from "../hooks/use-topology-graph";

const TYPE_LABELS: Record<string, string> = {
	openid_provider: "OP",
	openid_relying_party: "RP",
	oauth_authorization_server: "AS",
	federation_entity: "FE",
};

interface TopologyMetricsPanelProps {
	readonly metrics: TopologyMetrics;
}

export function TopologyMetricsPanel({ metrics }: TopologyMetricsPanelProps) {
	const typeEntries = Object.entries(metrics.entityTypeDistribution).sort(([, a], [, b]) => b - a);

	return (
		<div className="rounded-lg border bg-muted/30 p-3">
			<p className="text-xs font-medium mb-2">Topology Metrics</p>
			<div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
				<Stat label="Entities" value={metrics.entityCount} />
				<Stat label="Edges" value={metrics.totalEdges} />
				<Stat label="Max depth" value={metrics.maxDepth} />
				<Stat label="Avg subordinates" value={metrics.branchingFactor} />
				<Stat label="Trust Anchors" value={metrics.taCount} />
				<Stat label="Leaves" value={metrics.leafCount} />
				<Stat label="Intermediate %" value={`${metrics.intermediateRatio}%`} />
				<div className="col-span-2 pt-1">
					<span className="text-muted-foreground">Types: </span>
					{typeEntries.length === 0 && <span className="text-muted-foreground">—</span>}
					{typeEntries.map(([type, count]) => (
						<span key={type} className="inline-flex items-center gap-0.5 mr-2">
							<span className="font-medium">{TYPE_LABELS[type] ?? type}</span>
							<span className="text-muted-foreground">{count}</span>
						</span>
					))}
				</div>
			</div>
		</div>
	);
}

function Stat({ label, value }: { readonly label: string; readonly value: string | number }) {
	return (
		<div className="flex items-center justify-between">
			<span className="text-muted-foreground">{label}</span>
			<span className="font-medium tabular-nums">{value}</span>
		</div>
	);
}
