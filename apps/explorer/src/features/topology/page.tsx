import { Globe } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";
import { usePageTitle } from "@/hooks/use-page-title";
import { downloadBlob, downloadText } from "@/lib/export";
import { GraphCanvas, type GraphCanvasHandle } from "./components/graph-canvas";
import { SubtreeWalker } from "./components/subtree-walker";
import { TopologyForm } from "./components/topology-form";
import { TopologyMetricsPanel } from "./components/topology-metrics";
import { TopologyToolbar } from "./components/topology-toolbar";
import { useTopologyGraph } from "./hooks/use-topology-graph";
import type { LayoutDirection, SubordinateFilters } from "./types";

export function TopologyGraphPage() {
	usePageTitle("Topology Graph — OidFed Explorer");
	const graph = useTopologyGraph();
	const [layoutDir, setLayoutDir] = useLocalStorage<LayoutDirection>(
		"oidfed-explorer-topology-layoutDir",
		"breadthfirst",
	);
	const [filters, setFilters] = useState<SubordinateFilters>({});
	const [metricsOpen, setMetricsOpen] = useState(false);
	const canvasRef = useRef<GraphCanvasHandle>(null);

	// Sync filters to hook
	const handleFiltersChange = useCallback(
		(f: SubordinateFilters) => {
			setFilters(f);
			graph.setFilters(f);
		},
		[graph.setFilters],
	);

	const handleLoad = useCallback(
		(entityIds: string[]) => {
			const first = entityIds[0];
			if (!first) return;
			graph.initGraph(first);
			for (let i = 1; i < entityIds.length; i++) {
				const id = entityIds[i];
				if (id) graph.addRoot(id);
			}
		},
		[graph.initGraph, graph.addRoot],
	);

	const handleExportPng = useCallback(() => {
		const blob = canvasRef.current?.exportPng();
		if (blob) downloadBlob(blob, "federation-topology.png");
	}, []);

	const handleExportSvg = useCallback(() => {
		const svg = canvasRef.current?.exportSvg();
		if (svg) downloadText(svg, "federation-topology.svg", "image/svg+xml");
	}, []);

	return (
		<div className="flex flex-col gap-4 h-[calc(100vh-4rem)]">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Topology Graph</h1>
				<p className="text-sm text-muted-foreground">
					Interactive federation entity relationship visualization
				</p>
			</div>

			<TopologyForm onLoad={handleLoad} />

			{graph.nodes.length === 0 && (
				<div className="flex flex-1 items-center justify-center rounded-lg border border-dashed">
					<div className="text-center space-y-2 text-muted-foreground">
						<Globe className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">Enter an entity ID above to explore the federation topology</p>
					</div>
				</div>
			)}

			{graph.nodes.length > 0 && (
				<>
					<TopologyToolbar
						graph={graph}
						layoutDir={layoutDir}
						onLayoutChange={setLayoutDir}
						filters={filters}
						onFiltersChange={handleFiltersChange}
						metricsOpen={metricsOpen}
						onMetricsToggle={() => setMetricsOpen((o) => !o)}
						onExportPng={handleExportPng}
						onExportSvg={handleExportSvg}
					/>
					{metricsOpen && <TopologyMetricsPanel metrics={graph.metrics} />}
					{graph.autoExpandActive && (
						<SubtreeWalker progress={graph.walkProgress} onCancel={graph.cancelWalk} />
					)}
					<div className="flex-1 rounded-lg border overflow-hidden">
						<GraphCanvas
							nodes={graph.nodes}
							edges={graph.edges}
							filters={filters}
							onExpandNode={(nodeId, f) => graph.expandNode(nodeId, f)}
							onCollapseNode={graph.collapseNode}
							layoutDir={layoutDir}
							searchQuery={graph.searchQuery}
							matchedNodeIds={graph.matchedNodeIds}
							focusedMatchIndex={graph.focusedMatchIndex}
							canvasRef={canvasRef}
						/>
					</div>
				</>
			)}
		</div>
	);
}
