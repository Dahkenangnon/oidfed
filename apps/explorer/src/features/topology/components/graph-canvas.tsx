import { Button } from "@oidfed/ui";
import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { Maximize2, Minus, Plus } from "lucide-react";
import { useCallback, useEffect, useImperativeHandle, useRef, useState } from "react";
import { useNavigate } from "react-router";
import type {
	GraphEdge,
	GraphNode,
	LayoutDirection,
	SubordinateFilters,
	TopologyNodeData,
} from "../types";

cytoscape.use(fcose);

function shortLabel(entityId: string): string {
	try {
		const url = new URL(entityId);
		return url.hostname + (url.pathname !== "/" ? url.pathname : "");
	} catch {
		return entityId;
	}
}

function getNodeColor(data: TopologyNodeData): string {
	if (data.crossFederation) return "#e67e22";
	if (data.depth === 0) return "#e74c3c";
	const isIntermediate =
		data.entityTypes.includes("federation_entity") &&
		!data.entityTypes.includes("openid_provider") &&
		!data.entityTypes.includes("openid_relying_party") &&
		!data.entityTypes.includes("oauth_authorization_server");
	if (isIntermediate) return "#3498db";
	if (data.entityTypes.length > 0) return "#8fbc5a";
	return "#95a5a6";
}

function getNodeBorderColor(data: TopologyNodeData): string {
	if (data.crossFederation) return "#d35400";
	if (data.depth === 0) return "#c0392b";
	const isIntermediate =
		data.entityTypes.includes("federation_entity") &&
		!data.entityTypes.some((t) =>
			["openid_provider", "openid_relying_party", "oauth_authorization_server"].includes(t),
		);
	return isIntermediate ? "#2980b9" : "#6b9e3e";
}

interface ContextMenuState {
	x: number;
	y: number;
	entityId: string;
	hasSubordinates: boolean;
	expanded: boolean;
}

export interface GraphCanvasHandle {
	exportPng: () => Blob | null;
	exportSvg: () => string | null;
}

interface GraphCanvasProps {
	readonly nodes: GraphNode[];
	readonly edges: GraphEdge[];
	readonly filters: SubordinateFilters;
	readonly onExpandNode: (nodeId: string, filters: SubordinateFilters) => void;
	readonly onCollapseNode: (nodeId: string) => void;
	readonly layoutDir: LayoutDirection;
	readonly searchQuery: string;
	readonly matchedNodeIds: string[];
	readonly focusedMatchIndex: number;
	readonly canvasRef?: React.Ref<GraphCanvasHandle>;
}

export function GraphCanvas({
	nodes,
	edges,
	filters,
	onExpandNode,
	onCollapseNode,
	layoutDir,
	searchQuery,
	matchedNodeIds,
	focusedMatchIndex,
	canvasRef,
}: GraphCanvasProps) {
	const containerRef = useRef<HTMLDivElement>(null);
	const cyRef = useRef<cytoscape.Core | null>(null);
	const navigate = useNavigate();
	const navigateRef = useRef(navigate);
	const onExpandRef = useRef(onExpandNode);
	const onCollapseRef = useRef(onCollapseNode);
	const filtersRef = useRef(filters);
	const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
	const [pathHighlightedNodeId, setPathHighlightedNodeId] = useState<string | null>(null);
	const [hintDismissed, setHintDismissed] = useState(
		() => localStorage.getItem("oidfed-topology-hint-dismissed") === "1",
	);

	useEffect(() => {
		navigateRef.current = navigate;
	}, [navigate]);
	useEffect(() => {
		onExpandRef.current = onExpandNode;
	}, [onExpandNode]);
	useEffect(() => {
		onCollapseRef.current = onCollapseNode;
	}, [onCollapseNode]);
	useEffect(() => {
		filtersRef.current = filters;
	}, [filters]);

	// Expose export functions
	useImperativeHandle(
		canvasRef,
		() => ({
			exportPng: () => {
				const cy = cyRef.current;
				if (!cy || cy.nodes().length === 0) return null;
				const dataUrl: string = cy.png({ full: true, scale: 2, bg: "#fafafa" });
				const parts = dataUrl.split(",");
				if (parts.length < 2) return null;
				const byteString = atob(parts[1] as string);
				const ab = new ArrayBuffer(byteString.length);
				const ia = new Uint8Array(ab);
				for (let i = 0; i < byteString.length; i++) {
					ia[i] = byteString.charCodeAt(i);
				}
				return new Blob([ab], { type: "image/png" });
			},
			exportSvg: () => {
				const cy = cyRef.current;
				if (!cy || cy.nodes().length === 0) return null;
				// Generate SVG by embedding the PNG render as an <image> element
				const dataUrl: string = cy.png({ full: true, scale: 2, bg: "#fafafa" });
				const bb = cy.elements().boundingBox();
				const w = Math.ceil(bb.w + 100);
				const h = Math.ceil(bb.h + 100);
				return [
					`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">`,
					`  <image href="${dataUrl}" width="${w}" height="${h}" />`,
					"</svg>",
				].join("\n");
			},
		}),
		[],
	);

	// Initialize cytoscape once
	useEffect(() => {
		if (!containerRef.current) return;

		const cy = cytoscape({
			container: containerRef.current,
			style: [
				{
					selector: "node",
					style: {
						shape: "ellipse",
						width: 40,
						height: 40,
						"background-color": "data(color)",
						label: "data(label)",
						"text-valign": "bottom",
						"text-halign": "center",
						"font-size": "10px",
						color: "#333",
						"text-margin-y": 4,
						"text-max-width": "100px",
						"text-wrap": "ellipsis",
						"border-width": 2,
						"border-color": "data(borderColor)",
						// border-style set via selector overrides (crossLinked → dashed)
					},
				},
				{
					selector: "node:selected",
					style: {
						"border-width": 3,
						"border-color": "#fff",
					},
				},
				{
					selector: "node[loading]",
					style: {
						"background-color": "#bbb",
					},
				},
				{
					selector: "node[highlighted]",
					style: {
						"border-color": "#f1c40f",
						"border-width": 4,
					},
				},
				{
					selector: "node[focusedMatch]",
					style: {
						"border-color": "#e74c3c",
						"border-width": 5,
					},
				},
				{
					selector: "node[pathHighlighted]",
					style: {
						"border-color": "#2ecc71",
						"border-width": 5,
					},
				},
				{
					selector: "node[crossLinked]",
					style: {
						"border-style": "dashed",
					},
				},
				{
					selector: "node[crossFederation]",
					style: {
						"border-width": 4,
					},
				},
				{
					selector: "edge",
					style: {
						width: 1,
						"line-color": "#aaa",
						"curve-style": "bezier",
						"target-arrow-color": "#aaa",
						"target-arrow-shape": "triangle",
						"arrow-scale": 0.7,
					},
				},
				{
					selector: "edge[crossLink]",
					style: {
						"line-style": "dashed",
						"line-color": "#9b59b6",
						"target-arrow-color": "#9b59b6",
					},
				},
				{
					selector: "edge[pathHighlighted]",
					style: {
						width: 3,
						"line-color": "#2ecc71",
						"target-arrow-color": "#2ecc71",
					},
				},
			],
			layout: { name: "preset" },
			userZoomingEnabled: true,
			userPanningEnabled: true,
			boxSelectionEnabled: false,
		});

		// tap: expand/collapse
		cy.on("tap", "node", (evt) => {
			const node = evt.target as cytoscape.NodeSingular;
			const data = node.data() as TopologyNodeData;
			if (data.hasSubordinates) {
				if (data.expanded) {
					onCollapseRef.current(data.entityId);
				} else {
					onExpandRef.current(data.entityId, filtersRef.current);
				}
			}
		});

		// Close context menu and clear path highlighting on canvas tap
		cy.on("tap", () => {
			setContextMenu(null);
			clearPathHighlighting(cy);
			setPathHighlightedNodeId(null);
		});

		// Right-click context menu
		cy.on("cxttap", "node", (evt) => {
			const node = evt.target as cytoscape.NodeSingular;
			const data = node.data() as TopologyNodeData;
			const pos = node.renderedPosition();
			const rect = containerRef.current?.getBoundingClientRect();
			if (!rect) return;
			setContextMenu({
				x: rect.left + pos.x,
				y: rect.top + pos.y,
				entityId: data.entityId,
				hasSubordinates: data.hasSubordinates,
				expanded: data.expanded,
			});
		});

		cyRef.current = cy;
		return () => {
			cy.destroy();
			cyRef.current = null;
		};
	}, []);

	// Sync nodes/edges to cytoscape
	useEffect(() => {
		const cy = cyRef.current;
		if (!cy) return;

		const cyNodeIds = new Set(cy.nodes().map((n) => n.id()));
		const cyEdgeIds = new Set(cy.edges().map((e) => e.id()));

		let hasNewNodes = false;

		for (const node of nodes) {
			const nodeData = {
				id: node.id,
				entityId: node.data.entityId,
				label: shortLabel(node.data.entityId),
				color: getNodeColor(node.data),
				borderColor: getNodeBorderColor(node.data),
				hasSubordinates: node.data.hasSubordinates,
				expanded: node.data.expanded,
				loading: node.data.loading ? true : undefined,
				depth: node.data.depth,
				entityTypes: node.data.entityTypes,
				organizationName: node.data.organizationName,
				subordinateCount: node.data.subordinateCount,
				crossLinked: node.data.crossLinked || undefined,
				crossFederation: node.data.crossFederation || undefined,
			};

			if (!cyNodeIds.has(node.id)) {
				cy.add({
					group: "nodes",
					data: nodeData,
					position: { x: Math.random() * 400, y: Math.random() * 400 },
				});
				hasNewNodes = true;
			} else {
				cy.getElementById(node.id).data(nodeData);
			}
		}

		const newNodeIds = new Set(nodes.map((n) => n.id));
		for (const cyNodeId of cyNodeIds) {
			if (!newNodeIds.has(cyNodeId)) {
				cy.getElementById(cyNodeId).remove();
			}
		}

		for (const edge of edges) {
			if (!cyEdgeIds.has(edge.id)) {
				cy.add({
					group: "edges",
					data: {
						id: edge.id,
						source: edge.source,
						target: edge.target,
						crossLink: edge.crossLink || undefined,
					},
				});
			}
		}

		const newEdgeIds = new Set(edges.map((e) => e.id));
		for (const cyEdgeId of cyEdgeIds) {
			if (!newEdgeIds.has(cyEdgeId)) {
				cy.getElementById(cyEdgeId).remove();
			}
		}

		if (hasNewNodes && nodes.length > 0) {
			runLayout(cy, layoutDir);
		}
	}, [nodes, edges, layoutDir]);

	// Re-run layout when layoutDir changes
	const prevLayoutRef = useRef<LayoutDirection | null>(null);
	useEffect(() => {
		const cy = cyRef.current;
		if (!cy || cy.nodes().length === 0) return;
		if (prevLayoutRef.current === layoutDir) return;
		prevLayoutRef.current = layoutDir;
		runLayout(cy, layoutDir);
	}, [layoutDir]);

	// Search highlighting
	useEffect(() => {
		const cy = cyRef.current;
		if (!cy) return;
		if (!searchQuery) {
			cy.nodes().forEach((n) => {
				n.removeData("highlighted");
				n.removeData("focusedMatch");
			});
			return;
		}
		const focusedId = matchedNodeIds[focusedMatchIndex] ?? null;
		cy.nodes().forEach((n) => {
			const isMatch = matchedNodeIds.includes(n.id());
			if (isMatch) {
				n.data("highlighted", true);
			} else {
				n.removeData("highlighted");
			}
			if (n.id() === focusedId) {
				n.data("focusedMatch", true);
			} else {
				n.removeData("focusedMatch");
			}
		});
		// Center on focused match
		if (focusedId) {
			const focusedNode = cy.getElementById(focusedId);
			if (focusedNode.length > 0) {
				cy.animate({ center: { eles: focusedNode }, duration: 300 });
			}
		}
	}, [searchQuery, matchedNodeIds, focusedMatchIndex]);

	// Path highlighting: BFS upward from node to roots
	const highlightPaths = useCallback(
		(entityId: string) => {
			const cy = cyRef.current;
			if (!cy) return;

			clearPathHighlighting(cy);
			setPathHighlightedNodeId(entityId);

			// BFS upward through reversed edges
			const visited = new Set<string>([entityId]);
			const queue = [entityId];
			const pathEdgeIds = new Set<string>();

			while (queue.length > 0) {
				const current = queue.shift() as string;
				for (const edge of edges) {
					if (edge.target === current && !visited.has(edge.source)) {
						visited.add(edge.source);
						queue.push(edge.source);
						pathEdgeIds.add(edge.id);
					}
				}
			}

			// Apply highlighting
			cy.nodes().forEach((n) => {
				if (visited.has(n.id())) {
					n.data("pathHighlighted", true);
				}
			});
			cy.edges().forEach((e) => {
				if (pathEdgeIds.has(e.id())) {
					e.data("pathHighlighted", true);
				}
			});
		},
		[edges],
	);

	// Escape key clears path highlighting
	useEffect(() => {
		const handler = (e: KeyboardEvent) => {
			if (e.key === "Escape" && pathHighlightedNodeId) {
				const cy = cyRef.current;
				if (cy) clearPathHighlighting(cy);
				setPathHighlightedNodeId(null);
			}
		};
		document.addEventListener("keydown", handler);
		return () => document.removeEventListener("keydown", handler);
	}, [pathHighlightedNodeId]);

	const handleFit = useCallback(() => {
		cyRef.current?.fit(undefined, 40);
	}, []);

	const handleZoomIn = useCallback(() => {
		const cy = cyRef.current;
		if (!cy) return;
		cy.zoom({
			level: cy.zoom() * 1.3,
			renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
		});
	}, []);

	const handleZoomOut = useCallback(() => {
		const cy = cyRef.current;
		if (!cy) return;
		cy.zoom({
			level: cy.zoom() / 1.3,
			renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
		});
	}, []);

	return (
		<div style={{ width: "100%", height: "100%", position: "relative", background: "#fafafa" }}>
			<div ref={containerRef} style={{ width: "100%", height: "100%" }} />

			{/* Interaction hint overlay */}
			{!hintDismissed && (
				<div className="absolute top-2 left-1/2 -translate-x-1/2 z-10 flex items-center gap-3 bg-background/90 border rounded-full px-4 py-1.5 text-xs text-muted-foreground shadow-sm whitespace-nowrap">
					<span>
						Click node to expand/collapse · Right-click for options · Scroll to zoom · Drag to pan
					</span>
					<button
						type="button"
						onClick={() => {
							localStorage.setItem("oidfed-topology-hint-dismissed", "1");
							setHintDismissed(true);
						}}
					>
						✕
					</button>
				</div>
			)}

			{/* Controls overlay */}
			<div className="absolute bottom-4 right-4 flex flex-col gap-1">
				<Button
					variant="outline"
					size="icon"
					className="size-7 bg-background/80"
					onClick={handleFit}
				>
					<Maximize2 className="size-3.5" />
				</Button>
				<Button
					variant="outline"
					size="icon"
					className="size-7 bg-background/80"
					onClick={handleZoomIn}
				>
					<Plus className="size-3.5" />
				</Button>
				<Button
					variant="outline"
					size="icon"
					className="size-7 bg-background/80"
					onClick={handleZoomOut}
				>
					<Minus className="size-3.5" />
				</Button>
			</div>

			{/* Legend */}
			<div className="absolute bottom-4 left-4 flex flex-col gap-1 bg-background/80 rounded-md border p-2 text-xs">
				<div className="flex items-center gap-1.5">
					<span className="inline-block size-3 rounded-full" style={{ background: "#e74c3c" }} />
					Trust Anchor
				</div>
				<div className="flex items-center gap-1.5">
					<span className="inline-block size-3 rounded-full" style={{ background: "#3498db" }} />
					Intermediate
				</div>
				<div className="flex items-center gap-1.5">
					<span className="inline-block size-3 rounded-full" style={{ background: "#8fbc5a" }} />
					Leaf
				</div>
				<div className="flex items-center gap-1.5">
					<span
						className="inline-block size-3 rounded-full border-2 border-dashed"
						style={{ background: "#9b59b6", borderColor: "#7d3c98" }}
					/>
					Cross-linked
				</div>
				<div className="flex items-center gap-1.5">
					<span className="inline-block size-3 rounded-full" style={{ background: "#e67e22" }} />
					Cross-federation
				</div>
			</div>

			{/* Context menu */}
			{contextMenu && (
				<div
					className="fixed z-50 rounded-md border bg-popover shadow-md py-1 w-48 text-sm"
					style={{ left: contextMenu.x, top: contextMenu.y }}
				>
					<button
						type="button"
						className="w-full px-3 py-1.5 text-left hover:bg-accent text-xs"
						onClick={() => {
							setContextMenu(null);
							navigateRef.current(`/entity/${encodeURIComponent(contextMenu.entityId)}`);
						}}
					>
						Inspect entity
					</button>
					<button
						type="button"
						className="w-full px-3 py-1.5 text-left hover:bg-accent text-xs"
						onClick={() => {
							setContextMenu(null);
							navigator.clipboard.writeText(contextMenu.entityId);
						}}
					>
						Copy entity ID
					</button>
					<button
						type="button"
						className="w-full px-3 py-1.5 text-left hover:bg-accent text-xs"
						onClick={() => {
							setContextMenu(null);
							highlightPaths(contextMenu.entityId);
						}}
					>
						Highlight chain paths
					</button>
					{contextMenu.hasSubordinates && !contextMenu.expanded && (
						<button
							type="button"
							className="w-full px-3 py-1.5 text-left hover:bg-accent text-xs"
							onClick={() => {
								setContextMenu(null);
								onExpandRef.current(contextMenu.entityId, filtersRef.current);
							}}
						>
							Expand subordinates
						</button>
					)}
					{contextMenu.expanded && (
						<button
							type="button"
							className="w-full px-3 py-1.5 text-left hover:bg-accent text-xs"
							onClick={() => {
								setContextMenu(null);
								onCollapseRef.current(contextMenu.entityId);
							}}
						>
							Collapse
						</button>
					)}
				</div>
			)}
		</div>
	);
}

function clearPathHighlighting(cy: cytoscape.Core): void {
	cy.nodes().forEach((n) => {
		n.removeData("pathHighlighted");
	});
	cy.edges().forEach((e) => {
		e.removeData("pathHighlighted");
	});
}

function runLayout(cy: cytoscape.Core, layoutDir: LayoutDirection): void {
	const layoutName = layoutDir === "fcose" ? "fcose" : "breadthfirst";
	const baseOptions = {
		name: layoutName,
		animate: true,
		animationDuration: 400,
	};

	const fcoseOptions =
		layoutDir === "fcose"
			? {
					quality: "default" as const,
					randomize: false,
					nodeRepulsion: () => 4500,
					idealEdgeLength: () => 100,
					edgeElasticity: () => 0.45,
					nestingFactor: 0.1,
					gravity: 0.25,
					numIter: 2500,
					tile: true,
					tilingPaddingVertical: 10,
					tilingPaddingHorizontal: 10,
				}
			: {};

	const breadthfirstOptions =
		layoutDir === "breadthfirst"
			? {
					directed: true,
					padding: 30,
					spacingFactor: 1.5,
				}
			: {};

	const layout = cy.layout({
		...baseOptions,
		...fcoseOptions,
		...breadthfirstOptions,
	} as cytoscape.LayoutOptions);
	layout.one("layoutstop", () => cy.fit(undefined, 50));
	layout.run();
}
