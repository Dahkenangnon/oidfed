import {
	createConcurrencyLimiter,
	decodeEntityStatement,
	fetchEntityConfiguration,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";
import type {
	GraphEdge,
	GraphNode,
	SubordinateFilters,
	TopologyNodeData,
	WalkProgress,
} from "../types";

export interface TopologyMetrics {
	entityCount: number;
	maxDepth: number;
	branchingFactor: number;
	intermediateRatio: number;
	leafCount: number;
	taCount: number;
	entityTypeDistribution: Record<string, number>;
	totalEdges: number;
}

export interface UseTopologyGraphResult {
	nodes: GraphNode[];
	edges: GraphEdge[];
	metrics: TopologyMetrics;
	rootIds: string[];
	initGraph: (rootEntityId: string) => void;
	addRoot: (rootEntityId: string) => void;
	expandNode: (nodeId: string, filters: SubordinateFilters) => void;
	collapseNode: (nodeId: string) => void;
	searchQuery: string;
	setSearchQuery: (q: string) => void;
	setFilters: (f: SubordinateFilters) => void;
	matchedNodeIds: string[];
	focusedMatchIndex: number;
	focusMatch: (index: number) => void;
	walkProgress: WalkProgress | null;
	cancelWalk: () => void;
	autoExpandActive: boolean;
}

function extractEntityInfo(payload: Record<string, unknown>) {
	const metadata = payload.metadata as Record<string, Record<string, unknown>> | undefined;
	const federationEntity = extractFederationEntity(payload);
	const listEndpoint = federationEntity.federation_list_endpoint as string | undefined;
	const orgName =
		(federationEntity.organization_name as string | undefined) ??
		(payload.organization_name as string | undefined) ??
		null;

	const entityTypes = metadata ? Object.keys(metadata) : [];
	return { hasSubordinates: !!listEndpoint, listEndpoint, orgName, entityTypes };
}

function collectDescendants(nodeId: string, edges: GraphEdge[]): Set<string> {
	const descendants = new Set<string>();
	const queue = [nodeId];
	while (queue.length > 0) {
		const current = queue.shift() as string;
		for (const edge of edges) {
			if (edge.source === current && !descendants.has(edge.target)) {
				descendants.add(edge.target);
				queue.push(edge.target);
			}
		}
	}
	return descendants;
}

function makeNodeData(
	entityId: string,
	entityTypes: string[],
	orgName: string | null,
	hasSubordinates: boolean,
	depth: number,
	extra?: Partial<TopologyNodeData>,
): TopologyNodeData {
	return {
		entityId,
		entityTypes,
		organizationName: orgName,
		expanded: false,
		loading: false,
		hasSubordinates,
		subordinateCount: null,
		depth,
		...extra,
	};
}

export function useTopologyGraph(): UseTopologyGraphResult {
	const [nodes, setNodes] = useState<GraphNode[]>([]);
	const [edges, setEdges] = useState<GraphEdge[]>([]);
	const [searchQuery, setSearchQuery] = useState("");
	const [autoExpandActive, setAutoExpandActive] = useState(false);
	const [walkProgress, setWalkProgress] = useState<WalkProgress | null>(null);
	const [matchedNodeIds, setMatchedNodeIds] = useState<string[]>([]);
	const [focusedMatchIndex, setFocusedMatchIndex] = useState(0);
	const [rootIds, setRootIds] = useState<string[]>([]);
	const autoExpandQueuedRef = useRef(new Set<string>());
	const filtersRef = useRef<SubordinateFilters>({});
	const [settings] = useSettings();

	const setFilters = useCallback((f: SubordinateFilters) => {
		filtersRef.current = f;
	}, []);

	const focusMatch = useCallback(
		(index: number) => {
			if (matchedNodeIds.length === 0) return;
			const clamped =
				((index % matchedNodeIds.length) + matchedNodeIds.length) % matchedNodeIds.length;
			setFocusedMatchIndex(clamped);
		},
		[matchedNodeIds],
	);

	const cancelWalk = useCallback(() => {
		setAutoExpandActive(false);
		setWalkProgress(null);
	}, []);

	// Search matching
	useEffect(() => {
		if (!searchQuery) {
			setMatchedNodeIds([]);
			setFocusedMatchIndex(0);
			return;
		}
		let regex: RegExp;
		try {
			regex = new RegExp(searchQuery, "i");
		} catch {
			regex = new RegExp(searchQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
		}
		const matched = nodes
			.filter((n) => {
				return (
					regex.test(n.data.entityId) ||
					(n.data.organizationName !== null && regex.test(n.data.organizationName))
				);
			})
			.map((n) => n.id);
		setMatchedNodeIds(matched);
		setFocusedMatchIndex(0);
	}, [searchQuery, nodes]);

	const loadRoot = useCallback(
		async (rootEntityId: string, clearExisting: boolean) => {
			const validated = validateEntityId(rootEntityId);
			if (!validated.ok) return;

			if (clearExisting) {
				setNodes([]);
				setEdges([]);
				setRootIds([]);
				autoExpandQueuedRef.current = new Set();
			}

			const result = await fetchEntityConfiguration(validated.value, {
				httpTimeoutMs: settings.httpTimeoutMs,
			});
			if (!result.ok) return;
			const decoded = decodeEntityStatement(result.value);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			const { hasSubordinates, orgName, entityTypes } = extractEntityInfo(payload);

			const rootNode: GraphNode = {
				id: rootEntityId,
				data: makeNodeData(rootEntityId, entityTypes, orgName, hasSubordinates, 0),
			};

			setNodes((prev) => {
				if (prev.some((n) => n.id === rootEntityId)) return prev;
				return [...prev, rootNode];
			});
			setRootIds((prev) => (prev.includes(rootEntityId) ? prev : [...prev, rootEntityId]));
			setAutoExpandActive(true);
			setWalkProgress({ done: 0, total: 0, current: rootEntityId });
		},
		[settings.httpTimeoutMs],
	);

	const initGraph = useCallback(
		(rootEntityId: string) => {
			loadRoot(rootEntityId, true);
		},
		[loadRoot],
	);

	const addRoot = useCallback(
		(rootEntityId: string) => {
			loadRoot(rootEntityId, false);
		},
		[loadRoot],
	);

	const expandNode = useCallback(
		(nodeId: string, filters: SubordinateFilters) => {
			setNodes((prev) =>
				prev.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, loading: true } } : n)),
			);

			async function doExpand() {
				const parentNode = nodes.find((n) => n.id === nodeId);
				if (!parentNode) return;
				const depth = parentNode.data.depth;

				const validated = validateEntityId(nodeId);
				if (!validated.ok) return;

				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs: settings.httpTimeoutMs,
				});
				if (!ecResult.ok) {
					setNodes((prev) =>
						prev.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, loading: false } } : n)),
					);
					return;
				}

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				const { listEndpoint } = extractEntityInfo(payload);

				if (!listEndpoint) {
					setNodes((prev) =>
						prev.map((n) =>
							n.id === nodeId ? { ...n, data: { ...n.data, loading: false, expanded: true } } : n,
						),
					);
					return;
				}

				const params = new URLSearchParams();
				if (filters.entity_type) params.set("entity_type", filters.entity_type);
				if (filters.trust_marked !== undefined)
					params.set("trust_marked", String(filters.trust_marked));
				if (filters.intermediate !== undefined)
					params.set("intermediate", String(filters.intermediate));

				const url = params.toString() ? `${listEndpoint}?${params}` : listEndpoint;
				const resp = await fetch(url);
				if (!resp.ok) return;
				const data: unknown = await resp.json();
				if (!Array.isArray(data)) return;
				const childIds = data.filter((v): v is string => typeof v === "string");

				// Fetch child ECs concurrently
				const limiter = createConcurrencyLimiter(5);
				const childInfos = await Promise.all(
					childIds.map((childId) =>
						limiter(async () => {
							const vId = validateEntityId(childId);
							if (!vId.ok) return null;
							const r = await fetchEntityConfiguration(vId.value, {
								httpTimeoutMs: settings.httpTimeoutMs,
							});
							if (!r.ok)
								return {
									entityId: childId,
									entityTypes: [] as string[],
									orgName: null as string | null,
									hasSubordinates: false,
								};
							const dec = decodeEntityStatement(r.value);
							if (!dec.ok)
								return {
									entityId: childId,
									entityTypes: [] as string[],
									orgName: null as string | null,
									hasSubordinates: false,
								};
							const p = dec.value.payload as Record<string, unknown>;
							const info = extractEntityInfo(p);
							return { entityId: childId, ...info };
						}),
					),
				);

				const validChildren = childInfos.filter((c) => c !== null);

				setNodes((prev) => {
					const existingIds = new Set(prev.map((n) => n.id));
					const newNodes: GraphNode[] = [];
					for (const child of validChildren) {
						if (!existingIds.has(child.entityId)) {
							newNodes.push({
								id: child.entityId,
								data: makeNodeData(
									child.entityId,
									child.entityTypes,
									child.orgName,
									child.hasSubordinates,
									depth + 1,
								),
							});
						}
					}
					// Mark cross-linked and cross-federation nodes
					const updated = prev.map((n) => {
						if (n.id === nodeId) {
							return {
								...n,
								data: {
									...n.data,
									loading: false,
									expanded: true,
									subordinateCount: validChildren.length,
								},
							};
						}
						// If a child already existed, mark it as cross-linked
						const isExistingChild = validChildren.some(
							(c) => c.entityId === n.id && existingIds.has(n.id),
						);
						if (isExistingChild && n.id !== nodeId) {
							return {
								...n,
								data: {
									...n.data,
									crossLinked: true,
									// Cross-federation: child is itself a root
									crossFederation: n.data.crossFederation || rootIdsRef.current.includes(n.id),
								},
							};
						}
						return n;
					});
					return [...updated, ...newNodes];
				});

				setEdges((prev) => {
					const existingEdgeIds = new Set(prev.map((e) => e.id));
					const existingNodeIds = new Set(nodes.map((n) => n.id));
					const newEdges: GraphEdge[] = [];
					for (const child of validChildren) {
						const edgeId = `${nodeId}->${child.entityId}`;
						if (!existingEdgeIds.has(edgeId)) {
							const isCrossLink = existingNodeIds.has(child.entityId);
							newEdges.push({
								id: edgeId,
								source: nodeId,
								target: child.entityId,
								crossLink: isCrossLink || undefined,
							});
						}
					}
					return [...prev, ...newEdges];
				});

				// Update walk progress
				setWalkProgress((prev) =>
					prev ? { ...prev, done: prev.done + 1, current: nodeId } : null,
				);
			}

			doExpand().catch(() => {
				setNodes((prev) =>
					prev.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, loading: false } } : n)),
				);
			});
		},
		[nodes, settings.httpTimeoutMs],
	);

	// Keep rootIds accessible in expandNode closure
	const rootIdsRef = useRef(rootIds);
	useEffect(() => {
		rootIdsRef.current = rootIds;
	}, [rootIds]);

	// Recursive auto-expand: whenever nodes change, expand any that haven't been queued yet
	useEffect(() => {
		if (!autoExpandActive) return;
		let anyExpanded = false;
		for (const node of nodes) {
			if (
				node.data.hasSubordinates &&
				!node.data.expanded &&
				!node.data.loading &&
				!autoExpandQueuedRef.current.has(node.id)
			) {
				autoExpandQueuedRef.current.add(node.id);
				expandNode(node.id, filtersRef.current);
				anyExpanded = true;
			}
		}
		// If nothing left to expand, walk is done
		if (!anyExpanded) {
			const allExpandable = nodes.filter((n) => n.data.hasSubordinates);
			const allDone = allExpandable.every((n) => n.data.expanded || n.data.loading);
			if (allDone && allExpandable.length > 0) {
				setAutoExpandActive(false);
				setWalkProgress(null);
			}
		}
	}, [autoExpandActive, nodes, expandNode]);

	const collapseNode = useCallback((nodeId: string) => {
		setEdges((prevEdges) => {
			const descendants = collectDescendants(nodeId, prevEdges);
			const newEdges = prevEdges.filter(
				(e) => !descendants.has(e.target) && !(e.source === nodeId),
			);
			setNodes((prevNodes) => {
				const remaining = prevNodes.filter((n) => !descendants.has(n.id));
				return remaining.map((n) =>
					n.id === nodeId
						? { ...n, data: { ...n.data, expanded: false, subordinateCount: null } }
						: n,
				);
			});
			return newEdges;
		});
	}, []);

	// Metrics computation
	const metrics: TopologyMetrics = {
		entityCount: nodes.length,
		maxDepth: nodes.reduce((max, n) => Math.max(max, n.data.depth), 0),
		branchingFactor:
			nodes.length > 1
				? Math.round(
						(edges.length /
							(nodes.filter((n) => n.data.hasSubordinates && n.data.expanded).length || 1)) *
							10,
					) / 10
				: 0,
		intermediateRatio:
			nodes.length > 0
				? Math.round(
						(nodes.filter(
							(n) =>
								n.data.hasSubordinates &&
								n.data.entityTypes.includes("federation_entity") &&
								n.data.depth > 0,
						).length /
							nodes.length) *
							100,
					)
				: 0,
		leafCount: nodes.filter((n) => !n.data.hasSubordinates).length,
		taCount: nodes.filter((n) => n.data.depth === 0).length,
		entityTypeDistribution: nodes.reduce<Record<string, number>>((acc, n) => {
			for (const t of n.data.entityTypes) {
				acc[t] = (acc[t] ?? 0) + 1;
			}
			return acc;
		}, {}),
		totalEdges: edges.length,
	};

	return {
		nodes,
		edges,
		metrics,
		rootIds,
		initGraph,
		addRoot,
		expandNode,
		collapseNode,
		searchQuery,
		setSearchQuery,
		setFilters,
		matchedNodeIds,
		focusedMatchIndex,
		focusMatch,
		walkProgress,
		cancelWalk,
		autoExpandActive,
	};
}
