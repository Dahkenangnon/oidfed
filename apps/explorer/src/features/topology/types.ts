export interface TopologyNodeData {
	entityId: string;
	entityTypes: string[];
	organizationName: string | null;
	expanded: boolean;
	loading: boolean;
	hasSubordinates: boolean;
	subordinateCount: number | null;
	depth: number;
	crossLinked?: boolean | undefined;
	crossFederation?: boolean | undefined;
}

export interface SubordinateFilters {
	readonly entity_type?: string | undefined;
	readonly trust_marked?: boolean | undefined;
	readonly intermediate?: boolean | undefined;
}

export interface WalkProgress {
	done: number;
	total: number;
	current: string;
}

export type LayoutDirection = "fcose" | "breadthfirst";

export interface GraphNode {
	id: string;
	data: TopologyNodeData;
}

export interface GraphEdge {
	id: string;
	source: string;
	target: string;
	crossLink?: boolean | undefined;
}
