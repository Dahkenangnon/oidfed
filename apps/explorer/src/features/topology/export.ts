import type { GraphEdge, GraphNode } from "@/features/topology/types";

function shortLabel(entityId: string): string {
	try {
		const url = new URL(entityId);
		return url.hostname + (url.pathname !== "/" ? url.pathname : "");
	} catch {
		return entityId;
	}
}

export function exportMermaid(nodes: GraphNode[], edges: GraphEdge[]): string {
	const lines = ["graph TD"];
	for (const node of nodes) {
		const label =
			node.data.depth === 0
				? `TA: ${shortLabel(node.data.entityId)}`
				: node.data.hasSubordinates && node.data.depth > 0
					? `Int: ${shortLabel(node.data.entityId)}`
					: shortLabel(node.data.entityId);
		lines.push(`  "${node.data.entityId}"["${label}"]`);
	}
	for (const edge of edges) {
		lines.push(`  "${edge.source}" --> "${edge.target}"`);
	}
	return lines.join("\n");
}

function dotColor(node: GraphNode): string {
	const types = node.data.entityTypes;
	if (node.data.depth === 0) return "#e74c3c";
	const isIntermediate =
		types.includes("federation_entity") &&
		!types.includes("openid_provider") &&
		!types.includes("openid_relying_party") &&
		!types.includes("oauth_authorization_server");
	if (isIntermediate) return "#3498db";
	return "#8fbc5a";
}

export function exportDot(nodes: GraphNode[], edges: GraphEdge[]): string {
	const lines = ["digraph federation {", "  rankdir=TB;", "  node [shape=circle];"];
	for (const node of nodes) {
		const label = shortLabel(node.data.entityId);
		const color = dotColor(node);
		lines.push(
			`  "${node.data.entityId}" [label="${label}", style=filled, fillcolor="${color}", fontcolor="white"];`,
		);
	}
	for (const edge of edges) {
		lines.push(`  "${edge.source}" -> "${edge.target}";`);
	}
	lines.push("}");
	return lines.join("\n");
}

export function downloadText(content: string, filename: string, mimeType: string): void {
	const blob = new Blob([content], { type: mimeType });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}
