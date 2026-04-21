import type { ParsedEntityStatement } from "@oidfed/core";
import { Badge } from "@oidfed/ui";
import { JsonTree } from "@/components/shared/json-tree";

interface MetadataPolicyPanelProps {
	readonly statement: ParsedEntityStatement;
	readonly index: number;
}

export function MetadataPolicyPanel({ statement, index }: MetadataPolicyPanelProps) {
	const policy = statement.payload.metadata_policy;
	if (!policy || typeof policy !== "object") return null;

	return (
		<div className="rounded-lg border bg-card p-3 space-y-2">
			<div className="flex items-center gap-2">
				<Badge variant="secondary" className="text-xs">
					Level {index}
				</Badge>
				<span className="text-sm text-muted-foreground font-mono">
					{String(statement.payload.iss)}
				</span>
			</div>
			<JsonTree data={policy} collapsed={2} />
		</div>
	);
}
