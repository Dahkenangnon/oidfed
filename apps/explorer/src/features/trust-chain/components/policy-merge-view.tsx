import type { ParsedEntityStatement } from "@oidfed/core";
import { isErr, isOk, resolveMetadataPolicy } from "@oidfed/core";
import { AlertTriangle } from "lucide-react";
import { useMemo } from "react";
import { JsonTree } from "@/components/shared/json-tree";
import { MetadataPolicyPanel } from "./metadata-policy-panel";

interface PolicyMergeViewProps {
	readonly statements: readonly ParsedEntityStatement[];
}

export function PolicyMergeView({ statements }: PolicyMergeViewProps) {
	const statementsWithPolicy = statements.filter(
		(s) => s.payload.metadata_policy && typeof s.payload.metadata_policy === "object",
	);

	const mergeResult = useMemo(() => {
		if (statementsWithPolicy.length === 0) return null;
		// resolveMetadataPolicy expects subordinate statements (non-EC statements)
		const subordinates = [...statements].slice(1, -1);
		if (subordinates.length === 0) return null;
		return resolveMetadataPolicy(subordinates);
	}, [statements, statementsWithPolicy.length]);

	if (statementsWithPolicy.length === 0) {
		return (
			<p className="text-sm text-muted-foreground">No metadata policies in this trust chain.</p>
		);
	}

	return (
		<div className="space-y-4">
			<h3 className="text-sm font-medium">Per-level Policies</h3>
			{statementsWithPolicy.map((stmt, idx) => (
				<MetadataPolicyPanel
					// biome-ignore lint/suspicious/noArrayIndexKey: statements ordered by chain position
					key={`policy-${idx}-${stmt.payload.iss}`}
					statement={stmt}
					index={statements.indexOf(stmt)}
				/>
			))}

			<h3 className="text-sm font-medium">Merged Policy</h3>
			{mergeResult && isOk(mergeResult) ? (
				<JsonTree data={mergeResult.value} collapsed={2} />
			) : mergeResult && isErr(mergeResult) ? (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 flex items-start gap-2">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<div>
						<p className="text-sm font-medium text-destructive-foreground">Policy merge conflict</p>
						<p className="text-xs text-destructive-foreground/80">
							{mergeResult.error.description}
						</p>
					</div>
				</div>
			) : (
				<p className="text-sm text-muted-foreground">No subordinate statements to merge.</p>
			)}
		</div>
	);
}
