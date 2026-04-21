import type { ParsedEntityStatement } from "@oidfed/core";
import { Badge } from "@oidfed/ui";
import { AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { JsonTree } from "@/components/shared/json-tree";

interface ConstraintPanelProps {
	readonly statements: readonly ParsedEntityStatement[];
	readonly violations?: readonly string[];
}

export function ConstraintPanel({ statements, violations = [] }: ConstraintPanelProps) {
	const constraintStatements = statements.filter(
		(s) => s.payload.constraints && typeof s.payload.constraints === "object",
	);

	if (constraintStatements.length === 0) {
		return (
			<p className="text-sm text-muted-foreground">No constraints defined in this trust chain.</p>
		);
	}

	return (
		<div className="space-y-4">
			{violations.length > 0 && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 flex items-start gap-2">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<div className="space-y-1">
						<p className="text-sm font-medium text-destructive-foreground">Constraint violations</p>
						{violations.map((v) => (
							<p key={v} className="text-xs text-destructive-foreground/80">
								{v}
							</p>
						))}
					</div>
				</div>
			)}
			{constraintStatements.map((stmt, i) => {
				const constraints = stmt.payload.constraints as Record<string, unknown>;
				const maxPathLength = constraints.max_path_length as number | undefined;
				const naming = constraints.naming_constraints as Record<string, unknown> | undefined;
				const allowed = constraints.allowed_entity_types as string[] | undefined;

				return (
					<div
						// biome-ignore lint/suspicious/noArrayIndexKey: statements ordered by chain position
						key={`constraint-${i}-${stmt.payload.iss}`}
						className="rounded-lg border bg-card p-3 space-y-3"
					>
						<div className="flex items-center gap-2">
							<Badge variant="secondary" className="text-xs">
								From: {String(stmt.payload.iss)}
							</Badge>
						</div>

						{maxPathLength !== undefined && (
							<div className="flex items-center gap-2">
								<span className="text-sm text-muted-foreground">max_path_length:</span>
								<Badge variant="outline" className="font-mono text-xs">
									{maxPathLength}
								</Badge>
								<span className="text-xs text-muted-foreground">
									(chain has {statements.length - 2} intermediates)
								</span>
								{statements.length - 2 <= maxPathLength ? (
									<CheckCircle className="size-3.5 text-success-foreground" />
								) : (
									<XCircle className="size-3.5 text-destructive-foreground" />
								)}
							</div>
						)}

						{naming && (
							<div>
								<span className="text-sm text-muted-foreground">naming_constraints:</span>
								<JsonTree data={naming} collapsed={1} />
							</div>
						)}

						{allowed && (
							<div className="flex items-center gap-2 flex-wrap">
								<span className="text-sm text-muted-foreground">allowed_entity_types:</span>
								{allowed.map((t) => (
									<Badge key={t} variant="outline" className="font-mono text-xs">
										{t}
									</Badge>
								))}
							</div>
						)}
					</div>
				);
			})}
		</div>
	);
}
