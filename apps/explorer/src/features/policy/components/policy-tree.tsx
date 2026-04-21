import { operators, type PolicyOperatorDefinition } from "@oidfed/core";
import { OperatorBadge } from "./operator-badge";

interface PolicyTreeProps {
	readonly policy: Record<string, Record<string, Record<string, unknown>>>;
	readonly conflictFields?: ReadonlySet<string> | undefined;
}

export function PolicyTree({ policy, conflictFields }: PolicyTreeProps) {
	const entityTypes = Object.keys(policy);

	if (entityTypes.length === 0) {
		return <p className="text-sm text-muted-foreground">No policy operators in merged result.</p>;
	}

	return (
		<div className="space-y-4">
			{entityTypes.map((entityType) => {
				const fields = policy[entityType];
				if (!fields) return null;

				return (
					<div key={entityType} className="space-y-2">
						<h3 className="text-sm font-semibold font-mono">{entityType}</h3>
						<div className="space-y-1.5 pl-3 border-l-2 border-muted">
							{Object.entries(fields).map(([fieldName, ops]) => {
								if (!ops || typeof ops !== "object") return null;
								const fieldKey = `${entityType}.${fieldName}`;
								const hasConflict = conflictFields?.has(fieldKey) ?? false;

								return (
									<div
										key={fieldName}
										className={`space-y-0.5 rounded px-2 py-1 ${
											hasConflict ? "bg-destructive/5 border border-destructive/20" : ""
										}`}
									>
										<span className="text-xs font-mono font-medium">{fieldName}</span>
										<div className="flex flex-wrap gap-1.5">
											{Object.entries(ops as Record<string, unknown>)
												.sort(([a], [b]) => {
													const oa =
														(operators[a] as PolicyOperatorDefinition | undefined)?.order ?? 99;
													const ob =
														(operators[b] as PolicyOperatorDefinition | undefined)?.order ?? 99;
													return oa - ob;
												})
												.map(([opName, opValue]) => (
													<OperatorBadge
														key={opName}
														name={opName}
														value={opValue}
														definition={operators[opName] as PolicyOperatorDefinition | undefined}
														hasConflict={hasConflict}
													/>
												))}
										</div>
									</div>
								);
							})}
						</div>
					</div>
				);
			})}
		</div>
	);
}
