import { AlertTriangle } from "lucide-react";
import type { PolicyWarning } from "../hooks/use-policy-validation";

interface CombinationWarningsProps {
	readonly warnings: readonly PolicyWarning[];
}

export function CombinationWarnings({ warnings }: CombinationWarningsProps) {
	if (warnings.length === 0) return null;

	return (
		<div className="rounded-lg border border-warning/50 bg-warning/10 px-4 py-3 space-y-2">
			<div className="flex items-center gap-2">
				<AlertTriangle className="size-4 text-warning-foreground shrink-0" />
				<span className="text-sm font-medium text-warning-foreground">
					{warnings.length} operator combination{warnings.length !== 1 ? "s" : ""} violate §6.1.3.1
				</span>
			</div>
			<ul className="space-y-1 pl-6 list-disc">
				{warnings.map((w) => (
					<li
						key={`${w.entityType}.${w.field}.${w.op1}.${w.op2}`}
						className="text-xs text-warning-foreground"
					>
						<span className="font-mono">
							{w.entityType}.{w.field}
						</span>
						: {w.message}
					</li>
				))}
			</ul>
		</div>
	);
}
