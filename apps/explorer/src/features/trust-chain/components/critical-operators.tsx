import { Badge } from "@oidfed/ui";
import { AlertTriangle } from "lucide-react";

interface CriticalOperatorsProps {
	readonly criticalClaims: readonly string[];
}

export function CriticalOperators({ criticalClaims }: CriticalOperatorsProps) {
	if (criticalClaims.length === 0) return null;

	return (
		<div className="rounded-lg border border-warning/50 bg-warning/10 p-3">
			<div className="flex items-center gap-2 mb-2">
				<AlertTriangle className="size-4 text-warning-foreground" />
				<span className="text-sm font-medium text-warning-foreground">metadata_policy_crit</span>
			</div>
			<div className="flex gap-1 flex-wrap">
				{criticalClaims.map((claim) => (
					<Badge key={claim} variant="outline" className="font-mono text-xs">
						{claim}
					</Badge>
				))}
			</div>
			<p className="text-xs text-warning-foreground/80 mt-2">
				These policy operators must be understood by all consumers.
			</p>
		</div>
	);
}
