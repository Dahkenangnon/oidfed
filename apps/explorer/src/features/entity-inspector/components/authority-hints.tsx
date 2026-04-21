import { Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import { ArrowUpRight } from "lucide-react";
import { EntityLink } from "@/components/shared/entity-link";

interface AuthorityHintsProps {
	readonly hints: readonly string[];
}

export function AuthorityHints({ hints }: AuthorityHintsProps) {
	if (hints.length === 0) {
		return <p className="text-sm text-muted-foreground">No authority hints present.</p>;
	}

	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<ArrowUpRight className="size-4" />
					Authority Hints ({hints.length})
				</CardTitle>
			</CardHeader>
			<CardContent>
				<ul className="space-y-2">
					{hints.map((hint) => (
						<li key={hint}>
							<EntityLink entityId={hint} />
						</li>
					))}
				</ul>
			</CardContent>
		</Card>
	);
}
