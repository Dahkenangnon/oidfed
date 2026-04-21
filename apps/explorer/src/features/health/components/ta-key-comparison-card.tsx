import { Badge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@oidfed/ui";
import { Info, KeyRound } from "lucide-react";
import type { TaKeyComparisonResult } from "../hooks/use-ta-key-comparison";

interface TaKeyComparisonCardProps {
	readonly comparison: TaKeyComparisonResult;
}

const STATUS_STYLES = {
	match: "bg-success/15 text-success-foreground border-success/60",
	missing: "bg-destructive/15 text-destructive-foreground border-destructive/60",
	extra: "bg-warning/15 text-warning-foreground border-warning/60",
} as const;

const STATUS_LABELS = {
	match: "Match",
	missing: "Missing",
	extra: "Extra",
} as const;

export function TaKeyComparisonCard({ comparison }: TaKeyComparisonCardProps) {
	if (!comparison.isConfiguredTa) return null;

	if (!comparison.hasPinnedJwks) {
		return (
			<div className="rounded-lg border p-4 flex items-start gap-3">
				<Info className="size-4 text-muted-foreground shrink-0 mt-0.5" />
				<div className="space-y-1">
					<p className="text-sm font-medium">Trust Anchor Key Comparison</p>
					<p className="text-xs text-muted-foreground">
						No pinned JWKS configured for this trust anchor. Add JWKS in Settings to enable key
						comparison.
					</p>
				</div>
			</div>
		);
	}

	if (comparison.loading) return null;

	const matchCount = comparison.entries.filter((e) => e.status === "match").length;
	const missingCount = comparison.entries.filter((e) => e.status === "missing").length;
	const extraCount = comparison.entries.filter((e) => e.status === "extra").length;

	return (
		<div className="rounded-lg border space-y-3">
			<div className="flex items-center gap-2 px-4 pt-4">
				<KeyRound className="size-4 text-muted-foreground" />
				<h3 className="text-sm font-medium">Trust Anchor Key Comparison</h3>
			</div>

			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Thumbprint</TableHead>
						<TableHead>kid</TableHead>
						<TableHead>kty</TableHead>
						<TableHead>alg</TableHead>
						<TableHead>Status</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{comparison.entries.map((entry) => (
						<TableRow key={entry.thumbprint}>
							<TableCell className="font-mono text-xs" title={entry.thumbprint}>
								{entry.thumbprint.slice(0, 16)}…
							</TableCell>
							<TableCell className="font-mono text-xs">{entry.kid ?? "—"}</TableCell>
							<TableCell>
								<Badge variant="outline">{entry.kty}</Badge>
							</TableCell>
							<TableCell className="font-mono text-xs">{entry.alg ?? "—"}</TableCell>
							<TableCell>
								<Badge className={`text-xs ${STATUS_STYLES[entry.status]}`}>
									{STATUS_LABELS[entry.status]}
								</Badge>
							</TableCell>
						</TableRow>
					))}
				</TableBody>
			</Table>

			<p className="text-xs text-muted-foreground px-4 pb-3">
				{matchCount} matched, {missingCount} missing, {extraCount} extra
			</p>
		</div>
	);
}
