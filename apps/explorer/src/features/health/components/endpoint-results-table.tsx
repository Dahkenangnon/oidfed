import { Badge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@oidfed/ui";
import { CheckCircle, XCircle } from "lucide-react";
import type { EndpointResult } from "../hooks/use-health-check";

interface EndpointResultsTableProps {
	readonly results: readonly EndpointResult[];
}

function StatusBadge({ ok }: { readonly ok: boolean }) {
	if (ok) {
		return (
			<Badge variant="outline" className="bg-success/10 text-success-foreground border-success/20">
				<CheckCircle className="mr-1 size-3" />
				Pass
			</Badge>
		);
	}
	return (
		<Badge
			variant="outline"
			className="bg-destructive/10 text-destructive-foreground border-destructive/20"
		>
			<XCircle className="mr-1 size-3" />
			Fail
		</Badge>
	);
}

export function EndpointResultsTable({ results }: EndpointResultsTableProps) {
	if (results.length === 0) return null;

	return (
		<div className="rounded-lg border overflow-hidden">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Endpoint</TableHead>
						<TableHead>URL</TableHead>
						<TableHead className="w-20">Status</TableHead>
						<TableHead className="w-24">Latency</TableHead>
						<TableHead>Content-Type</TableHead>
						<TableHead className="w-20">Result</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{results.map((r) => (
						<TableRow key={r.name}>
							<TableCell className="font-mono text-xs">{r.name}</TableCell>
							<TableCell className="font-mono text-xs max-w-xs truncate">
								<a
									href={r.url}
									target="_blank"
									rel="noopener noreferrer"
									className="text-brand-500 hover:underline"
								>
									{r.url}
								</a>
							</TableCell>
							<TableCell>
								{r.status !== null ? (
									<span
										className={`text-sm font-mono ${r.status >= 200 && r.status < 300 ? "text-success-foreground" : "text-destructive-foreground"}`}
									>
										{r.status}
									</span>
								) : (
									<span className="text-muted-foreground text-sm">—</span>
								)}
							</TableCell>
							<TableCell className="text-sm">
								{r.latency !== null ? (
									<span className="font-mono">{r.latency}ms</span>
								) : (
									<span className="text-muted-foreground">—</span>
								)}
							</TableCell>
							<TableCell className="font-mono text-xs">
								{r.error ? (
									<span className="text-destructive-foreground">{r.error}</span>
								) : r.contentType ? (
									<span
										className={
											r.contentType.includes(r.expectedContentType)
												? "text-success-foreground"
												: "text-warning-foreground"
										}
									>
										{r.contentType}
									</span>
								) : (
									<span className="text-muted-foreground">—</span>
								)}
							</TableCell>
							<TableCell>
								<StatusBadge ok={r.ok} />
							</TableCell>
						</TableRow>
					))}
				</TableBody>
			</Table>
		</div>
	);
}
