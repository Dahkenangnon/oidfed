import { Badge, Collapsible, CollapsibleContent, CollapsibleTrigger, Progress } from "@oidfed/ui";
import { CheckCircle, XCircle } from "lucide-react";
import type { BatchHealthResult } from "../hooks/use-batch-health";

interface BatchHealthPanelProps {
	readonly results: ReadonlyMap<string, BatchHealthResult>;
	readonly progress: { readonly done: number; readonly total: number };
	readonly running: boolean;
}

export function BatchHealthPanel({ results, progress, running }: BatchHealthPanelProps) {
	const healthyCount = Array.from(results.values()).filter((r) => r.fail === 0).length;
	const unhealthyCount = results.size - healthyCount;
	const progressPercent =
		progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

	return (
		<Collapsible defaultOpen>
			<CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg border px-4 py-2 text-sm font-medium hover:bg-muted/50">
				<span>Batch Health Check</span>
				{!running && results.size > 0 && (
					<div className="flex items-center gap-2">
						<Badge variant="outline" className="bg-success/10 text-success-foreground text-xs">
							{healthyCount} healthy
						</Badge>
						{unhealthyCount > 0 && (
							<Badge
								variant="outline"
								className="bg-destructive/10 text-destructive-foreground text-xs"
							>
								{unhealthyCount} unhealthy
							</Badge>
						)}
						<Badge variant="secondary" className="text-xs">
							{results.size} total
						</Badge>
					</div>
				)}
			</CollapsibleTrigger>
			<CollapsibleContent className="pt-2">
				{running && (
					<div className="space-y-2">
						<div className="flex items-center justify-between text-sm text-muted-foreground">
							<span>
								Checking {progress.done} / {progress.total} entities…
							</span>
							<span>{progressPercent}%</span>
						</div>
						<Progress value={progressPercent} className="h-2" />
					</div>
				)}

				{!running && results.size === 0 && (
					<p className="text-sm text-muted-foreground py-2">No results yet.</p>
				)}

				{!running && results.size > 0 && (
					<div className="rounded-lg border divide-y max-h-60 overflow-y-auto">
						{Array.from(results.entries()).map(([entityId, result]) => (
							<div key={entityId} className="flex items-center justify-between px-4 py-1.5 text-xs">
								<span className="font-mono truncate flex-1">{entityId}</span>
								<div className="flex items-center gap-1.5 ml-2">
									{result.fail === 0 ? (
										<CheckCircle className="size-3.5 text-success-foreground" />
									) : (
										<XCircle className="size-3.5 text-destructive-foreground" />
									)}
									<span className="text-muted-foreground">
										{result.ok}/{result.total}
									</span>
								</div>
							</div>
						))}
					</div>
				)}
			</CollapsibleContent>
		</Collapsible>
	);
}
