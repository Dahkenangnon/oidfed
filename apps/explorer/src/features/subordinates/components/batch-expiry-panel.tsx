import { Badge, Collapsible, CollapsibleContent, CollapsibleTrigger, Progress } from "@oidfed/ui";
import { useMemo } from "react";
import { EntityLink } from "@/components/shared/entity-link";
import { ExpiryLegend } from "@/features/expiry/components/expiry-table";
import type { ExpiryEntry, ScanProgress } from "@/features/expiry/hooks/use-expiry-scan";
import { getExpiryStatus } from "@/features/expiry/hooks/use-expiry-scan";
import { useSettings } from "@/hooks/use-settings";

interface BatchExpiryPanelProps {
	readonly entries: readonly ExpiryEntry[];
	readonly progress: ScanProgress | null;
	readonly running: boolean;
}

export function BatchExpiryPanel({ entries, progress, running }: BatchExpiryPanelProps) {
	const [settings] = useSettings();
	const thresholds = settings.expirationWarningDays;

	const counts = useMemo(() => {
		const c = { expired: 0, critical: 0, warning: 0, soon: 0, ok: 0 };
		for (const entry of entries) {
			c[getExpiryStatus(entry.daysRemaining, thresholds)]++;
		}
		return c;
	}, [entries, thresholds]);

	const progressPercent =
		progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

	return (
		<Collapsible defaultOpen>
			<CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg border px-4 py-2 text-sm font-medium hover:bg-muted/50">
				<span>Batch Expiry Scan</span>
				{!running && entries.length > 0 && (
					<div className="flex items-center gap-2">
						{counts.expired > 0 && (
							<Badge variant="outline" className="bg-muted text-muted-foreground text-xs">
								{counts.expired} expired
							</Badge>
						)}
						{counts.critical > 0 && (
							<Badge
								variant="outline"
								className="bg-destructive/10 text-destructive-foreground text-xs"
							>
								{counts.critical} critical
							</Badge>
						)}
						{counts.warning > 0 && (
							<Badge variant="outline" className="bg-warning/10 text-warning-foreground text-xs">
								{counts.warning} warning
							</Badge>
						)}
						{counts.ok > 0 && (
							<Badge variant="outline" className="bg-success/10 text-success-foreground text-xs">
								{counts.ok} ok
							</Badge>
						)}
					</div>
				)}
			</CollapsibleTrigger>
			<CollapsibleContent className="space-y-2 pt-2">
				{running && progress && (
					<div className="space-y-2">
						<div className="flex items-center justify-between text-sm text-muted-foreground">
							<span>
								Scanning {progress.done} / {progress.total} entities…
							</span>
							<span>{progressPercent}%</span>
						</div>
						<Progress value={progressPercent} className="h-2" />
					</div>
				)}

				{!running && entries.length === 0 && (
					<p className="text-sm text-muted-foreground py-2">No results yet.</p>
				)}

				{entries.length > 0 && (
					<>
						<ExpiryLegend />
						<div className="rounded-lg border divide-y max-h-60 overflow-y-auto">
							{entries.map((entry) => {
								const status = getExpiryStatus(entry.daysRemaining, thresholds);
								return (
									<div
										key={`${entry.entityId}:${entry.trustAnchorId}`}
										className="flex items-center justify-between px-4 py-1.5 text-xs"
									>
										<EntityLink entityId={entry.entityId} />
										<div className="flex items-center gap-2 ml-2">
											<Badge
												variant="outline"
												className={`text-[10px] px-1.5 py-0 ${
													status === "expired"
														? "bg-muted"
														: status === "critical"
															? "bg-destructive/10"
															: status === "warning"
																? "bg-warning/10"
																: status === "soon"
																	? "bg-amber-500/10"
																	: "bg-success/10"
												}`}
											>
												{entry.expired ? "expired" : `${entry.daysRemaining}d`}
											</Badge>
										</div>
									</div>
								);
							})}
						</div>
					</>
				)}
			</CollapsibleContent>
		</Collapsible>
	);
}
