import { Badge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@oidfed/ui";
import { AlertTriangle, CheckCircle, Clock, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { EntityLink } from "@/components/shared/entity-link";
import { useSettings } from "@/hooks/use-settings";
import { type ExpiryEntry, type ExpiryStatus, getExpiryStatus } from "../hooks/use-expiry-scan";

export const STATUS_CONFIG: Record<
	ExpiryStatus,
	{ label: string; className: string; icon: React.ComponentType<{ className?: string }> }
> = {
	expired: {
		label: "Expired",
		className: "bg-muted text-muted-foreground border-muted-foreground/20",
		icon: XCircle,
	},
	critical: {
		label: "Critical",
		className: "bg-destructive/10 text-destructive-foreground border-destructive/20",
		icon: AlertTriangle,
	},
	warning: {
		label: "Warning",
		className: "bg-warning/10 text-warning-foreground border-warning/20",
		icon: AlertTriangle,
	},
	soon: {
		label: "Soon",
		className: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20",
		icon: Clock,
	},
	ok: {
		label: "OK",
		className: "bg-success/10 text-success-foreground border-success/20",
		icon: CheckCircle,
	},
};

function StatusBadge({ status }: { readonly status: ExpiryStatus }) {
	const { label, className, icon: Icon } = STATUS_CONFIG[status];
	return (
		<Badge variant="outline" className={className}>
			<Icon className="mr-1 size-3" />
			{label}
		</Badge>
	);
}

function formatDate(unix: number): string {
	return `${new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 16)} UTC`;
}

type SortField = "entityId" | "expiresAt" | "daysRemaining" | "trustAnchorId";

interface ExpiryTableProps {
	readonly entries: readonly ExpiryEntry[];
}

export function ExpiryTable({ entries }: ExpiryTableProps) {
	const [settings] = useSettings();
	const [sortField, setSortField] = useState<SortField>("expiresAt");
	const [sortAsc, setSortAsc] = useState(true);

	const thresholds = settings.expirationWarningDays;

	const sorted = useMemo(() => {
		return [...entries].sort((a, b) => {
			const mul = sortAsc ? 1 : -1;
			if (sortField === "entityId") return mul * a.entityId.localeCompare(b.entityId);
			if (sortField === "trustAnchorId")
				return mul * a.trustAnchorId.localeCompare(b.trustAnchorId);
			if (sortField === "daysRemaining") return mul * (a.daysRemaining - b.daysRemaining);
			return mul * (a.expiresAt - b.expiresAt);
		});
	}, [entries, sortField, sortAsc]);

	function toggleSort(field: SortField) {
		if (sortField === field) setSortAsc((v) => !v);
		else {
			setSortField(field);
			setSortAsc(true);
		}
	}

	function SortHeader({ field, children }: { field: SortField; children: React.ReactNode }) {
		return (
			<button
				type="button"
				onClick={() => toggleSort(field)}
				className="flex items-center gap-1 hover:text-foreground"
			>
				{children}
				{sortField === field && <span>{sortAsc ? "↑" : "↓"}</span>}
			</button>
		);
	}

	if (entries.length === 0) return null;

	return (
		<div className="rounded-lg border overflow-hidden">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>
							<SortHeader field="entityId">Entity ID</SortHeader>
						</TableHead>
						<TableHead>
							<SortHeader field="trustAnchorId">Trust Anchor</SortHeader>
						</TableHead>
						<TableHead>
							<SortHeader field="expiresAt">Expires</SortHeader>
						</TableHead>
						<TableHead>
							<SortHeader field="daysRemaining">Days</SortHeader>
						</TableHead>
						<TableHead>Status</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{sorted.map((entry) => {
						const status = getExpiryStatus(entry.daysRemaining, thresholds);
						return (
							<TableRow key={`${entry.entityId}:${entry.trustAnchorId}`}>
								<TableCell className="font-mono text-xs max-w-xs">
									<EntityLink entityId={entry.entityId} />
								</TableCell>
								<TableCell className="font-mono text-xs text-muted-foreground">
									{entry.trustAnchorId}
								</TableCell>
								<TableCell className="text-xs">{formatDate(entry.expiresAt)}</TableCell>
								<TableCell className="text-sm font-mono">
									{entry.expired ? (
										<span className="text-muted-foreground">—</span>
									) : (
										<span>{entry.daysRemaining}d</span>
									)}
								</TableCell>
								<TableCell>
									<StatusBadge status={status} />
								</TableCell>
							</TableRow>
						);
					})}
				</TableBody>
			</Table>
		</div>
	);
}

export function ExpiryLegend() {
	return (
		<div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
			<span>Status key:</span>
			{(
				Object.entries(STATUS_CONFIG) as [ExpiryStatus, (typeof STATUS_CONFIG)[ExpiryStatus]][]
			).map(([status, cfg]) => {
				const Icon = cfg.icon;
				return (
					<span key={status} className="flex items-center gap-1">
						<Icon className="size-3" />
						{cfg.label}
					</span>
				);
			})}
		</div>
	);
}
