import { Input } from "@oidfed/ui";
import { Search, X } from "lucide-react";
import { useMemo } from "react";
import { useSettings } from "@/hooks/use-settings";
import type { ExpiryEntry, ExpiryStatus } from "../hooks/use-expiry-scan";
import { getExpiryStatus } from "../hooks/use-expiry-scan";
import { STATUS_CONFIG } from "./expiry-table";

const ALL_STATUSES: readonly ExpiryStatus[] = ["expired", "critical", "warning", "soon", "ok"];

interface ExpiryFilterBarProps {
	readonly entries: readonly ExpiryEntry[];
	readonly activeStatuses: ReadonlySet<ExpiryStatus>;
	readonly onToggleStatus: (status: ExpiryStatus) => void;
	readonly searchText: string;
	readonly onSearchChange: (text: string) => void;
	readonly filteredCount: number;
}

export function ExpiryFilterBar({
	entries,
	activeStatuses,
	onToggleStatus,
	searchText,
	onSearchChange,
	filteredCount,
}: ExpiryFilterBarProps) {
	const [settings] = useSettings();
	const thresholds = settings.expirationWarningDays;

	const counts = useMemo(() => {
		const c: Record<ExpiryStatus, number> = { expired: 0, critical: 0, warning: 0, soon: 0, ok: 0 };
		for (const entry of entries) {
			c[getExpiryStatus(entry.daysRemaining, thresholds)]++;
		}
		return c;
	}, [entries, thresholds]);

	return (
		<div className="space-y-3">
			<div className="flex flex-wrap items-center gap-2">
				{ALL_STATUSES.map((status) => {
					const cfg = STATUS_CONFIG[status];
					const Icon = cfg.icon;
					const active = activeStatuses.has(status);
					return (
						<button
							key={status}
							type="button"
							onClick={() => onToggleStatus(status)}
							className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition-opacity ${
								active ? cfg.className : "opacity-30 bg-muted text-muted-foreground"
							}`}
						>
							<Icon className="size-3" />
							{cfg.label}
							<span className="ml-0.5 font-mono">{counts[status]}</span>
						</button>
					);
				})}
			</div>

			<div className="flex items-center gap-3">
				<div className="relative flex-1 max-w-sm">
					<Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
					<Input
						type="text"
						placeholder="Filter by entity ID or trust anchor…"
						value={searchText}
						onChange={(e) => onSearchChange(e.target.value)}
						className="pl-8 pr-8 h-8 text-xs"
					/>
					{searchText && (
						<button
							type="button"
							onClick={() => onSearchChange("")}
							className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
						>
							<X className="size-3.5" />
						</button>
					)}
				</div>
				<span className="text-xs text-muted-foreground">
					Showing {filteredCount} of {entries.length}
				</span>
			</div>
		</div>
	);
}
