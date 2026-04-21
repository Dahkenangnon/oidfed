import { Badge, Button, Input, Progress, Skeleton } from "@oidfed/ui";
import { AlertTriangle, Clock, Download, Search, Settings2, Square, X } from "lucide-react";
import Papa from "papaparse";
import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";
import { useSettings } from "@/hooks/use-settings";
import { NoTrustAnchorsWarning } from "../trust-chain/components/no-trust-anchors-warning";
import { useTrustAnchorSet } from "../trust-chain/hooks/use-trust-anchor-set";
import { ExpiryFilterBar } from "./components/expiry-filter-bar";
import { ExpiryLegend, ExpiryTable } from "./components/expiry-table";
import { ExpiryThresholdEditor } from "./components/expiry-threshold-editor";
import { type ExpiryStatus, getExpiryStatus, useExpiryScan } from "./hooks/use-expiry-scan";

const ALL_STATUSES: readonly ExpiryStatus[] = ["expired", "critical", "warning", "soon", "ok"];

export function ExpirationDashboardPage() {
	usePageTitle("Expiration Dashboard — OidFed Explorer");
	const [searchParams, setSearchParams] = useSearchParams();
	const initialEntity = searchParams.get("entity") ?? "";
	const [authorityId, setAuthorityId] = useState(initialEntity);
	const [submittedId, setSubmittedId] = useState<string | undefined>(initialEntity || undefined);
	const [settings] = useSettings();
	const [thresholdEditorOpen, setThresholdEditorOpen] = useState(false);

	// Filter state
	const [activeStatuses, setActiveStatuses] = useState<ReadonlySet<ExpiryStatus>>(
		new Set(ALL_STATUSES),
	);
	const [searchText, setSearchText] = useState("");

	const {
		trustAnchorSet,
		hasTrustAnchors,
		anchorsWithoutJwks,
		failedAnchors,
		loading: loadingAnchors,
	} = useTrustAnchorSet();

	const { entries, progress, loading, error, scan, abort } = useExpiryScan();

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmed = authorityId.trim();
			if (!trimmed || !trustAnchorSet) return;
			setSubmittedId(trimmed);
			setSearchParams({ entity: trimmed });
			scan(trimmed, trustAnchorSet);
		},
		[authorityId, trustAnchorSet, scan, setSearchParams],
	);

	const thresholds = settings.expirationWarningDays;

	// Summary counts by status
	const summary = useMemo(() => {
		const counts = { expired: 0, critical: 0, warning: 0, soon: 0, ok: 0 };
		for (const entry of entries) {
			counts[getExpiryStatus(entry.daysRemaining, thresholds)]++;
		}
		return counts;
	}, [entries, thresholds]);

	// Filtered entries
	const filteredEntries = useMemo(() => {
		const lowerSearch = searchText.toLowerCase();
		return entries.filter((entry) => {
			const status = getExpiryStatus(entry.daysRemaining, thresholds);
			if (!activeStatuses.has(status)) return false;
			if (
				lowerSearch &&
				!entry.entityId.toLowerCase().includes(lowerSearch) &&
				!entry.trustAnchorId.toLowerCase().includes(lowerSearch)
			) {
				return false;
			}
			return true;
		});
	}, [entries, activeStatuses, searchText, thresholds]);

	const handleToggleStatus = useCallback((status: ExpiryStatus) => {
		setActiveStatuses((prev) => {
			const next = new Set(prev);
			if (next.has(status)) next.delete(status);
			else next.add(status);
			return next;
		});
	}, []);

	const exportCsv = useCallback(() => {
		const csv = Papa.unparse(
			filteredEntries.map((e) => ({
				entity_id: e.entityId,
				trust_anchor_id: e.trustAnchorId,
				expires_at: new Date(e.expiresAt * 1000).toISOString(),
				days_remaining: e.daysRemaining,
				expired: e.expired,
			})),
		);
		const blob = new Blob([csv], { type: "text/csv" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = "expiry-scan.csv";
		a.click();
		URL.revokeObjectURL(url);
	}, [filteredEntries]);

	const exportJson = useCallback(() => {
		const json = JSON.stringify(filteredEntries, null, 2);
		const blob = new Blob([json], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = "expiry-scan.json";
		a.click();
		URL.revokeObjectURL(url);
	}, [filteredEntries]);

	const progressPercent =
		progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Expiration Dashboard</h1>
				<p className="text-sm text-muted-foreground">
					Scan all subordinates of an authority and monitor trust chain expirations
				</p>
			</div>

			{!loadingAnchors && !hasTrustAnchors && (
				<NoTrustAnchorsWarning
					anchorsWithoutJwks={anchorsWithoutJwks}
					failedAnchors={failedAnchors}
				/>
			)}

			<form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
				<div className="relative flex-1">
					<Input
						type="url"
						placeholder="https://authority.example.com — Enter authority Entity ID to scan"
						value={authorityId}
						onChange={(e) => setAuthorityId(e.target.value)}
						className="pr-8"
					/>
					{authorityId && (
						<button
							type="button"
							onClick={() => setAuthorityId("")}
							className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
						>
							<X className="size-4" />
						</button>
					)}
				</div>
				<Button
					type="submit"
					disabled={!authorityId.trim() || !trustAnchorSet || loading || loadingAnchors}
				>
					<Search className="mr-2 size-4" />
					Scan
				</Button>
				{loading && (
					<Button type="button" variant="outline" onClick={abort}>
						<Square className="mr-2 size-4" />
						Stop
					</Button>
				)}
				{entries.length > 0 && (
					<Button
						type="button"
						variant="outline"
						size="icon"
						onClick={() => setThresholdEditorOpen((v) => !v)}
						title="Configure thresholds"
					>
						<Settings2 className="size-4" />
					</Button>
				)}
			</form>

			<ExpiryThresholdEditor open={thresholdEditorOpen} onOpenChange={setThresholdEditorOpen} />

			{!submittedId && !loading && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<Clock className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Enter an authority entity ID above to scan subordinate trust chain expirations
						</p>
					</div>
				</div>
			)}

			{loading && progress && (
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

			{loading && !progress && (
				<div className="space-y-2">
					<Skeleton className="h-4 w-48" />
					<Skeleton className="h-2 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{error}</p>
				</div>
			)}

			{entries.length > 0 && (
				<>
					<div className="flex items-center justify-between flex-wrap gap-3">
						<div className="flex flex-wrap items-center gap-2">
							<span className="text-sm text-muted-foreground">
								{entries.length} chain{entries.length !== 1 ? "s" : ""}
							</span>
							{summary.expired > 0 && (
								<button type="button" onClick={() => handleToggleStatus("expired")}>
									<Badge
										variant="outline"
										className={`cursor-pointer bg-muted text-muted-foreground text-xs ${!activeStatuses.has("expired") ? "opacity-30" : ""}`}
									>
										{summary.expired} expired
									</Badge>
								</button>
							)}
							{summary.critical > 0 && (
								<button type="button" onClick={() => handleToggleStatus("critical")}>
									<Badge
										variant="outline"
										className={`cursor-pointer bg-destructive/10 text-destructive-foreground text-xs ${!activeStatuses.has("critical") ? "opacity-30" : ""}`}
									>
										{summary.critical} critical
									</Badge>
								</button>
							)}
							{summary.warning > 0 && (
								<button type="button" onClick={() => handleToggleStatus("warning")}>
									<Badge
										variant="outline"
										className={`cursor-pointer bg-warning/10 text-warning-foreground text-xs ${!activeStatuses.has("warning") ? "opacity-30" : ""}`}
									>
										{summary.warning} warning
									</Badge>
								</button>
							)}
							{summary.ok > 0 && (
								<button type="button" onClick={() => handleToggleStatus("ok")}>
									<Badge
										variant="outline"
										className={`cursor-pointer bg-success/10 text-success-foreground text-xs ${!activeStatuses.has("ok") ? "opacity-30" : ""}`}
									>
										{summary.ok} ok
									</Badge>
								</button>
							)}
						</div>
						<div className="flex flex-wrap gap-2">
							<Button variant="outline" size="sm" onClick={exportCsv}>
								<Download className="mr-1.5 size-3.5" />
								CSV
							</Button>
							<Button variant="outline" size="sm" onClick={exportJson}>
								<Download className="mr-1.5 size-3.5" />
								JSON
							</Button>
						</div>
					</div>

					<ExpiryFilterBar
						entries={entries}
						activeStatuses={activeStatuses}
						onToggleStatus={handleToggleStatus}
						searchText={searchText}
						onSearchChange={setSearchText}
						filteredCount={filteredEntries.length}
					/>

					<ExpiryLegend />
					<ExpiryTable entries={filteredEntries} />
				</>
			)}

			{submittedId && !loading && !error && entries.length === 0 && (
				<p className="text-sm text-muted-foreground">
					No trust chains resolved. Check that the authority has subordinates and trust anchors are
					configured.
				</p>
			)}
		</div>
	);
}
