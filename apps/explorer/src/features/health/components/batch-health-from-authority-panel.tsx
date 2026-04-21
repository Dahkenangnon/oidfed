import { decodeEntityStatement, fetchEntityConfiguration, validateEntityId } from "@oidfed/core";
import { Button, Input } from "@oidfed/ui";
import { AlertTriangle, RefreshCw, Search, X } from "lucide-react";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";
import { BatchHealthPanel } from "../../subordinates/components/batch-health-panel";
import { useBatchHealth } from "../../subordinates/hooks/use-batch-health";

export function BatchHealthFromAuthorityPanel() {
	const [settings] = useSettings();
	const [authorityId, setAuthorityId] = useState("");
	const [subordinateIds, setSubordinateIds] = useState<readonly string[]>([]);
	const [fetching, setFetching] = useState(false);
	const [fetchError, setFetchError] = useState<string | null>(null);
	const [noListEndpoint, setNoListEndpoint] = useState(false);

	const { results, progress, running, start, cancel } = useBatchHealth();

	const fetchSubordinates = useCallback(async () => {
		const trimmed = authorityId.trim();
		if (!trimmed) return;

		setFetching(true);
		setFetchError(null);
		setSubordinateIds([]);
		setNoListEndpoint(false);

		try {
			const validated = validateEntityId(trimmed);
			if (!validated.ok) throw new Error(validated.error.description);

			const ecResult = await fetchEntityConfiguration(validated.value, {
				httpTimeoutMs: settings.httpTimeoutMs,
			});
			if (!ecResult.ok) throw new Error(ecResult.error.description);

			const decoded = decodeEntityStatement(ecResult.value);
			if (!decoded.ok) throw new Error(decoded.error.description);

			const payload = decoded.value.payload as Record<string, unknown>;
			const fedEntity = extractFederationEntity(payload);
			const listUrl = fedEntity.federation_list_endpoint as string | undefined;

			if (!listUrl) {
				setNoListEndpoint(true);
				return;
			}

			const response = await fetch(listUrl);
			if (!response.ok) throw new Error(`List endpoint returned HTTP ${response.status}`);

			const data: unknown = await response.json();
			if (!Array.isArray(data)) throw new Error("List endpoint did not return a JSON array");

			setSubordinateIds(data.filter((v): v is string => typeof v === "string"));
		} catch (err: unknown) {
			setFetchError(err instanceof Error ? err.message : "Unknown error");
		} finally {
			setFetching(false);
		}
	}, [authorityId, settings.httpTimeoutMs]);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			fetchSubordinates();
		},
		[fetchSubordinates],
	);

	return (
		<div className="space-y-4">
			<form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
				<div className="relative flex-1">
					<Input
						type="url"
						placeholder="https://authority.example.com — Enter Authority ID"
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
				<Button type="submit" disabled={!authorityId.trim() || fetching}>
					{fetching ? (
						<RefreshCw className="mr-2 size-4 animate-spin" />
					) : (
						<Search className="mr-2 size-4" />
					)}
					Fetch Subordinates
				</Button>
			</form>

			{fetchError && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{fetchError}</p>
				</div>
			)}

			{noListEndpoint && (
				<div className="rounded-lg border border-warning/50 bg-warning/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-warning-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-warning-foreground">
						This entity does not declare a{" "}
						<code className="font-mono">federation_list_endpoint</code>.
					</p>
				</div>
			)}

			{subordinateIds.length > 0 && !running && results.size === 0 && (
				<div className="flex items-center justify-between rounded-lg border p-4">
					<p className="text-sm text-muted-foreground">
						Found <span className="font-medium text-foreground">{subordinateIds.length}</span>{" "}
						subordinate(s)
					</p>
					<Button onClick={() => start(subordinateIds)} size="sm">
						Run Health Check
					</Button>
				</div>
			)}

			{running && (
				<div className="flex justify-end">
					<Button variant="outline" size="sm" onClick={cancel}>
						Cancel
					</Button>
				</div>
			)}

			{(running || results.size > 0) && (
				<BatchHealthPanel results={results} progress={progress} running={running} />
			)}
		</div>
	);
}
