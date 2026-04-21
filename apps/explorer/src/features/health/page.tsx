import {
	Badge,
	Button,
	Input,
	Skeleton,
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@oidfed/ui";
import { AlertTriangle, HeartPulse, RefreshCw, Search, X } from "lucide-react";
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";
import { BatchHealthFromAuthorityPanel } from "./components/batch-health-from-authority-panel";
import { EndpointResultsTable } from "./components/endpoint-results-table";
import { TaKeyComparisonCard } from "./components/ta-key-comparison-card";
import { useHealthCheck } from "./hooks/use-health-check";
import { useTaKeyComparison } from "./hooks/use-ta-key-comparison";

export function HealthCheckPage() {
	usePageTitle("Health Check — OidFed Explorer");
	const [searchParams, setSearchParams] = useSearchParams();
	const initialEntity = searchParams.get("entity") ?? "";
	const [entityId, setEntityId] = useState(initialEntity);
	const [submitted, setSubmitted] = useState(false);
	const { summary, results, loading, error, liveJwks, run } = useHealthCheck();
	const taKeyComparison = useTaKeyComparison(summary?.entityId ?? null, liveJwks);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmed = entityId.trim();
			if (trimmed) {
				setSubmitted(true);
				setSearchParams({ entity: trimmed });
				run(trimmed);
			}
		},
		[entityId, run, setSearchParams],
	);

	const passCount = results.filter((r) => r.ok).length;
	const failCount = results.filter((r) => !r.ok).length;

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Health Check</h1>
				<p className="text-sm text-muted-foreground">
					Probe federation endpoints for any entity — validates HTTP status and content-type
				</p>
			</div>

			<Tabs defaultValue="single">
				<TabsList>
					<TabsTrigger value="single">Single Entity</TabsTrigger>
					<TabsTrigger value="batch">Batch from Authority</TabsTrigger>
				</TabsList>

				<TabsContent value="single" className="mt-4 space-y-6">
					<form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
						<div className="relative flex-1">
							<Input
								type="url"
								placeholder="https://entity.example.com — Enter Entity ID to probe"
								value={entityId}
								onChange={(e) => setEntityId(e.target.value)}
								className="pr-8"
							/>
							{entityId && (
								<button
									type="button"
									onClick={() => setEntityId("")}
									className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
								>
									<X className="size-4" />
								</button>
							)}
						</div>
						<Button type="submit" disabled={!entityId.trim() || loading}>
							{loading ? (
								<RefreshCw className="mr-2 size-4 animate-spin" />
							) : (
								<Search className="mr-2 size-4" />
							)}
							Run Health Check
						</Button>
					</form>

					{!submitted && !loading && (
						<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
							<div className="text-center space-y-2 text-muted-foreground">
								<HeartPulse className="size-10 mx-auto opacity-40 dark:opacity-30" />
								<p className="text-sm">
									Enter an entity ID above to probe its federation endpoints
								</p>
							</div>
						</div>
					)}

					{loading && (
						<div className="space-y-3">
							<Skeleton className="h-20 w-full" />
							<Skeleton className="h-48 w-full" />
						</div>
					)}

					{error && (
						<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
							<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
							<p className="text-sm text-destructive-foreground">{error}</p>
						</div>
					)}

					{summary && !loading && (
						<div className="rounded-lg border p-4 space-y-3">
							<div className="flex items-start justify-between gap-4">
								<div className="space-y-1">
									<p className="font-mono text-sm font-medium">{summary.entityId}</p>
									{(summary.displayName || summary.organizationName) && (
										<p className="text-sm text-muted-foreground">
											{summary.displayName ?? summary.organizationName}
											{summary.displayName &&
												summary.organizationName &&
												summary.displayName !== summary.organizationName && (
													<span className="ml-1 text-xs">({summary.organizationName})</span>
												)}
										</p>
									)}
									{summary.description && (
										<p className="text-xs text-muted-foreground/80">{summary.description}</p>
									)}
									{summary.contacts.length > 0 && (
										<p className="text-xs text-muted-foreground/80">
											Contact: {summary.contacts.join(", ")}
										</p>
									)}
									<div className="flex flex-wrap gap-1 pt-1">
										{summary.entityTypes.map((t) => (
											<Badge key={t} variant="secondary" className="text-xs font-mono">
												{t}
											</Badge>
										))}
									</div>
									{summary.endpointAuthAlgs.length > 0 && (
										<div className="flex flex-wrap items-center gap-1 pt-1">
											<span className="text-xs text-muted-foreground font-mono">
												endpoint_auth_signing_alg:
											</span>
											{summary.endpointAuthAlgs.map((alg) => (
												<Badge key={alg} variant="outline" className="text-xs font-mono">
													{alg}
												</Badge>
											))}
										</div>
									)}
								</div>
								{results.length > 0 && (
									<div className="flex items-center gap-3 shrink-0">
										<div className="flex items-center gap-1.5">
											<HeartPulse className="size-4 text-success-foreground" />
											<span className="text-sm font-medium text-success-foreground">
												{passCount} pass
											</span>
										</div>
										{failCount > 0 && (
											<div className="flex items-center gap-1.5">
												<AlertTriangle className="size-4 text-destructive-foreground" />
												<span className="text-sm font-medium text-destructive-foreground">
													{failCount} fail
												</span>
											</div>
										)}
									</div>
								)}
							</div>
						</div>
					)}

					{summary && !loading && <TaKeyComparisonCard comparison={taKeyComparison} />}

					{results.length > 0 && !loading && <EndpointResultsTable results={results} />}

					{submitted && !loading && !error && results.length === 0 && (
						<p className="text-sm text-muted-foreground">No federation endpoints declared.</p>
					)}
				</TabsContent>

				<TabsContent value="batch" className="mt-4">
					<BatchHealthFromAuthorityPanel />
				</TabsContent>
			</Tabs>
		</div>
	);
}
