import { Skeleton } from "@oidfed/ui";
import { AlertTriangle, Route } from "lucide-react";
import { useCallback } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import { ResolveComparison } from "./components/resolve-comparison";
import { ResolveForm } from "./components/resolve-form";
import type { ResolveQueryParams } from "./hooks/use-resolve-query";
import { useResolveQuery } from "./hooks/use-resolve-query";

export function ResolveProxyPage() {
	usePageTitle("Resolve Proxy — OidFed Explorer");
	const { result, loading, error, query } = useResolveQuery();

	const handleSubmit = useCallback(
		(params: ResolveQueryParams) => {
			query(params);
		},
		[query],
	);

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Resolve Endpoint Proxy</h1>
				<p className="text-sm text-muted-foreground">
					Query any entity's resolve endpoint and inspect the pre-computed resolved metadata. Enter
					one trust anchor to resolve, or add multiple to compare results side-by-side.
				</p>
			</div>

			<ResolveForm loading={loading} onSubmit={handleSubmit} />

			{!loading && !error && !result && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<Route className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Configure a resolve query above to inspect pre-computed resolved metadata
						</p>
					</div>
				</div>
			)}

			{loading && (
				<div className="space-y-3">
					<Skeleton className="h-32 w-full" />
					<Skeleton className="h-48 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{error}</p>
				</div>
			)}

			{result && !loading && <ResolveComparison results={result.results} />}
		</div>
	);
}
