import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@oidfed/ui";
import { AlertTriangle, BadgeCheck } from "lucide-react";
import { useCallback, useState } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import { TrustMarkDetail } from "./components/trust-mark-detail";
import { TrustMarkFetchForm } from "./components/trust-mark-fetch-form";
import { TrustMarkInput } from "./components/trust-mark-input";
import { TrustMarkListPanel } from "./components/trust-mark-list-panel";
import { useTrustMarkInspect } from "./hooks/use-trust-mark-inspect";

interface FetchDefaults {
	issuer: string;
	trustMarkType: string;
	sub: string;
}

export function TrustMarkViewerPage() {
	usePageTitle("Trust Marks — OidFed Explorer");
	const [activeJwt, setActiveJwt] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState("paste");
	const [fetchDefaults, setFetchDefaults] = useState<FetchDefaults | null>(null);
	const { result, loading, error, inspect } = useTrustMarkInspect();

	const handleSubmit = useCallback(
		(jwt: string) => {
			setActiveJwt(jwt);
			inspect(jwt);
		},
		[inspect],
	);

	const handleFetched = useCallback(
		(jwt: string) => {
			setActiveJwt(jwt);
			inspect(jwt);
		},
		[inspect],
	);

	const handleListSelect = useCallback((issuer: string, trustMarkType: string, sub: string) => {
		setFetchDefaults({ issuer, trustMarkType, sub });
		setActiveTab("fetch");
	}, []);

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Trust Mark Viewer</h1>
				<p className="text-sm text-muted-foreground">
					Decode, verify, and inspect a Trust Mark JWT — including signature validation and
					delegation chain
				</p>
			</div>

			<Tabs value={activeTab} onValueChange={setActiveTab}>
				<TabsList>
					<TabsTrigger value="paste">Paste JWT</TabsTrigger>
					<TabsTrigger value="fetch">Fetch from Issuer</TabsTrigger>
					<TabsTrigger value="list">List Issued</TabsTrigger>
				</TabsList>

				<TabsContent value="paste" className="mt-4">
					<TrustMarkInput loading={loading} onSubmit={handleSubmit} />
				</TabsContent>

				<TabsContent value="fetch" className="mt-4">
					<TrustMarkFetchForm
						key={
							fetchDefaults
								? `${fetchDefaults.issuer}-${fetchDefaults.trustMarkType}-${fetchDefaults.sub}`
								: "empty"
						}
						onFetched={handleFetched}
						initialIssuer={fetchDefaults?.issuer}
						initialTrustMarkType={fetchDefaults?.trustMarkType}
						initialSub={fetchDefaults?.sub}
					/>
				</TabsContent>

				<TabsContent value="list" className="mt-4">
					<TrustMarkListPanel onSelect={handleListSelect} />
				</TabsContent>
			</Tabs>

			{!loading && !error && !result && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<BadgeCheck className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Paste a Trust Mark JWT above to decode, verify, and inspect it
						</p>
					</div>
				</div>
			)}

			{loading && (
				<div className="space-y-3">
					<Skeleton className="h-32 w-full" />
					<Skeleton className="h-20 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 flex items-start gap-3">
					<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
					<p className="text-sm text-destructive-foreground">{error}</p>
				</div>
			)}

			{result && activeJwt && !loading && <TrustMarkDetail result={result} jwt={activeJwt} />}
		</div>
	);
}
