import {
	Badge,
	Button,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
	Skeleton,
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@oidfed/ui";
import { Building2, Download, FileSearch, Globe, Mail } from "lucide-react";
import { useParams } from "react-router";
import { JwkTable } from "@/components/shared/jwk-table";
import { JwtViewer } from "@/components/shared/jwt-viewer";
import { usePageTitle } from "@/hooks/use-page-title";
import { AuthorityHints } from "./components/authority-hints";
import { EntityForm } from "./components/entity-form";
import { HistoricalKeys } from "./components/historical-keys";
import { MetadataTabs } from "./components/metadata-tabs";
import { TrustMarkIssuersPanel } from "./components/trust-mark-issuers";
import { TrustMarksPanel } from "./components/trust-marks-panel";
import { ValidationSteps } from "./components/validation-steps";
import { useEntityConfig } from "./hooks/use-entity-config";
import { useSignedJwks } from "./hooks/use-signed-jwks";

function EntityInfoBanner({ fedEntity }: { readonly fedEntity: Record<string, unknown> }) {
	const orgName = fedEntity.organization_name as string | undefined;
	const displayName = fedEntity.display_name as string | undefined;
	const description = fedEntity.description as string | undefined;
	const contacts = fedEntity.contacts as string[] | undefined;
	const logoUri = fedEntity.logo_uri as string | undefined;
	const orgUri = fedEntity.organization_uri as string | undefined;
	const infoUri = fedEntity.information_uri as string | undefined;
	const policyUri = fedEntity.policy_uri as string | undefined;
	const keywords = fedEntity.keywords as string[] | undefined;

	const hasAny = orgName || displayName || description || contacts?.length || logoUri;
	if (!hasAny) return null;

	return (
		<Card>
			<CardContent className="pt-4">
				<div className="flex items-start gap-4">
					{logoUri && (
						<img
							src={logoUri}
							alt=""
							className="size-12 rounded-lg object-contain shrink-0 border"
						/>
					)}
					<div className="space-y-1.5 min-w-0 flex-1">
						{(orgName || displayName) && (
							<div className="flex items-center gap-2">
								<Building2 className="size-4 text-muted-foreground shrink-0" />
								<span className="font-medium text-sm">{displayName ?? orgName}</span>
								{displayName && orgName && displayName !== orgName && (
									<span className="text-xs text-muted-foreground">({orgName})</span>
								)}
							</div>
						)}
						{description && <p className="text-sm text-muted-foreground">{description}</p>}
						<div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
							{contacts && contacts.length > 0 && (
								<span className="flex items-center gap-1">
									<Mail className="size-3" />
									{contacts.join(", ")}
								</span>
							)}
							{(orgUri || infoUri) && (
								<a
									href={orgUri ?? infoUri}
									target="_blank"
									rel="noopener noreferrer"
									className="flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
								>
									<Globe className="size-3" />
									{orgUri ?? infoUri}
								</a>
							)}
							{policyUri && (
								<a
									href={policyUri}
									target="_blank"
									rel="noopener noreferrer"
									className="text-brand-600 dark:text-brand-400 hover:underline"
								>
									Policy
								</a>
							)}
						</div>
						{keywords && keywords.length > 0 && (
							<div className="flex flex-wrap gap-1 pt-0.5">
								{keywords.map((kw) => (
									<Badge key={kw} variant="secondary" className="text-[10px] px-1.5 py-0">
										{kw}
									</Badge>
								))}
							</div>
						)}
					</div>
				</div>
			</CardContent>
		</Card>
	);
}

function SignedJwksCard({
	entityType,
	uri,
	issuerJwks,
}: {
	readonly entityType: string;
	readonly uri: string;
	readonly issuerJwks: { keys: readonly Record<string, unknown>[] };
}) {
	const { keys, loading, error, signatureValid, fetch: fetchKeys } = useSignedJwks(uri, issuerJwks);

	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">{entityType} — signed_jwks_uri</CardTitle>
			</CardHeader>
			<CardContent className="space-y-3">
				<div className="flex items-center gap-2 flex-wrap">
					<span className="text-muted-foreground font-mono text-xs truncate max-w-[400px]">
						{uri}
					</span>
					<Button variant="outline" size="sm" onClick={fetchKeys} disabled={loading}>
						<Download className="size-3.5 mr-1" />
						{loading ? "Fetching…" : "Fetch Signed JWKS"}
					</Button>
				</div>

				{signatureValid != null && (
					<Badge variant={signatureValid ? "success" : "error"} size="sm">
						{signatureValid ? "Signature valid" : "Signature invalid"}
					</Badge>
				)}

				{error && <p className="text-sm text-destructive">{error}</p>}

				{keys && keys.length > 0 && <JwkTable jwks={{ keys }} />}

				{keys && keys.length === 0 && (
					<p className="text-sm text-muted-foreground">No keys returned.</p>
				)}
			</CardContent>
		</Card>
	);
}

function extractSignedJwksUris(
	metadata: Record<string, unknown>,
): Array<{ entityType: string; uri: string }> {
	const result: Array<{ entityType: string; uri: string }> = [];
	for (const [entityType, meta] of Object.entries(metadata)) {
		if (meta && typeof meta === "object" && "signed_jwks_uri" in meta) {
			const uri = (meta as Record<string, unknown>).signed_jwks_uri;
			if (typeof uri === "string") {
				result.push({ entityType, uri });
			}
		}
	}
	return result;
}

export function EntityInspectorPage() {
	usePageTitle("Entity Inspector — OidFed Explorer");
	const { entityId: rawEntityId } = useParams<{ entityId?: string }>();
	const entityId = rawEntityId ? decodeURIComponent(rawEntityId) : undefined;
	const { data, rawJwt, loading, error, refetch } = useEntityConfig(entityId);

	const metadata = data?.payload.metadata as Record<string, Record<string, unknown>> | undefined;
	const jwks = data?.payload.jwks as { keys: readonly Record<string, unknown>[] } | undefined;

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Entity Inspector</h1>
				<p className="text-sm text-muted-foreground">
					Fetch and inspect an OpenID Federation Entity Configuration
				</p>
			</div>

			<EntityForm initialEntityId={entityId} loading={loading} onRefetch={refetch} />

			{!loading && !error && !data && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<FileSearch className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Enter an entity identifier above to fetch and inspect its configuration
						</p>
					</div>
				</div>
			)}

			{loading && (
				<div className="space-y-4">
					<Skeleton className="h-8 w-48" />
					<Skeleton className="h-64 w-full" />
				</div>
			)}

			{error && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
					<p className="text-sm text-destructive-foreground font-medium">Error</p>
					<p className="text-sm text-destructive-foreground/80 mt-1">{error}</p>
				</div>
			)}

			{data && rawJwt && (
				<div className="space-y-6">
					<div className="flex items-center gap-2 flex-wrap">
						<Badge variant="outline" className="font-mono text-xs">
							iss: {String(data.payload.iss ?? "—")}
						</Badge>
						<Badge variant="outline" className="font-mono text-xs">
							sub: {String(data.payload.sub ?? "—")}
						</Badge>
						{data.payload.exp != null && (
							<Badge variant="outline" className="font-mono text-xs">
								exp: {new Date((data.payload.exp as number) * 1000).toISOString()}
							</Badge>
						)}
					</div>

					<Tabs defaultValue="overview">
						<TabsList className="flex-wrap">
							<TabsTrigger value="overview">Overview</TabsTrigger>
							<TabsTrigger value="metadata">Metadata</TabsTrigger>
							<TabsTrigger value="jwks">JWKS</TabsTrigger>
							<TabsTrigger value="jwt">Raw JWT</TabsTrigger>
							<TabsTrigger value="validation">Validation</TabsTrigger>
						</TabsList>

						<TabsContent value="overview" className="mt-4 space-y-4">
							{metadata?.federation_entity && (
								<EntityInfoBanner
									fedEntity={metadata.federation_entity as Record<string, unknown>}
								/>
							)}
							{Array.isArray(data.payload.authority_hints) && (
								<AuthorityHints hints={data.payload.authority_hints as string[]} />
							)}
							{Array.isArray(data.payload.trust_marks) && (
								<TrustMarksPanel
									trustMarks={
										data.payload.trust_marks as Array<{
											trust_mark_type: string;
											trust_mark: string;
										}>
									}
								/>
							)}
							<TrustMarkIssuersPanel
								trustMarkIssuers={
									data.payload.trust_mark_issuers as Record<string, string[]> | undefined
								}
								trustMarkOwners={
									data.payload.trust_mark_owners as
										| Record<string, { sub: string; jwks: unknown }>
										| undefined
								}
							/>
							<HistoricalKeys
								endpoint={
									metadata?.federation_entity?.federation_historical_keys_endpoint as
										| string
										| undefined
								}
								issuerJwks={jwks}
							/>
						</TabsContent>

						<TabsContent value="metadata" className="mt-4">
							{data.payload.metadata && typeof data.payload.metadata === "object" ? (
								<MetadataTabs metadata={data.payload.metadata as Record<string, unknown>} />
							) : (
								<p className="text-sm text-muted-foreground">
									No metadata in this entity configuration.
								</p>
							)}
						</TabsContent>

						<TabsContent value="jwks" className="mt-4 space-y-4">
							{jwks ? (
								<JwkTable jwks={jwks} />
							) : (
								<p className="text-sm text-muted-foreground">No JWKS found.</p>
							)}

							{metadata &&
								(() => {
									const signedJwksUris = extractSignedJwksUris(metadata);
									if (signedJwksUris.length === 0 || !jwks) return null;
									return signedJwksUris.map(({ entityType, uri }) => (
										<SignedJwksCard
											key={`${entityType}-${uri}`}
											entityType={entityType}
											uri={uri}
											issuerJwks={jwks}
										/>
									));
								})()}
						</TabsContent>

						<TabsContent value="jwt" className="mt-4">
							<JwtViewer jwt={rawJwt} contentType="application/entity-statement+jwt" />
						</TabsContent>

						<TabsContent value="validation" className="mt-4">
							<ValidationSteps
								header={data.header}
								payload={data.payload}
								schemaErrors={data.validationErrors}
							/>
						</TabsContent>
					</Tabs>
				</div>
			)}
		</div>
	);
}
