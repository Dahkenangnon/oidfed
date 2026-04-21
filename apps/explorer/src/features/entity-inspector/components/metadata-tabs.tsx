import {
	Badge,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@oidfed/ui";
import { JsonTree } from "@/components/shared/json-tree";

interface MetadataTabsProps {
	readonly metadata: Record<string, unknown>;
}

const ENTITY_TYPE_LABELS: Record<string, string> = {
	openid_relying_party: "OpenID RP",
	openid_provider: "OpenID OP",
	oauth_authorization_server: "OAuth AS",
	oauth_client: "OAuth Client",
	oauth_resource: "OAuth Resource",
	federation_entity: "Federation Entity",
};

const ENTITY_INFO_FIELDS = [
	"organization_name",
	"display_name",
	"description",
	"contacts",
	"logo_uri",
	"policy_uri",
	"information_uri",
	"organization_uri",
	"keywords",
] as const;

const URL_FIELDS = new Set(["logo_uri", "policy_uri", "information_uri", "organization_uri"]);

function InfoValue({ field, value }: { readonly field: string; readonly value: unknown }) {
	if (typeof value === "string" && URL_FIELDS.has(field)) {
		return (
			<a
				href={value}
				target="_blank"
				rel="noopener noreferrer"
				className="text-brand-600 dark:text-brand-400 hover:underline truncate"
			>
				{value}
			</a>
		);
	}
	if (Array.isArray(value)) {
		return (
			<div className="flex flex-wrap gap-1">
				{value.map((item, i) => (
					<Badge key={`${String(item)}-${String(i)}`} variant="secondary" className="text-xs">
						{String(item)}
					</Badge>
				))}
			</div>
		);
	}
	return (
		<span className="truncate">{typeof value === "string" ? value : JSON.stringify(value)}</span>
	);
}

function MetadataInfoCard({ data }: { readonly data: Record<string, unknown> }) {
	const entries = ENTITY_INFO_FIELDS.filter((f) => data[f] !== undefined).map(
		(f) => [f, data[f]] as const,
	);

	if (entries.length === 0) return null;

	return (
		<Card className="mb-4">
			<CardHeader className="pb-2">
				<CardTitle className="text-sm">Entity Information</CardTitle>
			</CardHeader>
			<CardContent className="space-y-1.5">
				{entries.map(([key, val]) => (
					<div key={key} className="flex items-start gap-2 text-sm">
						<span className="text-muted-foreground font-mono text-xs min-w-[160px] pt-0.5">
							{key}
						</span>
						<InfoValue field={key} value={val} />
					</div>
				))}
			</CardContent>
		</Card>
	);
}

export function MetadataTabs({ metadata }: MetadataTabsProps) {
	const types = Object.keys(metadata);

	if (types.length === 0) {
		return <p className="text-sm text-muted-foreground">No metadata present.</p>;
	}

	const defaultTab = types[0] ?? "";

	return (
		<Tabs defaultValue={defaultTab}>
			<TabsList>
				{types.map((type) => (
					<TabsTrigger key={type} value={type}>
						<Badge variant="outline" className="mr-1.5">
							{ENTITY_TYPE_LABELS[type] ?? type}
						</Badge>
					</TabsTrigger>
				))}
			</TabsList>
			{types.map((type) => {
				const data = metadata[type] as Record<string, unknown>;
				return (
					<TabsContent key={type} value={type} className="mt-4">
						<MetadataInfoCard data={data} />
						<JsonTree data={data} />
					</TabsContent>
				);
			})}
		</Tabs>
	);
}
