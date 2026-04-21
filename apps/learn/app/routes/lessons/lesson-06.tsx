import {
	Card,
	CardHeader,
	CardPanel,
	CardTitle,
	Tabs,
	TabsList,
	TabsPanel,
	TabsTab,
} from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Metadata & Policy — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"How entities describe their capabilities with metadata, and how superiors constrain them with metadata policies.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Metadata & Policy" },
		{
			property: "og:description",
			content: "Understand metadata, policy operators, and the policy cascade.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Core Mechanics" },
	];
}

const operators = [
	{
		name: "value",
		description: "Forces a specific value, completely overriding the subordinate's.",
		example: 'token_endpoint_auth_method: { value: "private_key_jwt" }',
	},
	{
		name: "one_of",
		description: "The value MUST be one of the listed options (like a dropdown).",
		example: 'application_type: { one_of: ["web", "native"] }',
	},
	{
		name: "subset_of",
		description: "Array values are reduced to the intersection with allowed values.",
		example: 'scopes_supported: { subset_of: ["openid", "profile", "email"] }',
	},
	{
		name: "superset_of",
		description: "Array MUST contain at least these values.",
		example: 'scopes_supported: { superset_of: ["openid"] }',
	},
	{
		name: "add",
		description: "Adds values to an array. Existing values are kept.",
		example: 'contacts: { add: ["sec@fed.gov"] }',
	},
	{
		name: "default",
		description: "Fallback value used only if the subordinate didn't provide one.",
		example: 'application_type: { default: "web" }',
	},
	{
		name: "essential",
		description: "When true, the parameter MUST be present in the final metadata.",
		example: "redirect_uris: { essential: true }",
	},
];

const pipelineSteps = [
	{
		title: "Step 1 — Leaf's Raw Metadata",
		content: (
			<div className="space-y-2">
				<p className="text-sm">
					The leaf entity declares its capabilities in its Entity Configuration:
				</p>
				<pre className="rounded bg-muted p-3 text-xs overflow-x-auto">{`{
  "scopes_supported": ["openid", "profile", "email", "phone", "address"],
  "grant_types": ["authorization_code", "implicit", "client_credentials"],
  "token_endpoint_auth_method": "client_secret_post",
  "contacts": ["admin@uni.edu"]
}`}</pre>
			</div>
		),
	},
	{
		title: "Step 2 — After Trust Anchor Policy",
		content: (
			<div className="space-y-2">
				<p className="text-sm">
					The TA applies <code>subset_of</code> on scopes and grant_types, <code>add</code> on
					contacts:
				</p>
				<pre className="rounded bg-muted p-3 text-xs overflow-x-auto">{`{
  "scopes_supported": ["openid", "profile", "email"],        // phone, address removed
  "grant_types": ["authorization_code"],                      // implicit, client_credentials removed
  "token_endpoint_auth_method": "client_secret_post",         // unchanged
  "contacts": ["admin@uni.edu", "sec@fed.gov"]                // sec@fed.gov added
}`}</pre>
			</div>
		),
	},
	{
		title: "Step 3 — After Intermediate Policy",
		content: (
			<div className="space-y-2">
				<p className="text-sm">
					The intermediate applies <code>value</code> on auth method — forcing{" "}
					<code>private_key_jwt</code>:
				</p>
				<pre className="rounded bg-muted p-3 text-xs overflow-x-auto">{`{
  "scopes_supported": ["openid", "profile", "email"],
  "grant_types": ["authorization_code"],
  "token_endpoint_auth_method": "private_key_jwt",            // OVERRIDDEN by value operator
  "contacts": ["admin@uni.edu", "sec@fed.gov"]
}`}</pre>
			</div>
		),
	},
	{
		title: "Step 4 — Resolved Metadata (Final)",
		content: (
			<div className="space-y-2">
				<p className="text-sm font-semibold text-emerald-600">
					This is the metadata used for the actual OIDC interaction:
				</p>
				<pre className="rounded bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800 p-3 text-xs overflow-x-auto">{`{
  "scopes_supported": ["openid", "profile", "email"],
  "grant_types": ["authorization_code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "contacts": ["admin@uni.edu", "sec@fed.gov"]
}`}</pre>
				<p className="text-xs text-muted-foreground">
					Policies can only make metadata more restrictive, never less. Each level in the hierarchy
					can tighten but never loosen.
				</p>
			</div>
		),
	},
];

export default function Lesson06() {
	return (
		<LessonPage lesson={getLesson(6)}>
			<h2>What is Metadata?</h2>
			<p>
				Every entity in a federation describes its capabilities through <strong>metadata</strong>
				<Ref id="1" /> — structured key-value pairs organized by Entity Type Identifier. The
				metadata tells other entities what protocols are supported, which endpoints are available,
				and how to interact.
			</p>

			<h2>Metadata by Entity Type</h2>
			<Tabs defaultValue="op">
				<TabsList>
					<TabsTab value="op">OpenID Provider</TabsTab>
					<TabsTab value="rp">Relying Party</TabsTab>
					<TabsTab value="rs">Resource Server</TabsTab>
					<TabsTab value="fe">Federation Entity</TabsTab>
				</TabsList>
				<TabsPanel value="op" className="mt-3">
					<div className="text-sm space-y-1 font-mono text-muted-foreground">
						{[
							"issuer",
							"authorization_endpoint",
							"token_endpoint",
							"userinfo_endpoint",
							"jwks_uri",
							"scopes_supported",
							"response_types_supported",
							"grant_types_supported",
							"subject_types_supported",
							"id_token_signing_alg_values_supported",
						].map((f) => (
							<div key={f}>· {f}</div>
						))}
					</div>
				</TabsPanel>
				<TabsPanel value="rp" className="mt-3">
					<div className="text-sm space-y-1 font-mono text-muted-foreground">
						{[
							"redirect_uris",
							"client_name",
							"logo_uri",
							"contacts",
							"grant_types",
							"response_types",
							"token_endpoint_auth_method",
							"scope",
							"application_type",
						].map((f) => (
							<div key={f}>· {f}</div>
						))}
					</div>
				</TabsPanel>
				<TabsPanel value="rs" className="mt-3">
					<div className="text-sm space-y-1 font-mono text-muted-foreground">
						{[
							"resource",
							"authorization_servers",
							"scopes_supported",
							"bearer_methods_supported",
							"resource_signing_alg_values_supported",
							"resource_documentation",
						].map((f) => (
							<div key={f}>· {f}</div>
						))}
					</div>
				</TabsPanel>
				<TabsPanel value="fe" className="mt-3">
					<div className="text-sm space-y-1 font-mono text-muted-foreground">
						{[
							"federation_fetch_endpoint",
							"federation_list_endpoint",
							"federation_resolve_endpoint",
							"federation_trust_mark_status_endpoint",
							"federation_trust_mark_list_endpoint",
							"organization_name",
							"organization_uri",
							"contacts",
						].map((f) => (
							<div key={f}>· {f}</div>
						))}
					</div>
				</TabsPanel>
			</Tabs>

			<h2>Policy Operators</h2>
			<p>
				Superiors constrain their subordinates' metadata using <strong>policy operators</strong>
				<Ref id="2" /> in the <code>metadata_policy</code> claim of Subordinate Statements. There
				are 7 operators:
			</p>
			<div className="grid gap-3 sm:grid-cols-2">
				{operators.map((op) => (
					<Card key={op.name}>
						<CardHeader className="pb-1">
							<CardTitle className="text-sm font-mono">{op.name}</CardTitle>
						</CardHeader>
						<CardPanel className="pt-0 space-y-1">
							<p className="text-sm">{op.description}</p>
							<code className="text-xs text-muted-foreground block">{op.example}</code>
						</CardPanel>
					</Card>
				))}
			</div>

			<h2>Policy Cascade — Watch It Work</h2>
			<p>
				Metadata policies are applied in order from the Trust Anchor down through each Intermediate
				to produce the final <strong>resolved metadata</strong>.<Ref id="3" />
			</p>
			<StepThrough steps={pipelineSteps} />

			<AnalogyBox>
				Think of job requirements: an employee lists their skills (metadata), the department head
				limits them to 3 relevant skills (intermediate policy), and the CEO adds a company-wide rule
				"nothing outside business hours" (TA policy). The resolved result is what the employee
				actually does — shaped by every level above.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 5 — Metadata",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-5",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 6.1.3.1 — Standard Operators",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 6.1.4 — Enforcement",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-6.1.4",
					},
				]}
			/>
		</LessonPage>
	);
}
