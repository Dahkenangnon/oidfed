import {
	Badge,
	Card,
	CardHeader,
	CardPanel,
	CardTitle,
	Tabs,
	TabsList,
	TabsPanel,
	TabsTab,
} from "@oidfed/ui";
import { useState } from "react";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { JsonExplorer } from "~/components/json-explorer";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Entity Statements — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Crack open a JWT and see what's inside an Entity Configuration and Subordinate Statement.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Entity Statements" },
		{
			property: "og:description",
			content: "The signed documents that carry trust in OpenID Federation.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Foundation" },
	];
}

const entityConfigPayload = {
	iss: "https://login.uni.edu",
	sub: "https://login.uni.edu",
	iat: 1712000000,
	exp: 1712086400,
	jwks: {
		keys: [
			{
				kty: "RSA",
				use: "sig",
				kid: "k1",
				n: "0vx7agoebGcQ...",
				e: "AQAB",
			},
		],
	},
	metadata: {
		openid_provider: {
			issuer: "https://login.uni.edu",
			authorization_endpoint: "https://login.uni.edu/authorize",
			token_endpoint: "https://login.uni.edu/token",
			scopes_supported: ["openid", "profile", "email"],
		},
	},
	authority_hints: ["https://uni.edu"],
	trust_marks: [
		{
			trust_mark_type: "https://edufed.gov/trust-marks/gdpr",
			trust_mark: "eyJhbGciOiJSUzI1NiJ9...",
		},
	],
};

const subordinatePayload = {
	iss: "https://uni.edu",
	sub: "https://login.uni.edu",
	iat: 1712000000,
	exp: 1712086400,
	jwks: {
		keys: [
			{
				kty: "RSA",
				use: "sig",
				kid: "k1",
				n: "0vx7agoebGcQ...",
				e: "AQAB",
			},
		],
	},
	metadata: {
		openid_provider: {
			organization_name: "University Login Service",
		},
	},
	metadata_policy: {
		openid_provider: {
			scopes_supported: { subset_of: ["openid", "profile", "email"] },
			token_endpoint_auth_methods_supported: {
				subset_of: ["private_key_jwt"],
			},
		},
	},
	source_endpoint: "https://uni.edu/federation/fetch",
};

const claims: {
	name: string;
	label: string;
	required: boolean;
	where: string;
	description: string;
}[] = [
	{
		name: "iss",
		label: "Issuer",
		required: true,
		where: "Both",
		description: "Entity Identifier of the creator and signer of the statement.",
	},
	{
		name: "sub",
		label: "Subject",
		required: true,
		where: "Both",
		description:
			"Entity Identifier of who the statement is about. In an Entity Configuration, iss equals sub (self-signed).",
	},
	{
		name: "iat",
		label: "Issued At",
		required: true,
		where: "Both",
		description: "Seconds since Unix epoch when the statement was issued.",
	},
	{
		name: "exp",
		label: "Expires At",
		required: true,
		where: "Both",
		description: "Statement MUST NOT be accepted after this time.",
	},
	{
		name: "jwks",
		label: "Public Keys",
		required: true,
		where: "Both",
		description: "JSON Web Key Set containing the subject's Federation Entity signing keys.",
	},
	{
		name: "metadata",
		label: "Metadata",
		required: false,
		where: "Both",
		description:
			"Protocol-specific configuration keyed by Entity Type Identifier. In a Subordinate Statement, metadata overrides the Entity Configuration.",
	},
	{
		name: "authority_hints",
		label: "Authority Hints",
		required: true,
		where: "EC only",
		description:
			"Array of Immediate Superior Entity Identifiers. REQUIRED for Leaf and Intermediate, MUST NOT appear for a Trust Anchor with no superiors. MUST NOT be empty.",
	},
	{
		name: "metadata_policy",
		label: "Policy",
		required: false,
		where: "Sub. Stmt only",
		description:
			"Policy operators applied to subordinate's metadata. Only in Subordinate Statements. Operators include subset_of, one_of, value, etc.",
	},
	{
		name: "trust_marks",
		label: "Trust Marks",
		required: false,
		where: "EC only",
		description: "Array of trust_mark_type and signed trust_mark JWT pairs.",
	},
	{
		name: "constraints",
		label: "Constraints",
		required: false,
		where: "Sub. Stmt only",
		description:
			"Structural constraints: max_path_length, naming_constraints, allowed_entity_types.",
	},
	{
		name: "trust_mark_issuers",
		label: "TM Issuers",
		required: false,
		where: "EC only",
		description:
			"TA declares which entities may issue which Trust Mark types. MUST be ignored if the entity is not a Trust Anchor.",
	},
	{
		name: "source_endpoint",
		label: "Source Endpoint",
		required: false,
		where: "Sub. Stmt only",
		description: "URL of the Fetch endpoint that issued this Subordinate Statement.",
	},
	{
		name: "crit",
		label: "Critical Claims",
		required: false,
		where: "Both",
		description:
			"Non-standard claims that MUST be understood by the receiver. Spec-defined claims MUST NOT be listed here.",
	},
];

export default function Lesson03() {
	const [selectedClaim, setSelectedClaim] = useState<number | null>(null);

	return (
		<LessonPage lesson={getLesson(3)}>
			<h2>What's a JWT? (30-second version)</h2>
			<p>
				An Entity Statement is a JSON Web Token (JWT)
				<Ref id="1" /> — a compact, signed JSON document with three parts separated by dots:
			</p>
			<div className="my-4 rounded-lg bg-muted p-4 font-mono text-sm break-all">
				<span className="text-red-500">
					eyJhbGciOiJSUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0In0
				</span>
				<span className="text-muted-foreground">.</span>
				<span className="text-purple-500">eyJpc3MiOiJodHRwczovL2xvZ2luLnVuaS5lZHUiLC...</span>
				<span className="text-muted-foreground">.</span>
				<span className="text-emerald-500">SflKxwRJSMeKKF2QT4fwpM...</span>
			</div>
			<p className="text-sm text-muted-foreground">
				<span className="text-red-500 font-semibold">Header</span> (algorithm, type) ·{" "}
				<span className="text-purple-500 font-semibold">Payload</span> (claims) ·{" "}
				<span className="text-emerald-500 font-semibold">Signature</span> (cryptographic proof)
			</p>

			<h2>Two Types of Entity Statements</h2>
			<Tabs defaultValue="ec">
				<TabsList>
					<TabsTab value="ec">Entity Configuration (Self-Signed)</TabsTab>
					<TabsTab value="sub">Subordinate Statement (Signed by Superior)</TabsTab>
				</TabsList>
				<TabsPanel value="ec" className="mt-4">
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Entity Configuration</CardTitle>
							<p className="text-sm text-muted-foreground">
								Published at <code>.well-known/openid-federation</code>
								<Ref id="2" />. <code>iss</code> equals <code>sub</code> — the entity describes
								itself. Signed with the entity's own private key.
							</p>
						</CardHeader>
						<CardPanel>
							<JsonExplorer data={entityConfigPayload} />
						</CardPanel>
					</Card>
				</TabsPanel>
				<TabsPanel value="sub" className="mt-4">
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Subordinate Statement</CardTitle>
							<p className="text-sm text-muted-foreground">
								Fetched from the superior's Fetch endpoint
								<Ref id="3" />. <code>iss</code> is the superior, <code>sub</code> is the
								subordinate. May override metadata and add policies. Signed with the superior's
								private key.
							</p>
						</CardHeader>
						<CardPanel>
							<JsonExplorer data={subordinatePayload} />
						</CardPanel>
					</Card>
				</TabsPanel>
			</Tabs>

			<h2>Explore Every Claim</h2>
			<p className="text-sm text-muted-foreground mb-4">
				Click any claim to see its full definition from Section 3.1.1–3.1.3 of the spec.
			</p>
			<div className="flex flex-wrap gap-2 mb-4">
				{claims.map((c, i) => (
					<button
						key={c.name}
						type="button"
						onClick={() => setSelectedClaim(selectedClaim === i ? null : i)}
						className={`px-3 py-1.5 rounded-md text-sm font-mono border transition-colors cursor-pointer ${
							selectedClaim === i
								? "bg-primary text-primary-foreground border-primary"
								: "bg-card border-border hover:bg-accent"
						}`}
					>
						{c.name}
						<span className="ml-1.5 text-xs opacity-70">{c.label}</span>
					</button>
				))}
			</div>
			{selectedClaim !== null &&
				(() => {
					const claim = claims[selectedClaim];
					if (!claim) return null;
					return (
						<Card className="border-primary/30">
							<CardHeader className="pb-2">
								<div className="flex items-center gap-2">
									<CardTitle className="text-base font-mono">{claim.name}</CardTitle>
									<Badge variant={claim.required ? "default" : "outline"} size="sm">
										{claim.required ? "REQUIRED" : "OPTIONAL"}
									</Badge>
									<Badge variant="secondary" size="sm">
										{claim.where}
									</Badge>
								</div>
							</CardHeader>
							<CardPanel className="pt-0 text-sm">{claim.description}</CardPanel>
						</Card>
					);
				})()}

			<AnalogyBox>
				<strong>Entity Configuration</strong> = a self-issued ID card — you write your own name and
				sign it yourself. <strong>Subordinate Statement</strong> = a notary's certification —
				someone higher up vouches for you, signed with the notary's own signature.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "RFC 7519 — JSON Web Token (JWT)",
						url: "https://www.rfc-editor.org/rfc/rfc7519",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 3.1.1 — Claims that MUST or MAY Appear in both Entity Configurations and Subordinate Statements",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.1",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 3.1.3 — Claims that MUST or MAY Appear in Subordinate Statements but Not in Entity Configurations",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.3",
					},
				]}
			/>
		</LessonPage>
	);
}
