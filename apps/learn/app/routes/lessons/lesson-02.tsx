import { Badge, Card, CardDescription, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";
import { useState } from "react";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Entities & Roles — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Meet the players in an OpenID Federation hierarchy — Trust Anchors, Intermediates, and Leaf Entities.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Entities & Roles" },
		{
			property: "og:description",
			content: "Every federation has a hierarchy. Learn who does what.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Foundation" },
	];
}

const roles = [
	{
		title: "Trust Anchor",
		tag: "Root of Trust",
		badge: "default" as const,
		description:
			"Every Trust Chain ends at a Trust Anchor. It is the top-level authority that publishes its own Entity Configuration and issues Subordinate Statements for its direct subordinates.",
		details: "MUST publish federation_fetch_endpoint and federation_list_endpoint.",
		section: "Section 1.2",
	},
	{
		title: "Intermediate Entity",
		tag: "Middle Layer",
		badge: "info" as const,
		description:
			"Issues Entity Statements appearing between those issued by the Trust Anchor and the subject of a Trust Chain. Can enforce metadata policies and delegate further.",
		details: "Has both superiors and subordinates. Can add policies on top of the Trust Anchor's.",
		section: "Section 1.2",
	},
	{
		title: "OpenID Provider",
		tag: "openid_provider",
		badge: "success" as const,
		description:
			"A login server where users authenticate. As a Leaf Entity, it MUST NOT publish federation_fetch_endpoint or federation_list_endpoint.",
		details:
			"Entity type: openid_provider. Publishes metadata about supported scopes, grant types, endpoints.",
		section: "Section 5.1.3",
	},
	{
		title: "Relying Party",
		tag: "openid_relying_party",
		badge: "success" as const,
		description:
			"An application or service that needs to verify user identity. Relies on an OpenID Provider for authentication.",
		details:
			"Entity type: openid_relying_party. Publishes redirect_uris, client_name, supported grant types.",
		section: "Section 5.1.2",
	},
	{
		title: "OAuth Authorization Server",
		tag: "oauth_authorization_server",
		badge: "warning" as const,
		description:
			"Issues access tokens for protected resources. Similar to an OP but for OAuth2 flows rather than OIDC.",
		details: "Entity type: oauth_authorization_server.",
		section: "Section 5.1.4",
	},
	{
		title: "Resource Server",
		tag: "oauth_resource",
		badge: "warning" as const,
		description:
			"Hosts protected resources and validates access tokens. Declares which authorization servers it trusts.",
		details: "Entity type: oauth_resource.",
		section: "Section 5.1.6",
	},
	{
		title: "OAuth Client",
		tag: "oauth_client",
		badge: "warning" as const,
		description:
			"An application that requests access to protected resources on behalf of a resource owner.",
		details: "Entity type: oauth_client.",
		section: "Section 5.1.5",
	},
	{
		title: "Federation Entity",
		tag: "federation_entity",
		badge: "secondary" as const,
		description:
			"Used for federation infrastructure metadata — endpoints like fetch, list, resolve, and trust mark management.",
		details:
			"Entity type: federation_entity. Contains federation-specific endpoints and organization info.",
		section: "Section 5.1.1",
	},
];

function HierarchySvg({ onSelect }: { onSelect: (idx: number) => void }) {
	const nodes = [
		{ x: 200, y: 40, r: 24, label: "Trust\nAnchor", idx: 0 },
		{ x: 120, y: 120, r: 20, label: "IA A", idx: 1 },
		{ x: 280, y: 120, r: 20, label: "IA B", idx: 1 },
		{ x: 60, y: 200, r: 16, label: "OP", idx: 2 },
		{ x: 150, y: 200, r: 16, label: "RP", idx: 3 },
		{ x: 250, y: 200, r: 16, label: "AS", idx: 4 },
		{ x: 340, y: 200, r: 16, label: "RS", idx: 5 },
	];
	const edges: [number, number][] = [
		[0, 1],
		[0, 2],
		[1, 3],
		[1, 4],
		[2, 5],
		[2, 6],
	];
	return (
		<svg
			viewBox="0 0 400 250"
			className="w-full max-w-md mx-auto"
			role="img"
			aria-labelledby="hierarchy-title"
		>
			<title id="hierarchy-title">Federation hierarchy diagram</title>
			{edges.map(([from, to]) => {
				const fromNode = nodes[from];
				const toNode = nodes[to];
				if (!fromNode || !toNode) return null;
				return (
					<line
						key={`${from}-${to}`}
						x1={fromNode.x}
						y1={fromNode.y}
						x2={toNode.x}
						y2={toNode.y}
						stroke="var(--color-border)"
						strokeWidth="2"
					/>
				);
			})}
			{nodes.map((n, i) => (
				// biome-ignore lint/suspicious/noArrayIndexKey: SVG nodes
				// biome-ignore lint/a11y/noStaticElementInteractions: SVG interactive element
				<g key={i} className="cursor-pointer" onClick={() => onSelect(n.idx)}>
					<circle
						cx={n.x}
						cy={n.y}
						r={n.r}
						className="fill-card stroke-primary hover:fill-primary/10 transition-colors"
						strokeWidth="2"
					/>
					<text
						x={n.x}
						y={n.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[9px] font-medium pointer-events-none"
					>
						{n.label}
					</text>
				</g>
			))}
		</svg>
	);
}

export default function Lesson02() {
	const [selected, setSelected] = useState<number | null>(null);

	return (
		<LessonPage lesson={getLesson(2)}>
			<h2>The Hierarchy — Click Any Node</h2>
			<p>
				Every federation is organized as a hierarchy.
				<Ref id="1" /> At the top sits the
				<strong> Trust Anchor</strong>, which may delegate authority to{" "}
				<strong>Intermediate Entities</strong>, who in turn manage <strong>Leaf Entities</strong> —
				the OpenID Providers, Relying Parties, and other services that participate in the
				federation.
			</p>

			<HierarchySvg onSelect={setSelected} />

			{selected !== null &&
				(() => {
					const role = roles[selected];
					if (!role) return null;
					return (
						<Card className="my-4 border-primary/30">
							<CardHeader>
								<div className="flex items-center gap-2">
									<CardTitle className="text-base">{role.title}</CardTitle>
									<Badge variant={role.badge} size="sm">
										{role.tag}
									</Badge>
								</div>
								<CardDescription>{role.section}</CardDescription>
							</CardHeader>
							<CardPanel className="pt-0 text-sm space-y-2">
								<p>{role.description}</p>
								<p className="text-muted-foreground">{role.details}</p>
							</CardPanel>
						</Card>
					);
				})()}

			<h2>Multi-Federation Membership</h2>
			<p>
				An entity MAY have multiple Entity Types
				<Ref id="2" /> and can be a member of multiple federations simultaneously. For example, a
				university identity provider might participate in both a national education federation and a
				research consortium federation, each with its own Trust Anchor.
			</p>

			<h2>Entity Types at a Glance</h2>
			<div className="grid gap-3 sm:grid-cols-2">
				{roles.map((role) => (
					<Card key={role.title}>
						<CardHeader className="pb-2">
							<div className="flex items-center gap-2">
								<CardTitle className="text-sm">{role.title}</CardTitle>
								<Badge variant={role.badge} size="sm">
									{role.tag}
								</Badge>
							</div>
						</CardHeader>
						<CardPanel className="pt-0 text-sm text-muted-foreground">{role.description}</CardPanel>
					</Card>
				))}
			</div>

			<AnalogyBox>
				Think of a government structure: the national government (Trust Anchor) sets the rules,
				state or regional agencies (Intermediates) enforce those rules locally, and citizens and
				businesses (Leaf Entities) operate under them. Each level can add its own requirements, but
				never weaken the level above.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 1.2 — Terminology",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 5 — Metadata",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-5",
					},
				]}
			/>
		</LessonPage>
	);
}
