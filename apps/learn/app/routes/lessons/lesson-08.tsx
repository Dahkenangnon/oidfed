import { Accordion, AccordionItem, AccordionPanel, AccordionTrigger, Badge } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Callout } from "~/components/callout";
import { CodeBlock } from "~/components/code-block";
import { LessonPage } from "~/components/lesson-page";
import { SpecRef } from "~/components/spec-ref";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-28" };

export function meta() {
	return lessonMetaForSlug("federation-endpoints");
}

const endpoints = [
	{
		name: "Entity Configuration",
		path: "/.well-known/openid-federation",
		method: "GET",
		who: "All Entities",
		section: "Section 9",
		description:
			"The discovery URL where every entity publishes its self-signed Entity Configuration JWT. This is the starting point for trust chain resolution.",
		request: "GET /.well-known/openid-federation HTTP/1.1\nHost: login.uni.edu",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/entity-statement+jwt\n\neyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...",
	},
	{
		name: "Fetch (Subordinate Statement)",
		path: "/federation/fetch?sub=...",
		method: "GET",
		who: "Intermediates & TA",
		section: "Section 8.1",
		description:
			"Returns a Subordinate Statement for the specified subject entity. The iss of the returned JWT is the entity serving this endpoint.",
		request: "GET /federation/fetch?sub=https://login.uni.edu HTTP/1.1\nHost: uni.edu",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/entity-statement+jwt\n\neyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...",
	},
	{
		name: "List (Subordinates)",
		path: "/federation/list",
		method: "GET",
		who: "Intermediates & TA",
		section: "Section 8.2",
		description:
			"Returns a JSON array of Entity Identifiers of all immediate subordinates. Supports optional entity_type, trust_marked, and trust_mark_type query parameters.",
		request: "GET /federation/list?entity_type=openid_provider HTTP/1.1\nHost: edufed.gov",
		response:
			'HTTP/1.1 200 OK\nContent-Type: application/json\n\n["https://uni.edu", "https://college.edu"]',
	},
	{
		name: "Resolve (Trust Chain)",
		path: "/federation/resolve?sub=...&trust_anchor=...",
		method: "GET",
		who: "Any Entity (optional)",
		section: "Section 8.3",
		description:
			"Returns pre-resolved metadata and the complete trust chain for a subject entity. A convenience endpoint that performs trust chain resolution on behalf of the caller.",
		request:
			"GET /federation/resolve?sub=https://login.uni.edu&trust_anchor=https://edufed.gov HTTP/1.1",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/resolve-response+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
	},
	{
		name: "Trust Mark Status",
		path: "/trust_mark_status?sub=...&trust_mark_type=...",
		method: "GET",
		who: "Trust Mark Issuers",
		section: "Section 8.4",
		description:
			"Checks whether a specific Trust Mark is still active, expired, or revoked. When client authentication is not used, the request MUST be GET with query parameters. POST is used when client authentication is present.",
		request:
			"GET /trust_mark_status?sub=https://login.uni.edu&trust_mark_type=https://edufed.gov/trust-marks/gdpr HTTP/1.1",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/trust-mark-status-response+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
	},
	{
		name: "Trust Marked Entities Listing",
		path: "/trust_mark_list?trust_mark_type=...",
		method: "GET",
		who: "Trust Mark Issuers",
		section: "Section 8.5",
		description: "Returns a JSON array of Entity Identifiers that hold a specific Trust Mark type.",
		request: "GET /trust_mark_list?trust_mark_type=https://edufed.gov/trust-marks/gdpr HTTP/1.1",
		response:
			'HTTP/1.1 200 OK\nContent-Type: application/json\n\n["https://login.uni.edu", "https://login.college.edu"]',
	},
	{
		name: "Trust Mark Endpoint",
		path: "/federation_trust_mark?trust_mark_type=...&sub=...",
		method: "GET",
		who: "Trust Mark Issuers",
		section: "Section 8.6",
		description:
			"Issues a new Trust Mark JWT for a specified entity and Trust Mark type. When client authentication is not used, the request MUST be GET. POST is used when client authentication is present.",
		request:
			"GET /federation_trust_mark?trust_mark_type=https://edufed.gov/trust-marks/gdpr&sub=https://login.uni.edu HTTP/1.1",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/trust-mark+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
	},
	{
		name: "Historical Keys",
		path: "/federation_historical_keys",
		method: "GET",
		who: "All Entities (optional)",
		section: "Section 8.7",
		description:
			"Returns a signed JWKS containing previously used signing keys. Essential for verifying old Entity Statements during key rotation.",
		request: "GET /federation_historical_keys HTTP/1.1\nHost: edufed.gov",
		response: "HTTP/1.1 200 OK\nContent-Type: application/jwk-set+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
	},
	{
		name: "Federation Registration",
		path: "/federation_registration",
		method: "POST",
		who: "OpenID Providers",
		section: "Section 12.2",
		description:
			"Explicit client registration endpoint. An RP submits its Entity Configuration JWT (or trust chain) to register with an OP. Declared in openid_provider metadata, not in federation_entity.",
		request:
			"POST /federation_registration HTTP/1.1\nContent-Type: application/entity-statement+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
		response:
			"HTTP/1.1 200 OK\nContent-Type: application/entity-statement+jwt\n\neyJhbGciOiJSUzI1NiJ9...",
	},
];

export default function Lesson08() {
	return (
		<LessonPage
			lesson={getLesson(8)}
			minutes={12}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "8", title: "Federation Endpoints" },
					{ sec: "8.1", title: "Fetching a Subordinate Statement" },
					{ sec: "8.2", title: "Subordinate Listing" },
					{ sec: "8.3", title: "Resolve Entity" },
					{ sec: "8.4", title: "Trust Mark Status" },
					{ sec: "8.5", title: "Trust Marked Entities Listing" },
					{ sec: "8.6", title: "Federation Trust Mark Endpoint" },
					{ sec: "8.7", title: "Historical Keys" },
					{ sec: "9", title: "Obtaining Federation Entity Configuration Information" },
					{ sec: "12.2", title: "Explicit Registration" },
					{ sec: "15", title: "Media Types" },
				],
				rfcs: [{ num: 8414, title: "OAuth 2.0 Authorization Server Metadata" }],
				external: [
					{
						title: "Building trust with OpenID Federation trust chain on Keycloak",
						source: "Yutaka Obuchi (Hitachi) · CNCF blog",
						date: "Apr 2025",
						href: "https://www.cncf.io/blog/2025/04/25/building-trust-with-openid-federation-trust-chain-on-keycloak/",
					},
				],
			}}
		>
			<p>
				OpenID Federation defines 1 well-known discovery URL (
				<SpecRef sec="9" title="Obtaining Federation Entity Configuration Information" />
				), 7 federation endpoints (
				<SpecRef sec="8" title="Federation Endpoints" />), and 1 registration endpoint (
				<SpecRef sec="12.2" title="Explicit Registration" />
				). Not every entity implements all of them — leaf entities only need the well-known URL,
				while Trust Anchors and Intermediates may implement up to eight. The registration endpoint
				is exposed by OpenID Providers, not Trust Anchors.
			</p>

			<Accordion>
				{endpoints.map((ep) => (
					<AccordionItem key={ep.name} value={ep.name}>
						<AccordionTrigger>
							<div className="flex items-center gap-2">
								<Badge variant="outline" size="sm">
									{ep.method}
								</Badge>
								<span className="font-semibold text-sm">{ep.name}</span>
								<span className="text-xs text-muted-foreground ml-auto mr-2">{ep.who}</span>
							</div>
						</AccordionTrigger>
						<AccordionPanel>
							<div className="space-y-3 text-sm">
								<p>{ep.description}</p>
								<p className="text-xs text-muted-foreground">{ep.section}</p>
								<div>
									<p className="text-xs font-semibold mb-1">Request</p>
									<CodeBlock lang="http" filename="request" bare>{ep.request}</CodeBlock>
								</div>
								<div>
									<p className="text-xs font-semibold mb-1">Response</p>
									<CodeBlock lang="http" filename="response" bare>{ep.response}</CodeBlock>
								</div>
							</div>
						</AccordionPanel>
					</AccordionItem>
				))}
			</Accordion>

			<h2 id="media-types">Media Types</h2>
			<p>
				The federation endpoints return JWT-encoded responses with specific IANA-registered media
				types defined in <SpecRef sec="15" title="Media Types" />. Servers MUST use the correct{" "}
				<code>Content-Type</code> header so clients can route the body to the right validator.
			</p>
			<div className="not-prose my-4 overflow-x-auto rounded-xl border border-border/60">
				<table className="w-full text-sm">
					<thead className="bg-muted/40">
						<tr>
							<th className="px-3 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
								Media Type
							</th>
							<th className="px-3 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
								Used By
							</th>
							<th className="px-3 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
								Spec
							</th>
						</tr>
					</thead>
					<tbody>
						{[
							{ mt: "application/entity-statement+jwt", who: "Entity Configurations & Subordinate Statements", sec: "15.1" },
							{ mt: "application/trust-mark+jwt", who: "Trust Marks", sec: "15.2" },
							{ mt: "application/resolve-response+jwt", who: "Resolve endpoint responses", sec: "15.3" },
							{ mt: "application/trust-chain+json", who: "Trust Chain header parameter", sec: "15.4" },
							{ mt: "application/trust-mark-delegation+jwt", who: "Trust Mark delegations", sec: "15.5" },
							{ mt: "application/jwk-set+jwt", who: "Historical Keys responses", sec: "15.6" },
							{ mt: "application/trust-mark-status-response+jwt", who: "Trust Mark Status responses", sec: "15.7" },
							{ mt: "application/explicit-registration-response+jwt", who: "Explicit Registration responses", sec: "15.8" },
						].map((row) => (
							<tr key={row.mt} className="border-t border-border/60">
								<td className="px-3 py-2 font-mono text-[12.5px] text-foreground">{row.mt}</td>
								<td className="px-3 py-2 text-muted-foreground">{row.who}</td>
								<td className="px-3 py-2"><SpecRef sec={row.sec} /></td>
							</tr>
						))}
					</tbody>
				</table>
			</div>

			<Callout variant="privacy" sec="19" secTitle="Privacy Considerations">
				The Fetch endpoint and the Trust Mark Status endpoint can leak entity relationships via
				server access logs and DNS lookups: every query reveals "entity X is investigating entity
				Y." Operators handling sensitive populations should mitigate this by serving short-lived
				static Trust Chains (so resolvers don't need to call back), and by avoiding the{" "}
				<code>sub</code> parameter on Trust Mark listing endpoints when possible.
			</Callout>

			<AnalogyBox>
				Think of a government building with multiple service windows — each serves a specific
				purpose. The "Entity Configuration" window is at the front door (everyone has it). The
				"Fetch" and "List" windows are inside, only available to entities that manage subordinates.
			</AnalogyBox>
		</LessonPage>
	);
}
