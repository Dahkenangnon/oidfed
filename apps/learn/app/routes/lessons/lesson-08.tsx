import { Accordion, AccordionItem, AccordionPanel, AccordionTrigger, Badge } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Federation Endpoints — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"The HTTP APIs that federation entities expose — 1 well-known discovery URL, 7 federation endpoints, and 1 registration endpoint.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Federation Endpoints" },
		{
			property: "og:description",
			content: "Every endpoint explained with request/response examples.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Advanced" },
	];
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
		<LessonPage lesson={getLesson(8)}>
			<p>
				OpenID Federation defines 1 well-known discovery URL
				<Ref id="1" />, 7 federation endpoints
				<Ref id="2" />, and 1 registration endpoint
				<Ref id="3" />. Not every entity implements all of them — leaf entities only need the
				well-known URL, while Trust Anchors and Intermediates may implement up to eight. The
				registration endpoint is available to OpenID Providers, not TAs.
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
									<p className="text-xs font-semibold mb-1">Request:</p>
									<pre className="rounded bg-muted p-2 text-xs overflow-x-auto">{ep.request}</pre>
								</div>
								<div>
									<p className="text-xs font-semibold mb-1">Response:</p>
									<pre className="rounded bg-muted p-2 text-xs overflow-x-auto">{ep.response}</pre>
								</div>
							</div>
						</AccordionPanel>
					</AccordionItem>
				))}
			</Accordion>

			<AnalogyBox>
				Think of a government building with multiple service windows — each serves a specific
				purpose. The "Entity Configuration" window is at the front door (everyone has it). The
				"Fetch" and "List" windows are inside, only available to entities that manage subordinates.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 9 — Obtaining Federation Entity Configuration Information",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-9",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 8 — Federation Endpoints",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-8",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 12.2 — Explicit Registration",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-12.2",
					},
				]}
			/>
		</LessonPage>
	);
}
