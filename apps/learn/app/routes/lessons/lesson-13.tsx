import { Accordion, AccordionItem, AccordionPanel, AccordionTrigger, Badge } from "@oidfed/ui";
import { LessonPage } from "~/components/lesson-page";
import { SearchFilter } from "~/components/search-filter";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-28" };

export function meta() {
	return lessonMetaForSlug("glossary");
}

interface GlossaryTerm {
	term: string;
	definition: string;
	section: string;
	sectionUrl: string;
	lesson: number;
	lessonTitle: string;
}

const terms: GlossaryTerm[] = [
	{
		term: "Authority Hints",
		definition:
			"Array of Immediate Superior Entity Identifiers in an Entity Configuration. REQUIRED for Leaf and Intermediate entities. Used during bottom-up trust chain resolution to discover the path to a Trust Anchor.",
		section: "Section 3.1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.2",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "Automatic Registration",
		definition:
			"Client registration method where the RP sends an Authorization Request (via JAR or PAR) without pre-registering. The OP resolves the RP's trust chain on the fly from the client_id.",
		section: "Section 12.1",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-12.1",
		lesson: 9,
		lessonTitle: "Client Registration",
	},
	{
		term: "Constraints",
		definition:
			"Structural limits in Subordinate Statements: max_path_length (delegation depth), naming_constraints (allowed entity identifiers), allowed_entity_types.",
		section: "Section 6.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-6.2",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Entity",
		definition:
			"Something that has a separate and distinct existence that can be identified in a context. In federation, each entity has a unique Entity Identifier (HTTPS URL).",
		section: "Section 1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
		lesson: 1,
		lessonTitle: "What is Federation?",
	},
	{
		term: "Entity Configuration",
		definition:
			"A self-signed Entity Statement published at .well-known/openid-federation. Contains the entity's own metadata, JWKS, authority_hints, and trust_marks. iss equals sub.",
		section: "Section 3.1.1",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.1",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "Entity Identifier",
		definition:
			"A globally unique URL using the https scheme that identifies an entity. MAY contain port or path components, MUST NOT contain query or fragment components.",
		section: "Section 1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
		lesson: 1,
		lessonTitle: "What is Federation?",
	},
	{
		term: "Entity Statement",
		definition:
			"A signed JWT that carries trust information. Two types: Entity Configuration (self-signed) and Subordinate Statement (signed by superior).",
		section: "Section 3",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-3",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "Explicit Registration",
		definition:
			"Client registration method where the RP POSTs its Entity Configuration to the OP's federation_registration_endpoint. The OP creates a persistent client record.",
		section: "Section 12.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-12.2",
		lesson: 9,
		lessonTitle: "Client Registration",
	},
	{
		term: "Fetch Endpoint",
		definition:
			"Federation endpoint where an Intermediate or TA returns a Subordinate Statement for a specified subject entity.",
		section: "Section 8.1",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-8.1",
		lesson: 8,
		lessonTitle: "Federation Endpoints",
	},
	{
		term: "Historical Keys Endpoint",
		definition:
			"Endpoint returning a signed JWKS of previously used signing keys. Essential for verifying old Entity Statements during key rotation.",
		section: "Section 8.7",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-8.7",
		lesson: 8,
		lessonTitle: "Federation Endpoints",
	},
	{
		term: "Intermediate Entity",
		definition:
			"An entity between the Trust Anchor and Leaf Entities. Issues Subordinate Statements and can enforce metadata policies. Has both superiors and subordinates.",
		section: "Section 1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
		lesson: 2,
		lessonTitle: "Entities & Roles",
	},
	{
		term: "JWKS",
		definition:
			"JSON Web Key Set — a collection of public keys used for signature verification. Published in the jwks claim of Entity Statements.",
		section: "Section 3.1.1",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.1",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "Leaf Entity",
		definition:
			"An entity at the bottom of the hierarchy with no subordinates. MUST NOT publish federation_fetch_endpoint or federation_list_endpoint.",
		section: "Section 1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
		lesson: 2,
		lessonTitle: "Entities & Roles",
	},
	{
		term: "List Endpoint",
		definition:
			"Federation endpoint returning a JSON array of Entity Identifiers of all immediate subordinates. Supports entity_type and trust_marked filters.",
		section: "Section 8.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-8.2",
		lesson: 8,
		lessonTitle: "Federation Endpoints",
	},
	{
		term: "max_path_length",
		definition:
			"Constraint limiting the number of Intermediates allowed between the issuer and a Leaf Entity. 0 means only direct subordinates.",
		section: "Section 6.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-6.2",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Metadata",
		definition:
			"Protocol-specific configuration keyed by Entity Type Identifier. Describes an entity's capabilities, endpoints, and supported features.",
		section: "Section 5",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-5",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Metadata Policy",
		definition:
			"Policy operators in Subordinate Statements that constrain subordinate metadata. Applied in cascade from TA through Intermediates. Can only make metadata more restrictive.",
		section: "Section 6.1",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-6.1",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "naming_constraints",
		definition:
			"Constraint specifying permitted/excluded entity identifier patterns. Limits which entities an Intermediate can vouch for.",
		section: "Section 6.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-6.2",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Resolve Endpoint",
		definition:
			"Convenience endpoint that performs trust chain resolution on behalf of the caller. Returns resolved metadata and the complete trust chain.",
		section: "Section 8.3",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-8.3",
		lesson: 5,
		lessonTitle: "Trust Chain Resolution",
	},
	{
		term: "Resolved Metadata",
		definition:
			"The final metadata after applying all metadata policies from the trust chain cascade. This is the metadata used for actual protocol interactions.",
		section: "Section 6.1.4",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-6.1.4",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Subordinate Statement",
		definition:
			"An Entity Statement signed by a superior entity about a subordinate. Contains the subordinate's JWKS, may override metadata, and may add metadata_policy and constraints.",
		section: "Section 3.1.3",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-3.1.3",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "Trust Anchor",
		definition:
			"The top-level authority in a federation. Every trust chain ends at a Trust Anchor. Its public key must be pre-configured in the relying party's trust store.",
		section: "Section 1.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
		lesson: 1,
		lessonTitle: "What is Federation?",
	},
	{
		term: "Trust Chain",
		definition:
			"An ordered sequence of Entity Statements from a Leaf Entity Configuration to a Trust Anchor Entity Configuration. Each link is cryptographically signed by the issuer.",
		section: "Section 4",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-4",
		lesson: 4,
		lessonTitle: "Trust Chains",
	},
	{
		term: "Trust Chain Resolution",
		definition:
			"The algorithm that fetches, assembles, and verifies a complete trust chain. Most commonly done bottom-up by following authority_hints.",
		section: "Section 10",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-10",
		lesson: 5,
		lessonTitle: "Trust Chain Resolution",
	},
	{
		term: "Trust Mark",
		definition:
			"A signed JWT certifying that an entity meets specific requirements. Contains trust_mark_type, issuer, subject, and optional delegation. Included in the trust_marks array of Entity Configurations.",
		section: "Section 7",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-7",
		lesson: 7,
		lessonTitle: "Trust Marks",
	},
	{
		term: "Trust Mark Issuer",
		definition:
			"An entity authorized to issue Trust Marks. Authorized via trust_mark_issuers in the TA's Entity Configuration or via delegation JWT from a Trust Mark Owner.",
		section: "Section 7.2",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-7.2",
		lesson: 7,
		lessonTitle: "Trust Marks",
	},
	{
		term: "Trust Mark Status Endpoint",
		definition:
			"Endpoint to check whether a Trust Mark is active, expired, or revoked. Returns status information for a submitted Trust Mark JWT.",
		section: "Section 8.4",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-8.4",
		lesson: 7,
		lessonTitle: "Trust Marks",
	},
	{
		term: "Well-Known Endpoint",
		definition:
			"The .well-known/openid-federation URL where every entity publishes its Entity Configuration. The universal discovery starting point.",
		section: "Section 9",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-9",
		lesson: 8,
		lessonTitle: "Federation Endpoints",
	},
	{
		term: "jwks (general-purpose JWT claim)",
		definition:
			"A JSON Web Key Set claim usable across multiple JWT profiles (Entity Statements, Trust Marks, etc.). Contains the public keys for verifying the subject's signatures.",
		section: "Section 13",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-13",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "metadata (general-purpose JWT claim)",
		definition:
			"A JSON object indexed by Entity Type Identifier containing protocol-specific configuration. Defined as a general-purpose claim in Section 13 — applies to Entity Statements and any future profiles built on this framework.",
		section: "Section 13",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-13",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "crit (general-purpose JWT claim)",
		definition:
			"Array listing non-standard claims that the receiver MUST understand to safely process the statement. Spec-defined claims MUST NOT be listed in crit. Failure to understand any listed claim invalidates the entire statement.",
		section: "Section 13",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-13",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
	{
		term: "BCP 47 language tagging",
		definition:
			"Human-readable claims (e.g., organization_name) MAY appear in multiple language/script variants by appending #lang-script — for example organization_name#ja-Kana-JP. The language-tagged variant is independent of the untagged claim.",
		section: "Section 14",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-14",
		lesson: 6,
		lessonTitle: "Metadata & Policy",
	},
	{
		term: "Media Types (federation)",
		definition:
			"IANA-registered MIME types for federation responses: application/entity-statement+jwt, application/trust-mark+jwt, application/resolve-response+jwt, application/trust-chain+json, application/trust-mark-delegation+jwt, application/jwk-set+jwt, application/trust-mark-status-response+jwt, application/explicit-registration-response+jwt.",
		section: "Section 15",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-15",
		lesson: 8,
		lessonTitle: "Federation Endpoints",
	},
	{
		term: "String Operations (Entity ID comparison)",
		definition:
			"Entity Identifier comparisons MUST NOT apply Unicode Normalization (NFC/NFD). Compare strings by direct code-point equality after JSON unescaping only. Prevents canonicalization attacks that exploit visually identical IDs.",
		section: "Section 16",
		sectionUrl: "https://openid.net/specs/openid-federation-1_0.html#section-16",
		lesson: 3,
		lessonTitle: "Entity Statements",
	},
];

export default function Lesson13() {
	return (
		<LessonPage
			lesson={getLesson(13)}
			minutes={8}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "1.2", title: "Terminology" },
					{ sec: "13", title: "General-Purpose JWT Claims" },
					{ sec: "14", title: "Claims Languages and Scripts" },
					{ sec: "15", title: "Media Types" },
					{ sec: "16", title: "String Operations" },
				],
			}}
		>
			<SearchFilter
				items={terms}
				filterFn={(item, query) =>
					item.term.toLowerCase().includes(query) || item.definition.toLowerCase().includes(query)
				}
				placeholder="Search terms..."
			>
				{(filtered) => (
					<>
						<p className="text-sm text-muted-foreground mb-4">
							{filtered.length} of {terms.length} terms shown
						</p>
						<Accordion>
							{filtered.map((t) => (
								<AccordionItem key={t.term} value={t.term}>
									<AccordionTrigger className="text-sm font-medium">{t.term}</AccordionTrigger>
									<AccordionPanel className="text-sm space-y-2">
										<p>{t.definition}</p>
										<div className="flex flex-wrap gap-2">
											<a
												href={t.sectionUrl}
												target="_blank"
												rel="noopener noreferrer"
												className="text-primary hover:underline"
											>
												<Badge variant="outline" size="sm">
													{t.section}
												</Badge>
											</a>
											<Badge variant="secondary" size="sm">
												Lesson {t.lesson}: {t.lessonTitle}
											</Badge>
										</div>
									</AccordionPanel>
								</AccordionItem>
							))}
						</Accordion>
					</>
				)}
			</SearchFilter>

		</LessonPage>
	);
}
