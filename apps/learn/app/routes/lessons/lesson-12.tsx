import { Accordion, AccordionItem, AccordionPanel, AccordionTrigger, Badge } from "@oidfed/ui";
import { Callout } from "~/components/callout";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-28" };

export function meta() {
	return lessonMetaForSlug("faq");
}

const faqSections = [
	{
		category: "Basics",
		questions: [
			{
				q: "What's the difference between OpenID Connect and OpenID Federation?",
				a: "OpenID Connect (OIDC) is an authentication protocol — it handles login flows, tokens, and user info. OpenID Federation is a trust layer that sits above OIDC (and OAuth 2.0), automating discovery, verification, and configuration through signed Entity Statements and Trust Chains.",
			},
			{
				q: "Can I use OpenID Federation without OpenID Connect?",
				a: "Yes. The core federation primitives (Entity Statements, Trust Chains, metadata policies) are protocol-agnostic. You can define custom metadata types for non-OIDC use cases — IoT, banking, healthcare, etc.",
			},
			{
				q: "What problem does federation solve that plain OIDC doesn't?",
				a: "Without federation, you need O(n × m) bilateral registrations between RPs and OPs. Federation provides automated discovery, cryptographic trust from a hierarchy, policy enforcement from superiors, and automatic client registration.",
			},
			{
				q: "How is this different from SAML federation?",
				a: "SAML federation uses static metadata aggregates that are centralized and updated periodically. OpenID Federation is decentralized, dynamic, with real-time resolution and on-demand chain building. Entities can join or leave without batch republishing.",
			},
		],
	},
	{
		category: "Trust & Security",
		questions: [
			{
				q: "What happens if a Trust Anchor's key is compromised?",
				a: "This is the most severe event in a federation. Prevention: use HSMs for TA keys. Recovery: rotate the key, publish old keys via the Historical Keys endpoint, and re-issue all Subordinate Statements. Multi-anchor topologies provide resilience.",
			},
			{
				q: "How do I revoke an entity?",
				a: "Federation uses omission and expiry rather than CRLs. Stop issuing Subordinate Statements for the entity, remove it from the List endpoint, and use short exp values so existing statements expire quickly.",
			},
			{
				q: "Can two separate federations interoperate?",
				a: "Yes, through multi-anchor trust or bridge entities. An entity can trust multiple Trust Anchors, and bridge entities can serve as cross-federation intermediaries. Requires naming_constraints coordination.",
			},
			{
				q: "What prevents a rogue intermediate?",
				a: "Several mechanisms: naming_constraints limit which entity identifiers an intermediate can vouch for, max_path_length limits delegation depth, policy cascading only allows more restrictive policies (never less), and short-lived statements limit exposure time.",
			},
		],
	},
	{
		category: "Implementation",
		questions: [
			{
				q: "Do I need to implement all 9 endpoints?",
				a: "No. A Leaf Entity only needs .well-known/openid-federation. An Intermediate adds Fetch and List. A Trust Anchor optionally adds Historical Keys, Resolve, and Trust Mark endpoints. Implement only what your role requires.",
			},
			{
				q: "What's the minimum viable federation?",
				a: "One Trust Anchor, one OpenID Provider, and one Relying Party. The TA publishes its EC and issues Subordinate Statements for the OP and RP. The OP and RP publish their own ECs with authority_hints pointing to the TA.",
			},
			{
				q: "How do I migrate from non-federated OIDC?",
				a: "Four phases: (1) Publish Entity Configurations alongside existing metadata, (2) Establish a Trust Anchor, (3) Enable dual-mode operation (support both federated and non-federated flows), (4) Switch over once all parties are federated.",
			},
			{
				q: "Which signing algorithms should I use?",
				a: "RS256 is widely supported and a safe default. ES256 produces smaller signatures. PS256 is stronger and recommended for new deployments. The key is consistency within your federation — declare supported algorithms in metadata.",
			},
		],
	},
	{
		category: "Operations",
		questions: [
			{
				q: "What's the recommended statement lifetime (exp)?",
				a: "Entity Configurations: 24-72 hours. Subordinate Statements: 24-48 hours for fast revocation, up to 7 days for low-risk scenarios. Trust Marks: varies by certification type. Shorter lifetimes = faster revocation but more frequent fetching.",
			},
			{
				q: "How should key rotation be handled?",
				a: "Use an overlap model: add the new key to JWKS, continue signing with the old key for a transition period, switch signing to the new key, then remove the old key. TA key rotation follows a 4-step process (Section 11).",
			},
			{
				q: "How does caching work?",
				a: "The exp claim serves as the cache TTL. Cache Entity Configurations, Subordinate Statements, and resolved chains. Respect HTTP Cache-Control as a secondary signal. Never use expired data for trust decisions.",
			},
			{
				q: "How do I monitor federation health?",
				a: "Track: endpoint availability, statement freshness (time-to-expiry), resolution success rate, key rotation compliance, and list endpoint drift (subordinates appearing/disappearing unexpectedly).",
			},
		],
	},
];

export default function Lesson12() {
	return (
		<LessonPage
			lesson={getLesson(12)}
			minutes={12}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "6.2", title: "Constraints" },
					{ sec: "11", title: "Updating Metadata, Key Rollover, and Revocation" },
					{ sec: "11.1", title: "Federation Key Rollover" },
					{ sec: "11.2", title: "Trust Anchor Rollover" },
					{ sec: "11.3", title: "Revocation" },
					{ sec: "17", title: "Implementation Considerations" },
					{ sec: "18", title: "Security Considerations" },
					{ sec: "19", title: "Privacy Considerations" },
				],
			}}
		>
			{faqSections.map((section) => (
				<div key={section.category} className="mb-8">
					<h2 id={section.category.toLowerCase().replace(/\s+/g, "-")} className="flex items-center gap-2">
						{section.category}
						<Badge variant="secondary" size="sm">
							{section.questions.length} questions
						</Badge>
					</h2>
					{section.category === "Operations" && (
						<Callout variant="implementation-note">
							The answers below describe <strong>operational practice</strong> drawn from the
							industry — recommended lifetimes, monitoring, caching, and key-rotation strategies.
							The OpenID Federation 1.0 specification does not mandate specific durations or
							procedures here; it requires only that <code>exp</code> be honored, that historical
							keys be available during overlap, and that revocation be achievable. Tune the values
							to your federation's risk profile.
						</Callout>
					)}
					{section.category === "Implementation" && (
						<Callout variant="implementation-note">
							These are deployment recommendations from federation operators, not spec mandates.
							The spec defines what each role <em>requires</em>; how you stage rollout, choose
							algorithms, and stand up infrastructure is up to you.
						</Callout>
					)}
					<Accordion>
						{section.questions.map((faq) => (
							<AccordionItem key={faq.q} value={faq.q}>
								<AccordionTrigger className="text-sm font-medium text-left">
									{faq.q}
								</AccordionTrigger>
								<AccordionPanel className="text-sm text-muted-foreground">{faq.a}</AccordionPanel>
							</AccordionItem>
						))}
					</Accordion>
				</div>
			))}
		</LessonPage>
	);
}
