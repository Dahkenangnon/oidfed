import { Badge, Card, CardPanel, Tabs, TabsList, TabsPanel, TabsTab } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Client Registration — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"How a Relying Party introduces itself to an OpenID Provider in a federation — automatic vs explicit registration.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Client Registration" },
		{ property: "og:description", content: "Automatic and explicit registration flows compared." },
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Advanced" },
	];
}

const autoSteps = [
	{
		title: "1. RP discovers OP",
		content: (
			<p className="text-sm">
				The RP discovers the OP and resolves its trust chain, confirming they share a common Trust
				Anchor.
				<Ref id="1" />
			</p>
		),
	},
	{
		title: "2. RP sends Authorization Request",
		content: (
			<div className="text-sm space-y-2">
				<p>
					The RP sends an Authorization Request using a Request Object (signed JWT per JAR)
					<Ref id="2" /> or PAR. <code>client_id</code> is the RP's Entity Identifier URL. No{" "}
					<code>client_secret</code> needed.
				</p>
			</div>
		),
	},
	{
		title: "3. OP resolves RP's trust chain",
		content: (
			<p className="text-sm">
				The OP fetches the RP's Entity Configuration from{" "}
				<code>client_id/.well-known/openid-federation</code>, resolves its trust chain, and applies
				metadata policies. The resolved metadata becomes the RP's "registration."
			</p>
		),
	},
	{
		title: "4. OP proceeds with authorization",
		content: (
			<p className="text-sm">
				The OP uses the resolved RP metadata to process the authorization request. No
				pre-registration was needed — everything was resolved on the fly.
			</p>
		),
	},
];

const explicitSteps = [
	{
		title: "1. RP discovers OP",
		content: <p className="text-sm">The RP discovers the OP and resolves its trust chain.</p>,
	},
	{
		title: "2. RP POSTs to registration endpoint",
		content: (
			<div className="text-sm space-y-2">
				<p>
					The RP POSTs its Entity Configuration JWT (<code>application/entity-statement+jwt</code>)
					or full trust chain (<code>application/trust-chain+json</code>) to the OP's{" "}
					<code>federation_registration_endpoint</code>.<Ref id="3" />
				</p>
			</div>
		),
	},
	{
		title: "3. OP verifies and creates client",
		content: (
			<p className="text-sm">
				The OP verifies the trust chain, applies metadata policy, and creates a persistent client
				record.
			</p>
		),
	},
	{
		title: "4. OP returns registration response",
		content: (
			<p className="text-sm">
				The OP returns the registration response as an Entity Statement (
				<code>application/entity-statement+jwt</code>) containing the assigned{" "}
				<code>client_id</code>, resolved metadata, and <code>trust_anchor</code>.
			</p>
		),
	},
	{
		title: "5. RP uses registered client_id",
		content: (
			<p className="text-sm">
				The RP sends authorization requests using the registered client_id. Standard OIDC flows
				apply from here.
			</p>
		),
	},
];

const comparison = [
	{ feature: "Pre-registration", auto: "No", explicit: "Yes" },
	{
		feature: "Trust chain verified",
		auto: "At authorization time",
		explicit: "At registration time",
	},
	{ feature: "Client ID", auto: "Entity Identifier (URL)", explicit: "Assigned by OP" },
	{
		feature: "Auth request format",
		auto: "Request Object (JAR) or PAR required",
		explicit: "Standard",
	},
	{ feature: "Cryptography", auto: "Asymmetric only", explicit: "Asymmetric or symmetric" },
	{ feature: "OP stores RP info", auto: "No (resolves on the fly)", explicit: "Yes (persisted)" },
	{
		feature: "Best for",
		auto: "Dynamic, large federations",
		explicit: "Stable, long-term relationships",
	},
];

export default function Lesson09() {
	return (
		<LessonPage lesson={getLesson(9)}>
			<p>
				In a federation, a Relying Party doesn't need to manually register with every OpenID
				Provider. There are two approaches
				<Ref id="1" />: <strong>Automatic</strong> (no pre-registration, resolved at authorization
				time) and <strong>Explicit</strong> (pre-registration via a dedicated endpoint).
			</p>

			<Tabs defaultValue="auto">
				<TabsList>
					<TabsTab value="auto">Automatic Registration</TabsTab>
					<TabsTab value="explicit">Explicit Registration</TabsTab>
				</TabsList>
				<TabsPanel value="auto" className="mt-4">
					<StepThrough steps={autoSteps} />
				</TabsPanel>
				<TabsPanel value="explicit" className="mt-4">
					<StepThrough steps={explicitSteps} />
				</TabsPanel>
			</Tabs>

			<h2>Side-by-Side Comparison</h2>
			<Card>
				<CardPanel>
					<div className="overflow-x-auto">
						<table className="w-full text-sm">
							<thead>
								<tr className="border-b border-border">
									<th className="text-left py-2 pr-4 font-medium">Feature</th>
									<th className="text-left py-2 pr-4 font-medium">
										<Badge variant="info" size="sm">
											Automatic
										</Badge>
									</th>
									<th className="text-left py-2 font-medium">
										<Badge variant="success" size="sm">
											Explicit
										</Badge>
									</th>
								</tr>
							</thead>
							<tbody>
								{comparison.map((row) => (
									<tr key={row.feature} className="border-b border-border/50">
										<td className="py-2 pr-4 font-medium">{row.feature}</td>
										<td className="py-2 pr-4 text-muted-foreground">{row.auto}</td>
										<td className="py-2 text-muted-foreground">{row.explicit}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</CardPanel>
			</Card>

			<AnalogyBox>
				<strong>Automatic</strong> = walking into a government building, stating your name, and they
				look you up in the national registry on the spot. <strong>Explicit</strong> = walking into a
				private members' club, showing your credentials, filling out an application form, and
				receiving a membership card for future visits.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 12 — OpenID Connect Client Registration",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-12",
					},
					{
						id: "2",
						text: "RFC 9101 — JWT-Secured Authorization Request (JAR)",
						url: "https://www.rfc-editor.org/rfc/rfc9101",
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
