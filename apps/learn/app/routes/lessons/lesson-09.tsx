import { Badge, Card, CardPanel, Tabs, TabsList, TabsPanel, TabsTab } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Callout } from "~/components/callout";
import { LessonPage } from "~/components/lesson-page";
import { SpecRef } from "~/components/spec-ref";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-25" };

export function meta() {
	return lessonMetaForSlug("client-registration");
}

const autoSteps = [
	{
		title: "1. RP discovers OP",
		content: (
			<p className="text-sm">
				The RP discovers the OP and resolves its trust chain, confirming they share a common Trust
				Anchor (<SpecRef sec="12.1" />).
			</p>
		),
	},
	{
		title: "2. RP sends Authorization Request",
		content: (
			<div className="text-sm space-y-2">
				<p>
					The RP sends an Authorization Request using a Request Object (signed JWT per JAR,{" "}
					<SpecRef sec="12.1.1" />) or PAR. <code>client_id</code> is the RP's Entity Identifier
					URL. No <code>client_secret</code> needed.
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
					<code>federation_registration_endpoint</code> (<SpecRef sec="12.2" />).
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
		<LessonPage
			lesson={getLesson(9)}
			minutes={10}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "12", title: "OpenID Connect Client Registration" },
					{ sec: "12.1", title: "Automatic Registration" },
					{ sec: "12.1.1", title: "Authentication Request" },
					{ sec: "12.2", title: "Explicit Registration" },
					{ sec: "3.1.4", title: "Claims Used in Explicit Registration Requests" },
					{ sec: "3.1.5", title: "Claims Used in Explicit Registration Responses" },
				],
				rfcs: [
					{ num: 9101, title: "JWT-Secured Authorization Request (JAR)" },
					{ num: 9126, title: "OAuth 2.0 Pushed Authorization Requests (PAR)" },
					{ num: 7591, title: "OAuth 2.0 Dynamic Client Registration Protocol" },
				],
			}}
		>
			<p>
				In a federation, a Relying Party doesn't need to manually register with every OpenID
				Provider. There are two approaches (
				<SpecRef sec="12" title="OpenID Connect Client Registration" />
				): <strong>Automatic</strong> (no pre-registration, resolved at authorization time) and{" "}
				<strong>Explicit</strong> (pre-registration via a dedicated endpoint).
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

			<Callout variant="security" sec="12.1.1" secTitle="Authentication Request">
				The Request Object used in Automatic Registration MUST include a unique <code>jti</code>{" "}
				(JWT ID) claim. The OP MUST track recent <code>jti</code> values and reject any duplicate —
				Request Objects are <strong>single-use by default</strong> to prevent replay attacks. Reuse
				is only allowed under negotiated conditions outside this spec's scope.
			</Callout>

			<h2 id="comparison">Side-by-Side Comparison</h2>
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
		</LessonPage>
	);
}
