import { Badge, Card, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";
import { LessonPage } from "~/components/lesson-page";
import { SpecRef } from "~/components/spec-ref";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-28" };

export function meta() {
	return lessonMetaForSlug("putting-it-together");
}

function PhaseTag({ phase }: { phase: string }) {
	const colors: Record<string, string> = {
		Setup: "bg-brand-500/10 text-brand-700 dark:text-brand-300",
		"Login Flow": "bg-purple-500/10 text-purple-700 dark:text-purple-300",
		Discovery: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
		Resolution: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
		Auth: "bg-orange-500/10 text-orange-700 dark:text-orange-300",
		Done: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
	};
	return (
		<Badge variant="secondary" size="sm" className={colors[phase]}>
			{phase}
		</Badge>
	);
}

const timelineSteps = [
	{
		title: "1. TA publishes Entity Configuration",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Setup" />
				<p>
					Trust Anchor <code>edu-federation.gov</code> publishes its Entity Configuration at{" "}
					<code>.well-known/openid-federation</code> (<SpecRef sec="9" />). It contains the TA's
					JWKS, federation endpoints, and <code>trust_mark_issuers</code>.
				</p>
			</div>
		),
	},
	{
		title: "2. TA registers Intermediate",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Setup" />
				<p>
					The TA registers <code>uni-alliance.edu</code> as a subordinate, issuing a Subordinate
					Statement (<SpecRef sec="3.1.3" />) with <code>metadata_policy</code> that enforces
					scoping rules and <code>max_path_length: 1</code> (<SpecRef sec="6.2.1" />).
				</p>
			</div>
		),
	},
	{
		title: "3. Intermediate registers University OP",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Setup" />
				<p>
					<code>uni-alliance.edu</code> registers <code>login.state-university.edu</code> as an
					OpenID Provider subordinate, with additional metadata policy constraints.
				</p>
			</div>
		),
	},
	{
		title: "4. TA issues GDPR Trust Mark to OP",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Setup" />
				<p>
					The TA issues a GDPR compliance Trust Mark (<SpecRef sec="7" />) to the University OP. The
					OP adds it to its <code>trust_marks</code> array in its Entity Configuration.
				</p>
			</div>
		),
	},
	{
		title: "5. RP publishes Entity Configuration",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Setup" />
				<p>
					<code>research-portal.gov</code> publishes its Entity Configuration with{" "}
					<code>authority_hints</code> pointing to its own superior, and{" "}
					<code>client_registration_types: ["automatic"]</code>.
				</p>
			</div>
		),
	},
	{
		title: "6. Student clicks 'Log in with State University'",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Login Flow" />
				<p>
					The student visits the research portal and initiates login. The RP needs to communicate
					with the OP — but has never interacted with it before.
				</p>
			</div>
		),
	},
	{
		title: "7. RP fetches OP's Entity Configuration",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Discovery" />
				<p>
					The RP fetches <code>login.state-university.edu/.well-known/openid-federation</code> to
					discover the OP's capabilities and <code>authority_hints</code>.
				</p>
			</div>
		),
	},
	{
		title: "8. RP builds trust chain bottom-up",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Resolution" />
				<p>
					Following <code>authority_hints</code>, the RP resolves the full trust chain (
					<SpecRef sec="10.1" />): OP → uni-alliance.edu → edu-federation.gov. It fetches
					Subordinate Statements from each superior's Fetch endpoint.
				</p>
			</div>
		),
	},
	{
		title: "9. RP verifies chain and applies policies",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Resolution" />
				<p>
					The RP verifies signatures top-down (<SpecRef sec="10.2" />), checks <code>exp</code>/
					<code>iat</code>, enforces <code>max_path_length</code>, and cascades metadata policies
					to produce the OP's resolved metadata.
				</p>
			</div>
		),
	},
	{
		title: "10. RP checks GDPR Trust Mark",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Resolution" />
				<p>
					The RP verifies the GDPR Trust Mark on the OP's Entity Configuration (
					<SpecRef sec="7.3" />): signature check, issuer authorization, expiry, and optional
					status endpoint call.
				</p>
			</div>
		),
	},
	{
		title: "11. RP sends Authorization Request",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Auth" />
				<p>
					Using automatic registration (<SpecRef sec="12.1" />), the RP sends an Authorization
					Request via a signed Request Object (JAR). The <code>client_id</code> is the RP's Entity
					Identifier URL.
				</p>
			</div>
		),
	},
	{
		title: "12. OP resolves RP's trust chain",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Auth" />
				<p>
					The OP independently resolves the RP's trust chain from the <code>client_id</code>. The
					resolved RP metadata becomes the client registration.
				</p>
			</div>
		),
	},
	{
		title: "13. Student authenticates",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Auth" />
				<p>
					The student authenticates at the University OP (username/password, MFA, etc.). The OP
					issues an authorization code to the RP's registered redirect_uri.
				</p>
			</div>
		),
	},
	{
		title: "14. Login complete!",
		content: (
			<div className="text-sm space-y-2">
				<PhaseTag phase="Done" />
				<p className="font-semibold text-emerald-600">
					The RP exchanges the authorization code for tokens. The student is logged in to the
					research portal — all through federated trust, with zero pre-registration.
				</p>
			</div>
		),
	},
];

const recapCards = [
	{
		lesson: 1,
		title: "Federation",
		desc: "Scalable trust hierarchy instead of N x N bilateral agreements",
	},
	{
		lesson: 2,
		title: "Entities & Roles",
		desc: "TA, Intermediate, OP, RP — each with clear responsibilities",
	},
	{
		lesson: 3,
		title: "Entity Statements",
		desc: "Self-signed Entity Configs and superior-signed Subordinate Statements",
	},
	{
		lesson: 4,
		title: "Trust Chains",
		desc: "Linked sequence of signed statements from leaf to anchor",
	},
	{ lesson: 5, title: "Chain Resolution", desc: "Bottom-up algorithm following authority_hints" },
	{
		lesson: 6,
		title: "Metadata & Policy",
		desc: "Capabilities described, constrained by cascade of policies",
	},
	{ lesson: 7, title: "Trust Marks", desc: "Certified badges verifying compliance requirements" },
	{
		lesson: 8,
		title: "Endpoints",
		desc: "9 HTTP APIs for discovery, fetch, resolve, and registration",
	},
	{ lesson: 9, title: "Registration", desc: "Automatic (on-the-fly) or explicit (pre-registered)" },
];

export default function Lesson10() {
	return (
		<LessonPage
			lesson={getLesson(10)}
			minutes={15}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "9", title: "Federation Entity Configuration" },
					{ sec: "3.1.3", title: "Subordinate Statement Claims" },
					{ sec: "7", title: "Trust Marks" },
					{ sec: "10.1", title: "Fetching Entity Statements" },
					{ sec: "10.2", title: "Validating a Trust Chain" },
					{ sec: "12.1", title: "Automatic Registration" },
				],
			}}
		>
			<h2 id="scenario">Scenario: A Student Logs In to a Research Portal</h2>
			<p>
				This capstone walkthrough follows a complete, real-world scenario that uses
				<strong> every concept</strong> from the previous 9 lessons.
			</p>
			<div className="my-4 rounded-lg bg-muted p-4 text-sm space-y-1">
				<p>
					<strong>Trust Anchor:</strong> edu-federation.gov
				</p>
				<p>
					<strong>Intermediate:</strong> uni-alliance.edu
				</p>
				<p>
					<strong>OpenID Provider:</strong> login.state-university.edu
				</p>
				<p>
					<strong>Relying Party:</strong> research-portal.gov
				</p>
			</div>

			<StepThrough steps={timelineSteps} />

			<h2>Concept Recap — Everything You Learned</h2>
			<div className="grid gap-3 sm:grid-cols-3">
				{recapCards.map((card) => (
					<Card key={card.lesson}>
						<CardHeader className="pb-1">
							<CardTitle className="text-sm">
								<Badge variant="secondary" size="sm" className="mr-2">
									L{card.lesson}
								</Badge>
								{card.title}
							</CardTitle>
						</CardHeader>
						<CardPanel className="pt-0 text-xs text-muted-foreground">{card.desc}</CardPanel>
					</Card>
				))}
			</div>

			<div className="mt-8 rounded-lg border-2 border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/20 p-6 text-center">
				<p className="text-lg font-bold">Congratulations!</p>
				<p className="text-muted-foreground mt-1">
					You've completed the core curriculum. Continue to the Advanced and Going Deeper sections
					to explore topology design, real-world use cases, and hands-on exercises.
				</p>
			</div>

		</LessonPage>
	);
}
