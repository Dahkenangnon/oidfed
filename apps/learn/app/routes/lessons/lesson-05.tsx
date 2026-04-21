import { Badge, Card, CardDescription, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Trust Chain Resolution — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"The step-by-step algorithm that fetches, assembles, and verifies a trust chain in OpenID Federation.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Trust Chain Resolution" },
		{
			property: "og:description",
			content: "Watch the resolution algorithm happen live, step by step.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Core Mechanics" },
	];
}

function HttpArrow({
	from,
	to,
	method,
	path,
}: {
	from: string;
	to: string;
	method: string;
	path: string;
}) {
	return (
		<div className="flex items-center gap-2 rounded border border-border bg-muted/50 px-3 py-1.5 text-xs font-mono">
			<Badge variant="outline" size="sm">
				{method}
			</Badge>
			<span className="text-muted-foreground">
				{from} → {to}
			</span>
			<span className="text-primary truncate">{path}</span>
		</div>
	);
}

function LogEntry({ text, type = "info" }: { text: string; type?: "info" | "success" | "fetch" }) {
	const colors = {
		info: "text-foreground",
		success: "text-emerald-600 dark:text-emerald-400",
		fetch: "text-brand-600 dark:text-brand-400",
	};
	return <p className={`text-sm ${colors[type]}`}>{text}</p>;
}

const resolutionSteps = [
	{
		title: "1. Fetch Leaf's Entity Configuration",
		content: (
			<div className="space-y-2">
				<HttpArrow
					from="You"
					to="login.uni.edu"
					method="GET"
					path="/.well-known/openid-federation"
				/>
				<LogEntry text="Fetching leaf's Entity Configuration..." type="fetch" />
			</div>
		),
	},
	{
		title: "2. Read authority_hints",
		content: (
			<div className="space-y-2">
				<LogEntry text='Entity Config received. authority_hints: ["uni.edu"]' type="success" />
				<LogEntry text="Leaf claims uni.edu as its superior. Follow the hint..." />
			</div>
		),
	},
	{
		title: "3. Fetch Intermediate's Entity Configuration",
		content: (
			<div className="space-y-2">
				<HttpArrow from="You" to="uni.edu" method="GET" path="/.well-known/openid-federation" />
				<LogEntry text="Fetching intermediate's Entity Configuration..." type="fetch" />
			</div>
		),
	},
	{
		title: "4. Intermediate has further hints",
		content: (
			<div className="space-y-2">
				<LogEntry
					text='uni.edu Entity Config received. authority_hints: ["edufed.gov"]'
					type="success"
				/>
				<LogEntry text="Found federation_fetch_endpoint: https://uni.edu/federation/fetch" />
			</div>
		),
	},
	{
		title: "5. Fetch Subordinate Statement (Int → Leaf)",
		content: (
			<div className="space-y-2">
				<HttpArrow
					from="You"
					to="uni.edu"
					method="GET"
					path="/federation/fetch?sub=login.uni.edu"
				/>
				<LogEntry text="Requesting Subordinate Statement for the leaf..." type="fetch" />
			</div>
		),
	},
	{
		title: "6. Subordinate Statement received",
		content: (
			<div className="space-y-2">
				<LogEntry
					text="Subordinate Statement received: uni.edu vouches for login.uni.edu"
					type="success"
				/>
				<LogEntry text="Contains jwks confirming leaf's key, plus metadata_policy." />
			</div>
		),
	},
	{
		title: "7. Fetch Trust Anchor's Entity Configuration",
		content: (
			<div className="space-y-2">
				<HttpArrow from="You" to="edufed.gov" method="GET" path="/.well-known/openid-federation" />
				<LogEntry text="Fetching Trust Anchor's Entity Configuration..." type="fetch" />
			</div>
		),
	},
	{
		title: "8. Trust Anchor found",
		content: (
			<div className="space-y-2">
				<LogEntry
					text="TA Entity Config received. edufed.gov is a pre-trusted Trust Anchor!"
					type="success"
				/>
				<LogEntry text="Found federation_fetch_endpoint: https://edufed.gov/federation/fetch" />
			</div>
		),
	},
	{
		title: "9. Fetch Subordinate Statement (TA → Int)",
		content: (
			<div className="space-y-2">
				<HttpArrow from="You" to="edufed.gov" method="GET" path="/federation/fetch?sub=uni.edu" />
				<LogEntry text="Requesting Subordinate Statement for the intermediate..." type="fetch" />
			</div>
		),
	},
	{
		title: "10. All statements collected",
		content: (
			<div className="space-y-2">
				<LogEntry
					text="Subordinate Statement received: edufed.gov vouches for uni.edu"
					type="success"
				/>
				<LogEntry text="All 4 statements collected. Assembling chain..." />
			</div>
		),
	},
	{
		title: "11. Chain assembled!",
		content: (
			<div className="space-y-2">
				<LogEntry text="Trust Chain complete!" type="success" />
				<div className="rounded-lg border border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/20 p-3 text-xs font-mono space-y-1">
					<div>[0] Leaf Entity Config — login.uni.edu (self-signed)</div>
					<div>[1] Subordinate Stmt — uni.edu → login.uni.edu</div>
					<div>[2] Subordinate Stmt — edufed.gov → uni.edu</div>
					<div>[3] TA Entity Config — edufed.gov (self-signed, pre-trusted)</div>
				</div>
				<LogEntry text="Now verify signatures top-down and apply metadata policies." />
			</div>
		),
	},
];

const approaches = [
	{
		title: "Bottom-Up Resolution",
		badge: "Most Common",
		section: "Section 17.2.1",
		description:
			"Fetch the subject's Entity Configuration, read authority_hints, fetch superiors' Entity Configurations, use their federation_fetch_endpoint for Subordinate Statements, repeat until you reach a pre-trusted Trust Anchor. Then validate the chain and apply metadata policies.",
	},
	{
		title: "Top-Down Discovery",
		badge: "Discovery / Enumeration",
		section: "Section 17.2.2",
		description:
			"Query the Trust Anchor's List endpoint to get subordinate Entity IDs, filter by entity_type, recursively list Intermediates' subordinates. Useful for enumerating all entities in a federation.",
	},
	{
		title: "Resolve Endpoint",
		badge: "Shortcut",
		section: "Section 8.3",
		description:
			"Send the subject Entity ID and trust_anchor to a resolver's federation_resolve_endpoint. Get back pre-resolved metadata and the full trust chain in a single response.",
	},
];

export default function Lesson05() {
	return (
		<LessonPage lesson={getLesson(5)}>
			<h2>Watch the Algorithm</h2>
			<p>
				Trust Chain Resolution is the process of fetching and assembling all the Entity Statements
				needed to build a complete chain from a leaf entity to a Trust Anchor.
				<Ref id="1" /> The most common approach is <strong>bottom-up resolution</strong>, which
				follows <code>authority_hints</code> upward.
			</p>
			<StepThrough steps={resolutionSteps} />

			<h2>Three Ways to Resolve</h2>
			<div className="grid gap-4 sm:grid-cols-3">
				{approaches.map((a) => (
					<Card key={a.title}>
						<CardHeader>
							<div className="flex items-center gap-2">
								<CardTitle className="text-sm">{a.title}</CardTitle>
								<Badge variant="secondary" size="sm">
									{a.badge}
								</Badge>
							</div>
							<CardDescription>{a.section}</CardDescription>
						</CardHeader>
						<CardPanel className="pt-0 text-sm text-muted-foreground">{a.description}</CardPanel>
					</Card>
				))}
			</div>

			<AnalogyBox>
				It's like calling to verify someone's employment. You call the university to confirm the
				professor works there — they say their accreditation comes from the National Education
				Board. You call the Board, who confirms. Bottom-up: start with the person, climb up until
				you reach an authority you already trust.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 10 — Resolving the Trust Chain and Metadata",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-10",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 17.2.1 — Bottom-Up Trust Chain Resolution",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-17.2.1",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 8.3 — Resolve Entity",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-8.3",
					},
				]}
			/>
		</LessonPage>
	);
}
