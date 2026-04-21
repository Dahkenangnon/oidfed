import {
	Badge,
	Button,
	Card,
	CardDescription,
	CardHeader,
	CardPanel,
	CardTitle,
	Tabs,
	TabsList,
	TabsPanel,
	TabsTab,
} from "@oidfed/ui";
import { CheckCircle, Circle } from "lucide-react";
import { useState } from "react";
import { SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Hands-On Object Lab — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Build physical objects that map to every core federation concept — tangible metaphors you can hold and use to explain federation.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Hands-On Object Lab" },
		{
			property: "og:description",
			content: "10 hands-on exercises mapping physical objects to federation concepts.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Going Deeper" },
	];
}

const objects = [
	{
		id: "id-card",
		title: "The ID Card",
		concept: "Entity Configuration (Section 3.1)",
		materials: "Index card, pen, personal stamp/sticker",
		steps: [
			"Write your entity name on the front (= iss/sub, they're the same)",
			"List your abilities/services (= metadata)",
			"Draw a unique symbol (= jwks — your public key)",
			"On the back: write who vouches for you (= authority_hints)",
			"Stamp it with your personal stamp (= self-signature)",
			"Write today's date and expiry (= iat/exp)",
		],
		mapping:
			"Card = JWT, Name = iss/sub, Abilities = metadata, Symbol = jwks, Stamp = signature, Dates = iat/exp",
		tryThis:
			"Make a second card with a different stamp. Notice how you can tell it's a forgery — the stamp doesn't match the registered one.",
	},
	{
		id: "letter",
		title: "The Letter of Recommendation",
		concept: "Subordinate Statement (Section 3.1.3)",
		materials: "Paper, pen, superior's stamp, red pen",
		steps: [
			"Write 'From:' (= iss) and 'About:' (= sub) — they're DIFFERENT!",
			"List the subordinate's allowed actions (= metadata)",
			"In red, write restrictions (= metadata_policy)",
			"Note max delegation depth (= max_path_length)",
			"Stamp with the SUPERIOR's stamp (not the subordinate's!)",
		],
		mapping:
			"Letter = Subordinate Statement JWT, From/About = iss ≠ sub, Red ink = policy, Superior's stamp = superior's signature",
		tryThis:
			"Compare the ID Card and Letter side by side. Key difference: iss == sub vs iss != sub.",
	},
	{
		id: "chain",
		title: "The Paper Clip Chain",
		concept: "Trust Chain (Section 4)",
		materials: "3-5 paper clips, sticky labels",
		steps: [
			"Label clips: [0] Leaf EC, [1] Sub Stmt by Intermediate, [2] Intermediate EC, [3] Sub Stmt by TA, [4] TA EC",
			"Link them in order — [0] at bottom, TA EC at top",
			"Hang from the top (the anchor point)",
		],
		mapping:
			"Each clip = an Entity Statement, Link order = chain structure, Top clip = Trust Anchor, Hanging = trust flows from anchor down",
		tryThis:
			"Remove the middle clip — the chain breaks! This is what happens when an Intermediate is revoked.",
	},
	{
		id: "stamp",
		title: "The Rubber Stamp",
		concept: "Trust Anchor (Section 1.2)",
		materials: "Rubber stamp, ink pad, reference card",
		steps: [
			"Create your stamp (= private key)",
			"Make a reference card with the stamp impression (= public key pre-configured in trust store)",
			"Use the stamp to sign letters and ID cards",
		],
		mapping:
			"Stamp = private key, Impression = public key, Reference card = pre-configured TA, Carving new stamp = key rotation, Old stamp in museum = Historical Keys",
		tryThis:
			"Key rotation: create a second stamp, show both are valid for a transition period, then retire the old one.",
	},
	{
		id: "notary",
		title: "The Notary with Delegated Stamp",
		concept: "Intermediate Entity (Section 1.2)",
		materials: "Second stamp, paper, TA's letter, red marker",
		steps: [
			"TA writes a letter authorizing the notary, with red jurisdiction notes (= naming_constraints)",
			"Note maximum delegation depth (= max_path_length)",
			"Notary can now stamp within their jurisdiction only",
		],
		mapping:
			"Notary = Intermediate, TA's letter = Subordinate Statement, Red notes = naming_constraints, Jurisdiction = allowed entity patterns",
		tryThis:
			"Have the notary stamp something outside their jurisdiction — verification catches it!",
	},
	{
		id: "template",
		title: "The Template with Cutouts",
		concept: "Metadata Policy (Section 6)",
		materials: "Stiff cardboard, scissors, ruler, red marker, ID card",
		steps: [
			"Cut windows where values ARE allowed (= subset_of, one_of)",
			"Leave cardboard solid where values are BLOCKED",
			"Write required values in red (= value operator)",
			"Overlay the template on an ID card — only visible parts become resolved metadata",
		],
		mapping:
			"Template = metadata_policy, Windows = allowed values, Solid areas = blocked values, Red text = forced values, Overlay result = resolved metadata",
		tryThis:
			"Stack TWO templates (TA + Intermediate) — the result must satisfy both. Policies only get more restrictive!",
	},
	{
		id: "sticker",
		title: "The Certification Sticker",
		concept: "Trust Mark (Section 7)",
		materials: "Round stickers, pen, issuer's stamp",
		steps: [
			"Write certification name (= trust_mark_type)",
			"Write recipient (= sub)",
			"Write expiry date (= exp)",
			"Stamp the back with the issuer's stamp",
			"Stick it on the entity's ID card",
		],
		mapping:
			"Sticker = Trust Mark JWT, Name = trust_mark_type, Stamp = issuer signature, Placement on card = trust_marks array in EC",
		tryThis: "Write an expired date — the mark is invalid. Peel it off — that's revocation.",
	},
	{
		id: "post-office",
		title: "The Post Office",
		concept: "Federation Endpoints (Section 8)",
		materials: "Shoebox, scissors, index cards, tape, markers",
		steps: [
			"Cut 6 windows in the shoebox, label each:",
			"Window 1: Entity Configuration (.well-known)",
			"Window 2: Fetch (Subordinate Statements)",
			"Window 3: List (subordinate IDs)",
			"Window 4: Resolve (pre-built chains)",
			"Window 5: Trust Mark Status",
			"Window 6: Trust Mark Endpoint",
		],
		mapping: "Shoebox = entity server, Windows = endpoints, Items behind windows = response data",
		tryThis:
			"Cover windows with tape for different roles. Leaf: only Window 1 open. TA: all windows open. Intermediate: Windows 1-3.",
	},
	{
		id: "treasure-hunt",
		title: "The Treasure Hunt",
		concept: "Trust Chain Resolution (Section 10)",
		materials: "3-4 envelopes, ID cards, letters, clue cards",
		steps: [
			"Place envelopes at different locations",
			"Each envelope contains: entity's ID card + authority_hints clue card pointing to the next location",
			"At superior locations, also include a Subordinate Statement (letter)",
			"Start at the leaf's location, follow clues upward",
			"Collect all documents, verify stamps at each step",
		],
		mapping:
			"Locations = entities, Envelopes = .well-known endpoint, Clues = authority_hints, Collected documents = assembled trust chain",
		tryThis:
			"Have a friend set up the hunt while you resolve it. Remove an envelope — the hunt fails (entity not found).",
	},
	{
		id: "ruler",
		title: "The Ruler & Name Stencil",
		concept: "Constraints (Section 6.2)",
		materials: "Ruler, cardboard stencil, paper clip chain, name cards",
		steps: [
			"Mark positions on the ruler (= max_path_length)",
			"Cut a stencil window: '*.university.edu' (= naming_constraints.permitted)",
			"Test: 'login.mit.edu' fits through the window, 'bank.example.com' doesn't",
		],
		mapping:
			"Ruler = max_path_length, Stencil = naming_constraints, Window = permitted patterns, Name cards = entity identifiers",
		tryThis:
			"Set max_path_length to 1, try adding intermediate + leaf — chain too long! Demonstrates max_path_length: 0 = direct subordinates only.",
	},
];

export default function Lesson15() {
	const [completed, setCompleted] = useState<Set<string>>(() => {
		if (typeof window === "undefined") return new Set<string>();
		try {
			const stored = localStorage.getItem("lab-progress");
			return stored ? new Set(JSON.parse(stored) as string[]) : new Set<string>();
		} catch {
			return new Set<string>();
		}
	});

	function toggle(id: string) {
		setCompleted((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			try {
				localStorage.setItem("lab-progress", JSON.stringify([...next]));
			} catch {}
			return next;
		});
	}

	return (
		<LessonPage lesson={getLesson(15)}>
			<p>
				Build physical objects that map to every core federation concept. Each object is a tangible
				metaphor you can hold, manipulate, and use to explain federation to anyone.
			</p>

			<div className="flex items-center gap-2 my-4 p-3 rounded-lg bg-muted">
				<Badge variant="default">
					{completed.size} / {objects.length}
				</Badge>
				<span className="text-sm text-muted-foreground">exercises completed</span>
			</div>

			<Tabs defaultValue="id-card">
				<TabsList className="flex-wrap">
					{objects.map((obj) => (
						<TabsTab key={obj.id} value={obj.id} className="text-xs">
							{completed.has(obj.id) ? "✓" : ""} {obj.title}
						</TabsTab>
					))}
				</TabsList>
				{objects.map((obj) => (
					<TabsPanel key={obj.id} value={obj.id} className="mt-4">
						<Card>
							<CardHeader>
								<div className="flex items-center justify-between">
									<div>
										<CardTitle>{obj.title}</CardTitle>
										<CardDescription>{obj.concept}</CardDescription>
									</div>
									<Button
										variant={completed.has(obj.id) ? "default" : "outline"}
										size="sm"
										onClick={() => toggle(obj.id)}
									>
										{completed.has(obj.id) ? (
											<>
												<CheckCircle className="size-4 mr-1" /> Done
											</>
										) : (
											<>
												<Circle className="size-4 mr-1" /> Mark Done
											</>
										)}
									</Button>
								</div>
							</CardHeader>
							<CardPanel className="space-y-4">
								<div>
									<h4 className="text-sm font-semibold mb-1">Materials</h4>
									<p className="text-sm text-muted-foreground">{obj.materials}</p>
								</div>
								<div>
									<h4 className="text-sm font-semibold mb-1">Build Steps</h4>
									<ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
										{obj.steps.map((s) => (
											<li key={s}>{s}</li>
										))}
									</ol>
								</div>
								<div>
									<h4 className="text-sm font-semibold mb-1">Physical → Digital Mapping</h4>
									<p className="text-sm text-muted-foreground">{obj.mapping}</p>
								</div>
								<div className="rounded bg-brand-50 dark:bg-brand-950/20 p-3">
									<h4 className="text-sm font-semibold mb-1">Try This!</h4>
									<p className="text-sm">{obj.tryThis}</p>
								</div>
							</CardPanel>
						</Card>
					</TabsPanel>
				))}
			</Tabs>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 3 — Entity Statement",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-3",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 4 — Trust Chain",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-4",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 6.2 — Constraints",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-6.2",
					},
					{
						id: "4",
						text: "OpenID Federation 1.0, Section 7 — Trust Marks",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-7",
					},
				]}
			/>
		</LessonPage>
	);
}
