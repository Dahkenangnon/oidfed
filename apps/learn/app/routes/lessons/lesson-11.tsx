import { Alert, AlertDescription, AlertTitle, Card, CardPanel, CardTitle } from "@oidfed/ui";
import { AlertTriangle } from "lucide-react";
import { useState } from "react";
import { AnalogyBox } from "~/components/analogy-box";
import { LessonPage } from "~/components/lesson-page";
import { SpecRef } from "~/components/spec-ref";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-25" };

export function meta() {
	return lessonMetaForSlug("topology-design");
}

const topologies = [
	{
		name: "Single Anchor",
		pros: ["Simple to manage", "Short trust chains"],
		cons: ["Single point of failure", "Doesn't scale beyond small federations"],
		svg: (
			<svg viewBox="0 0 200 150" className="w-full max-w-[200px] mx-auto" role="img">
				<title>Single Anchor topology</title>
				<line x1="100" y1="30" x2="40" y2="110" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="30" x2="100" y2="110" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="30" x2="160" y2="110" stroke="var(--color-border)" strokeWidth="2" />
				<circle
					cx="100"
					cy="30"
					r="16"
					className="fill-brand-100 dark:fill-brand-900/40 stroke-brand-500"
					strokeWidth="2"
				/>
				<text
					x="100"
					y="34"
					textAnchor="middle"
					className="fill-foreground text-[8px] font-semibold"
				>
					TA
				</text>
				{[40, 100, 160].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy={110}
							r="12"
							className="fill-emerald-100 dark:fill-emerald-900/40 stroke-emerald-500"
							strokeWidth="2"
						/>
						<text x={x} y={114} textAnchor="middle" className="fill-foreground text-[7px]">
							Leaf
						</text>
					</g>
				))}
			</svg>
		),
	},
	{
		name: "Hierarchical (Tiered)",
		pros: ["Natural organizational mapping", "Delegated administration"],
		cons: ["Longer chains add latency", "IA failure breaks a branch"],
		svg: (
			<svg viewBox="0 0 200 150" className="w-full max-w-[200px] mx-auto" role="img">
				<title>Hierarchical topology</title>
				<line x1="100" y1="20" x2="50" y2="65" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="20" x2="150" y2="65" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="50" y1="65" x2="25" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="50" y1="65" x2="75" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="150" y1="65" x2="125" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="150" y1="65" x2="175" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<circle
					cx="100"
					cy="20"
					r="14"
					className="fill-brand-100 dark:fill-brand-900/40 stroke-brand-500"
					strokeWidth="2"
				/>
				<text
					x="100"
					y="24"
					textAnchor="middle"
					className="fill-foreground text-[7px] font-semibold"
				>
					TA
				</text>
				{[50, 150].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="65"
							r="12"
							className="fill-purple-100 dark:fill-purple-900/40 stroke-purple-500"
							strokeWidth="2"
						/>
						<text x={x} y="69" textAnchor="middle" className="fill-foreground text-[7px]">
							IA
						</text>
					</g>
				))}
				{[25, 75, 125, 175].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="120"
							r="10"
							className="fill-emerald-100 dark:fill-emerald-900/40 stroke-emerald-500"
							strokeWidth="2"
						/>
						<text x={x} y="124" textAnchor="middle" className="fill-foreground text-[6px]">
							L
						</text>
					</g>
				))}
			</svg>
		),
	},
	{
		name: "Multi-Anchor",
		pros: ["No single point of failure", "Cross-domain trust"],
		cons: ["Policy conflicts possible", "RP must decide which anchors to trust"],
		svg: (
			<svg viewBox="0 0 200 150" className="w-full max-w-[200px] mx-auto" role="img">
				<title>Multi-Anchor topology</title>
				<line x1="60" y1="25" x2="100" y2="70" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="140" y1="25" x2="100" y2="70" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="70" x2="50" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="70" x2="100" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="100" y1="70" x2="150" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				{[60, 140].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="25"
							r="14"
							className="fill-brand-100 dark:fill-brand-900/40 stroke-brand-500"
							strokeWidth="2"
						/>
						<text
							x={x}
							y="29"
							textAnchor="middle"
							className="fill-foreground text-[7px] font-semibold"
						>
							TA
						</text>
					</g>
				))}
				<circle
					cx="100"
					cy="70"
					r="12"
					className="fill-purple-100 dark:fill-purple-900/40 stroke-purple-500"
					strokeWidth="2"
				/>
				<text x="100" y="74" textAnchor="middle" className="fill-foreground text-[7px]">
					IA
				</text>
				{[50, 100, 150].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="120"
							r="10"
							className="fill-emerald-100 dark:fill-emerald-900/40 stroke-emerald-500"
							strokeWidth="2"
						/>
						<text x={x} y="124" textAnchor="middle" className="fill-foreground text-[6px]">
							L
						</text>
					</g>
				))}
			</svg>
		),
	},
	{
		name: "Mesh / Bridge",
		pros: ["Cross-federation interop", "Each federation retains autonomy"],
		cons: ["Long chains crossing bridge", "Bridge becomes critical"],
		svg: (
			<svg viewBox="0 0 200 150" className="w-full max-w-[200px] mx-auto" role="img">
				<title>Mesh / Bridge topology</title>
				<line x1="50" y1="25" x2="50" y2="70" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="150" y1="25" x2="150" y2="70" stroke="var(--color-border)" strokeWidth="2" />
				<line
					x1="50"
					y1="25"
					x2="100"
					y2="45"
					stroke="var(--color-amber-500)"
					strokeWidth="2"
					strokeDasharray="4"
				/>
				<line
					x1="150"
					y1="25"
					x2="100"
					y2="45"
					stroke="var(--color-amber-500)"
					strokeWidth="2"
					strokeDasharray="4"
				/>
				<line x1="50" y1="70" x2="25" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="50" y1="70" x2="75" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="150" y1="70" x2="125" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				<line x1="150" y1="70" x2="175" y2="120" stroke="var(--color-border)" strokeWidth="2" />
				{[50, 150].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="25"
							r="14"
							className="fill-brand-100 dark:fill-brand-900/40 stroke-brand-500"
							strokeWidth="2"
						/>
						<text
							x={x}
							y="29"
							textAnchor="middle"
							className="fill-foreground text-[7px] font-semibold"
						>
							TA
						</text>
					</g>
				))}
				<circle
					cx="100"
					cy="45"
					r="10"
					className="fill-amber-100 dark:fill-amber-900/40 stroke-amber-500"
					strokeWidth="2"
				/>
				<text x="100" y="49" textAnchor="middle" className="fill-foreground text-[6px]">
					Bridge
				</text>
				{[50, 150].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="70"
							r="10"
							className="fill-purple-100 dark:fill-purple-900/40 stroke-purple-500"
							strokeWidth="2"
						/>
						<text x={x} y="74" textAnchor="middle" className="fill-foreground text-[6px]">
							IA
						</text>
					</g>
				))}
				{[25, 75, 125, 175].map((x) => (
					<g key={x}>
						<circle
							cx={x}
							cy="120"
							r="8"
							className="fill-emerald-100 dark:fill-emerald-900/40 stroke-emerald-500"
							strokeWidth="2"
						/>
						<text x={x} y="123" textAnchor="middle" className="fill-foreground text-[5px]">
							L
						</text>
					</g>
				))}
			</svg>
		),
	},
];

const antiPatterns = [
	{ name: "Single Point of Failure", fix: "Use multi-anchor or standby anchor." },
	{
		name: "Overly Deep Chains (5+ levels)",
		fix: "Keep 2-3 levels. Use max_path_length constraints.",
	},
	{
		name: "Unrestricted Intermediates",
		fix: "Always set naming_constraints on subordinate statements.",
	},
	{
		name: "Policy Conflicts Between Paths",
		fix: "Use subset_of/one_of instead of hard value operators.",
	},
	{
		name: "Ignoring Key Rotation",
		fix: "Plan rotation schedules. Use the Historical Keys endpoint.",
	},
];

export default function Lesson11() {
	const [selected, setSelected] = useState(0);

	return (
		<LessonPage
			lesson={getLesson(11)}
			minutes={14}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "4", title: "Trust Chain" },
					{ sec: "6", title: "Federation Policy" },
					{ sec: "6.2", title: "Constraints" },
					{ sec: "6.2.1", title: "Max Path Length" },
					{ sec: "6.2.2", title: "Naming Constraints" },
					{ sec: "10", title: "Resolving the Trust Chain and Metadata" },
					{ sec: "17.1", title: "Federation Topologies" },
					{ sec: "17.2", title: "Federation Discovery and Trust Chain Resolution Patterns" },
					{ sec: "17.3", title: "Trust Anchors and Resolvers Go Together" },
				],
				external: [
					{
						title: "Nine countries prove OpenID Federation interoperability",
						source: "OpenID Foundation",
						date: "Feb 2026",
						href: "https://openid.net/nine-countries-prove-openid-federation-interoperability/",
					},
				],
			}}
		>
			<h2>What Is a Federation Topology?</h2>
			<p>
				A federation topology describes the <strong>shape of trust relationships</strong> — how
				Trust Anchors, Intermediates, and Leaf Entities are organized and connected. The right
				topology depends on your scale, governance model, and resilience requirements.
			</p>

			<h2>Explore Topology Patterns</h2>
			<div className="flex flex-wrap gap-2 mb-4">
				{topologies.map((t, i) => (
					<button
						key={t.name}
						type="button"
						onClick={() => setSelected(i)}
						className={`px-3 py-1.5 rounded-md text-sm border transition-colors cursor-pointer ${
							selected === i
								? "bg-primary text-primary-foreground border-primary"
								: "bg-card border-border hover:bg-accent"
						}`}
					>
						{t.name}
					</button>
				))}
			</div>
			{(() => {
				const topo = topologies[selected];
				if (!topo) return null;
				return (
					<Card>
						<CardPanel className="flex flex-col sm:flex-row gap-4">
							<div className="flex-shrink-0">{topo.svg}</div>
							<div className="space-y-3">
								<CardTitle className="text-base">{topo.name}</CardTitle>
								<div>
									<p className="text-xs font-semibold text-emerald-600 mb-1">Pros:</p>
									<ul className="text-sm text-muted-foreground list-disc list-inside">
										{topo.pros.map((p) => (
											<li key={p}>{p}</li>
										))}
									</ul>
								</div>
								<div>
									<p className="text-xs font-semibold text-red-500 mb-1">Cons:</p>
									<ul className="text-sm text-muted-foreground list-disc list-inside">
										{topo.cons.map((c) => (
											<li key={c}>{c}</li>
										))}
									</ul>
								</div>
							</div>
						</CardPanel>
					</Card>
				);
			})()}

			<h2>Step-by-Step Topology Design</h2>
			<StepThrough
				steps={[
					{
						title: "1. Identify the Problem",
						content: (
							<p className="text-sm">
								What trust problem are you solving? Cross-org auth? Multi-sector interop? Scale of
								participants?
							</p>
						),
					},
					{
						title: "2. List All Entities",
						content: (
							<p className="text-sm">
								Enumerate every entity that needs to participate: identity providers, apps, resource
								servers, etc.
							</p>
						),
					},
					{
						title: "3. Assign Roles",
						content: (
							<p className="text-sm">
								Determine which entities are Trust Anchors, Intermediates, and Leaves. Consider
								organizational boundaries.
							</p>
						),
					},
					{
						title: "4. Draw Trust Paths",
						content: (
							<p className="text-sm">
								Map the Subordinate Statement relationships. Each arrow is a signed vouching
								relationship (<SpecRef sec="3" />).
							</p>
						),
					},
					{
						title: "5. Define Policies & Constraints",
						content: (
							<p className="text-sm">
								Set <code>max_path_length</code> (<SpecRef sec="6.2.1" />),{" "}
								<code>naming_constraints</code> (<SpecRef sec="6.2.2" />), and metadata policies at
								each level (<SpecRef sec="6.1" />).
							</p>
						),
					},
					{
						title: "6. Plan Key Management",
						content: (
							<p className="text-sm">
								Define key rotation schedules, backup procedures, and the Historical Keys endpoint
								strategy.
							</p>
						),
					},
					{
						title: "7. Validate & Iterate",
						content: (
							<p className="text-sm">
								Test trust chain resolution from every leaf (<SpecRef sec="10" />). Verify policies
								cascade correctly. Run security review.
							</p>
						),
					},
				]}
			/>

			<h2>Anti-Patterns to Avoid</h2>
			{antiPatterns.map((ap) => (
				<Alert key={ap.name} variant="warning" className="mb-3">
					<AlertTriangle className="size-4" />
					<AlertTitle>{ap.name}</AlertTitle>
					<AlertDescription>
						<strong>Fix:</strong> {ap.fix}
					</AlertDescription>
				</Alert>
			))}

			<AnalogyBox>
				Designing a federation topology is like designing a national postal system. Do you have one
				central sorting office (single anchor) or regional hubs (hierarchical)? Do you connect
				international networks through a bridge? Same trade-offs: speed, resilience, and cost.
			</AnalogyBox>

		</LessonPage>
	);
}
