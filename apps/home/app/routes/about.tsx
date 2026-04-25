import { Badge } from "@oidfed/ui";
import { ArrowRight, Globe, Package, Terminal } from "lucide-react";
import {
	DotGrid,
	RowHeader,
	SectionIntro,
	SectionTitle,
	SignalLabel,
	StatusDot,
} from "../components/section-ui";
import { buildMeta, DOMAIN } from "../lib/seo";

export const handle = { lastUpdated: "2026-04-25" };

export function meta() {
	return buildMeta({
		title: "About — @oidfed",
		description:
			"About the @oidfed project — 4 spec packages, 3 apps, 14 CLI commands, MIT licensed. The complete OpenID Federation 1.0 implementation for JavaScript.",
		path: "/about",
		jsonLd: {
			"@context": "https://schema.org",
			"@type": "AboutPage",
			"@id": `${DOMAIN}/about#webpage`,
			url: `${DOMAIN}/about`,
			name: "About @oidfed",
			isPartOf: { "@id": `${DOMAIN}/#website` },
			mainEntity: { "@id": `${DOMAIN}/#organization` },
		},
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Data
// ─────────────────────────────────────────────────────────────────────────────

const highlights = [
	{ value: "04", label: "Spec packages", sub: "core · authority · leaf · oidc" },
	{ value: "03", label: "Apps", sub: "home · explorer · learn" },
	{ value: "14", label: "CLI commands", sub: "resolve · chain · verify · …" },
	{ value: "MIT", label: "License", sub: "Commercial-friendly" },
];

const architecture = [
	{
		Icon: Package,
		title: "Spec packages",
		kind: "packages",
		description:
			"Full OpenID Federation 1.0 coverage — from primitives to OIDC registration flows. Tree-shakable, framework-agnostic.",
		items: [
			{ name: "@oidfed/core", note: "primitives · chain · policy" },
			{ name: "@oidfed/authority", note: "TA · intermediate" },
			{ name: "@oidfed/leaf", note: "RP · OP (leaf)" },
			{ name: "@oidfed/oidc", note: "auto · explicit registration" },
		],
	},
	{
		Icon: Globe,
		title: "Apps",
		kind: "apps",
		description:
			"Home page, an interactive 15-lesson course, and a visual federation topology explorer.",
		items: [
			{ name: "@oidfed/home", note: "oidfed.com" },
			{ name: "@oidfed/learn", note: "learn.oidfed.com" },
			{ name: "@oidfed/explorer", note: "explore.oidfed.com" },
		],
	},
	{
		Icon: Terminal,
		title: "Tools",
		kind: "tools",
		description:
			"Inspect, validate, and debug federation deployments from the command line — 14 purpose-built commands.",
		items: [{ name: "@oidfed/cli", note: "npm i -g @oidfed/cli" }],
	},
];

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function About() {
	return (
		<article className="relative">
			<Hero />
			<Stats />
			<Architecture />
		</article>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §01 · Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
	return (
		<section className="relative border-b border-border/60">
			<DotGrid />
			<div
				aria-hidden
				className="pointer-events-none absolute left-1/2 top-0 -z-10 h-[280px] w-[720px] -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl dark:bg-brand-500/15"
			/>

			<div className="relative mx-auto max-w-4xl px-6 py-20 lg:py-24">
				<SignalLabel id="01" label="About the project" />

				<h1 className="mt-6 font-heading text-4xl font-bold leading-[1.05] tracking-[-0.03em] text-balance sm:text-5xl lg:text-[60px]">
					<span className="block text-muted-foreground/80">The complete</span>
					<span className="block bg-gradient-to-r from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
						OpenID Federation 1.0
					</span>
					<span className="block">implementation for JavaScript.</span>
				</h1>

				<p className="mt-7 max-w-2xl text-lg leading-relaxed text-muted-foreground text-balance">
					Runtime-agnostic, spec-compliant, built on Web API standards. Modular by design — use only
					what you need, from core primitives to OIDC registration flows and visual exploration
					tools.
				</p>

				<div className="mt-8 flex flex-wrap gap-x-6 gap-y-2">
					<StatusDot tone="success">MIT licensed</StatusDot>
					<StatusDot tone="brand">v0.1.0 pre-release</StatusDot>
				</div>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §02 · Stats
// ─────────────────────────────────────────────────────────────────────────────

function Stats() {
	return (
		<section className="border-b border-border/60 bg-muted/30">
			<div className="mx-auto max-w-6xl px-6 py-14">
				<SignalLabel id="02" label="By the numbers" />
				<ul className="mt-8 grid grid-cols-2 gap-0 rounded-2xl border border-border/60 bg-card/40 sm:grid-cols-4">
					{highlights.map((s, i) => (
						<li
							key={s.label}
							className={`relative p-6 ${
								i > 0 ? "border-t border-border/60 sm:border-l sm:border-t-0" : ""
							} ${i === 2 ? "border-t sm:border-t-0" : ""}`}
						>
							<div className="font-heading text-[44px] font-semibold tabular-nums leading-none tracking-[-0.03em] text-brand-500 sm:text-[52px]">
								{s.value}
							</div>
							<div className="mt-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
								{s.label}
							</div>
							<div className="mt-1.5 text-[12px] text-muted-foreground/70">{s.sub}</div>
						</li>
					))}
				</ul>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §03 · Architecture
// ─────────────────────────────────────────────────────────────────────────────

function Architecture() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="grid gap-10 lg:grid-cols-[1fr_1.6fr] lg:gap-16">
					{/* Left intro */}
					<div className="lg:sticky lg:top-24 lg:self-start">
						<SignalLabel id="03" label="Architecture" />
						<SectionTitle>A monorepo structured into packages, apps, and tools.</SectionTitle>
						<SectionIntro>
							Each workspace is independently versioned and published. Nothing is coupled across
							siblings — a contract-driven design that keeps every layer swap-ready.
						</SectionIntro>
						<div className="mt-6 inline-flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
							<span className="tabular-nums text-foreground">packages</span>
							<ArrowRight className="size-3" />
							<span className="tabular-nums text-foreground">apps</span>
							<ArrowRight className="size-3" />
							<span className="tabular-nums text-foreground">tools</span>
						</div>
					</div>

					{/* Right list */}
					<div className="space-y-14">
						{architecture.map((section) => {
							const { Icon } = section;
							const count = section.items.length;
							return (
								<div key={section.title}>
									<RowHeader
										icon={<Icon className="size-3.5" />}
										label={section.title}
										right={`${String(count).padStart(2, "0")} entr${count === 1 ? "y" : "ies"}`}
									/>
									<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
										{section.description}
									</p>
									<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
										{section.items.map((item) => (
											<li
												key={item.name}
												className="grid grid-cols-[1fr_auto] items-center gap-4 p-4 text-[13.5px] sm:grid-cols-[minmax(200px,1fr)_2fr_auto] sm:gap-6"
											>
												<span className="font-mono font-semibold tracking-tight text-foreground">
													{item.name}
												</span>
												<span className="hidden font-mono text-[12px] text-muted-foreground/80 sm:inline">
													{item.note}
												</span>
												<Badge variant="secondary" className="ml-auto font-mono text-[10px]">
													{section.kind}
												</Badge>
											</li>
										))}
									</ul>
								</div>
							);
						})}
					</div>
				</div>
			</div>
		</section>
	);
}
