import { Badge } from "@oidfed/ui";
import { ArrowRight, Globe, Package, Terminal } from "lucide-react";
import { RowHeader, SectionIntro, SectionTitle } from "../components/section-ui";
import { SiteHero } from "../components/site-hero";
import { DOCS, REPOSITORY } from "../lib/links";
import { buildMeta, DOMAIN } from "../lib/seo";

export function meta() {
	return buildMeta({
		title: "About — @oidfed",
		description:
			"About @oidfed: 6 libraries, 3 apps, and 17 CLI commands for OpenID Federation. Apache 2.0 for libraries and CLI; MIT for apps.",
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

const architecture = [
	{
		Icon: Package,
		title: "Libraries",
		kind: "packages",
		description:
			"Federation primitives, authority and leaf hosts, OIDC registration, and wallet trust operations. The libraries use standard Web APIs.",
		items: [
			{ name: "@oidfed/crypto", note: "engines · signers · keyrings" },
			{ name: "@oidfed/core", note: "primitives · chain · policy" },
			{ name: "@oidfed/authority", note: "TA · intermediate" },
			{ name: "@oidfed/leaf", note: "RP · OP (leaf)" },
			{ name: "@oidfed/oidc", note: "auto · explicit registration" },
			{ name: "@oidfed/wallet", note: "provider · issuer · verifier roles" },
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
		description: "Inspect, validate, and debug federation deployments with 17 commands.",
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
			<Architecture />
		</article>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §01 · Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
	return (
		<SiteHero
			title="About OidFed"
			description="OidFed is an open-source JavaScript and TypeScript project for building federations and understanding how trust flows between their participants."
		>
			<div className="mt-7 flex flex-wrap justify-center gap-3">
				<a href={`${DOCS}/api`} className="site-button">
					Browse the API
				</a>
				<a href={REPOSITORY} className="site-button site-button-outline">
					View on GitHub
				</a>
			</div>
		</SiteHero>
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
						<SectionTitle>Libraries, apps, and tools</SectionTitle>
						<SectionIntro>
							Libraries are versioned and published independently and share core contracts.
							Applications connect them to their protocol implementations.
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
