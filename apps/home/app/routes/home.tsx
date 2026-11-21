import { ArrowRight, ArrowUpRight } from "lucide-react";
import { Link } from "react-router";
import { CopyButton } from "../components/copy-button";
import { HighlightedCode } from "../components/highlighted-code";
import { Quickstart, quickstartExamples } from "../components/quickstart";
import { SiteHero } from "../components/site-hero";
import { highlightCode } from "../lib/highlight.server";
import { DOCS, EXPLORER, FEDERATIONS, LEARN, REPOSITORY } from "../lib/links";
import {
	buildMeta,
	HOME_DESCRIPTION,
	organizationJsonLd,
	softwareSourceCodeJsonLd,
	websiteJsonLd,
} from "../lib/seo";
import type { Route } from "./+types/home";

export function meta() {
	return buildMeta({
		title: "OpenID Federation SDK for OIDC, OAuth & Wallets | OidFed",
		description: HOME_DESCRIPTION,
		path: "/",
		jsonLd: [organizationJsonLd, websiteJsonLd, softwareSourceCodeJsonLd],
	});
}

const resolveCommand = "oidfed --json resolve https://op.example --trust-anchor https://ta.example";
const resolveExample = `{
  "chains_found": 1,
  "errors": 0,
  "chains": [{
    "entity_id": "https://op.example",
    "trust_anchor_id": "https://ta.example",
    "statements": 3,
    "expires_at": "2030-01-01T12:00:00.000Z"
  }]
}`;

export function loader() {
	return {
		quickstart: Object.fromEntries(
			quickstartExamples.map(({ id, code, filename }) => [
				id,
				highlightCode(code, "typescript", filename),
			]),
		),
		command: highlightCode(resolveCommand, "bash", "Example CLI command"),
		output: highlightCode(resolveExample, "json", "Example CLI output"),
	};
}

const packages = [
	{
		name: "core",
		description:
			"Discover and validate trust chains, apply metadata policy, and verify Trust Marks.",
	},
	{
		name: "crypto",
		description: "Connect Web Crypto, a native keystore, or a remote signing service.",
	},
	{
		name: "authority",
		description: "Run a Trust Anchor or Intermediate, manage subordinates, and issue statements.",
	},
	{
		name: "leaf",
		description:
			"Publish an Entity Configuration and attach protocol roles to a federation participant.",
	},
	{
		name: "oidc",
		description:
			"Connect OpenID Providers and Relying Parties, OAuth clients, authorization servers, and protected resources.",
	},
	{
		name: "wallet",
		description:
			"Add trust discovery and attestation checks for Wallet Providers, Credential Issuers, and Credential Verifiers.",
	},
];

export default function Home({ loaderData }: Route.ComponentProps) {
	return (
		<>
			<SiteHero
				title={
					<>
						Build OpenID Federations{" "}
						<span className="block text-site-accent">
							for <span className="whitespace-nowrap">OIDC, OAuth</span> &amp; wallets
						</span>
					</>
				}
				description="Create Trust Anchors, Intermediates, and Leaves with one TypeScript API. Add OpenID Connect, OAuth, or digital wallet roles and bring your own keys and protocol engines."
				variant="home"
			>
				<div className="mt-8 flex flex-wrap items-center justify-center gap-3">
					<a href="#quickstart" className="site-button">
						Build with OidFed <ArrowRight aria-hidden className="size-4" />
					</a>
					<a href={DOCS} className="site-button site-button-outline">
						Read the docs
					</a>
				</div>
			</SiteHero>

			<div className="mx-auto max-w-6xl px-5 pb-20 sm:px-8 sm:pb-24">
				<Quickstart highlighted={loaderData.quickstart} />

				<section
					id="packages"
					aria-labelledby="packages-heading"
					className="mt-18 scroll-mt-20 sm:mt-24"
				>
					<div className="max-w-2xl">
						<h2 id="packages-heading" className="site-section-title">
							The OidFed packages
						</h2>
						<p className="mt-3 leading-relaxed text-muted-foreground">
							Construct a host with create(), add the roles it serves, and mount its HTTP handler.
							Use Core on its own for trust-chain discovery, metadata policy, and Trust Mark checks.
						</p>
					</div>
					<ul className="mt-7 grid overflow-hidden rounded-2xl border border-border bg-border [gap:1px] sm:grid-cols-2 lg:grid-cols-3">
						{packages.map(({ name, description }) => (
							<li key={name} className="bg-card">
								<a
									href={`${DOCS}/api/${name}`}
									className="group block h-full p-5 hover:bg-site-code sm:p-6"
								>
									<span className="flex items-center justify-between gap-3 font-mono text-base font-semibold text-site-accent">
										@oidfed/{name}
										<ArrowUpRight
											aria-hidden
											className="size-4 shrink-0 text-muted-foreground group-hover:text-site-accent"
										/>
									</span>
									<p className="mt-2 text-sm leading-relaxed text-muted-foreground">
										{description}
									</p>
								</a>
							</li>
						))}
					</ul>
					<div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-sm">
						<a href={`${DOCS}/features/11.5.http-wiring`} className="site-link">
							Wiring guide
						</a>
						<a href={`${DOCS}/api/core/storage`} className="site-link">
							Storage contracts
						</a>
						<a href={`${DOCS}/api/react-native`} className="site-link">
							React Native compatibility
						</a>
					</div>
				</section>

				<section
					aria-labelledby="learn-heading"
					className="mt-18 grid gap-x-16 gap-y-7 border-t border-border pt-10 sm:mt-24 sm:pt-12 lg:grid-cols-[1fr_1.25fr]"
				>
					<div>
						<h2 id="learn-heading" className="site-section-title">
							How federation establishes trust
						</h2>
						<p className="mt-4 max-w-[42ch] leading-relaxed text-muted-foreground">
							Organizations publish signed statements about themselves and their subordinates. A
							participant can follow those statements to a Trust Anchor it already trusts, then
							apply the federation’s policies.
						</p>
					</div>
					<ul className="divide-y divide-border border-y border-border">
						<li className="py-4">
							<a href={LEARN} className="site-link font-semibold">
								Learn OpenID Federation
							</a>
							<p className="mt-1 text-sm text-muted-foreground">
								Fifteen interactive lessons, from the first trust chain to federation design.
							</p>
						</li>
						<li className="py-4">
							<a href={EXPLORER} className="site-link font-semibold">
								Open the Explorer
							</a>
							<p className="mt-1 text-sm text-muted-foreground">
								Inspect signed statements and trace trust chains from live entities.
							</p>
						</li>
						<li className="py-4">
							<a href={FEDERATIONS} className="site-link font-semibold">
								Browse demo federations
							</a>
							<p className="mt-1 text-sm text-muted-foreground">
								See hierarchies, multiple Trust Anchors, and metadata policies in action.
							</p>
						</li>
						<li className="py-4">
							<Link to="/ecosystem" className="site-link font-semibold">
								See where federation is used
							</Link>
							<p className="mt-1 text-sm text-muted-foreground">
								Review deployments, pilots, and interoperability reports.
							</p>
						</li>
						<li className="py-4">
							<Link to="/trust-journal" className="site-link font-semibold">
								Read the Trust Journal
							</Link>
							<p className="mt-1 text-sm text-muted-foreground">
								Follow standards updates and find practical guides from federation operators.
							</p>
						</li>
					</ul>
				</section>

				<section
					aria-labelledby="cli-heading"
					className="mt-18 grid overflow-hidden rounded-2xl border border-border bg-card sm:mt-24 lg:grid-cols-[1fr_1fr]"
				>
					<div className="px-6 py-8 sm:p-9">
						<h2 id="cli-heading" className="site-section-title">
							Inspect a federation from your terminal
						</h2>
						<p className="mt-4 max-w-[48ch] leading-relaxed text-muted-foreground">
							Use the OidFed CLI to resolve trust chains, verify signatures, and query federation
							endpoints. It ships with 17 commands.
						</p>
						<div className="mt-5 flex flex-wrap items-center gap-2.5">
							<code className="rounded-md border border-border bg-background px-3 py-2 text-xs sm:text-sm">
								npm install -g @oidfed/cli
							</code>
							<CopyButton text="npm install -g @oidfed/cli" label="CLI install command" />
						</div>
						<a
							className="site-link mt-5 inline-block text-sm"
							href={`${REPOSITORY}/blob/main/tools/cli/docs/readme.md`}
						>
							CLI reference
						</a>
					</div>
					<div className="min-w-0 border-t border-border bg-site-code p-5 sm:p-7 lg:border-t-0 lg:border-l">
						<p className="text-xs font-medium text-muted-foreground">Example command</p>
						<HighlightedCode
							html={loaderData.command}
							className="mt-2 text-xs leading-relaxed sm:text-[13px]"
						/>
						<p className="mt-5 text-xs font-medium text-muted-foreground">Example output</p>
						<HighlightedCode
							html={loaderData.output}
							className="mt-2 text-xs leading-relaxed sm:text-[13px]"
						/>
					</div>
				</section>
			</div>
		</>
	);
}
