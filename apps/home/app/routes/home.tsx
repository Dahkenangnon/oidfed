import { ArrowRight, ArrowUpRight } from "lucide-react";
import { Link } from "react-router";
import { Quickstart, quickstartExamples } from "../components/quickstart";
import { SiteHero } from "../components/site-hero";
import { highlightCode } from "../lib/highlight.server";
import { DOCS, EXPLORER, FEDERATIONS, LEARN } from "../lib/links";
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
		title: "OpenID Federation SDK for OIDC, OAuth & Wallets",
		description: HOME_DESCRIPTION,
		path: "/",
		jsonLd: [organizationJsonLd, websiteJsonLd, softwareSourceCodeJsonLd],
	});
}

export function loader() {
	return {
		quickstart: Object.fromEntries(
			quickstartExamples.map(({ id, code, filename }) => [
				id,
				highlightCode(code, "typescript", filename),
			]),
		),
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
						Join or run an OpenID Federation{" "}
						<span className="block text-site-accent">
							in <span className="whitespace-nowrap">TypeScript</span>
						</span>
					</>
				}
				description="Resolve trust chains, apply metadata policy, and verify Trust Marks with one library. Works for OIDC, OAuth, and wallet ecosystems, and uses your own keys and protocol stack."
				variant="home"
			>
				<div className="mt-8 flex flex-wrap items-center justify-center gap-3">
					<a href="#quickstart" className="site-button">
						Build with OidFed <ArrowRight aria-hidden className="size-4" />
					</a>
					<Link to={DOCS} className="site-button site-button-outline">
						Read the docs
					</Link>
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
								<Link
									to={`${DOCS}/api/${name}`}
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
								</Link>
							</li>
						))}
					</ul>
					<div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-sm">
						<Link to={`${DOCS}/features/11.5.http-wiring`} className="site-link">
							Wiring guide
						</Link>
						<Link to={`${DOCS}/api/core/storage`} className="site-link">
							Storage contracts
						</Link>
						<Link to={`${DOCS}/api/react-native`} className="site-link">
							React Native compatibility
						</Link>
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
							<a
								href={LEARN}
								className="site-link inline-flex items-center gap-1.5 font-semibold"
							>
								Learn OpenID Federation
								<ArrowUpRight aria-hidden className="size-3.5" />
							</a>
							<p className="mt-1 text-sm text-muted-foreground">
								Fifteen interactive lessons, from the first trust chain to federation design.
							</p>
						</li>
						<li className="py-4">
							<a
								href={EXPLORER}
								className="site-link inline-flex items-center gap-1.5 font-semibold"
							>
								Open the Explorer
								<ArrowUpRight aria-hidden className="size-3.5" />
							</a>
							<p className="mt-1 text-sm text-muted-foreground">
								Inspect signed statements and trace trust chains from live entities.
							</p>
						</li>
						<li className="py-4">
							<a
								href={FEDERATIONS}
								className="site-link inline-flex items-center gap-1.5 font-semibold"
							>
								Browse demo federations
								<ArrowUpRight aria-hidden className="size-3.5" />
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
			</div>
		</>
	);
}
