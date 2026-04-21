import { Badge, buttonVariants, Card, CardHeader, CardTitle } from "@oidfed/ui";
import {
	ArrowRight,
	ExternalLink,
	Globe,
	Lock,
	Network,
	Package,
	Shield,
	Terminal,
} from "lucide-react";
import { FederationGraph, HeroBackground, SectionDivider } from "../components/illustrations";
import type { Route } from "./+types/home";

export const handle = { lastUpdated: "2026-04-20" };

export function meta(_args: Route.MetaArgs) {
	return [
		{ title: "OpenID Federation — @oidfed" },
		{
			name: "description",
			content:
				"The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic, spec-compliant, built on Web API standards.",
		},
		{ property: "og:title", content: "OpenID Federation — @oidfed" },
		{
			property: "og:description",
			content:
				"The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic, spec-compliant, built on Web API standards.",
		},
		{ property: "og:type", content: "website" },
	];
}

const specPackages = [
	{
		name: "@oidfed/core",
		description:
			"Federation primitives — entity statements, trust chain resolution, metadata policy, and cryptographic verification.",
		href: "https://www.npmjs.com/package/@oidfed/core",
	},
	{
		name: "@oidfed/authority",
		description:
			"Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, and policy enforcement.",
		href: "https://www.npmjs.com/package/@oidfed/authority",
	},
	{
		name: "@oidfed/leaf",
		description:
			"Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation.",
		href: "https://www.npmjs.com/package/@oidfed/leaf",
	},
	{
		name: "@oidfed/oidc",
		description:
			"OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation.",
		href: "https://www.npmjs.com/package/@oidfed/oidc",
	},
];

const apps = [
	{
		name: "@oidfed/home",
		description: "Project homepage (this site).",
		href: "https://oidfed.com",
	},
	{
		name: "@oidfed/learn",
		description:
			"An interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design.",
		href: "https://learn.oidfed.com",
	},
	{
		name: "@oidfed/explorer",
		description:
			"A visual tool for exploring live OpenID Federation deployments — inspect entity configurations, trace trust chains, and validate topology.",
		href: "https://explore.oidfed.com",
	},
];

const adopters = [
	{
		name: "EU Digital Identity Wallet",
		detail: "eIDAS 2.0 Architecture Reference Framework mandates OpenID Federation",
		href: "https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET",
	},
	{
		name: "Italy SPID/CIE",
		detail: "National-scale deployment with millions of users",
		href: "https://www.agid.gov.it/en/platforms/spid",
	},
	{
		name: "GÉANT/eduGAIN",
		detail: "Academic identity federation for research and education",
		href: "https://wiki.geant.org/display/gn42jra3/T3.1A+OpenID+Connect+Federation",
	},
	{
		name: "Sweden SUNET",
		detail: "Satosa integration for Swedish academic identity",
		href: "https://openid.net/the-openid-federation-interoperability-event/",
	},
];

export default function Home() {
	return (
		<div>
			{/* Hero */}
			<section className="relative overflow-hidden py-20 sm:py-28">
				<HeroBackground />
				<div className="relative mx-auto max-w-5xl px-6 text-center">
					<h1 className="font-heading text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
						<span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent dark:from-brand-300 dark:to-brand-500">
							OpenID Federation 1.0 for JavaScript.
						</span>
					</h1>
					<p className="mx-auto mt-6 max-w-2xl text-lg text-muted-foreground">
						The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic,
						spec-compliant, built on Web API standards.
					</p>
					<div className="mt-10 flex flex-wrap items-center justify-center gap-3">
						<a
							href="https://explore.oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants()}
						>
							Explorer <ArrowRight className="ml-1 size-4" />
						</a>
						<a
							href="https://learn.oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline" })}
						>
							Learn
						</a>
						<a
							href="https://github.com/Dahkenangnon/oidfed"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline" })}
						>
							GitHub
						</a>
						<a
							href="https://www.npmjs.com/org/oidfed"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline" })}
						>
							npm
						</a>
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* Why Federation? */}
			<section className="bg-muted/30 py-16">
				<div className="mx-auto max-w-5xl px-6">
					<div className="flex items-start justify-between gap-8">
						<div className="flex-1">
							<h2 className="font-heading text-2xl font-bold tracking-tight sm:text-3xl">
								Why Federation?
							</h2>
							<p className="mt-3 text-muted-foreground">
								Traditional approaches to establishing trust between systems rely on bilateral
								agreements and manual metadata exchange. OpenID Federation introduces
								cryptographically verifiable trust chains — enabling dynamic, scalable trust without
								per-party configuration.
							</p>
						</div>
						<div className="hidden lg:block">
							<FederationGraph />
						</div>
					</div>
					<div className="mt-8 grid gap-4 sm:grid-cols-3">
						<Card className="group transition-all hover:-translate-y-0.5 hover:shadow-md">
							<CardHeader>
								<Network className="size-5 text-primary" />
								<CardTitle className="text-base">No More Bilateral Agreements</CardTitle>
							</CardHeader>
							<p className="px-6 pb-6 text-sm text-muted-foreground">
								Entities join a federation once. Trust is derived from the chain, not from
								individual contracts between every pair of participants.
							</p>
						</Card>
						<Card className="group transition-all hover:-translate-y-0.5 hover:shadow-md">
							<CardHeader>
								<Shield className="size-5 text-primary" />
								<CardTitle className="text-base">Verifiable Trust at Scale</CardTitle>
							</CardHeader>
							<p className="px-6 pb-6 text-sm text-muted-foreground">
								Every claim is signed. Trust Anchors publish constraints and metadata policies that
								are cryptographically enforced down the chain.
							</p>
						</Card>
						<Card className="group transition-all hover:-translate-y-0.5 hover:shadow-md">
							<CardHeader>
								<Globe className="size-5 text-primary" />
								<CardTitle className="text-base">Protocol-Independent</CardTitle>
							</CardHeader>
							<p className="px-6 pb-6 text-sm text-muted-foreground">
								Works with OpenID Connect, OAuth 2.0, and beyond. The federation layer is orthogonal
								to the protocol used for authentication or authorization.
							</p>
						</Card>
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* What's Inside */}
			<section className="py-16">
				<div className="mx-auto max-w-5xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight sm:text-3xl">
						What's Inside
					</h2>
					<p className="mt-3 text-muted-foreground">
						Modular by design. Use only what you need — from core primitives to full OIDC
						registration flows, interactive learning, and visual exploration tools.
					</p>

					{/* Spec Packages */}
					<h3 className="mt-10 text-lg font-semibold">Packages (spec implementation)</h3>
					<div className="mt-4 grid gap-4 sm:grid-cols-2">
						{specPackages.map((pkg) => (
							<a
								key={pkg.name}
								href={pkg.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group block"
							>
								<Card className="h-full transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
									<CardHeader>
										<Package className="size-4 text-primary" />
										<CardTitle className="font-mono text-sm">{pkg.name}</CardTitle>
									</CardHeader>
									<p className="px-6 pb-6 text-sm text-muted-foreground">{pkg.description}</p>
								</Card>
							</a>
						))}
					</div>

					{/* Apps */}
					<h3 className="mt-10 text-lg font-semibold">Apps</h3>
					<div className="mt-4 grid gap-4 sm:grid-cols-3">
						{apps.map((app) => (
							<a
								key={app.name}
								href={app.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group block"
							>
								<Card className="h-full transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
									<CardHeader>
										<Globe className="size-4 text-primary" />
										<CardTitle className="font-mono text-sm">{app.name}</CardTitle>
									</CardHeader>
									<p className="px-6 pb-6 text-sm text-muted-foreground">{app.description}</p>
								</Card>
							</a>
						))}
					</div>

					{/* Tools */}
					<h3 className="mt-10 text-lg font-semibold">Tools</h3>
					<div className="mt-4">
						<a
							href="https://www.npmjs.com/package/@oidfed/cli"
							target="_blank"
							rel="noopener noreferrer"
							className="group block sm:max-w-md"
						>
							<Card className="transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
								<CardHeader>
									<Terminal className="size-4 text-primary" />
									<CardTitle className="font-mono text-sm">@oidfed/cli</CardTitle>
								</CardHeader>
								<p className="px-6 pb-6 text-sm text-muted-foreground">
									Command-line interface for inspecting, validating, and debugging OpenID Federation
									deployments — resolve trust chains, decode entity statements, verify signatures.
								</p>
							</Card>
						</a>
					</div>

					<div className="mt-6 flex items-center gap-4">
						<Badge variant="secondary">TypeScript</Badge>
						<Badge variant="secondary">Runtime-agnostic</Badge>
						<Badge variant="secondary">Web API standards</Badge>
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* OpenID Federation Adoption */}
			<section className="bg-muted/30 py-16">
				<div className="mx-auto max-w-5xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight sm:text-3xl">
						OpenID Federation Adoption
					</h2>
					<p className="mt-3 text-muted-foreground">
						OpenID Federation is adopted in production by governments and academic networks
						worldwide.
					</p>
					<div className="mt-8 grid gap-4 sm:grid-cols-2">
						{adopters.map((adopter) => (
							<a
								key={adopter.name}
								href={adopter.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group block"
							>
								<Card className="transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
									<CardHeader>
										<CardTitle className="text-sm">{adopter.name}</CardTitle>
										<ExternalLink className="size-3 text-muted-foreground" />
									</CardHeader>
									<p className="px-6 pb-6 text-sm text-muted-foreground">{adopter.detail}</p>
								</Card>
							</a>
						))}
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* AI & Machine Identity */}
			<section className="py-16 pb-24">
				<div className="mx-auto max-w-5xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight sm:text-3xl">
						AI & Machine Identity
					</h2>
					<p className="mt-3 text-muted-foreground">
						As AI agents interact on behalf of users and organizations, verifiable trust becomes
						critical. OpenID Federation provides the infrastructure for agent-to-agent trust —
						machines can verify each other's identity and capabilities through the same
						cryptographic trust chains.
					</p>
					<div className="mt-4">
						<a
							href="https://learn.oidfed.com/lessons/real-use-cases"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline", size: "sm" })}
						>
							<Lock className="mr-1 size-3" />
							Learn more: Real Use Cases of OpenID Federation 
						</a>
					</div>
				</div>
			</section>
		</div>
	);
}
