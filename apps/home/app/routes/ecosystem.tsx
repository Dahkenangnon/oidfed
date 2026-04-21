import { Badge, buttonVariants, Card, CardHeader, CardTitle } from "@oidfed/ui";
import { ArrowRight, ExternalLink, FileText, Globe, Landmark, School } from "lucide-react";
import { HeroBackground, SectionDivider } from "../components/illustrations";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Ecosystem — @oidfed" },
		{
			name: "description",
			content: "Real-world OpenID Federation adoption, implementations, and spec status.",
		},
		{ property: "og:title", content: "Ecosystem — @oidfed" },
		{
			property: "og:description",
			content: "Real-world OpenID Federation adoption, implementations, and spec status.",
		},
		{ property: "og:type", content: "website" },
	];
}

const adoptions = [
	{
		name: "EU Digital Identity Wallet (eIDAS 2.0)",
		icon: Landmark,
		description:
			"The Architecture Reference Framework mandates OpenID Federation for trust establishment between wallet providers, credential issuers, and relying parties across EU member states.",
		href: "https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET",
		region: "Europe",
	},
	{
		name: "Italy SPID/CIE",
		icon: Landmark,
		description:
			"Italy's national digital identity system uses OpenID Federation at scale — connecting millions of citizens to public and private services through federated OIDC.",
		href: "https://www.agid.gov.it/en/platforms/spid",
		region: "Italy",
	},
	{
		name: "GÉANT/eduGAIN",
		icon: School,
		description:
			"The academic identity federation for research and education networks is adopting OpenID Federation to complement existing SAML infrastructure.",
		href: "https://wiki.geant.org/display/gn42jra3/T3.1A+OpenID+Connect+Federation",
		region: "Global",
	},
	{
		name: "Sweden SUNET (Satosa)",
		icon: Globe,
		description:
			"SUNET integrates OpenID Federation into the Satosa proxy for Swedish academic identity infrastructure, bridging SAML and OIDC ecosystems.",
		href: "https://openid.net/the-openid-federation-interoperability-event/",
		region: "Sweden",
	},
];

export default function Ecosystem() {
	return (
		<div>
			{/* Hero */}
			<section className="relative overflow-hidden border-b border-border py-16 sm:py-20">
				<HeroBackground />
				<div className="relative mx-auto max-w-5xl px-6">
					<Badge variant="secondary" className="mb-4">
						Ecosystem
					</Badge>
					<h1 className="font-heading text-3xl font-bold tracking-tight sm:text-4xl">
						<span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent dark:from-brand-300 dark:to-brand-500">
							OpenID Federation
						</span>{" "}
						in the wild
					</h1>
					<p className="mt-3 max-w-2xl text-lg text-muted-foreground">
						Governments, academic networks, and identity platforms are adopting OpenID Federation
						worldwide — from national identity systems to cross-border academic research.
					</p>
				</div>
			</section>

			<SectionDivider />

			{/* Real-World Adoption */}
			<section className="py-16">
				<div className="mx-auto max-w-5xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight">Production Deployments</h2>
					<p className="mt-2 text-muted-foreground">
						Organizations running OpenID Federation in production today.
					</p>
					<div className="mt-8 grid gap-4 sm:grid-cols-2">
						{adoptions.map((item) => (
							<a
								key={item.name}
								href={item.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group block"
							>
								<Card className="h-full transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
									<CardHeader>
										<item.icon className="size-5 text-primary" />
										<CardTitle className="text-base">{item.name}</CardTitle>
										<Badge variant="outline" className="ml-auto text-xs">
											{item.region}
										</Badge>
									</CardHeader>
									<div className="px-6 pb-6">
										<p className="text-sm text-muted-foreground">{item.description}</p>
										<span className="mt-3 inline-flex items-center gap-1 text-xs text-primary opacity-0 transition-opacity group-hover:opacity-100">
											Visit <ExternalLink className="size-3" />
										</span>
									</div>
								</Card>
							</a>
						))}
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* Implementation */}
			<section className="bg-muted/30 py-16">
				<div className="mx-auto max-w-5xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight">Implementation</h2>
					<p className="mt-2 text-muted-foreground">
						This project provides the complete OpenID Federation 1.0 implementation for JavaScript.
					</p>
					<div className="mt-8">
						<a
							href="https://github.com/Dahkenangnon/oidfed"
							target="_blank"
							rel="noopener noreferrer"
							className="group block"
						>
							<Card className="transition-all group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-md">
								<div className="flex items-start justify-between p-6">
									<div>
										<div className="flex items-center gap-3">
											<span className="font-mono text-base font-semibold">@oidfed/*</span>
											<Badge variant="secondary">TypeScript</Badge>
											<Badge variant="outline">Runtime-agnostic</Badge>
										</div>
										<p className="mt-2 text-sm text-muted-foreground">
											The complete OpenID Federation 1.0 implementation for JavaScript —
											runtime-agnostic, spec-compliant, built on Web API standards.
										</p>
										<p className="mt-2 text-xs text-muted-foreground">by Justin Dah-kenangnon</p>
									</div>
									<ExternalLink className="size-4 shrink-0 text-muted-foreground transition-colors group-hover:text-primary" />
								</div>
							</Card>
						</a>
					</div>
					<div className="mt-6 flex flex-wrap items-center gap-3">
						<a
							href="https://openid.net/developers/openid-federation-implementations/"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline", size: "sm" })}
						>
							All implementations on openid.net <ArrowRight className="ml-1 size-3" />
						</a>
					</div>
				</div>
			</section>

			<SectionDivider />

			{/* Spec Status */}
			<section className="py-16">
				<div className="mx-auto max-w-5xl px-6">
					<div className="flex items-start gap-4">
						<div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
							<FileText className="size-5 text-primary" />
						</div>
						<div>
							<h2 className="font-heading text-2xl font-bold tracking-tight">
								Specification Status
							</h2>
							<p className="mt-3 text-muted-foreground">
								<strong className="text-foreground">OpenID Federation 1.0</strong> reached final
								specification status. The working group is preparing a 1.1 split that separates the
								core federation protocol from entity-type-specific profiles.
							</p>
							<p className="mt-3 text-sm text-muted-foreground">
								For a deep dive into the specification, its structure, and where it's heading, see
								the{" "}
								<a
									href="https://learn.oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									className="text-primary underline underline-offset-4 hover:no-underline"
								>
									Learn app
								</a>
								.
							</p>
						</div>
					</div>
				</div>
			</section>
		</div>
	);
}
