import { Badge, buttonVariants, Card } from "@oidfed/ui";
import {
	ArrowRight,
	ArrowUpRight,
	BookOpen,
	Bot,
	Briefcase,
	CheckCircle2,
	GraduationCap,
	Landmark,
	Library,
} from "lucide-react";
import { RegionPill, RowHeader, SectionIntro, SectionTitle } from "../components/section-ui";
import { Link } from "react-router";
import { SiteHero } from "../components/site-hero";
import { buildMeta, DOMAIN } from "../lib/seo";

export function meta() {
	return buildMeta({
		title: "Ecosystem — OpenID Federation adoption, pilots, and AI-agent identity | @oidfed",
		description:
			"OpenID Federation is being adopted, piloted, or specified across governments, academic networks, and AI-agent identity research — EU Digital Identity Wallet, Italy SPID/CIE, eduGAIN pilot, OpenID Foundation AI-agent whitepaper. Verified, source-linked.",
		path: "/ecosystem",
		jsonLd: {
			"@context": "https://schema.org",
			"@type": "WebPage",
			"@id": `${DOMAIN}/ecosystem#webpage`,
			url: `${DOMAIN}/ecosystem`,
			name: "OpenID Federation Ecosystem",
			description:
				"Documented adoption and interest in OpenID Federation across governments, academic networks, and AI-agent identity research.",
			isPartOf: { "@id": `${DOMAIN}/#website` },
			about: [
				{ "@type": "Thing", name: "OpenID Federation 1.0" },
				{ "@type": "Thing", name: "EU Digital Identity Wallet" },
				{ "@type": "Thing", name: "SPID" },
				{ "@type": "Thing", name: "eduGAIN" },
				{ "@type": "Thing", name: "Agentic AI identity" },
			],
		},
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment and reading links
// ─────────────────────────────────────────────────────────────────────────────

const sectorGroups = [
	{
		key: "government",
		Icon: Landmark,
		title: "Government & national digital identity",
		entries: [
			{
				name: "European Digital Identity Wallet trust architecture",
				status: "Architecture and Reference Framework",
				region: "EU",
				detail:
					"The reference framework describes the EUDI Wallet trust model. DC4EU explored OpenID Federation as part of a proposed trust model.",
				href: "https://eu-digital-identity-wallet.github.io/",
			},
			{
				name: "Italy — SPID / CIE OIDC Federation",
				status: "Published technical rules (Jan 2023)",
				region: "IT",
				detail:
					"AgID published OpenID Connect Federation technical rules for SPID and CIE in January 2023; reference implementation italia/spid-cie-oidc-django.",
				href: "https://www.agid.gov.it/en/agenzia/stampa-e-comunicazione/notizie/2023/01/17/openid-connect-technical-rules-spid-and-cie-are-online",
			},
			{
				name: "Italy national eID (2022)",
				status: "Chosen as trust architecture",
				region: "IT",
				detail:
					"OpenID Federation was chosen in 2022 for Italy's national eID to federate IdPs across thousands of applications (per Connect2id's OpenID Federation overview).",
				href: "https://connect2id.com/learn/openid-federation",
			},
			{
				name: "Sweden Connect technical framework",
				status: "October 2026 technical framework",
				region: "SE",
				detail:
					"Sweden Connect publishes its OpenID Connect profile, federation metadata requirements, and links to the Swedish OpenID Federation deployment profile.",
				href: "https://docs.swedenconnect.se/technical-framework/index.html",
			},
		],
	},
	{
		key: "academic",
		Icon: GraduationCap,
		title: "Academic & research networks",
		entries: [
			{
				name: "eduGAIN — OpenID Federation pilot",
				status: "Pilot findings (August 2026)",
				region: "GÉANT",
				detail:
					"The UK Federation shares what it learned from testing OpenID Federation alongside eduGAIN’s SAML infrastructure.",
				href: "https://trustandidentity.jiscinvolve.org/wp/2026/08/05/reflecting-on-the-uk-federations-participation-in-the-edugain-openid-federation-pilot/",
			},
			{
				name: "DC4EU final report (Feb 2026)",
				status: "Pluralistic trust model proposal",
				region: "EU",
				detail:
					"Proposes a pluralistic trust model using eduGAIN + OpenID Federation for the EUDI wallet.",
				href: "https://connect.geant.org/2026/02/03/dc4eu-final-report-proposes-pluralistic-trust-model-to-realise-eudi-wallet-vision",
			},
			{
				name: "SUNET — satosa-idpy",
				status: "Reference implementation",
				region: "SE",
				detail:
					"OpenID Federation-capable OP frontend for SATOSA. SUNET hosted the Stockholm 2025 interop event.",
				href: "https://github.com/SUNET/satosa-idpy",
			},
		],
	},
	{
		key: "ai-agents",
		Icon: Bot,
		title: "AI agents & agentic identity (emerging)",
		entries: [
			{
				name: "OpenID Foundation — Identity Management for Agentic AI (Oct 2025)",
				status: "Whitepaper",
				region: "OIDF",
				detail:
					"Names OpenID Federation with HTTPS-based identifiers as a candidate interoperable trust fabric for agents operating across diverse domains without a central identity provider.",
				href: "https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/",
			},
			{
				name: "Ping Identity — Identity for AI (April 2026)",
				status: "IAM vendor briefing",
				region: "Industry",
				detail: "IAM vendor publication on AI-agent identity architecture.",
				href: "https://cdn-docs.pingidentity.com/archive/pdf/identity-for-ai/identity_for_ai.pdf",
			},
			{
				name: "Academic research — arXiv 2510.25819",
				status: "Preprint",
				region: "Research",
				detail:
					"Identity Management for Agentic AI: the new frontier of authorization, authentication, and security for an AI-agent world.",
				href: "https://arxiv.org/abs/2510.25819",
			},
		],
	},
];

const interopEvents = [
	{
		title: "Stockholm interop",
		date: "28–30 April 2025",
		host: "Hosted by SUNET",
		detail:
			"30 delegates, 14 implementations. Participants from 15 countries: Sweden, Finland, Netherlands, Italy, Germany, Denmark, Portugal, Poland, Serbia, Croatia, UK, Brazil, Australia, New Zealand, US.",
		href: "https://openid.net/openid-federation-interop-apr-28-30-2025/",
	},
	{
		title: "Amsterdam TIIME interop",
		date: "13 February 2026",
		host: "TIIME Europe",
		detail:
			"12 participants, 9 implementations from Croatia, Finland, Greece, Italy, Netherlands, Poland, Serbia, Sweden, and the US. OpenID Federation 1.0 reached Final status around the same date.",
		href: "https://openid.net/nine-countries-prove-openid-federation-interoperability/",
	},
];

const commercialImpls = [
	{ name: "Authlete", href: "https://www.authlete.com/developers/oidcfed/" },
	{ name: "Connect2id server", href: "https://connect2id.com/products/server" },
	{
		name: "Raidiam Connect",
		href: "https://docs.connect.raidiam.io/openid-federation-trust-anchor",
	},
];

const languageImpls = [
	{
		lang: "Go",
		entries: [{ name: "zachmann/go-oidfed", href: "https://github.com/zachmann/go-oidfed" }],
	},
	{
		lang: "Java",
		entries: [
			{
				name: "Nimbus OAuth 2.0 SDK",
				href: "https://connect2id.com/products/nimbus-oauth-openid-connect-sdk",
			},
			{ name: "italia/spid-cie-oidc-java", href: "https://github.com/italia/spid-cie-oidc-java" },
		],
	},
	{
		lang: "Kotlin",
		entries: [
			{
				name: "Sphereon OpenID Federation",
				href: "https://github.com/Sphereon-Opensource/OpenID-Federation",
			},
		],
	},
	{
		lang: "Python",
		entries: [
			{ name: "rohe/fedservice", href: "https://github.com/rohe/fedservice" },
			{
				name: "italia/spid-cie-oidc-django",
				href: "https://github.com/italia/spid-cie-oidc-django",
			},
		],
	},
	{
		lang: "PHP",
		entries: [{ name: "simplesamlphp/openid", href: "https://github.com/simplesamlphp/openid" }],
	},
	{
		lang: "Node.js",
		entries: [
			{
				name: "italia/spid-cie-oidc-nodejs",
				href: "https://github.com/italia/spid-cie-oidc-nodejs",
			},
		],
	},
];

const fapiAdjacent = [
	{
		name: "Norway HelseID",
		detail:
			"First nationwide healthcare FAPI 2.0 deployment — up to 50,000 healthcare organisations and ~6M Norwegians.",
		href: "https://openid.net/scaling-fapi-2-0-to-transform-healthcare-security-in-norway/",
	},
	{
		name: "UK Open Banking",
		detail: "FAPI 1.0 mandated as the open-banking profile.",
		href: "https://openid.net/wg/fapi/",
	},
	{
		name: "Australia Consumer Data Right",
		detail: "CDR uses OpenID Connect constrained further by FAPI.",
		href: "https://consumerdatastandardsaustralia.github.io/standards/",
	},
	{
		name: "Brazil Open Finance / Open Insurance",
		detail: "FAPI at national scale across Brazilian financial and insurance programs.",
		href: "https://openid.net/wg/fapi/",
	},
];

const furtherReading: {
	name: string;
	source: string;
	date: string;
	detail: string;
	href: string;
}[] = [
	{
		name: "A Trusted Foundation for the EUDI Wallet in Research and Education",
		source: "Paul den Hertog, Niels van Dijk, Klaas Wierenga · GÉANT CONNECT",
		date: "Jul 2025",
		detail:
			"The DC4EU case for integrating eduGAIN with the EUDI Wallet via OpenID Federation — framed around institutional autonomy, differentiated Levels of Assurance, and digital sovereignty.",
		href: "https://connect.geant.org/2025/07/24/a-trusted-foundation-for-the-eudi-wallet-in-research-and-education-why-edugain-and-openid-federation-matter",
	},
	{
		name: "The Journey to OpenID Federation 1.0 is Complete",
		source: "Mike Jones · self-issued.info",
		date: "Feb 2026",
		detail:
			"Spec co-editor retrospective on a decade of work — from Lucy Lynch challenging Roland Hedberg at TNC 2016 to Final status, security analysis by University of Stuttgart, and the 2026 Amsterdam interop.",
		href: "https://self-issued.info/?p=2813",
	},
	{
		name: "Nine countries prove OpenID Federation interoperability",
		source: "OpenID Foundation",
		date: "Feb 2026",
		detail:
			"Twelve implementers, nine independent implementations, nine countries — Croatia, Finland, Greece, Italy, Netherlands, Poland, Serbia, Sweden, US — successfully interop-tested at TIIME Amsterdam.",
		href: "https://openid.net/nine-countries-prove-openid-federation-interoperability/",
	},
	{
		name: "Selecting OpenID Federation for the DCC & Credential Engine Issuer Registry",
		source: "R.X. Schwartz · Digital Credentials Consortium blog",
		date: "Jan 2025",
		detail:
			"Rationale for choosing OpenID Federation as the trust backbone for a US verifiable-credential issuer registry serving universities, employers, and training programs.",
		href: "https://blog.dcconsortium.org/selecting-the-openid-federation-specification-for-the-dcc-and-credential-engine-issuer-registry-f9079f620472",
	},
	{
		name: "Building trust with OpenID Federation trust chain on Keycloak",
		source: "Yutaka Obuchi (Hitachi) · CNCF blog",
		date: "Apr 2025",
		detail:
			"A concrete walk-through of how OpenID Federation 1.0 establishes trust between an RP and an OP with no direct relationship, grounded in a Keycloak implementation.",
		href: "https://www.cncf.io/blog/2025/04/25/building-trust-with-openid-federation-trust-chain-on-keycloak/",
	},
	{
		name: "2025: A year worth talking about for the OpenID Foundation",
		source: "OpenID Foundation · year in review",
		date: "Dec 2025",
		detail:
			"Dozens of governments and ecosystem operators selected OpenID Foundation standards to power their digital wallet and verifiable-credential programs in 2025 — context on the year OpenID Federation moved from draft to final.",
		href: "https://openid.net/2025-a-year-worth-talking-about-for-the-openid-foundation/",
	},
	{
		name: "eduGAIN: structure, governance and sovereignty in European academia (DC4EU Paper 15)",
		source: "DC4EU project",
		date: "Nov 2025",
		detail:
			"Full DC4EU report on eduGAIN's governance model, its fit for the EUDI Wallet, and why a decentralised academic trust fabric matters for European digital sovereignty.",
		href: "https://www.dc4eu.eu/wp-content/uploads/2025/11/Paper-15-eduGAIN_Full_Report_DC4EU.pdf",
	},
];

const specDocs = [
	{
		label: "OpenID Federation 1.0",
		status: "Final",
		href: "https://openid.net/specs/openid-federation-1_0.html",
		implemented: true,
	},
	{
		label: "OpenID Federation 1.1",
		status: "Final",
		href: "https://openid.net/specs/openid-federation-1_1-final.html",
		implemented: true,
	},
	{
		label: "OpenID Federation for OpenID Connect 1.1",
		status: "Final",
		href: "https://openid.net/specs/openid-federation-connect-1_1-final.html",
		implemented: true,
	},
	{
		label: "OpenID Federation Extended Subordinate Listing 1.0",
		status: "Implementer’s Draft 1",
		href: "https://openid.net/specs/openid-federation-extended-listing-1_0-ID1.html",
		implemented: true,
	},
	{
		label: "OpenID Federation Subordinate Events Endpoint 1.0",
		status: "Implementer’s Draft 1",
		href: "https://openid.net/specs/openid-federation-subordinate-events-1_0-ID1.html",
		implemented: true,
	},
	{
		label: "OpenID Federation Entity Collection 1.0",
		status: "Draft 01",
		href: "https://openid.net/specs/openid-federation-entity-collection-1_0-01.html",
		implemented: true,
	},
	{
		label: "OpenID Federation for Wallet Architectures 1.0",
		status: "Draft 05",
		href: "https://openid.net/specs/openid-federation-wallet-1_0-05.html",
		implemented: true,
	},
	{
		label: "ACME with OpenID Federation 1.0",
		status: "Expired Internet-Draft",
		href: "https://datatracker.ietf.org/doc/draft-ietf-acme-openid-federation/",
		implemented: false,
	},
];

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function Ecosystem() {
	return (
		<div>
			<Hero />
			<AdoptionBySector />
			<Interoperability />
			<Implementations />
			<OurImplementation />
			<SpecStatus />
			<FurtherReading />
			<FamilySignals />
		</div>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §01 · Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
	return (
		<SiteHero
			title="OpenID Federation in practice"
			description="See how governments and research networks use federation, what interoperability pilots have tested, and which specifications are ready to implement."
		>
			<div className="mt-7 flex flex-wrap justify-center gap-3">
				<a href="#specifications" className="site-button">
					View specifications <ArrowRight aria-hidden className="size-4" />
				</a>
				<Link to="/trust-journal" className="site-button site-button-outline">
					Trust Journal
				</Link>
			</div>
		</SiteHero>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §02 · Adoption by sector
// ─────────────────────────────────────────────────────────────────────────────

function AdoptionBySector() {
	return (
		<section className="border-b border-border/60 bg-muted/30">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SectionTitle>Deployments and pilots by sector</SectionTitle>
					<SectionIntro>
						Documented examples of OpenID Federation being adopted, piloted, or specified across
						sectors. Every entry links to an authoritative source.
					</SectionIntro>
				</div>

				<div className="mt-12 space-y-14">
					{sectorGroups.map((group) => {
						const { Icon } = group;
						return (
							<div key={group.key}>
								<RowHeader
									icon={<Icon className="size-3.5" />}
									label={group.title}
									right={`${String(group.entries.length).padStart(2, "0")} entries`}
								/>
								<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
									{group.entries.map((item) => (
										<li key={item.name}>
											<a
												href={item.href}
												target="_blank"
												rel="noopener noreferrer"
												className="group grid grid-cols-[auto_1fr_auto] items-start gap-4 p-5 transition-colors hover:bg-muted/50 sm:grid-cols-[auto_minmax(260px,1fr)_2fr_auto] sm:items-center sm:gap-6"
											>
												<RegionPill region={item.region} />
												<div className="min-w-0">
													<div className="font-heading text-[15.5px] font-semibold leading-snug tracking-tight">
														{item.name}
													</div>
													<div className="mt-1 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground">
														{item.status}
													</div>
												</div>
												<p className="col-span-3 text-[13.5px] leading-relaxed text-muted-foreground sm:col-span-1">
													{item.detail}
												</p>
												<ArrowUpRight className="size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
											</a>
										</li>
									))}
								</ul>
							</div>
						);
					})}
				</div>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §03 · Interoperability
// ─────────────────────────────────────────────────────────────────────────────

function Interoperability() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SectionTitle>Interoperability events</SectionTitle>
					<SectionIntro>
						OpenID Federation implementations meet to interoperate. Two recent events anchor the
						specification's maturity.
					</SectionIntro>
				</div>

				<div className="mt-10 grid gap-5 sm:grid-cols-2">
					{interopEvents.map((event) => (
						<a
							key={event.title}
							href={event.href}
							target="_blank"
							rel="noopener noreferrer"
							className="group block"
						>
							<Card className="flex h-full flex-col gap-4 p-6 transition-all group-hover:-translate-y-0.5 group-hover:border-brand-500/40 group-hover:shadow-md">
								<div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
									<CheckCircle2 className="size-3.5 text-emerald-500" />
									<span>{event.date}</span>
									<span className="ml-auto text-muted-foreground/60">{event.host}</span>
								</div>
								<div>
									<div className="font-heading text-xl font-semibold tracking-tight">
										{event.title}
									</div>
									<p className="mt-3 text-[14px] leading-relaxed text-muted-foreground">
										{event.detail}
									</p>
								</div>
								<div className="mt-auto flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.18em] text-brand-500">
									Read the recap
									<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
								</div>
							</Card>
						</a>
					))}
				</div>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §04 · Implementations
// ─────────────────────────────────────────────────────────────────────────────

function Implementations() {
	return (
		<section className="border-b border-border/60 bg-muted/30">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SectionTitle>OpenID Federation implementations</SectionTitle>
					<SectionIntro>
						The OpenID Foundation maintains the canonical directory of known implementations by
						language and commercial product. Below is a representative selection — jump straight to
						the official registry for the full list.
					</SectionIntro>
				</div>

				<div className="mt-12 grid gap-10 lg:grid-cols-[1fr_1.2fr] lg:gap-16">
					{/* Commercial */}
					<div className="min-w-0">
						<RowHeader icon={<Briefcase className="size-3.5" />} label="Commercial products" />
						<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
							{commercialImpls.map((impl) => (
								<li key={impl.name}>
									<a
										href={impl.href}
										target="_blank"
										rel="noopener noreferrer"
										className="group flex items-center gap-4 p-4 transition-colors hover:bg-muted/50"
									>
										<span className="font-heading text-[15px] font-semibold tracking-tight">
											{impl.name}
										</span>
										<ArrowUpRight className="ml-auto size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
									</a>
								</li>
							))}
						</ul>
					</div>

					{/* Language implementations */}
					<div className="min-w-0">
						<RowHeader icon={<Library className="size-3.5" />} label="Language implementations" />
						<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
							{languageImpls.map((row) => (
								<li
									key={row.lang}
									className="grid gap-2 p-4 sm:grid-cols-[100px_minmax(0,1fr)] sm:items-center sm:gap-4"
								>
									<span className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
										{row.lang}
									</span>
									<div className="flex flex-wrap gap-3">
										{row.entries.map((entry) => (
											<a
												key={entry.name}
												href={entry.href}
												target="_blank"
												rel="noopener noreferrer"
												className="group inline-flex items-center gap-1 rounded-md border border-border/60 bg-background/60 px-2.5 py-1 font-mono text-[12px] text-foreground transition-colors hover:border-brand-500/40 hover:text-brand-500"
											>
												{entry.name}
												<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
											</a>
										))}
									</div>
								</li>
							))}
						</ul>
					</div>
				</div>

				<div className="mt-8">
					<a
						href="https://openid.net/developers/openid-federation-implementations/"
						target="_blank"
						rel="noopener noreferrer"
						className={`${buttonVariants({ variant: "outline", size: "sm" })} group`}
					>
						Browse the official registry
						<ArrowRight className="ml-1.5 size-3 transition-transform group-hover:translate-x-0.5" />
					</a>
				</div>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §05 · Our implementation
// ─────────────────────────────────────────────────────────────────────────────

function OurImplementation() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SectionTitle>OpenID Federation for JavaScript</SectionTitle>
					<SectionIntro>
						@oidfed implements federation trust chains, entity publication and protocol roles.
						Applications choose their crypto backend and manage their signing keys. Apache 2.0
						licensed (with MIT-licensed apps) and free to use.
					</SectionIntro>
				</div>

				<div className="mt-10 overflow-hidden rounded-xl border border-border/60 bg-card/40">
					<div className="grid gap-0 sm:grid-cols-[1.2fr_1px_1fr]">
						<div className="flex flex-col gap-4 p-6 sm:p-8">
							<div className="flex flex-wrap items-center gap-2">
								<span className="font-mono text-[17px] font-semibold tracking-tight">
									@oidfed/*
								</span>
								<Badge variant="secondary" className="font-mono text-[10px]">
									TypeScript
								</Badge>
								<Badge variant="outline" className="font-mono text-[10px]">
									Runtime-agnostic
								</Badge>
								<Badge variant="outline" className="font-mono text-[10px]">
									Apache 2.0
								</Badge>
							</div>
							<p className="text-[14px] leading-relaxed text-muted-foreground">
								6 libraries, 3 apps, and 17 CLI commands. The library test suite runs on Node.js,
								Deno, Bun, workerd, Electron, and Chromium. Source at{" "}
								<a
									href="https://github.com/Dahkenangnon/oidfed"
									target="_blank"
									rel="noopener noreferrer"
									className="font-mono text-foreground underline underline-offset-4 hover:no-underline"
								>
									github.com/Dahkenangnon/oidfed
								</a>
								.
							</p>
						</div>

						<div aria-hidden className="hidden bg-border/60 sm:block" />

						<div className="grid grid-cols-2 gap-0 bg-muted/40 sm:grid-cols-1">
							<Mini
								label="Packages"
								value="06"
								note="crypto · core · authority · leaf · oidc · wallet"
							/>
							<Mini
								label="Runtimes"
								value="06"
								note="Node · Deno · Bun · workerd · Electron · browser"
								border
							/>
							<Mini
								label="Crypto backend"
								value="Host supplied"
								note="Web Crypto · optional jose · custom engines"
								border
								className="col-span-2 sm:col-span-1"
							/>
						</div>
					</div>
				</div>
			</div>
		</section>
	);
}

function Mini({
	label,
	value,
	note,
	border,
	className = "",
}: {
	label: string;
	value: string;
	note: string;
	border?: boolean;
	className?: string;
}) {
	return (
		<div
			className={`p-5 ${border ? "border-t border-border/60 sm:border-l sm:border-t-0" : ""} ${className}`}
		>
			<div className="font-heading text-3xl font-semibold tabular-nums leading-none tracking-[-0.02em] text-brand-500">
				{value}
			</div>
			<div className="mt-2 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
				{label}
			</div>
			<div className="mt-1 font-mono text-[10.5px] text-muted-foreground/70">{note}</div>
		</div>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §06 · Specification Status
// ─────────────────────────────────────────────────────────────────────────────

function SpecStatus() {
	return (
		<section id="specifications" className="scroll-mt-8 border-b border-border bg-muted/30">
			<div className="mx-auto grid max-w-6xl gap-9 px-5 py-16 sm:px-8 lg:grid-cols-[1fr_1.5fr] lg:gap-14 lg:py-22">
				<div>
					<h2 className="site-section-title">OpenID Federation specifications</h2>
					<p className="mt-4 leading-relaxed text-muted-foreground">
						OpenID Federation 1.0 became final in February 2026. The two final 1.1 specifications,
						approved in May, cover the core trust framework and the OpenID Connect and OAuth
						bindings.
					</p>
					<p className="mt-3 leading-relaxed text-muted-foreground">
						The list identifies the versions OidFed implements. Find newer publications in the Trust
						Journal, including Wallet Draft 06 and Entity Collection Draft 02.
					</p>
					<Link
						to="/trust-journal#standards"
						className="site-link mt-5 inline-flex items-center gap-2 text-sm font-medium"
					>
						Standards updates <ArrowRight aria-hidden className="size-4" />
					</Link>
				</div>
				<ul className="divide-y divide-border rounded-xl border border-border bg-card">
					{specDocs.map(({ label, status, href, implemented }) => (
						<li key={href}>
							<a href={href} className="group flex items-start gap-3 p-4 hover:bg-site-code sm:p-5">
								<div className="min-w-0 flex-1">
									<p className="text-sm font-semibold">{label}</p>
									<p className="mt-1 text-xs text-muted-foreground">{status}</p>
								</div>
								{implemented && <Badge variant="secondary">Implemented</Badge>}
								<ArrowUpRight
									aria-hidden
									className="mt-0.5 size-4 shrink-0 text-muted-foreground group-hover:text-site-accent"
								/>
							</a>
						</li>
					))}
				</ul>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §07 · Further reading
// ─────────────────────────────────────────────────────────────────────────────

function FurtherReading() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SectionTitle>Further reading</SectionTitle>
					<SectionIntro>
						Curated essays, blog posts, and reports that explain <em>why</em> organizations are
						adopting OpenID Federation — from spec editors, federation operators, national wallet
						teams, and individual contributors.
					</SectionIntro>
				</div>

				<div className="mt-10 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
					<BookOpen className="size-3.5" />
					External reading
					<span className="h-px flex-1 bg-border" />
					<span className="tabular-nums">{furtherReading.length} items</span>
				</div>

				<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
					{furtherReading.map((item) => (
						<li key={item.href}>
							<a
								href={item.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group grid grid-cols-[1fr_auto] items-start gap-4 p-5 transition-colors hover:bg-muted/50"
							>
								<div className="min-w-0">
									<div className="font-heading text-[15.5px] font-semibold leading-snug tracking-tight">
										{item.name}
									</div>
									<div className="mt-1.5 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
										{item.source} · {item.date}
									</div>
									<p className="mt-2 text-[13.5px] leading-relaxed text-muted-foreground">
										{item.detail}
									</p>
								</div>
								<ArrowUpRight className="size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
							</a>
						</li>
					))}
				</ul>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §08 · Adjacent OID Foundation standards (FAPI)
// ─────────────────────────────────────────────────────────────────────────────

function FamilySignals() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-16 lg:py-20">
				<div className="max-w-2xl">
					<SectionTitle>Related profiles in finance and healthcare</SectionTitle>
					<SectionIntro>
						Adjacent OpenID Foundation standards (FAPI) are in production at national scale — a
						maturity signal for the broader standards family, even where OpenID Federation itself is
						not yet the trust layer.
					</SectionIntro>
				</div>

				<ul className="mt-10 grid gap-4 sm:grid-cols-2">
					{fapiAdjacent.map((item) => (
						<li key={item.name}>
							<a
								href={item.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group flex h-full flex-col gap-2 rounded-xl border border-border/60 bg-card/40 p-5 transition-all hover:-translate-y-0.5 hover:border-brand-500/40 hover:shadow-md"
							>
								<div className="flex items-center justify-between">
									<span className="font-heading text-[15px] font-semibold tracking-tight">
										{item.name}
									</span>
									<ArrowUpRight className="size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
								</div>
								<p className="text-[13.5px] leading-relaxed text-muted-foreground">{item.detail}</p>
							</a>
						</li>
					))}
				</ul>
			</div>
		</section>
	);
}
