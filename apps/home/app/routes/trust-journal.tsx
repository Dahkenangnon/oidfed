import { ArrowUpRight } from "lucide-react";
import { SiteHero } from "../components/site-hero";
import { buildMeta, DOMAIN } from "../lib/seo";

export function meta() {
	return buildMeta({
		title: "Trust Journal: OpenID Federation standards updates",
		description:
			"Standards updates, guides, and deployment reports about OpenID Federation and related ways to establish digital trust.",
		path: "/trust-journal",
		jsonLd: {
			"@context": "https://schema.org",
			"@type": "CollectionPage",
			"@id": `${DOMAIN}/trust-journal#webpage`,
			url: `${DOMAIN}/trust-journal`,
			name: "OpenID Federation Trust Journal",
			description:
				"A curated reading list of OpenID Federation specifications, guides, and deployment reports.",
			inLanguage: "en",
			isPartOf: { "@id": `${DOMAIN}/#website` },
			about: { "@type": "Thing", name: "OpenID Federation" },
		},
	});
}

interface Resource {
	title: string;
	publisher: string;
	format: string;
	href: string;
	description: string;
	date?: string;
}

const sections: readonly { id: string; title: string; resources: readonly Resource[] }[] = [
	{
		id: "standards",
		title: "Standards updates",
		resources: [
			{
				title: "Entity Collection enters public review",
				publisher: "OpenID Foundation",
				format: "Announcement",
				href: "https://openid.net/public-review-period-for-proposed-implementers-draft-of-openid-federation-entity-collection-endpoint/",
				description:
					"The announced review period for the proposed first Implementer’s Draft runs through 31 December 2026.",
				date: "2026-11-16",
			},
			{
				title: "Entity Collection Endpoint 1.0, Draft 02",
				publisher: "OpenID Foundation",
				format: "Draft specification",
				href: "https://openid.net/specs/openid-federation-entity-collection-1_0-02.html",
				description:
					"Clarifies what can change between pages, when a continuation may be invalidated, and how clients should verify returned Trust Marks.",
				date: "2026-11-13",
			},
			{
				title: "Wallet Architectures 1.0, Draft 06",
				publisher: "OpenID Foundation",
				format: "Draft specification",
				href: "https://openid.net/specs/openid-federation-wallet-1_0-06.html",
				description:
					"Introduces Credential Verifier Providers and explains how a wallet evaluates a Verifier Attestation and ties it to an OpenID4VP request.",
				date: "2026-11-12",
			},
			{
				title: "Implementer’s Drafts approved for two Federation extensions",
				publisher: "OpenID Foundation",
				format: "Announcement",
				href: "https://openid.net/implementers-drafts-of-two-openid-federation-extensions-approved/",
				description:
					"Links to the approved drafts for Extended Subordinate Listing and the Subordinate Events Endpoint.",
				date: "2026-09-09",
			},
			{
				title: "OpenID Federation 1.1 final specifications",
				publisher: "OpenID Foundation",
				format: "Announcement",
				href: "https://openid.net/openid-federation-1-1-final-specifications-approved/",
				description:
					"Links to the two final specifications covering the protocol-independent trust framework and its OpenID Connect and OAuth bindings.",
				date: "2026-05-06",
			},
		],
	},
	{
		id: "guides",
		title: "Guides and implementations",
		resources: [
			{
				title: "OpenID Federation explained",
				publisher: "Credenco",
				format: "Explainer",
				href: "https://www.credenco.com/explained/openid-federation",
				description:
					"Introduces Trust Anchors, Intermediates, and Leaves through an education credential example.",
			},
			{
				title: "OpenID Federation and Trust Chains Guide",
				publisher: "NHI Mgmt Group",
				format: "Guide",
				href: "https://nhimg.org/openid-federation-guide",
				description:
					"A practitioner’s guide to building trust chains and applying federation policy in OAuth and OIDC deployments.",
			},
			{
				title: "OpenID Federation implementations",
				publisher: "OpenID Foundation",
				format: "Directory",
				href: "https://openid.net/developers/openid-federation-implementations/",
				description:
					"Find libraries, tools, and reference implementations for different federation roles.",
			},
		],
	},
	{
		id: "deployments",
		title: "Profiles and deployments",
		resources: [
			{
				title: "The UK Federation’s experience in the eduGAIN pilot",
				publisher: "Jisc",
				format: "Pilot report",
				href: "https://trustandidentity.jiscinvolve.org/wp/2026/08/05/reflecting-on-the-uk-federations-participation-in-the-edugain-openid-federation-pilot/",
				description:
					"An operator’s account of testing OpenID Federation for research and education, with lessons from the eduGAIN pilot.",
			},
			{
				title: "InCommon investment in OpenID Federation",
				publisher: "InCommon",
				format: "Deployment plan",
				href: "https://incommon.org/resources/blogs/incommon-investment-in-openid-federation",
				description:
					"A phased plan for engaging with the eduGAIN pilot, developing a profile, and testing infrastructure for US research and education.",
			},
			{
				title: "The Italian SPID and CIE federations",
				publisher: "Docs Italia",
				format: "Technical profile in Italian",
				href: "https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/la_federazione_delle_identita.html",
				description:
					"Technical rules for joining Italy’s SPID and CIE identity federations and publishing participant metadata.",
			},
			{
				title: "Sweden Connect Federation specifications",
				publisher: "Sweden Connect",
				format: "Technical specifications",
				href: "https://docs.swedenconnect.se/technical-framework/",
				description:
					"Sweden’s deployment profile, participant metadata requirements, and extensions for federation.",
			},
			{
				title: "Building bridges between the EUDI Wallet and OpenID Federation",
				publisher: "Francesco Antonio Marino and Pasquale Cerqua",
				format: "TDI 2025 slides (PDF)",
				href: "https://st.fbk.eu/assets/areas/events/TDI2025/slides/2_1_Marino_Cerqua.pdf",
				description:
					"Compares the EUDI Wallet’s certificate and trusted-list model with OpenID Federation and explores how they could work together.",
			},
			{
				title: "EU Digital Identity Wallet Architecture and Reference Framework",
				publisher: "EU Digital Identity Wallet",
				format: "Reference framework",
				href: "https://eu-digital-identity-wallet.github.io/",
				description:
					"Start with the wallet architecture, participant roles, and trust model for the European Digital Identity Wallet ecosystem.",
			},
		],
	},
	{
		id: "related",
		title: "Related trust mechanisms",
		resources: [
			{
				title: "OpenID4VC High Assurance Interoperability Profile 1.0",
				publisher: "OpenID Foundation",
				format: "Final specification",
				href: "https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html",
				description:
					"A profile of OpenID4VCI and OpenID4VP for interoperable credential issuance and presentation at high assurance.",
			},
			{
				title: "GitHub Actions OIDC Federation Hardening Guide",
				publisher: "NHI Mgmt Group",
				format: "Workload identity guide",
				href: "https://nhimg.org/github-actions-oidc-federation-guide",
				description:
					"Explains how to constrain cloud trust policies when GitHub Actions exchanges OIDC tokens for short-lived workload credentials.",
			},
		],
	},
];

const formatDate = new Intl.DateTimeFormat("en-GB", {
	day: "numeric",
	month: "short",
	year: "numeric",
	timeZone: "UTC",
});

export default function TrustJournal() {
	return (
		<>
			<SiteHero
				title="Trust Journal"
				description="Standards updates and practical reading on OpenID Federation, wallet ecosystems, and related ways to establish digital trust."
			/>
			<div className="mx-auto max-w-6xl px-5 pb-16 sm:px-8 sm:pb-24">
				<nav aria-label="Journal sections" className="border-y border-border py-2">
					<ul className="flex flex-wrap gap-x-6">
						{sections.map(({ id, title }) => (
							<li key={id}>
								<a
									href={`#${id}`}
									className="inline-block py-2.5 text-sm font-medium text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
								>
									{title}
								</a>
							</li>
						))}
					</ul>
				</nav>

				<div className="space-y-12 pt-10 sm:space-y-16 sm:pt-14">
					{sections.map(({ id, title, resources }) => (
						<section
							key={id}
							id={id}
							aria-labelledby={`${id}-heading`}
							className="grid scroll-mt-24 gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,3fr)] lg:gap-12"
						>
							<h2
								id={`${id}-heading`}
								className="font-heading text-xl font-semibold tracking-tight sm:text-2xl"
							>
								{title}
							</h2>

							<ul className="divide-y divide-border border-y border-border">
								{resources.map(({ title, publisher, format, href, description, date }) => (
									<li key={href} className="relative py-4 pr-7 sm:py-5 sm:pr-10">
										<h3 className="font-heading text-lg font-semibold leading-snug">
											<a
												href={href}
												className="group text-foreground underline-offset-4 hover:underline"
											>
												{title}
												<ArrowUpRight
													aria-hidden
													className="absolute right-0 top-5 size-4 text-muted-foreground group-hover:text-foreground sm:top-6"
												/>
											</a>
										</h3>
										<p className="mt-1 text-sm text-muted-foreground">
											{publisher} · {format}
											{date && (
												<>
													{" · "}
													<time dateTime={date} className="whitespace-nowrap">
														{formatDate.format(new Date(date))}
													</time>
												</>
											)}
										</p>
										<p className="mt-2 max-w-[68ch] text-sm leading-relaxed text-muted-foreground">
											{description}
										</p>
									</li>
								))}
							</ul>
						</section>
					))}
				</div>
			</div>
		</>
	);
}
