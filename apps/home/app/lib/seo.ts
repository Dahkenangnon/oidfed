/**
 * Shared SEO helpers for @oidfed/home.
 * Builds the standardized `meta()` output consumed by React Router route modules.
 */

export const DOMAIN = "https://oidfed.com";
export const SITE_NAME = "OidFed";
export const HOME_DESCRIPTION =
	"Build OpenID Federation Trust Anchors, Intermediates, and Leaves with a simple TypeScript API. Compose OIDC, OAuth, and wallet roles, or verify trust chains.";
export const DEFAULT_OG_IMAGE = `${DOMAIN}/og-image.png`;
export const DEFAULT_OG_IMAGE_WIDTH = "1200";
export const DEFAULT_OG_IMAGE_HEIGHT = "630";

export interface BuildMetaInput {
	title: string;
	description: string;
	path: string;
	ogType?: "website" | "article";
	ogImage?: string;
	jsonLd?: Record<string, unknown> | Array<Record<string, unknown>>;
	noindex?: boolean;
}

type MetaDescriptor =
	| { title: string }
	| { name: string; content: string }
	| { property: string; content: string }
	| { tagName: "link"; rel: string; href: string }
	| { "script:ld+json": Record<string, unknown> };

export function buildMeta(input: BuildMetaInput): MetaDescriptor[] {
	const canonical = `${DOMAIN}${input.path === "/" ? "" : input.path}`;
	const ogImage = input.ogImage ?? DEFAULT_OG_IMAGE;
	const ogType = input.ogType ?? "website";

	const tags: MetaDescriptor[] = [
		{ title: input.title },
		{ name: "description", content: input.description },
		{ tagName: "link", rel: "canonical", href: canonical },
		{ property: "og:site_name", content: SITE_NAME },
		{ property: "og:locale", content: "en_US" },
		{ property: "og:type", content: ogType },
		{ property: "og:url", content: canonical },
		{ property: "og:title", content: input.title },
		{ property: "og:description", content: input.description },
		{ property: "og:image", content: ogImage },
		{ property: "og:image:width", content: DEFAULT_OG_IMAGE_WIDTH },
		{ property: "og:image:height", content: DEFAULT_OG_IMAGE_HEIGHT },
		{ property: "og:image:alt", content: "OidFed. OpenID Federation for OIDC, OAuth and wallets." },
		{ name: "twitter:card", content: "summary_large_image" },
		{ name: "twitter:title", content: input.title },
		{ name: "twitter:description", content: input.description },
		{ name: "twitter:image", content: ogImage },
	];

	if (input.noindex) {
		tags.push({ name: "robots", content: "noindex,nofollow" });
	}

	if (input.jsonLd) {
		const blocks = Array.isArray(input.jsonLd) ? input.jsonLd : [input.jsonLd];
		for (const block of blocks) {
			tags.push({ "script:ld+json": block });
		}
	}

	return tags;
}

/** Organization schema used across the site */
export const organizationJsonLd: Record<string, unknown> = {
	"@context": "https://schema.org",
	"@type": "Organization",
	"@id": `${DOMAIN}/#organization`,
	name: SITE_NAME,
	alternateName: "@oidfed",
	url: DOMAIN,
	logo: `${DOMAIN}/favicon.svg`,
	description: "Open-source libraries and learning resources for OpenID Federation.",
	founder: {
		"@type": "Person",
		name: "Justin Dah-kenangnon",
		url: "https://github.com/Dahkenangnon",
	},
	sameAs: [
		"https://github.com/Dahkenangnon/oidfed",
		"https://www.npmjs.com/org/oidfed",
		"https://explore.oidfed.com",
		"https://learn.oidfed.com",
	],
};

/** WebSite schema for the home */
export const websiteJsonLd: Record<string, unknown> = {
	"@context": "https://schema.org",
	"@type": "WebSite",
	"@id": `${DOMAIN}/#website`,
	url: DOMAIN,
	name: SITE_NAME,
	description:
		"Build with OidFed, learn OpenID Federation, and explore live deployments and standards updates.",
	publisher: { "@id": `${DOMAIN}/#organization` },
	inLanguage: "en",
};

/** SoftwareSourceCode schema for the headline package */
export const softwareSourceCodeJsonLd: Record<string, unknown> = {
	"@context": "https://schema.org",
	"@type": "SoftwareSourceCode",
	"@id": `${DOMAIN}/#sdk`,
	name: "OidFed OpenID Federation SDK",
	alternateName: "@oidfed",
	description: HOME_DESCRIPTION,
	url: DOMAIN,
	documentation: `${DOMAIN}/docs`,
	mainEntityOfPage: DOMAIN,
	codeRepository: "https://github.com/Dahkenangnon/oidfed",
	programmingLanguage: ["TypeScript", "JavaScript"],
	runtimePlatform: ["Node.js", "Deno", "Bun", "workerd", "Electron", "Browser"],
	license: "https://spdx.org/licenses/Apache-2.0.html",
	author: { "@id": `${DOMAIN}/#organization` },
	keywords: [
		"OpenID Federation",
		"OpenID Federation 1.1",
		"OpenID Federation JavaScript SDK",
		"Trust Anchor",
		"Intermediate",
		"Leaf",
		"Entity Configuration",
		"Trust Chain",
		"Subordinate Statement",
		"Metadata Policy",
		"Trust Mark",
		"OAuth 2.0",
		"OpenID Connect",
		"OIDC federation registration",
		"OpenID Federation for Wallet Architectures",
		"Wallet Provider",
		"Credential Issuer",
		"Credential Verifier",
	],
};
