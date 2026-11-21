/**
 * Search and citation metadata for the documentation routes.
 *
 * A markdown H1 is written for a reader who already has the page open: a guide
 * leads with its manual section number, and a package index names its npm
 * scope. A search result, a social card, and an answer engine quoting the page
 * carry none of that context, so these helpers derive a title that stands on
 * its own, stays inside the roughly 60 characters a result listing renders, and
 * leaves the brand suffix to `buildMeta`.
 */

export const DOCS_PACKAGES = ["core", "crypto", "authority", "leaf", "oidc", "wallet"] as const;

export type DocsPackage = (typeof DOCS_PACKAGES)[number];

/** Short, human label per package; the npm scope belongs in the description. */
const PACKAGE_LABELS: Record<DocsPackage, string> = {
	core: "Core",
	crypto: "Crypto",
	authority: "Authority",
	leaf: "Leaf",
	oidc: "OIDC",
	wallet: "Wallet",
};

/** Separates a page from its section. The pipe is reserved for the brand. */
export const SECTION_SEPARATOR = " · ";

/** A guide's position in the manual: useful in the sidebar, noise in a title. */
const SECTION_NUMBER = /^\d+(?:\.\d+)*\.\s+/;

const PACKAGE_PATH = new RegExp(`^/docs/api/(${DOCS_PACKAGES.join("|")})(?:/|$)`);

/**
 * Titles that cannot be derived: the index pages, which need the subject a
 * heading like "API reference" leaves implicit, and the few guides whose
 * heading is a full sentence that a result listing would truncate.
 */
const TITLE_OVERRIDES: Record<string, string> = {
	"/docs": "OpenID Federation Documentation & API Reference",
	"/docs/api": "OpenID Federation API Reference",
	"/docs/features": "OpenID Federation Feature Guides",
	"/docs/features/4.1.metadata-publication": "Publish partial, not effective, metadata",
};

/** Descriptions for pages whose source carries no prose to summarize. */
const DESCRIPTION_OVERRIDES: Record<string, string> = {
	"/docs/examples/software-crypto":
		"A runnable TypeScript example: create a Web Crypto engine, generate software signing keys, and build the keyring an OidFed host needs.",
	"/docs/examples/custom-crypto":
		"A runnable TypeScript example: implement a custom CryptoEngine, Signer, and private-use JWS algorithm profile for host-provided key custody.",
};

export interface DocsBreadcrumb {
	readonly name: string;
	readonly path: string;
}

export interface DocsSeoInput {
	/** The page's markdown H1. */
	readonly heading: string;
	/** The lead paragraph the renderer extracted. */
	readonly description: string;
	readonly path: string;
}

export interface DocsSeo {
	readonly title: string;
	readonly description: string;
	/** The section a page sits in, for `TechArticle.articleSection`. */
	readonly section: string;
	readonly breadcrumbs: readonly DocsBreadcrumb[];
}

/** The package an API path documents, or `undefined` outside `/docs/api/<pkg>`. */
export function docsPackage(path: string): DocsPackage | undefined {
	return PACKAGE_PATH.exec(path)?.[1] as DocsPackage | undefined;
}

/** Turns an example's file slug into prose: `software-crypto` → `Software crypto`. */
function humanize(slug: string): string {
	const words = slug.replace(/[-_]+/g, " ").trim();
	return words.charAt(0).toUpperCase() + words.slice(1);
}

function pageName({ heading, path }: Pick<DocsSeoInput, "heading" | "path">): string {
	const override = TITLE_OVERRIDES[path];
	if (override) return override;

	const example = /^\/docs\/examples\/([^/]+)$/.exec(path);
	if (example?.[1]) return `${humanize(example[1])} example`;

	const api = docsPackage(path);
	if (api && path === `/docs/api/${api}`) return `${PACKAGE_LABELS[api]} API reference`;

	return heading.replace(SECTION_NUMBER, "").trim();
}

/** A short label for a breadcrumb, where the trail already supplies context. */
function crumbName(path: string): string {
	const api = docsPackage(path);
	if (path === "/docs") return "Documentation";
	if (path === "/docs/api") return "API reference";
	if (path === "/docs/features") return "Feature guides";
	if (api && path === `/docs/api/${api}`) return `${PACKAGE_LABELS[api]} API`;
	return path;
}

function sectionFor(path: string): string {
	const api = docsPackage(path);
	if (api) return `${PACKAGE_LABELS[api]} API`;
	if (path.startsWith("/docs/features")) return "Feature guides";
	if (path.startsWith("/docs/examples")) return "Examples";
	if (path.startsWith("/docs/maintenance")) return "Maintenance";
	return "Documentation";
}

/**
 * Ancestors that are themselves documentation pages. `/docs/examples` and
 * `/docs/maintenance` have no index, so a trail skips straight to `/docs`
 * rather than pointing a crawler at an address that does not resolve.
 */
function trail(path: string): string[] {
	const api = docsPackage(path);
	const ancestors = ["/docs"];
	if (path.startsWith("/docs/api")) ancestors.push("/docs/api");
	if (api) ancestors.push(`/docs/api/${api}`);
	if (path.startsWith("/docs/features")) ancestors.push("/docs/features");
	return [...new Set(ancestors.filter((ancestor) => ancestor !== path)), path];
}

export function docsSeo(input: DocsSeoInput): DocsSeo {
	const { path } = input;
	const name = pageName(input);
	const section = sectionFor(path);
	const api = docsPackage(path);
	const titled = api && path !== `/docs/api/${api}` ? `${name}${SECTION_SEPARATOR}${section}` : name;

	return {
		title: titled,
		description: DESCRIPTION_OVERRIDES[path] ?? input.description,
		section,
		breadcrumbs: trail(path).map((ancestor) => ({
			name: ancestor === path ? name : crumbName(ancestor),
			path: ancestor,
		})),
	};
}
