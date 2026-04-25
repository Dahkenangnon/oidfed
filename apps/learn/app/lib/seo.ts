/**
 * Shared SEO helpers for @oidfed/learn.
 * Builds the standardized `meta()` output consumed by React Router route modules.
 */

export const DOMAIN = "https://learn.oidfed.com";
export const SITE_NAME = "@oidfed";
export const DEFAULT_OG_IMAGE = `${DOMAIN}/og-image.svg`;
export const DEFAULT_OG_IMAGE_WIDTH = "1200";
export const DEFAULT_OG_IMAGE_HEIGHT = "630";

export interface BuildMetaInput {
	title: string;
	description: string;
	path: string;
	ogType?: "website" | "article" | undefined;
	ogImage?: string | undefined;
	jsonLd?: Record<string, unknown> | Array<Record<string, unknown>> | undefined;
	prev?: string | undefined;
	next?: string | undefined;
	articleSection?: string | undefined;
	noindex?: boolean | undefined;
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
		{ property: "og:type", content: ogType },
		{ property: "og:url", content: canonical },
		{ property: "og:title", content: input.title },
		{ property: "og:description", content: input.description },
		{ property: "og:image", content: ogImage },
		{ property: "og:image:width", content: DEFAULT_OG_IMAGE_WIDTH },
		{ property: "og:image:height", content: DEFAULT_OG_IMAGE_HEIGHT },
		{ name: "twitter:card", content: "summary_large_image" },
		{ name: "twitter:site", content: "@oidfed" },
		{ name: "twitter:title", content: input.title },
		{ name: "twitter:description", content: input.description },
		{ name: "twitter:image", content: ogImage },
	];

	if (input.articleSection) {
		tags.push({ property: "article:section", content: input.articleSection });
		tags.push({ property: "article:author", content: "Justin Dah-kenangnon" });
	}

	if (input.prev) {
		tags.push({ tagName: "link", rel: "prev", href: `${DOMAIN}${input.prev}` });
	}
	if (input.next) {
		tags.push({ tagName: "link", rel: "next", href: `${DOMAIN}${input.next}` });
	}

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

/** Lesson metadata registry — single source of truth for sitemap, llms.txt, and JSON-LD. */
export interface LessonMeta {
	slug: string;
	number: number;
	title: string;
	description: string;
	phase: "Foundation" | "Core" | "Advanced" | "Capstone" | "Deeper";
	keyConcept: string;
}

export const LESSONS: readonly LessonMeta[] = [
	{
		slug: "what-is-federation",
		number: 1,
		title: "What is OpenID Federation?",
		description:
			"Why OpenID Federation exists, what problem it solves, and how it turns an N-squared bilateral trust problem into a scalable hierarchy.",
		phase: "Foundation",
		keyConcept: "Multilateral Federation",
	},
	{
		slug: "entities-and-roles",
		number: 2,
		title: "Entities & Roles",
		description:
			"The players in an OpenID Federation hierarchy — Trust Anchors, Intermediate Authorities, and Leaf Entities (RPs, OPs, Resource Servers).",
		phase: "Foundation",
		keyConcept: "Trust Anchor",
	},
	{
		slug: "entity-statements",
		number: 3,
		title: "Entity Statements",
		description:
			"Signed JWT documents that establish trust — Entity Configurations (self-signed) and Subordinate Statements (superior-signed).",
		phase: "Foundation",
		keyConcept: "Entity Configuration",
	},
	{
		slug: "trust-chains",
		number: 4,
		title: "Trust Chains",
		description:
			"The linked sequence of signed statements from a Leaf Entity up to a Trust Anchor — the cryptographic proof of federation membership.",
		phase: "Core",
		keyConcept: "Trust Chain",
	},
	{
		slug: "trust-chain-resolution",
		number: 5,
		title: "Trust Chain Resolution",
		description:
			"The bottom-up algorithm that automatically assembles and verifies a complete trust chain via `authority_hints` and `federation_fetch_endpoint`.",
		phase: "Core",
		keyConcept: "Authority Hints",
	},
	{
		slug: "metadata-and-policy",
		number: 6,
		title: "Metadata & Policy",
		description:
			"How entities declare capabilities and how superior authorities enforce constraints through cascading metadata policies.",
		phase: "Core",
		keyConcept: "Metadata Policy",
	},
	{
		slug: "trust-marks",
		number: 7,
		title: "Trust Marks",
		description:
			"Certified badges that prove an entity meets specific compliance or security requirements — issuance, verification, and status checks.",
		phase: "Advanced",
		keyConcept: "Trust Mark",
	},
	{
		slug: "federation-endpoints",
		number: 8,
		title: "Federation Endpoints",
		description:
			"The 9 HTTP APIs that federation entities expose for discovery, fetch, resolution, listing, trust-mark issuance and status, and historical keys.",
		phase: "Advanced",
		keyConcept: "Federation Endpoints",
	},
	{
		slug: "client-registration",
		number: 9,
		title: "Client Registration",
		description:
			"Two paths to client registration: Automatic (on-the-fly via resolved metadata and a signed Request Object) and Explicit (pre-registered).",
		phase: "Advanced",
		keyConcept: "Automatic Registration",
	},
	{
		slug: "putting-it-together",
		number: 10,
		title: "Putting It All Together",
		description:
			"A complete real-world scenario — 14 steps from Trust Anchor setup through user authentication — using every OpenID Federation concept.",
		phase: "Capstone",
		keyConcept: "End-to-end Federation Flow",
	},
	{
		slug: "topology-design",
		number: 11,
		title: "Topology Design",
		description:
			"Choosing the right federation structure: single vs. multi-level hierarchies, hub-and-spoke vs. tree models, and governance considerations.",
		phase: "Deeper",
		keyConcept: "Federation Topology",
	},
	{
		slug: "faq",
		number: 12,
		title: "FAQ",
		description:
			"Common questions from fundamentals to operations — entity multi-role, migrations, key rotation, revocation, and topology choice.",
		phase: "Deeper",
		keyConcept: "Federation Operations",
	},
	{
		slug: "glossary",
		number: 13,
		title: "Glossary",
		description:
			"Every key OpenID Federation term defined, linked, and cross-referenced — from Authority Hints to Subordinate Statement.",
		phase: "Deeper",
		keyConcept: "Federation Terminology",
	},
	{
		slug: "real-use-cases",
		number: 14,
		title: "Real-World Use Cases",
		description:
			"How universities (eduGAIN), government (EU DIW, SPID), enterprise, and healthcare use federation to solve trust and identity at scale.",
		phase: "Deeper",
		keyConcept: "Real-world Adoption",
	},
	{
		slug: "hands-on-objects",
		number: 15,
		title: "Hands-On: Build Federation Objects",
		description:
			"Interactive exercises — construct Entity Configurations, Subordinate Statements, trust chains, and metadata policies by hand.",
		phase: "Deeper",
		keyConcept: "Hands-on Construction",
	},
];

export function lessonPath(slug: string): string {
	return `/lessons/${slug}`;
}

export function lessonByIndex(i: number): LessonMeta | undefined {
	return LESSONS[i];
}

export function lessonBySlug(slug: string): LessonMeta | undefined {
	return LESSONS.find((l) => l.slug === slug);
}

/** Build a lesson's full meta() — title, OG, JSON-LD, prev/next link rels. */
export function lessonMetaForSlug(slug: string): MetaDescriptor[] {
	const lesson = lessonBySlug(slug);
	if (!lesson) {
		return [{ title: "Lesson — Learn OpenID Federation" }];
	}
	const idx = LESSONS.indexOf(lesson);
	const prevLesson = idx > 0 ? LESSONS[idx - 1] : undefined;
	const nextLesson = idx < LESSONS.length - 1 ? LESSONS[idx + 1] : undefined;
	const prev = prevLesson ? lessonPath(prevLesson.slug) : undefined;
	const next = nextLesson ? lessonPath(nextLesson.slug) : undefined;
	return buildMeta({
		title: `Lesson ${lesson.number} — ${lesson.title} | Learn OpenID Federation`,
		description: lesson.description,
		path: lessonPath(lesson.slug),
		ogType: "article",
		articleSection: lesson.phase,
		prev,
		next,
		jsonLd: lessonJsonLd(lesson),
	});
}

/** Organization JSON-LD (reused across routes) */
export const organizationJsonLd: Record<string, unknown> = {
	"@context": "https://schema.org",
	"@type": "Organization",
	"@id": "https://oidfed.com/#organization",
	name: "@oidfed",
	url: "https://oidfed.com",
	logo: "https://oidfed.com/favicon.svg",
	sameAs: [
		"https://github.com/Dahkenangnon/oidfed",
		"https://www.npmjs.com/org/oidfed",
		"https://explore.oidfed.com",
		"https://learn.oidfed.com",
	],
};

/** Course JSON-LD for the learn index page */
export const courseJsonLd: Record<string, unknown> = {
	"@context": "https://schema.org",
	"@type": "Course",
	"@id": `${DOMAIN}/#course`,
	name: "Learn OpenID Federation 1.0",
	description:
		"Interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design, with hands-on exercises and spec-accurate references.",
	url: DOMAIN,
	provider: { "@id": "https://oidfed.com/#organization" },
	inLanguage: "en",
	isAccessibleForFree: true,
	educationalLevel: "Intermediate",
	teaches: [
		"Trust Anchor",
		"Entity Configuration",
		"Subordinate Statement",
		"Trust Chain",
		"Metadata Policy",
		"Trust Mark",
		"Federation Endpoints",
		"Automatic Client Registration",
		"Explicit Client Registration",
		"Federation Topology Design",
	],
	hasCourseInstance: {
		"@type": "CourseInstance",
		"@id": `${DOMAIN}/#course-instance`,
		courseMode: "online",
		courseWorkload: "PT3H",
	},
	syllabusSections: LESSONS.map((lesson) => ({
		"@type": "Syllabus",
		name: `Lesson ${lesson.number} — ${lesson.title}`,
		description: lesson.description,
		url: `${DOMAIN}${lessonPath(lesson.slug)}`,
	})),
};

export function lessonJsonLd(lesson: LessonMeta): Record<string, unknown>[] {
	const url = `${DOMAIN}${lessonPath(lesson.slug)}`;
	return [
		{
			"@context": "https://schema.org",
			"@type": "LearningResource",
			"@id": `${url}#learning-resource`,
			name: `Lesson ${lesson.number} — ${lesson.title}`,
			description: lesson.description,
			url,
			inLanguage: "en",
			isAccessibleForFree: true,
			educationalLevel: "Intermediate",
			learningResourceType: "Lesson",
			about: { "@type": "Thing", name: lesson.keyConcept },
			isPartOf: { "@id": `${DOMAIN}/#course` },
			provider: { "@id": "https://oidfed.com/#organization" },
		},
		{
			"@context": "https://schema.org",
			"@type": "Article",
			"@id": `${url}#article`,
			headline: `${lesson.title} — Learn OpenID Federation`,
			description: lesson.description,
			url,
			articleSection: lesson.phase,
			author: {
				"@type": "Person",
				name: "Justin Dah-kenangnon",
				url: "https://github.com/Dahkenangnon",
			},
			publisher: { "@id": "https://oidfed.com/#organization" },
			inLanguage: "en",
			keywords: [
				"OpenID Federation",
				"OpenID Federation 1.0",
				lesson.keyConcept,
				"identity",
				"trust",
			],
		},
		{
			"@context": "https://schema.org",
			"@type": "BreadcrumbList",
			itemListElement: [
				{
					"@type": "ListItem",
					position: 1,
					name: "Learn OpenID Federation",
					item: DOMAIN,
				},
				{
					"@type": "ListItem",
					position: 2,
					name: "Lessons",
					item: `${DOMAIN}/lessons`,
				},
				{
					"@type": "ListItem",
					position: 3,
					name: lesson.title,
					item: url,
				},
			],
		},
	];
}
