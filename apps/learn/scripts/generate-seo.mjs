#!/usr/bin/env node
/**
 * Generates apps/learn/public/{sitemap.xml,llms.txt} from the LESSONS
 * registry in apps/learn/app/lib/seo.ts. Keeps the three sources of lesson
 * metadata (prerender config, sitemap, llms.txt) from drifting.
 *
 * Run via `pnpm --filter @oidfed/learn build` (wired into the package `build`
 * script) or standalone: `node apps/learn/scripts/generate-seo.mjs`.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const APP_ROOT = resolve(__dirname, "..");
const PUBLIC = resolve(APP_ROOT, "public");
const DOMAIN = "https://learn.oidfed.com";

// Parse LESSONS out of seo.ts without a TS compiler. We rely on the well-known
// shape { slug: "...", number: N, title: "...", description: "..." } and only
// grab the slug/number/title/description fields we need here.
const seoSource = readFileSync(resolve(APP_ROOT, "app/lib/seo.ts"), "utf8");
const lessonBlocksMatch = seoSource.match(/export const LESSONS:[^\[]*\[([\s\S]*?)\]\s*;/);
if (!lessonBlocksMatch) {
	throw new Error("Could not locate LESSONS export in app/lib/seo.ts");
}
const block = lessonBlocksMatch[1];

const lessons = [];
const entryRegex = /\{\s*slug:\s*"([^"]+)",\s*number:\s*(\d+),\s*title:\s*"([^"]+)",\s*description:\s*"([^"]+)"[\s\S]*?\}/g;
for (const m of block.matchAll(entryRegex)) {
	lessons.push({ slug: m[1], number: Number(m[2]), title: m[3], description: m[4] });
}
if (lessons.length !== 15) {
	throw new Error(`Expected 15 lessons, parsed ${lessons.length}. Regex needs updating.`);
}

// ── sitemap.xml ────────────────────────────────────────────────────────────
const staticUrls = [
	{ loc: `${DOMAIN}/`, changefreq: "weekly", priority: "1.0" },
	{ loc: `${DOMAIN}/lessons`, changefreq: "monthly", priority: "0.8" },
];
const lessonUrls = lessons.map((l) => ({
	loc: `${DOMAIN}/lessons/${l.slug}`,
	changefreq: "monthly",
	priority: "0.9",
}));
const urls = [...staticUrls, ...lessonUrls];
const sitemap =
	`<?xml version="1.0" encoding="UTF-8"?>\n` +
	`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
	urls
		.map(
			(u) =>
				`\t<url>\n\t\t<loc>${u.loc}</loc>\n\t\t<changefreq>${u.changefreq}</changefreq>\n\t\t<priority>${u.priority}</priority>\n\t</url>`,
		)
		.join("\n") +
	"\n</urlset>\n";
writeFileSync(resolve(PUBLIC, "sitemap.xml"), sitemap);
console.log(`[seo] wrote sitemap.xml (${urls.length} urls)`);

// ── robots.txt ─────────────────────────────────────────────────────────────
const robots = `User-agent: *\nAllow: /\n\nSitemap: ${DOMAIN}/sitemap.xml\n`;
writeFileSync(resolve(PUBLIC, "robots.txt"), robots);
console.log(`[seo] wrote robots.txt`);

// ── llms.txt ───────────────────────────────────────────────────────────────
const llmsLines = [
	`# Learn OpenID Federation`,
	``,
	`> Interactive OpenID Federation 1.0 course — 15 lessons from first principles to federation topology design, with hands-on exercises and spec-accurate references.`,
	``,
	`## About`,
	``,
	`This is the canonical educational resource for @oidfed. It is not the @oidfed project home and it is not the @oidfed explorer.`,
	``,
	`- @oidfed project home: https://oidfed.com`,
	`- @oidfed federation explorer (tool): https://explore.oidfed.com`,
	`- Source code: https://github.com/Dahkenangnon/oidfed`,
	``,
	`## Lessons`,
	``,
	...lessons.map(
		(l) => `- [Lesson ${l.number} — ${l.title}](${DOMAIN}/lessons/${l.slug}): ${l.description}`,
	),
	``,
	`## Related`,
	``,
	`- [OpenID Federation 1.0 specification](https://openid.net/specs/openid-federation-1_0.html) — the authoritative protocol definition this course teaches.`,
	`- [OpenID Federation 1.1 (draft)](https://openid.net/specs/openid-federation-1_1.html) — protocol-independent successor layer.`,
	`- [OpenID Federation for OpenID Connect 1.1 (draft)](https://openid.net/specs/openid-federation-connect-1_1.html) — protocol-specific successor layer.`,
	``,
	`## Project Metadata`,
	``,
	`- Author: Justin Dah-kenangnon (https://github.com/Dahkenangnon)`,
	`- License: MIT`,
	`- Machine-readable project overview: https://oidfed.com/llms.txt`,
	``,
];
writeFileSync(resolve(PUBLIC, "llms.txt"), llmsLines.join("\n"));
console.log(`[seo] wrote llms.txt`);
