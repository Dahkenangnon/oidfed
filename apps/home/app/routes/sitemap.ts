import { prerenderedPages } from "../lib/docs.server";
import { DOMAIN } from "../lib/seo";

export function loader() {
	const locations = prerenderedPages
		.map((path) => `\t<url><loc>${DOMAIN}${path}</loc></url>`)
		.join("\n");
	return new Response(
		`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${locations}\n</urlset>\n`,
		{ headers: { "Content-Type": "application/xml; charset=utf-8" } },
	);
}
