import { index, layout, type RouteConfig, route } from "@react-router/dev/routes";

export default [
	route("sitemap.xml", "routes/sitemap.ts"),
	layout("routes/layout.tsx", [
		index("routes/home.tsx"),
		route("docs/*", "routes/docs.tsx"),
		route("ecosystem", "routes/ecosystem.tsx"),
		route("trust-journal", "routes/trust-journal.tsx"),
		route("about", "routes/about.tsx"),
		route("*", "routes/not-found.tsx"),
	]),
] satisfies RouteConfig;
