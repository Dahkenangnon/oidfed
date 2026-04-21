import { index, layout, type RouteConfig, route } from "@react-router/dev/routes";

export default [
	layout("routes/layout.tsx", [
		index("routes/home.tsx"),
		route("ecosystem", "routes/ecosystem.tsx"),
		route("about", "routes/about.tsx"),
		route("*", "routes/not-found.tsx"),
	]),
] satisfies RouteConfig;
