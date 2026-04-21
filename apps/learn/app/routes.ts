import { index, layout, prefix, type RouteConfig, route } from "@react-router/dev/routes";

export default [
	index("routes/home.tsx"),
	route("resources", "routes/resources.tsx"),
	layout("routes/lessons/layout.tsx", [
		...prefix("lessons", [
			index("routes/lessons/index.tsx"),
			route("what-is-federation", "routes/lessons/lesson-01.tsx"),
			route("entities-and-roles", "routes/lessons/lesson-02.tsx"),
			route("entity-statements", "routes/lessons/lesson-03.tsx"),
			route("trust-chains", "routes/lessons/lesson-04.tsx"),
			route("trust-chain-resolution", "routes/lessons/lesson-05.tsx"),
			route("metadata-and-policy", "routes/lessons/lesson-06.tsx"),
			route("trust-marks", "routes/lessons/lesson-07.tsx"),
			route("federation-endpoints", "routes/lessons/lesson-08.tsx"),
			route("client-registration", "routes/lessons/lesson-09.tsx"),
			route("putting-it-together", "routes/lessons/lesson-10.tsx"),
			route("topology-design", "routes/lessons/lesson-11.tsx"),
			route("faq", "routes/lessons/lesson-12.tsx"),
			route("glossary", "routes/lessons/lesson-13.tsx"),
			route("real-use-cases", "routes/lessons/lesson-14.tsx"),
			route("hands-on-objects", "routes/lessons/lesson-15.tsx"),
		]),
	]),
] satisfies RouteConfig;
