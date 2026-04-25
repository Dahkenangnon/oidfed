import type { Config } from "@react-router/dev/config";

export default {
	ssr: false,
	prerender: [
		"/",
		"/lessons",
		"/lessons/what-is-federation",
		"/lessons/entities-and-roles",
		"/lessons/entity-statements",
		"/lessons/trust-chains",
		"/lessons/trust-chain-resolution",
		"/lessons/metadata-and-policy",
		"/lessons/trust-marks",
		"/lessons/federation-endpoints",
		"/lessons/client-registration",
		"/lessons/putting-it-together",
		"/lessons/topology-design",
		"/lessons/faq",
		"/lessons/glossary",
		"/lessons/real-use-cases",
		"/lessons/hands-on-objects",
	],
} satisfies Config;
