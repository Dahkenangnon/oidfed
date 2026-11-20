import type { Config } from "@react-router/dev/config";
import { prerenderedPages } from "./app/lib/docs.server";

export default {
	ssr: false,
	prerender: [...prerenderedPages, "/sitemap.xml"],
} satisfies Config;
