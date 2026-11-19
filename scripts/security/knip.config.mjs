/** Public entrypoints remain roots even when no repository consumer imports them. */

import { packages } from "./scope.mjs";

export default {
	include: ["files", "exports", "types", "duplicates", "unresolved"],
	workspaces: {
		".": { entry: [], project: [] },
		...Object.fromEntries(
			packages.map((name) => [
				`packages/${name}`,
				{
					entry:
						name === "crypto" ? ["src/index.ts", "src/web.ts", "src/jose.ts"] : ["src/index.ts"],
					project: ["src/**/*.ts"],
				},
			]),
		),
	},
};
