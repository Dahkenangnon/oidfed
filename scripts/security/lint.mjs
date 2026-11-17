/** Run security lint only when every protocol package contributes analyzed source files. */

import { ESLint } from "eslint";
import { join, relative, sep } from "node:path";
import { root, sources, isPackageSource } from "./scope.mjs";

export async function lintSources() {
	const engine = new ESLint({
		cwd: root,
		overrideConfigFile: join(root, "scripts/security/eslint.config.mjs"),
	});
	const results = await engine.lintFiles(sources);
	if (results.some((result) => !isPackageSource(result.filePath)))
		throw new Error("Security lint analyzed an out-of-scope file");
	for (const source of sources) {
		if (
			!results.some((result) =>
				relative(root, result.filePath).split(sep).join("/").startsWith(`${source}/`),
			)
		)
			throw new Error(`Security lint did not analyze ${source}`);
	}
	const output = await (await engine.loadFormatter("stylish")).format(results);
	if (output) console.log(output);
	if (results.some((result) => result.errorCount || result.warningCount || result.fatalErrorCount))
		throw new Error("Security lint failed; source or scanner errors require review");
	console.log(`Security lint: ${results.length} source files across all five protocol packages`);
}
