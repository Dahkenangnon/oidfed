import { createHighlighterCoreSync } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import bash from "shiki/langs/bash.mjs";
import json from "shiki/langs/json.mjs";
import mermaid from "shiki/langs/mermaid.mjs";
import typescript from "shiki/langs/typescript.mjs";
import yaml from "shiki/langs/yaml.mjs";
import dark from "shiki/themes/github-dark-dimmed.mjs";
import light from "shiki/themes/github-light.mjs";

const highlighter = createHighlighterCoreSync({
	engine: createJavaScriptRegexEngine(),
	langs: [bash, json, mermaid, typescript, yaml],
	themes: [light, dark],
});

const languages = new Set(highlighter.getLoadedLanguages());

/** Empty output asks MarkdownIt to render an escaped plaintext block. */
export function highlightCode(code: string, language: string, label?: string): string {
	if (!languages.has(language)) return "";
	return highlighter.codeToHtml(code.replace(/\n$/, ""), {
		lang: language,
		themes: { light: "github-light", dark: "github-dark-dimmed" },
		defaultColor: false,
		transformers: [
			{
				pre(node) {
					if (label) node.properties["aria-label"] = label;
				},
				code(node) {
					this.addClassToHast(node, `language-${language}`);
				},
			},
		],
	});
}
