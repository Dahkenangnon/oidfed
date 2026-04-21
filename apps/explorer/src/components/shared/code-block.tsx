import { useEffect, useState } from "react";
import { getHighlighter } from "@/lib/shiki";
import { CopyButton } from "./copy-button";

interface CodeBlockProps {
	readonly code: string;
	readonly language?: string;
	readonly className?: string;
}

export function CodeBlock({ code, language = "json", className }: CodeBlockProps) {
	const [html, setHtml] = useState<string>("");

	useEffect(() => {
		let cancelled = false;
		getHighlighter().then((highlighter) => {
			if (cancelled) return;
			const result = highlighter.codeToHtml(code, {
				lang: language,
				themes: { light: "light-plus", dark: "dark-plus" },
			});
			setHtml(result);
		});
		return () => {
			cancelled = true;
		};
	}, [code, language]);

	return (
		<div className={`relative rounded-lg border bg-code ${className ?? ""}`}>
			<CopyButton value={code} className="absolute right-2 top-2 size-7" />
			{html ? (
				<div
					className="overflow-auto p-4 text-sm [&_pre]:!bg-transparent"
					// biome-ignore lint/security/noDangerouslySetInnerHtml: shiki produces safe HTML
					dangerouslySetInnerHTML={{ __html: html }}
				/>
			) : (
				<pre className="overflow-auto p-4 text-sm font-mono text-code-foreground">{code}</pre>
			)}
		</div>
	);
}
