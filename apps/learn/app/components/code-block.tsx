import { cn } from "@oidfed/ui";
import { Check, Copy, FileCode } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";

type Language = "json" | "typescript" | "javascript" | "bash" | "http" | "text";

interface CodeBlockProps {
	children: string;
	lang?: Language | undefined;
	filename?: string | undefined;
	/** If true, suppress the top chrome bar (filename + lang + copy). */
	bare?: boolean | undefined;
	className?: string | undefined;
}

interface Token {
	content: string;
	color?: string;
}

interface TokenResult {
	light: Token[][];
	dark: Token[][];
}

let highlighterPromise: Promise<unknown> | null = null;

async function getHighlighter() {
	if (!highlighterPromise) {
		highlighterPromise = import("shiki").then((shiki) =>
			shiki.createHighlighter({
				themes: ["github-dark-dimmed", "github-light"],
				langs: ["json", "typescript", "javascript", "bash", "http"],
			}),
		);
	}
	return highlighterPromise;
}

async function tokenize(code: string, lang: Language): Promise<TokenResult | null> {
	if (lang === "text") return null;
	try {
		// biome-ignore lint/suspicious/noExplicitAny: shiki highlighter has complex types
		const shiki = (await getHighlighter()) as any;
		const lightTokens = shiki.codeToTokens(code, { lang, theme: "github-light" });
		const darkTokens = shiki.codeToTokens(code, { lang, theme: "github-dark-dimmed" });
		return {
			light: lightTokens.tokens as Token[][],
			dark: darkTokens.tokens as Token[][],
		};
	} catch {
		return null;
	}
}

/**
 * Syntax-highlighted code block with a top bar (filename + language chip + copy button).
 * Highlighting is performed on the client after hydration via shiki's `codeToTokens`
 * (no dangerouslySetInnerHTML — tokens are rendered as React nodes). Prerendered output
 * shows a plain <pre>.
 */
export function CodeBlock({
	children,
	lang = "text",
	filename,
	bare = false,
	className,
}: CodeBlockProps) {
	const code = children.replace(/\n+$/, "");
	const [tokens, setTokens] = useState<TokenResult | null>(null);
	const [copied, setCopied] = useState(false);

	useEffect(() => {
		let cancelled = false;
		tokenize(code, lang).then((result) => {
			if (!cancelled) setTokens(result);
		});
		return () => {
			cancelled = true;
		};
	}, [code, lang]);

	const handleCopy = useCallback(() => {
		if (typeof navigator === "undefined" || !navigator.clipboard) return;
		navigator.clipboard.writeText(code).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}, [code]);

	return (
		<div
			className={cn(
				"not-prose my-6 overflow-hidden rounded-xl border border-border/60 bg-[#f6f8fa] dark:bg-[#22272e]",
				className,
			)}
		>
			{!bare && (
				<div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
					<div className="flex min-w-0 items-center gap-2">
						<FileCode className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
						<span className="truncate font-mono text-[11px] text-muted-foreground">
							{filename ?? lang}
						</span>
					</div>
					<div className="flex items-center gap-2">
						<span className="rounded-sm border border-border/60 bg-background/60 px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground">
							{lang}
						</span>
						<button
							type="button"
							onClick={handleCopy}
							aria-label={copied ? "Copied" : "Copy code to clipboard"}
							className="inline-flex size-6 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
						>
							{copied ? (
								<Check className="size-3.5 text-emerald-500" />
							) : (
								<Copy className="size-3.5" />
							)}
						</button>
					</div>
				</div>
			)}
			{tokens ? (
				<>
					<TokenPre lines={tokens.light} className="block dark:hidden" />
					<TokenPre lines={tokens.dark} className="hidden dark:block" />
				</>
			) : (
				<pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed">
					<code>{code}</code>
				</pre>
			)}
		</div>
	);
}

function TokenPre({ lines, className }: { lines: Token[][]; className: string }) {
	return (
		<pre
			className={cn(
				"overflow-x-auto p-4 font-mono text-[13px] leading-relaxed",
				className,
			)}
		>
			<code>
				{lines.map((line, i) => {
					const lineKey = `line-${i}-${line.map((t) => t.content).join("").slice(0, 20)}`;
					return (
						<div key={lineKey}>
							{line.length === 0 ? (
								"\n"
							) : (
								line.map((tok, j) => (
									<span
										key={`tok-${i}-${j}-${tok.content.slice(0, 10)}`}
										style={tok.color ? { color: tok.color } : undefined}
									>
										{tok.content}
									</span>
								))
							)}
						</div>
					);
				})}
			</code>
		</pre>
	);
}

/**
 * Lightweight inline code wrapper that keeps the same visual weight as prose `<code>` but
 * works outside the prose container (where Tailwind typography defaults no longer apply).
 */
export function InlineCode({ children }: { children: ReactNode }) {
	return (
		<code className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[13px] tracking-tight text-foreground">
			{children}
		</code>
	);
}
