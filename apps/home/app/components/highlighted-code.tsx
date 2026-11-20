export function HighlightedCode({ html, className }: { html: string; className?: string }) {
	// biome-ignore lint/security/noDangerouslySetInnerHtml: the server highlighter escapes code before producing markup
	return <div className={className} dangerouslySetInnerHTML={{ __html: html }} />;
}
