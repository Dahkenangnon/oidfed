import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { INSTALL } from "../lib/links";

export function InstallCommand({
	command = INSTALL,
	label = "install command",
}: {
	command?: string;
	label?: string;
}) {
	return (
		<div className="grid w-fit max-w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-2 rounded-lg border border-border bg-background px-3 py-1.5">
			<code className="wrap-break-word text-xs leading-relaxed">{command}</code>
			<CopyButton text={command} label={label} />
		</div>
	);
}

export function CopyButton({ text, label }: { text: string; label: string }) {
	const [status, setStatus] = useState("idle");

	async function copy() {
		try {
			await navigator.clipboard.writeText(text);
			setStatus("copied");
		} catch {
			setStatus("failed");
		}
	}

	return (
		<>
			<button
				type="button"
				onClick={copy}
				aria-label={`Copy ${label}`}
				className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
			>
				{status === "copied" ? (
					<Check aria-hidden className="size-3.5" />
				) : (
					<Copy aria-hidden className="size-3.5" />
				)}
				{status === "copied" ? "Copied" : "Copy"}
			</button>
			<span
				role="status"
				className={status === "failed" ? "col-span-full text-xs text-muted-foreground" : "sr-only"}
			>
				{status === "copied"
					? "Copied to clipboard."
					: status === "failed"
						? "Select the text to copy it."
						: ""}
			</span>
		</>
	);
}
