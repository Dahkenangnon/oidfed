import { Button, Tooltip, TooltipPopup, TooltipTrigger } from "@oidfed/ui";
import { Check, Copy } from "lucide-react";
import { useCallback, useState } from "react";

interface CopyButtonProps {
	readonly value: string;
	readonly className?: string;
}

export function CopyButton({ value, className }: CopyButtonProps) {
	const [copied, setCopied] = useState(false);

	const handleCopy = useCallback(() => {
		navigator.clipboard
			.writeText(value)
			.then(() => {
				setCopied(true);
				setTimeout(() => setCopied(false), 2000);
			})
			.catch(() => {
				/* clipboard unavailable in insecure contexts */
			});
	}, [value]);

	return (
		<Tooltip>
			<TooltipTrigger
				render={
					<Button
						variant="ghost"
						size="icon"
						className={className}
						onClick={handleCopy}
						aria-label="Copy to clipboard"
					/>
				}
			>
				{copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
			</TooltipTrigger>
			<TooltipPopup>{copied ? "Copied!" : "Copy"}</TooltipPopup>
		</Tooltip>
	);
}
