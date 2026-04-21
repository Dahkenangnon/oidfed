import { Button, Label, Textarea } from "@oidfed/ui";
import { RefreshCw, Search, X } from "lucide-react";
import { useCallback } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";

interface TrustMarkInputProps {
	readonly loading?: boolean;
	readonly onSubmit: (jwt: string) => void;
}

function normalizeJwt(value: string): string {
	return value.replace(/\s+/g, "");
}

function isJwtLike(value: string): boolean {
	return value.split(".").length === 3;
}

export function TrustMarkInput({ loading, onSubmit }: TrustMarkInputProps) {
	const [value, setValue] = useLocalStorage("oidfed-explorer-trust-mark-input-value", "");
	const normalized = normalizeJwt(value);
	const hasContent = normalized.length > 0;
	const isValid = isJwtLike(normalized);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			if (isValid) onSubmit(normalized);
		},
		[normalized, isValid, onSubmit],
	);

	return (
		<form onSubmit={handleSubmit} className="space-y-3">
			<div className="space-y-2">
				<Label htmlFor="trust-mark-jwt">Trust Mark JWT</Label>
				<div className="relative">
					<Textarea
						id="trust-mark-jwt"
						placeholder="Paste a trust-mark+jwt here (three dot-separated base64url parts)"
						value={value}
						onChange={(e) => setValue(e.target.value)}
						className="font-mono text-xs min-h-[100px] pr-8 resize-y"
						spellCheck={false}
					/>
					{hasContent && (
						<button
							type="button"
							onClick={() => setValue("")}
							className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
						>
							<X className="size-4" />
						</button>
					)}
				</div>
				{hasContent && !isValid && (
					<p className="text-xs text-destructive-foreground">
						Not a valid JWT — expected three dot-separated parts
					</p>
				)}
			</div>

			<Button type="submit" disabled={!isValid || loading}>
				{loading ? (
					<RefreshCw className="mr-2 size-4 animate-spin" />
				) : (
					<Search className="mr-2 size-4" />
				)}
				Inspect
			</Button>
		</form>
	);
}
