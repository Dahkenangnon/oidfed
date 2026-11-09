import { isValidEntityId } from "@oidfed/core";
import { Button, Input, Label, Textarea } from "@oidfed/ui";
import { RefreshCw, Search, X } from "lucide-react";
import { useCallback, useState } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";

interface TrustMarkInputProps {
	readonly loading?: boolean;
	readonly onSubmit: (jwt: string, expectedSubject: string) => void;
}

function normalizeJwt(value: string): string {
	return value.replace(/\s+/g, "");
}

function isJwtLike(value: string): boolean {
	return value.split(".").length === 3;
}

export function TrustMarkInput({ loading, onSubmit }: TrustMarkInputProps) {
	const [value, setValue] = useLocalStorage("oidfed-explorer-trust-mark-input-value", "");
	const [subject, setSubject] = useState("");
	const subjectValid = isValidEntityId(subject);
	const normalized = normalizeJwt(value);
	const hasContent = normalized.length > 0;
	const isValid = isJwtLike(normalized);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			if (isValid && subjectValid) onSubmit(normalized, subject);
		},
		[normalized, isValid, subjectValid, subject, onSubmit],
	);

	return (
		<form onSubmit={handleSubmit} className="space-y-3">
			<div className="space-y-2">
				<Label htmlFor="trust-mark-subject">Expected subject Entity ID</Label>
				<Input
					id="trust-mark-subject"
					type="url"
					required
					value={subject}
					onChange={(e) => setSubject(e.target.value)}
					placeholder="https://member.example.com"
					aria-describedby="trust-mark-subject-help"
				/>
				<p id="trust-mark-subject-help" className="text-xs text-muted-foreground">
					Enter the entity whose Trust Mark you want to verify.
				</p>
			</div>
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

			<Button type="submit" disabled={!isValid || !subjectValid || loading}>
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
