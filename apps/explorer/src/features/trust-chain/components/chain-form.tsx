import { Button, Input } from "@oidfed/ui";
import { RefreshCw, Search, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";

interface ChainFormProps {
	readonly initialEntityId?: string | undefined;
	readonly loading?: boolean | undefined;
	readonly onRefetch?: (() => void) | undefined;
}

export function ChainForm({ initialEntityId, loading, onRefetch }: ChainFormProps) {
	const [value, setValue] = useState(initialEntityId ?? "");
	const navigate = useNavigate();

	useEffect(() => {
		if (initialEntityId) setValue(initialEntityId);
	}, [initialEntityId]);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmed = value.trim();
			if (trimmed) {
				navigate(`/chain/${encodeURIComponent(trimmed)}`);
			}
		},
		[value, navigate],
	);

	return (
		<form onSubmit={handleSubmit} className="flex gap-2">
			<div className="relative flex-1">
				<Input
					type="url"
					placeholder="https://example.com — Enter Entity ID to resolve trust chains"
					value={value}
					onChange={(e) => setValue(e.target.value)}
					className="pr-8"
				/>
				{value && (
					<button
						type="button"
						onClick={() => setValue("")}
						className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
					>
						<X className="size-4" />
					</button>
				)}
			</div>
			<Button type="submit" disabled={!value.trim() || loading}>
				<Search className="mr-2 size-4" />
				Resolve
			</Button>
			{initialEntityId && onRefetch && (
				<Button type="button" variant="outline" onClick={onRefetch} disabled={loading}>
					<RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
				</Button>
			)}
		</form>
	);
}
