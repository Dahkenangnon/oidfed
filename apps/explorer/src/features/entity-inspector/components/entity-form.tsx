import { Button, Input } from "@oidfed/ui";
import { RefreshCw, Search, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { loadRecentEntities } from "@/lib/settings";

interface EntityFormProps {
	readonly initialEntityId?: string | undefined;
	readonly loading?: boolean | undefined;
	readonly onRefetch?: (() => void) | undefined;
}

export function EntityForm({ initialEntityId, loading, onRefetch }: EntityFormProps) {
	const [value, setValue] = useState(initialEntityId ?? "");
	const navigate = useNavigate();
	const [showRecent, setShowRecent] = useState(false);
	const recent = loadRecentEntities();

	useEffect(() => {
		if (initialEntityId) setValue(initialEntityId);
	}, [initialEntityId]);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmed = value.trim();
			if (trimmed) {
				navigate(`/entity/${encodeURIComponent(trimmed)}`);
			}
		},
		[value, navigate],
	);

	const handleSelectRecent = useCallback(
		(entityId: string) => {
			setValue(entityId);
			setShowRecent(false);
			navigate(`/entity/${encodeURIComponent(entityId)}`);
		},
		[navigate],
	);

	return (
		<div className="space-y-2">
			<form onSubmit={handleSubmit} className="flex gap-2">
				<div className="relative flex-1">
					<Input
						type="url"
						placeholder="https://example.com — Enter Entity ID"
						value={value}
						onChange={(e) => setValue(e.target.value)}
						onFocus={() => setShowRecent(true)}
						onBlur={() => setTimeout(() => setShowRecent(false), 200)}
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
					Fetch
				</Button>
				{initialEntityId && onRefetch && (
					<Button type="button" variant="outline" onClick={onRefetch} disabled={loading}>
						<RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
					</Button>
				)}
			</form>

			{showRecent && recent.length > 0 && (
				<div className="rounded-lg border bg-popover p-2 shadow-md">
					<p className="px-2 pb-1 text-xs font-medium text-muted-foreground">Recent</p>
					{recent.slice(0, 5).map((r) => (
						<button
							key={r.entityId}
							type="button"
							onMouseDown={() => handleSelectRecent(r.entityId)}
							className="w-full rounded px-2 py-1.5 text-left text-sm font-mono hover:bg-accent truncate"
						>
							{r.entityId}
						</button>
					))}
				</div>
			)}
		</div>
	);
}
