import { Button } from "@oidfed/ui";
import { AlertCircle, X } from "lucide-react";
import type { WalkProgress } from "../types";

interface SubtreeWalkerProps {
	readonly progress: WalkProgress | null;
	readonly onCancel: () => void;
	readonly error?: string | null;
}

export function SubtreeWalker({ progress, onCancel, error }: SubtreeWalkerProps) {
	if (error) {
		return (
			<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 flex items-center gap-3">
				<AlertCircle className="size-4 text-destructive shrink-0" />
				<span className="text-sm flex-1 min-w-0 truncate text-destructive">{error}</span>
				<Button variant="outline" size="sm" onClick={onCancel}>
					<X className="size-3.5 mr-1" />
					Dismiss
				</Button>
			</div>
		);
	}

	if (!progress) return null;

	return (
		<div className="rounded-lg border bg-muted/50 p-3 flex items-center gap-3">
			<div className="flex-1 min-w-0 space-y-1">
				<div className="flex items-center gap-2">
					<div className="size-2 rounded-full bg-blue-500 animate-pulse shrink-0" />
					<span className="text-sm font-medium">
						Walking subtree: {progress.done} entities discovered…
					</span>
				</div>
				<p className="text-xs text-muted-foreground font-mono truncate">
					Current: {progress.current}
				</p>
				<div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
					<div
						className="h-full bg-blue-500 transition-all duration-300"
						style={{
							width:
								progress.total > 0
									? `${Math.min(100, (progress.done / progress.total) * 100)}%`
									: "10%",
							animation:
								progress.total === 0 ? "indeterminate 1.5s ease-in-out infinite" : undefined,
						}}
					/>
				</div>
			</div>
			<Button variant="outline" size="sm" onClick={onCancel}>
				<X className="size-3.5 mr-1" />
				Cancel
			</Button>
		</div>
	);
}
