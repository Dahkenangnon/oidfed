import { Clock } from "lucide-react";

interface ChainExpirationBarProps {
	readonly expiresAt: number;
}

function formatDuration(seconds: number): string {
	if (seconds <= 0) return "Expired";
	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);

	if (days > 0) return `${days}d ${hours}h remaining`;
	if (hours > 0) return `${hours}h ${minutes}m remaining`;
	return `${minutes}m remaining`;
}

function getExpirationColor(remainingSeconds: number): string {
	if (remainingSeconds <= 0) return "bg-destructive text-destructive-foreground";
	if (remainingSeconds < 3600) return "bg-destructive/80 text-destructive-foreground";
	if (remainingSeconds < 86400) return "bg-warning/80 text-warning-foreground";
	if (remainingSeconds < 86400 * 7)
		return "border border-warning/60 bg-warning/15 text-warning-foreground";
	return "border border-success/60 bg-success/15 text-success-foreground";
}

export function ChainExpirationBar({ expiresAt }: ChainExpirationBarProps) {
	const nowSeconds = Math.floor(Date.now() / 1000);
	const remaining = expiresAt - nowSeconds;

	return (
		<div
			className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ${getExpirationColor(remaining)}`}
		>
			<Clock className="size-3" />
			<span>{formatDuration(remaining)}</span>
			<span className="opacity-70">(exp: {new Date(expiresAt * 1000).toISOString()})</span>
		</div>
	);
}
