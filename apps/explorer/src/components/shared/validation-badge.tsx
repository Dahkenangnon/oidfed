import { Badge } from "@oidfed/ui";
import { AlertTriangle, CheckCircle, XCircle } from "lucide-react";

type Status = "pass" | "fail" | "warn" | "pending";

interface ValidationBadgeProps {
	readonly status: Status;
	readonly label?: string;
}

const config = {
	pass: {
		icon: CheckCircle,
		text: "Pass",
		className: "bg-success/10 text-success-foreground border-success/20",
	},
	fail: {
		icon: XCircle,
		text: "Fail",
		className: "bg-destructive/10 text-destructive-foreground border-destructive/20",
	},
	warn: {
		icon: AlertTriangle,
		text: "Warning",
		className: "bg-warning/10 text-warning-foreground border-warning/20",
	},
	pending: { icon: AlertTriangle, text: "Pending", className: "bg-muted text-muted-foreground" },
} as const;

export function ValidationBadge({ status, label }: ValidationBadgeProps) {
	const { icon: Icon, text, className } = config[status];
	return (
		<Badge variant="outline" className={className}>
			<Icon className="mr-1 size-3" />
			{label ?? text}
		</Badge>
	);
}
