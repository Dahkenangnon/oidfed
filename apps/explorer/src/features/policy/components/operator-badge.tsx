import { PolicyOperator, type PolicyOperatorDefinition } from "@oidfed/core";
import { Badge } from "@oidfed/ui";

const operatorStyles: Record<string, { color: string; order: number }> = {
	[PolicyOperator.Value]: {
		color: "bg-purple-500/10 text-purple-700 border-purple-500/20 dark:text-purple-300",
		order: 1,
	},
	[PolicyOperator.Add]: {
		color: "bg-blue-500/10 text-blue-700 border-blue-500/20 dark:text-blue-300",
		order: 2,
	},
	[PolicyOperator.Default]: {
		color: "bg-gray-500/10 text-gray-700 border-gray-500/20 dark:text-gray-300",
		order: 3,
	},
	[PolicyOperator.OneOf]: {
		color: "bg-amber-500/10 text-amber-700 border-amber-500/20 dark:text-amber-300",
		order: 4,
	},
	[PolicyOperator.SubsetOf]: {
		color: "bg-teal-500/10 text-teal-700 border-teal-500/20 dark:text-teal-300",
		order: 5,
	},
	[PolicyOperator.SupersetOf]: {
		color: "bg-green-500/10 text-green-700 border-green-500/20 dark:text-green-300",
		order: 6,
	},
	[PolicyOperator.Essential]: {
		color: "bg-red-500/10 text-red-700 border-red-500/20 dark:text-red-300",
		order: 7,
	},
};

interface OperatorBadgeProps {
	readonly name: string;
	readonly value: unknown;
	readonly definition?: PolicyOperatorDefinition | undefined;
	readonly hasConflict?: boolean | undefined;
}

export function OperatorBadge({ name, value, definition, hasConflict }: OperatorBadgeProps) {
	const style = operatorStyles[name];
	const order = style?.order ?? definition?.order ?? "?";
	const action = definition?.action ?? "unknown";

	const actionLabel =
		action === "modify"
			? "modifies"
			: action === "check"
				? "checks"
				: action === "both"
					? "modifies & checks"
					: action;

	const colorClass = hasConflict
		? "bg-destructive/10 text-destructive-foreground border-destructive/20"
		: (style?.color ?? "bg-muted text-muted-foreground");

	return (
		<span className="inline-flex items-center gap-1" title={`Order: ${order} — ${actionLabel}`}>
			<Badge variant="outline" className={`text-xs ${colorClass}`}>
				<span className="opacity-60 mr-0.5">{order}</span>
				{name}
			</Badge>
			<span className="text-xs text-muted-foreground font-mono max-w-48 truncate">
				{formatValue(value)}
			</span>
		</span>
	);
}

function formatValue(value: unknown): string {
	if (value === true || value === false) return String(value);
	if (typeof value === "string") return `"${value}"`;
	if (Array.isArray(value)) return `[${value.map((v) => formatValue(v)).join(", ")}]`;
	return JSON.stringify(value);
}
