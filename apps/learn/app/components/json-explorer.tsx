import { Collapsible, CollapsiblePanel, CollapsibleTrigger } from "@oidfed/ui";
import { ChevronRight } from "lucide-react";
import { useState } from "react";

function JsonValue({ value, depth }: { value: unknown; depth: number }) {
	if (value === null) return <span className="text-muted-foreground">null</span>;
	if (typeof value === "boolean")
		return <span className="text-purple-600 dark:text-purple-400">{String(value)}</span>;
	if (typeof value === "number")
		return <span className="text-blue-600 dark:text-blue-400">{value}</span>;
	if (typeof value === "string")
		return <span className="text-emerald-600 dark:text-emerald-400">"{value}"</span>;
	if (Array.isArray(value)) return <JsonArray items={value} depth={depth} />;
	if (typeof value === "object")
		return <JsonObject obj={value as Record<string, unknown>} depth={depth} />;
	return null;
}

function JsonArray({ items, depth }: { items: unknown[]; depth: number }) {
	const [open, setOpen] = useState(depth < 2);
	if (items.length === 0) return <span>[]</span>;
	return (
		<Collapsible open={open} onOpenChange={setOpen}>
			<CollapsibleTrigger className="inline-flex items-center cursor-pointer">
				<ChevronRight className={`size-3 transition-transform ${open ? "rotate-90" : ""}`} />
				<span className="text-muted-foreground ml-1">[{!open && `${items.length} items`}</span>
			</CollapsibleTrigger>
			<CollapsiblePanel>
				<div className="ml-4 border-l border-border pl-3">
					{items.map((item, i) => (
						// biome-ignore lint/suspicious/noArrayIndexKey: JSON array items have no stable key
						<div key={i}>
							<JsonValue value={item} depth={depth + 1} />
							{i < items.length - 1 && ","}
						</div>
					))}
				</div>
			</CollapsiblePanel>
			{open && <span className="text-muted-foreground">]</span>}
		</Collapsible>
	);
}

function JsonObject({ obj, depth }: { obj: Record<string, unknown>; depth: number }) {
	const [open, setOpen] = useState(depth < 2);
	const keys = Object.keys(obj);
	if (keys.length === 0) return <span>{"{}"}</span>;
	return (
		<Collapsible open={open} onOpenChange={setOpen}>
			<CollapsibleTrigger className="inline-flex items-center cursor-pointer">
				<ChevronRight className={`size-3 transition-transform ${open ? "rotate-90" : ""}`} />
				<span className="text-muted-foreground ml-1">
					{"{"}
					{!open && `${keys.length} keys`}
				</span>
			</CollapsibleTrigger>
			<CollapsiblePanel>
				<div className="ml-4 border-l border-border pl-3">
					{keys.map((key, i) => (
						<div key={key}>
							<span className="text-red-600 dark:text-red-400">"{key}"</span>
							<span className="text-muted-foreground">: </span>
							<JsonValue value={obj[key]} depth={depth + 1} />
							{i < keys.length - 1 && ","}
						</div>
					))}
				</div>
			</CollapsiblePanel>
			{open && <span className="text-muted-foreground">{"}"}</span>}
		</Collapsible>
	);
}

export function JsonExplorer({ data }: { data: unknown }) {
	return (
		<div className="my-4 rounded-lg border border-border bg-card p-4 font-mono text-sm overflow-x-auto">
			<JsonValue value={data} depth={0} />
		</div>
	);
}
