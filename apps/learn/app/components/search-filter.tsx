import { Input } from "@oidfed/ui";
import { Search } from "lucide-react";
import { useState } from "react";

export function SearchFilter<T>({
	items,
	filterFn,
	children,
	placeholder = "Search...",
}: {
	items: T[];
	filterFn: (item: T, query: string) => boolean;
	children: (filtered: T[]) => React.ReactNode;
	placeholder?: string;
}) {
	const [query, setQuery] = useState("");
	const filtered = query ? items.filter((item) => filterFn(item, query.toLowerCase())) : items;

	return (
		<div>
			<div className="relative mb-4">
				<Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
				<Input
					type="search"
					placeholder={placeholder}
					value={query}
					onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
					className="pl-9"
				/>
			</div>
			{children(filtered)}
		</div>
	);
}
