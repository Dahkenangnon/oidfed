import { Button, Checkbox, Input, Label } from "@oidfed/ui";
import { useCallback, useState } from "react";
import type { SubordinateFilters } from "../hooks/use-subordinate-list";

interface SubordinateFiltersProps {
	readonly onChange: (filters: SubordinateFilters) => void;
}

export function SubordinateFiltersPanel({ onChange }: SubordinateFiltersProps) {
	const [entityType, setEntityType] = useState("");
	const [trustMarked, setTrustMarked] = useState<boolean | undefined>(undefined);
	const [intermediate, setIntermediate] = useState<boolean | undefined>(undefined);

	const handleApply = useCallback(() => {
		onChange({
			entity_type: entityType.trim() || undefined,
			trust_marked: trustMarked,
			intermediate,
		});
	}, [entityType, trustMarked, intermediate, onChange]);

	const handleReset = useCallback(() => {
		setEntityType("");
		setTrustMarked(undefined);
		setIntermediate(undefined);
		onChange({});
	}, [onChange]);

	return (
		<div className="rounded-lg border p-4 space-y-4">
			<h3 className="text-sm font-medium">Filters</h3>
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
				<div className="space-y-2">
					<Label htmlFor="filter-entity-type">Entity type</Label>
					<Input
						id="filter-entity-type"
						placeholder="e.g. openid_provider"
						value={entityType}
						onChange={(e) => setEntityType(e.target.value)}
						className="font-mono text-sm"
					/>
				</div>

				<div className="flex items-center gap-3 pt-6">
					<Checkbox
						id="filter-trust-marked"
						checked={trustMarked === true}
						onCheckedChange={(checked) => setTrustMarked(checked === true ? true : undefined)}
					/>
					<Label htmlFor="filter-trust-marked" className="cursor-pointer">
						Trust-marked only
					</Label>
				</div>

				<div className="flex items-center gap-3 pt-6">
					<Checkbox
						id="filter-intermediate"
						checked={intermediate === true}
						onCheckedChange={(checked) => setIntermediate(checked === true ? true : undefined)}
					/>
					<Label htmlFor="filter-intermediate" className="cursor-pointer">
						Intermediates only
					</Label>
				</div>
			</div>

			<div className="flex gap-2">
				<Button type="button" size="sm" onClick={handleApply}>
					Apply
				</Button>
				<Button type="button" size="sm" variant="outline" onClick={handleReset}>
					Reset
				</Button>
			</div>
		</div>
	);
}
