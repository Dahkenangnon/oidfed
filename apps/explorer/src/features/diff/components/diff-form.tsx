import { Button, Input, Label } from "@oidfed/ui";
import { Search, X } from "lucide-react";
import { useCallback } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";

interface DiffParams {
	readonly entityId: string;
	readonly taA: string;
	readonly taB: string;
}

interface DiffFormProps {
	readonly loading?: boolean;
	readonly onSubmit: (params: DiffParams) => void;
}

export function DiffForm({ loading, onSubmit }: DiffFormProps) {
	const [entityId, setEntityId] = useLocalStorage("oidfed-explorer-diff-entityId", "");
	const [taA, setTaA] = useLocalStorage("oidfed-explorer-diff-taA", "");
	const [taB, setTaB] = useLocalStorage("oidfed-explorer-diff-taB", "");

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const trimmedEntity = entityId.trim();
			const trimmedA = taA.trim();
			const trimmedB = taB.trim();
			if (trimmedEntity && trimmedA && trimmedB) {
				onSubmit({ entityId: trimmedEntity, taA: trimmedA, taB: trimmedB });
			}
		},
		[entityId, taA, taB, onSubmit],
	);

	const canSubmit = entityId.trim() && taA.trim() && taB.trim() && !loading;

	return (
		<form onSubmit={handleSubmit} className="space-y-4">
			<div className="space-y-2">
				<Label htmlFor="diff-entity-id">Entity ID</Label>
				<div className="relative">
					<Input
						id="diff-entity-id"
						type="url"
						placeholder="https://leaf.example.com"
						value={entityId}
						onChange={(e) => setEntityId(e.target.value)}
						className="pr-8"
					/>
					{entityId && (
						<button
							type="button"
							onClick={() => setEntityId("")}
							className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
						>
							<X className="size-4" />
						</button>
					)}
				</div>
			</div>

			<div className="grid grid-cols-2 gap-4">
				<div className="space-y-2">
					<Label htmlFor="diff-ta-a">Trust Anchor A</Label>
					<div className="relative">
						<Input
							id="diff-ta-a"
							type="url"
							placeholder="https://ta-a.example.com"
							value={taA}
							onChange={(e) => setTaA(e.target.value)}
							className="pr-8"
						/>
						{taA && (
							<button
								type="button"
								onClick={() => setTaA("")}
								className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
							>
								<X className="size-4" />
							</button>
						)}
					</div>
				</div>

				<div className="space-y-2">
					<Label htmlFor="diff-ta-b">Trust Anchor B</Label>
					<div className="relative">
						<Input
							id="diff-ta-b"
							type="url"
							placeholder="https://ta-b.example.com"
							value={taB}
							onChange={(e) => setTaB(e.target.value)}
							className="pr-8"
						/>
						{taB && (
							<button
								type="button"
								onClick={() => setTaB("")}
								className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
							>
								<X className="size-4" />
							</button>
						)}
					</div>
				</div>
			</div>

			<Button type="submit" disabled={!canSubmit}>
				<Search className="mr-2 size-4" />
				Compare
			</Button>
		</form>
	);
}
