import { Button, Input } from "@oidfed/ui";
import { Network, Plus, X } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";
import { loadRecentEntities } from "@/lib/settings";

interface InputEntry {
	key: number;
	value: string;
}

interface TopologyFormProps {
	readonly onLoad: (entityIds: string[]) => void;
	readonly loading?: boolean;
}

export function TopologyForm({ onLoad, loading }: TopologyFormProps) {
	const [storedValues, setStoredValues] = useLocalStorage<string[]>(
		"oidfed-explorer-topology-inputs",
		[""],
	);
	const nextKeyRef = useRef(storedValues.length);
	const [inputs, setInputs] = useState<InputEntry[]>(() =>
		storedValues.map((value, i) => ({ key: i, value })),
	);
	const [showRecent, setShowRecent] = useState(false);
	const recent = loadRecentEntities();

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			const ids = inputs.map((entry) => entry.value.trim()).filter(Boolean);
			if (ids.length > 0) onLoad(ids);
		},
		[inputs, onLoad],
	);

	const persistInputs = useCallback(
		(entries: InputEntry[]) => {
			setInputs(entries);
			setStoredValues(entries.map((e) => e.value));
		},
		[setStoredValues],
	);

	const addInput = useCallback(() => {
		const key = nextKeyRef.current++;
		setInputs((prev) => {
			const next = [...prev, { key, value: "" }];
			setStoredValues(next.map((e) => e.value));
			return next;
		});
	}, [setStoredValues]);

	const removeInput = useCallback(
		(key: number) => {
			setInputs((prev) => {
				if (prev.length <= 1) return prev;
				const next = prev.filter((entry) => entry.key !== key);
				setStoredValues(next.map((e) => e.value));
				return next;
			});
		},
		[setStoredValues],
	);

	const updateInput = useCallback(
		(key: number, value: string) => {
			setInputs((prev) => {
				const next = prev.map((entry) => (entry.key === key ? { ...entry, value } : entry));
				setStoredValues(next.map((e) => e.value));
				return next;
			});
		},
		[setStoredValues],
	);

	const handleSelectRecent = useCallback(
		(entityId: string) => {
			persistInputs([{ key: 0, value: entityId }]);
			setShowRecent(false);
			onLoad([entityId]);
		},
		[onLoad, persistInputs],
	);

	const hasValidInput = inputs.some((entry) => entry.value.trim().length > 0);

	return (
		<div className="space-y-2">
			<form onSubmit={handleSubmit} className="space-y-2">
				{inputs.map((entry, index) => (
					<div key={entry.key} className="flex gap-2">
						<div className="relative flex-1">
							<Input
								type="url"
								placeholder={
									index === 0
										? "https://ta.example.com — Enter Trust Anchor Entity ID"
										: "https://ta2.example.com — Additional Trust Anchor"
								}
								value={entry.value}
								onChange={(e) => updateInput(entry.key, e.target.value)}
								onFocus={() => index === 0 && setShowRecent(true)}
								onBlur={() => setTimeout(() => setShowRecent(false), 200)}
								className="pr-8"
							/>
							{entry.value && (
								<button
									type="button"
									onClick={() => updateInput(entry.key, "")}
									className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
								>
									<X className="size-4" />
								</button>
							)}
						</div>
						{inputs.length > 1 && (
							<Button
								type="button"
								variant="ghost"
								size="icon"
								onClick={() => removeInput(entry.key)}
								className="shrink-0"
							>
								<X className="size-4" />
							</Button>
						)}
					</div>
				))}
				<div className="flex gap-2">
					<Button type="button" variant="outline" size="sm" onClick={addInput} className="text-xs">
						<Plus className="size-3.5 mr-1" />
						Add TA
					</Button>
					<div className="flex-1" />
					<Button type="submit" disabled={!hasValidInput || loading}>
						<Network className="mr-2 size-4" />
						Load Graph
					</Button>
				</div>
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
