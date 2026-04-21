import { Button, Input, Label } from "@oidfed/ui";
import { Plus, RefreshCw, Search, X } from "lucide-react";
import { useCallback, useState } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";
import type { ResolveQueryParams } from "../hooks/use-resolve-query";

interface ResolveFormProps {
	readonly loading?: boolean;
	readonly onSubmit: (params: ResolveQueryParams) => void;
}

function ClearableInput({
	id,
	label,
	placeholder,
	value,
	onChange,
	type = "url",
	required = false,
}: {
	readonly id: string;
	readonly label: string;
	readonly placeholder: string;
	readonly value: string;
	readonly onChange: (v: string) => void;
	readonly type?: string;
	readonly required?: boolean;
}) {
	return (
		<div className="space-y-2">
			<Label htmlFor={id}>
				{label}
				{required && <span className="ml-1 text-destructive-foreground">*</span>}
			</Label>
			<div className="relative">
				<Input
					id={id}
					type={type}
					placeholder={placeholder}
					value={value}
					onChange={(e) => onChange(e.target.value)}
					className="pr-8"
				/>
				{value && (
					<button
						type="button"
						onClick={() => onChange("")}
						className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
					>
						<X className="size-4" />
					</button>
				)}
			</div>
		</div>
	);
}

function extractHostname(entityId: string): string {
	try {
		return new URL(entityId).hostname;
	} catch {
		return entityId;
	}
}

export function ResolveForm({ loading, onSubmit }: ResolveFormProps) {
	const [resolverEntityId, setResolverEntityId] = useLocalStorage(
		"oidfed-explorer-resolve-resolverEntityId",
		"",
	);
	const [subject, setSubject] = useLocalStorage("oidfed-explorer-resolve-subject", "");
	const [taInput, setTaInput] = useState("");
	const [trustAnchors, setTrustAnchors] = useLocalStorage<readonly string[]>(
		"oidfed-explorer-resolve-trustAnchors",
		[],
	);
	const [entityType, setEntityType] = useLocalStorage("oidfed-explorer-resolve-entityType", "");

	const canSubmit =
		resolverEntityId.trim() && subject.trim() && trustAnchors.length > 0 && !loading;

	const addTA = useCallback(() => {
		const trimmed = taInput.trim();
		if (!trimmed) return;
		if (trustAnchors.includes(trimmed)) return;
		setTrustAnchors([...trustAnchors, trimmed]);
		setTaInput("");
	}, [taInput, trustAnchors, setTrustAnchors]);

	const removeTA = useCallback(
		(ta: string) => {
			setTrustAnchors(trustAnchors.filter((t) => t !== ta));
		},
		[trustAnchors, setTrustAnchors],
	);

	const handleSubmit = useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();
			if (!canSubmit) return;

			onSubmit({
				resolverEntityId: resolverEntityId.trim(),
				subject: subject.trim(),
				trustAnchors,
				entityType: entityType.trim() || undefined,
			});
		},
		[resolverEntityId, subject, trustAnchors, entityType, canSubmit, onSubmit],
	);

	return (
		<form onSubmit={handleSubmit} className="space-y-4">
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
				<ClearableInput
					id="resolve-resolver"
					label="Resolver entity ID"
					placeholder="https://resolver.example.com"
					value={resolverEntityId}
					onChange={setResolverEntityId}
					required
				/>
				<ClearableInput
					id="resolve-subject"
					label="Subject entity ID"
					placeholder="https://leaf.example.com"
					value={subject}
					onChange={setSubject}
					required
				/>
			</div>

			{/* Trust anchor input */}
			<div className="space-y-2">
				<Label>
					Trust anchors <span className="ml-1 text-destructive-foreground">*</span>
				</Label>
				<p className="text-xs text-muted-foreground">
					Enter one trust anchor to resolve, or add multiple to compare results side-by-side.
				</p>

				<div className="flex gap-2">
					<Input
						type="url"
						placeholder="https://ta.example.com"
						value={taInput}
						onChange={(e) => setTaInput(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") {
								e.preventDefault();
								addTA();
							}
						}}
						className="flex-1"
					/>
					<Button
						type="button"
						variant="outline"
						size="icon"
						onClick={addTA}
						disabled={!taInput.trim()}
					>
						<Plus className="size-4" />
					</Button>
				</div>

				{trustAnchors.length > 0 && (
					<div className="flex flex-wrap gap-1.5">
						{trustAnchors.map((ta) => (
							<span
								key={ta}
								className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-1 text-xs font-mono"
							>
								{extractHostname(ta)}
								<button
									type="button"
									onClick={() => removeTA(ta)}
									className="text-muted-foreground hover:text-foreground"
								>
									<X className="size-3" />
								</button>
							</span>
						))}
					</div>
				)}
			</div>

			<ClearableInput
				id="resolve-type"
				label="Entity type filter (optional)"
				placeholder="e.g. openid_provider"
				value={entityType}
				onChange={setEntityType}
				type="text"
			/>

			<Button type="submit" disabled={!canSubmit}>
				{loading ? (
					<RefreshCw className="mr-2 size-4 animate-spin" />
				) : (
					<Search className="mr-2 size-4" />
				)}
				Resolve{trustAnchors.length > 1 ? ` (${trustAnchors.length} TAs)` : ""}
			</Button>
		</form>
	);
}
