import { Button, Label, Textarea } from "@oidfed/ui";
import { useState } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";

interface PolicyInputs {
	metadata: Record<string, unknown>;
	policyLevels: Record<string, unknown>[];
	metadataPolicyCrit?: string[] | undefined;
}

interface PolicyInputFormProps {
	onChange: (inputs: PolicyInputs | null) => void;
}

let nextId = 0;
function newField(): FieldState {
	return { id: nextId++, raw: "", error: null, parsed: null };
}

interface FieldState {
	id: number;
	raw: string;
	error: string | null;
	parsed: Record<string, unknown> | null;
}

function parseField(raw: string): { parsed: Record<string, unknown> | null; error: string | null } {
	if (!raw.trim()) return { parsed: null, error: null };
	try {
		const parsed = JSON.parse(raw);
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
			return { parsed: null, error: "Must be a JSON object" };
		}
		return { parsed: parsed as Record<string, unknown>, error: null };
	} catch (e) {
		return { parsed: null, error: e instanceof Error ? e.message : "Invalid JSON" };
	}
}

function parseCritField(raw: string): { parsed: string[] | null; error: string | null } {
	if (!raw.trim()) return { parsed: null, error: null };
	try {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed) || !parsed.every((v) => typeof v === "string")) {
			return { parsed: null, error: "Must be a JSON array of strings" };
		}
		return { parsed: parsed as string[], error: null };
	} catch (e) {
		return { parsed: null, error: e instanceof Error ? e.message : "Invalid JSON" };
	}
}

function fieldFromRaw(raw: string): FieldState {
	const { parsed, error } = parseField(raw);
	return { id: nextId++, raw, error, parsed };
}

export function PolicyInputForm({ onChange }: PolicyInputFormProps) {
	const [storedMetadataRaw, setStoredMetadataRaw] = useLocalStorage(
		"oidfed-explorer-policy-metadataRaw",
		"",
	);
	const [storedPolicyRaws, setStoredPolicyRaws] = useLocalStorage<string[]>(
		"oidfed-explorer-policy-policyRaws",
		[""],
	);
	const [storedCritRaw, setStoredCritRaw] = useLocalStorage("oidfed-explorer-policy-critRaw", "");

	const [metadataField, setMetadataField] = useState<FieldState>(() =>
		fieldFromRaw(storedMetadataRaw),
	);
	const [policyFields, setPolicyFields] = useState<FieldState[]>(() =>
		storedPolicyRaws.length > 0 ? storedPolicyRaws.map(fieldFromRaw) : [newField()],
	);
	const [critRaw, setCritRaw] = useState(storedCritRaw);
	const [critError, setCritError] = useState<string | null>(null);

	function emitChange(newMetadata: FieldState, newPolicies: FieldState[], newCritRaw: string) {
		const allParsed = newPolicies.every((f) => f.parsed !== null);
		if (newMetadata.parsed && allParsed && newPolicies.length > 0) {
			const { parsed: critParsed } = parseCritField(newCritRaw);
			onChange({
				metadata: newMetadata.parsed,
				policyLevels: newPolicies.map((f) => f.parsed as Record<string, unknown>),
				metadataPolicyCrit: critParsed ?? undefined,
			});
		} else {
			onChange(null);
		}
	}

	function handleMetadataChange(raw: string) {
		const { parsed, error } = parseField(raw);
		const updated = { ...metadataField, raw, error, parsed };
		setMetadataField(updated);
		setStoredMetadataRaw(raw);
		emitChange(updated, policyFields, critRaw);
	}

	function handlePolicyChange(index: number, raw: string) {
		const { parsed, error } = parseField(raw);
		const updated = policyFields.map((f, i) => (i === index ? { ...f, raw, error, parsed } : f));
		setPolicyFields(updated);
		setStoredPolicyRaws(updated.map((f) => f.raw));
		emitChange(metadataField, updated, critRaw);
	}

	function handleCritChange(raw: string) {
		setCritRaw(raw);
		setStoredCritRaw(raw);
		const { error } = parseCritField(raw);
		setCritError(error);
		emitChange(metadataField, policyFields, raw);
	}

	function addLevel() {
		const updated = [...policyFields, newField()];
		setPolicyFields(updated);
		setStoredPolicyRaws(updated.map((f) => f.raw));
		onChange(null);
	}

	function removeLevel(index: number) {
		const updated = policyFields.filter((_, i) => i !== index);
		setPolicyFields(updated);
		setStoredPolicyRaws(updated.map((f) => f.raw));
		emitChange(metadataField, updated, critRaw);
	}

	return (
		<div className="space-y-6">
			<div className="space-y-2">
				<Label htmlFor="metadata-input">Leaf Entity Metadata (JSON object)</Label>
				<Textarea
					id="metadata-input"
					placeholder={'{"openid_relying_party": {"redirect_uris": ["https://example.com/cb"]}}'}
					className="font-mono text-sm min-h-32"
					value={metadataField.raw}
					onChange={(e) => handleMetadataChange(e.target.value)}
				/>
				{metadataField.error && <p className="text-sm text-destructive">{metadataField.error}</p>}
			</div>

			<div className="space-y-3">
				<div className="flex items-center justify-between">
					<Label>Policy Levels (TA → leaf order)</Label>
					<Button type="button" variant="outline" size="sm" onClick={addLevel}>
						+ Add level
					</Button>
				</div>

				{policyFields.map((field, i) => (
					<div key={field.id} className="space-y-1">
						<div className="flex items-center justify-between">
							<span className="text-xs text-muted-foreground">
								Level {i + 1} —{" "}
								{i === 0
									? "Trust Anchor"
									: i === policyFields.length - 1
										? "Closest to leaf"
										: "Intermediate"}
							</span>
							{policyFields.length > 1 && (
								<Button
									type="button"
									variant="ghost"
									size="sm"
									className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
									onClick={() => removeLevel(i)}
								>
									×
								</Button>
							)}
						</div>
						<Textarea
							placeholder={
								'{"openid_relying_party": {"redirect_uris": {"subset_of": ["https://example.com/cb"]}}}'
							}
							className="font-mono text-sm min-h-28"
							value={field.raw}
							onChange={(e) => handlePolicyChange(i, e.target.value)}
						/>
						{field.error && <p className="text-sm text-destructive">{field.error}</p>}
					</div>
				))}
			</div>

			<div className="space-y-2">
				<Label htmlFor="crit-input">
					metadata_policy_crit{" "}
					<span className="text-muted-foreground font-normal">
						(optional, JSON array of strings)
					</span>
				</Label>
				<Textarea
					id="crit-input"
					placeholder='["custom_operator"]'
					className="font-mono text-sm min-h-[48px]"
					value={critRaw}
					onChange={(e) => handleCritChange(e.target.value)}
				/>
				{critError && <p className="text-sm text-destructive">{critError}</p>}
			</div>
		</div>
	);
}
