import { Button, Label, Textarea } from "@oidfed/ui";
import { List, Search } from "lucide-react";
import { useLocalStorage } from "@/hooks/use-local-storage";
import { useTrustMarkList } from "../hooks/use-trust-mark-list";

interface TrustMarkListPanelProps {
	readonly onSelect: (issuer: string, trustMarkType: string, sub: string) => void;
}

export function TrustMarkListPanel({ onSelect }: TrustMarkListPanelProps) {
	const [issuer, setIssuer] = useLocalStorage("oidfed-explorer-trust-mark-list-issuer", "");
	const [trustMarkType, setTrustMarkType] = useLocalStorage(
		"oidfed-explorer-trust-mark-list-type",
		"",
	);
	const [sub, setSub] = useLocalStorage("oidfed-explorer-trust-mark-list-sub", "");
	const { items, loading, error, fetchList } = useTrustMarkList();

	const isValid = issuer.trim().length > 0 && trustMarkType.trim().length > 0;

	function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!isValid) return;
		fetchList(issuer.trim(), trustMarkType.trim(), sub.trim() || undefined);
	}

	return (
		<div className="space-y-4">
			<form onSubmit={handleSubmit} className="space-y-3">
				<div className="space-y-2">
					<Label htmlFor="list-issuer">Issuer Entity ID</Label>
					<Textarea
						id="list-issuer"
						placeholder="https://trust-mark-issuer.example.com"
						className="font-mono text-xs min-h-[48px]"
						value={issuer}
						onChange={(e) => setIssuer(e.target.value)}
						spellCheck={false}
					/>
				</div>
				<div className="space-y-2">
					<Label htmlFor="list-type">Trust Mark Type</Label>
					<Textarea
						id="list-type"
						placeholder="https://example.com/trust-marks/certified"
						className="font-mono text-xs min-h-[48px]"
						value={trustMarkType}
						onChange={(e) => setTrustMarkType(e.target.value)}
						spellCheck={false}
					/>
				</div>
				<div className="space-y-2">
					<Label htmlFor="list-sub">
						Subject <span className="text-muted-foreground">(optional)</span>
					</Label>
					<Textarea
						id="list-sub"
						placeholder="https://subject.example.com"
						className="font-mono text-xs min-h-[48px]"
						value={sub}
						onChange={(e) => setSub(e.target.value)}
						spellCheck={false}
					/>
				</div>
				<Button type="submit" disabled={!isValid} loading={loading}>
					<Search className="mr-2 size-3.5" />
					List Entities
				</Button>
				{error && <p className="text-xs text-destructive">{error}</p>}
			</form>

			{items && (
				<div className="space-y-2">
					<p className="text-xs text-muted-foreground">
						{items.length} entit{items.length !== 1 ? "ies" : "y"} found
					</p>
					{items.length === 0 && (
						<p className="text-sm text-muted-foreground">No entities with this trust mark type.</p>
					)}
					<ul className="space-y-1">
						{items.map((entityId) => (
							<li key={entityId}>
								<button
									type="button"
									className="flex items-center gap-2 text-xs font-mono text-brand-500 hover:underline break-all text-left"
									onClick={() => onSelect(issuer.trim(), trustMarkType.trim(), entityId)}
								>
									<List className="size-3 shrink-0" />
									{entityId}
								</button>
							</li>
						))}
					</ul>
				</div>
			)}
		</div>
	);
}
