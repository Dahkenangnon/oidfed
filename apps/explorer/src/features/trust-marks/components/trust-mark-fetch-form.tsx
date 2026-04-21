import { Button, Label, Textarea } from "@oidfed/ui";
import { Download } from "lucide-react";
import { useEffect } from "react";
import { useLocalStorage } from "@/hooks/use-local-storage";
import { useTrustMarkFetch } from "../hooks/use-trust-mark-fetch";

interface TrustMarkFetchFormProps {
	readonly onFetched: (jwt: string) => void;
	readonly initialIssuer?: string | undefined;
	readonly initialTrustMarkType?: string | undefined;
	readonly initialSub?: string | undefined;
}

export function TrustMarkFetchForm({
	onFetched,
	initialIssuer,
	initialTrustMarkType,
	initialSub,
}: TrustMarkFetchFormProps) {
	const [issuer, setIssuer] = useLocalStorage(
		"oidfed-explorer-trust-mark-fetch-issuer",
		initialIssuer ?? "",
	);
	const [trustMarkType, setTrustMarkType] = useLocalStorage(
		"oidfed-explorer-trust-mark-fetch-type",
		initialTrustMarkType ?? "",
	);
	const [sub, setSub] = useLocalStorage("oidfed-explorer-trust-mark-fetch-sub", initialSub ?? "");
	const { jwt, loading, error, fetchTrustMark } = useTrustMarkFetch();

	const isValid =
		issuer.trim().length > 0 && trustMarkType.trim().length > 0 && sub.trim().length > 0;

	function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!isValid) return;
		fetchTrustMark(issuer.trim(), trustMarkType.trim(), sub.trim());
	}

	// Feed fetched JWT to parent via effect to avoid setState during render
	useEffect(() => {
		if (jwt) {
			onFetched(jwt);
		}
	}, [jwt, onFetched]);

	return (
		<form onSubmit={handleSubmit} className="space-y-3">
			<div className="space-y-2">
				<Label htmlFor="fetch-issuer">Issuer Entity ID</Label>
				<Textarea
					id="fetch-issuer"
					placeholder="https://trust-mark-issuer.example.com"
					className="font-mono text-xs min-h-[48px]"
					value={issuer}
					onChange={(e) => setIssuer(e.target.value)}
					spellCheck={false}
				/>
			</div>
			<div className="space-y-2">
				<Label htmlFor="fetch-type">Trust Mark Type</Label>
				<Textarea
					id="fetch-type"
					placeholder="https://example.com/trust-marks/certified"
					className="font-mono text-xs min-h-[48px]"
					value={trustMarkType}
					onChange={(e) => setTrustMarkType(e.target.value)}
					spellCheck={false}
				/>
			</div>
			<div className="space-y-2">
				<Label htmlFor="fetch-sub">Subject Entity ID</Label>
				<Textarea
					id="fetch-sub"
					placeholder="https://subject.example.com"
					className="font-mono text-xs min-h-[48px]"
					value={sub}
					onChange={(e) => setSub(e.target.value)}
					spellCheck={false}
				/>
			</div>
			<Button type="submit" disabled={!isValid} loading={loading}>
				<Download className="mr-2 size-3.5" />
				Fetch Trust Mark
			</Button>
			{error && <p className="text-xs text-destructive">{error}</p>}
		</form>
	);
}
