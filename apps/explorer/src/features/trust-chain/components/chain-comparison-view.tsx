import type { TrustChain } from "@oidfed/core";
import ReactDiffViewer from "react-diff-viewer-continued";
import { useSettings } from "@/hooks/use-settings";
import { ChainExpirationBar } from "./chain-expiration-bar";

interface ChainComparisonViewProps {
	readonly chains: readonly TrustChain[];
	readonly chainAIndex: number | null;
	readonly chainBIndex: number | null;
	readonly onSelectA: (index: number) => void;
	readonly onSelectB: (index: number) => void;
}

export function ChainComparisonView({
	chains,
	chainAIndex,
	chainBIndex,
	onSelectA,
	onSelectB,
}: ChainComparisonViewProps) {
	const [settings] = useSettings();
	const isDark =
		settings.theme === "dark" ||
		(settings.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);

	if (chains.length < 2) {
		return (
			<p className="text-sm text-muted-foreground">At least 2 chains are needed for comparison.</p>
		);
	}

	const chainA = chainAIndex !== null ? chains[chainAIndex] : undefined;
	const chainB = chainBIndex !== null ? chains[chainBIndex] : undefined;

	return (
		<div className="space-y-4">
			<div className="flex gap-4">
				<div className="flex-1 space-y-1">
					<label htmlFor="chain-a-select" className="text-sm font-medium">
						Chain A
					</label>
					<select
						id="chain-a-select"
						className="w-full rounded-md border bg-background px-3 py-2 text-sm"
						value={chainAIndex ?? ""}
						onChange={(e) => onSelectA(Number(e.target.value))}
					>
						<option value="">Select chain...</option>
						{chains.map((c, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: chains have no stable unique ID
							<option key={`a-${i}`} value={i}>
								Chain {i + 1} — {c.statements.length} stmts via {new URL(c.trustAnchorId).hostname}
							</option>
						))}
					</select>
				</div>
				<div className="flex-1 space-y-1">
					<label htmlFor="chain-b-select" className="text-sm font-medium">
						Chain B
					</label>
					<select
						id="chain-b-select"
						className="w-full rounded-md border bg-background px-3 py-2 text-sm"
						value={chainBIndex ?? ""}
						onChange={(e) => onSelectB(Number(e.target.value))}
					>
						<option value="">Select chain...</option>
						{chains.map((c, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: chains have no stable unique ID
							<option key={`b-${i}`} value={i}>
								Chain {i + 1} — {c.statements.length} stmts via {new URL(c.trustAnchorId).hostname}
							</option>
						))}
					</select>
				</div>
			</div>

			{chainA && chainB && (
				<div className="space-y-4">
					<div className="flex gap-4">
						<div className="flex-1">
							<ChainExpirationBar expiresAt={chainA.expiresAt} />
						</div>
						<div className="flex-1">
							<ChainExpirationBar expiresAt={chainB.expiresAt} />
						</div>
					</div>

					<div className="rounded-lg border overflow-hidden">
						<ReactDiffViewer
							oldValue={JSON.stringify(
								{
									entityId: chainA.entityId,
									trustAnchor: chainA.trustAnchorId,
									statements: chainA.statements.length,
									resolvedMetadata: chainA.resolvedMetadata,
								},
								null,
								2,
							)}
							newValue={JSON.stringify(
								{
									entityId: chainB.entityId,
									trustAnchor: chainB.trustAnchorId,
									statements: chainB.statements.length,
									resolvedMetadata: chainB.resolvedMetadata,
								},
								null,
								2,
							)}
							splitView
							leftTitle={`Chain ${(chainAIndex ?? 0) + 1}`}
							rightTitle={`Chain ${(chainBIndex ?? 0) + 1}`}
							useDarkTheme={isDark}
						/>
					</div>
				</div>
			)}
		</div>
	);
}
