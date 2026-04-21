import { Badge, Button } from "@oidfed/ui";
import { ArrowDown, ArrowUp, Star } from "lucide-react";

interface ChainSelectorProps {
	readonly chains: readonly {
		readonly trustAnchorId: string;
		readonly statements: readonly string[];
		readonly expiresAt: number;
	}[];
	readonly selectedIndex: number;
	readonly onSelect: (index: number) => void;
}

function describeChainSimple(chain: {
	readonly statements: readonly string[];
	readonly trustAnchorId: string;
}): string {
	return `${chain.statements.length} statements via ${new URL(chain.trustAnchorId).hostname}`;
}

export function ChainSelector({ chains, selectedIndex, onSelect }: ChainSelectorProps) {
	if (chains.length <= 1) return null;

	const selectShortest = () => {
		let minIdx = 0;
		for (let i = 1; i < chains.length; i++) {
			if ((chains[i]?.statements.length ?? 0) < (chains[minIdx]?.statements.length ?? 0)) {
				minIdx = i;
			}
		}
		onSelect(minIdx);
	};

	const selectLongestExpiry = () => {
		let maxIdx = 0;
		for (let i = 1; i < chains.length; i++) {
			if ((chains[i]?.expiresAt ?? 0) > (chains[maxIdx]?.expiresAt ?? 0)) {
				maxIdx = i;
			}
		}
		onSelect(maxIdx);
	};

	return (
		<div className="space-y-3">
			<div className="flex items-center gap-2 flex-wrap">
				<span className="text-sm font-medium text-muted-foreground">
					{chains.length} chains found
				</span>
				<div className="flex gap-1">
					<Button variant="outline" size="sm" onClick={selectShortest}>
						<ArrowDown className="mr-1 size-3" />
						Shortest
					</Button>
					<Button variant="outline" size="sm" onClick={selectLongestExpiry}>
						<ArrowUp className="mr-1 size-3" />
						Longest Expiry
					</Button>
				</div>
			</div>

			<div className="flex gap-2 flex-wrap">
				{chains.map((chain, i) => (
					<button
						// biome-ignore lint/suspicious/noArrayIndexKey: chains lack stable unique ID
						key={`chain-${i}-${chain.trustAnchorId}`}
						type="button"
						onClick={() => onSelect(i)}
						className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors ${
							i === selectedIndex
								? "border-brand-500 bg-brand-500/10 text-brand-600"
								: "border-border hover:bg-accent"
						}`}
					>
						{i === selectedIndex && <Star className="size-3 fill-current" />}
						<span>Chain {i + 1}</span>
						<Badge variant="outline" className="text-xs">
							{describeChainSimple(chain)}
						</Badge>
					</button>
				))}
			</div>
		</div>
	);
}
