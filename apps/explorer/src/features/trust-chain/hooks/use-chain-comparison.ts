import { useCallback, useState } from "react";

interface UseChainComparisonResult {
	readonly chainAIndex: number | null;
	readonly chainBIndex: number | null;
	readonly selectA: (index: number) => void;
	readonly selectB: (index: number) => void;
	readonly clear: () => void;
}

export function useChainComparison(): UseChainComparisonResult {
	const [chainAIndex, setChainAIndex] = useState<number | null>(null);
	const [chainBIndex, setChainBIndex] = useState<number | null>(null);

	const selectA = useCallback((index: number) => setChainAIndex(index), []);
	const selectB = useCallback((index: number) => setChainBIndex(index), []);
	const clear = useCallback(() => {
		setChainAIndex(null);
		setChainBIndex(null);
	}, []);

	return { chainAIndex, chainBIndex, selectA, selectB, clear };
}
