import {
	type TrustAnchorSet,
	type TrustChain,
	type ValidatedTrustChain,
	type ValidationError,
	validateTrustChain,
} from "@oidfed/core";
import { useEffect, useState } from "react";

export interface ValidatedChainDetails {
	readonly valid: boolean;
	readonly chain: ValidatedTrustChain | undefined;
	readonly errors: readonly ValidationError[];
}

interface UseChainValidationResult {
	readonly details: ValidatedChainDetails | null;
	readonly loading: boolean;
	readonly error: string | null;
}

export function useChainValidation(
	selectedChain: TrustChain | null,
	trustAnchorSet: TrustAnchorSet | null,
): UseChainValidationResult {
	const [details, setDetails] = useState<ValidatedChainDetails | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!selectedChain || !trustAnchorSet) {
			setDetails(null);
			setError(null);
			return;
		}

		const controller = new AbortController();
		setLoading(true);
		setError(null);

		validateTrustChain([...selectedChain.statements], trustAnchorSet, { signal: controller.signal })
			.then((result) => {
				if (controller.signal.aborted) return;
				setDetails({
					valid: result.valid,
					chain: result.chain,
					errors: result.errors,
				});
			})
			.catch((err: unknown) => {
				if (controller.signal.aborted) return;
				setError(err instanceof Error ? err.message : "Validation failed");
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false);
			});

		return () => {
			controller.abort();
		};
	}, [selectedChain, trustAnchorSet]);

	return { details, loading, error };
}
