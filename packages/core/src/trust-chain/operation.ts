import { InternalErrorCode } from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import type { FederationOptions } from "../types.js";

/** One transport allowance across discovery and every candidate's validation. */
export function createTrustChainOperation(
	options: FederationOptions = {},
): Result<{ options: FederationOptions; exhausted: () => boolean }> {
	let remaining = options.maxTotalFetches ?? 50;
	if (!Number.isSafeInteger(remaining) || remaining < 0)
		return err({
			code: InternalErrorCode.TrustChainInvalid,
			description: "maxTotalFetches must be a non-negative safe integer",
		});
	let exhausted = false;
	const transport = options.httpClient ?? fetch;
	return ok({
		exhausted: () => exhausted || options.signal?.aborted === true,
		options: {
			...options,
			httpClient: async (input, init) => {
				if (options.offline || options.signal?.aborted)
					throw new Error("Network access is unavailable for this operation");
				if (remaining <= 0) {
					exhausted = true;
					throw new Error("Trust chain operation fetch budget exhausted");
				}
				remaining--;
				return transport(input, init);
			},
		},
	});
}
