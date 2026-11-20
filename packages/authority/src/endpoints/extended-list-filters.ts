import { cloneData } from "@oidfed/core";

/** Standard and application-defined filters for Extended Subordinate Listing. */

import type { SubordinateRecord } from "@oidfed/core";
import {
	endpointCredentialParameterNames,
	err,
	FederationErrorCode,
	federationError,
	freezeSnapshot,
	isJsonData,
	isReservedEndpointParameter,
	ok,
	type Result,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";

export interface ExtendedListingFilterContext {
	readonly signal: AbortSignal;
}

/** Custom selectors supplement the standard filters; all supplied filters must match. */
export interface ExtendedListingRequestFilter {
	/** Parse once, including for empty stores. Values must be JSON data (or undefined for a flag). */
	readonly parse: (
		values: readonly string[],
		context: Readonly<ExtendedListingFilterContext>,
	) => Result<unknown> | Promise<Result<unknown>>;
	readonly matches: (
		record: Readonly<SubordinateRecord>,
		value: unknown,
		context: Readonly<ExtendedListingFilterContext>,
	) => boolean | Promise<boolean>;
}

/** Capture callbacks, never dispatch through inherited object members. */
export function createExtendedListFilters(
	definitions: Readonly<Record<string, ExtendedListingRequestFilter>> | undefined,
	ctx: HandlerContext,
) {
	const credentials = endpointCredentialParameterNames(ctx.endpointAuthentication);
	const filters = new Map<string, ExtendedListingRequestFilter>();
	for (const [name, definition] of Object.entries(definitions ?? {})) {
		if (!name || isReservedEndpointParameter(name) || credentials.has(name))
			throw new TypeError(
				"Extended listing filters cannot replace protocol selectors or credentials",
			);
		if (
			!definition ||
			typeof definition.parse !== "function" ||
			typeof definition.matches !== "function"
		)
			throw new TypeError("Extended listing filters require parse and matches callbacks");
		filters.set(name, Object.freeze({ parse: definition.parse, matches: definition.matches }));
	}
	return {
		present: (params: URLSearchParams) => [...filters.keys()].some((name) => params.has(name)),
		async prepare(
			params: URLSearchParams,
			signal: AbortSignal,
		): Promise<Result<(record: SubordinateRecord) => Promise<boolean>>> {
			const context = Object.freeze({ signal });
			const active: Array<{ definition: ExtendedListingRequestFilter; value: unknown }> = [];
			for (const [name, definition] of filters) {
				if (!params.has(name)) continue;
				if (signal.aborted) throw new Error("Extended listing cancelled");
				const parsed = await definition.parse(Object.freeze(params.getAll(name)), context);
				if (!parsed || typeof parsed !== "object" || typeof parsed.ok !== "boolean")
					throw new TypeError("Invalid filter parser result");
				if (!parsed.ok) {
					if (
						!parsed.error ||
						typeof parsed.error.description !== "string" ||
						typeof parsed.error.code !== "string"
					)
						throw new TypeError("Invalid filter parser error");
					return err(federationError(FederationErrorCode.InvalidRequest, parsed.error.description));
				}
				if (
					!Object.hasOwn(parsed, "value") ||
					(parsed.value !== undefined && !isJsonData(parsed.value))
				)
					throw new TypeError("Filter values must be JSON data");
				active.push({ definition, value: freezeSnapshot(cloneData(parsed.value)) });
			}
			return ok(async (record) => {
				if (!active.length) return true;
				const snapshot = freezeSnapshot(cloneData(record));
				for (const { definition, value } of active) {
					if (signal.aborted) throw new Error("Extended listing cancelled");
					const matched = await definition.matches(snapshot, value, context);
					if (typeof matched !== "boolean") throw new TypeError("Invalid filter predicate result");
					if (!matched) return false;
				}
				return true;
			});
		},
	};
}
