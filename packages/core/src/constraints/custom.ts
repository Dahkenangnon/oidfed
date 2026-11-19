import { cloneData } from "../data-copy.js";
/** Registration and isolated execution of application-defined trust chain constraints. */

import { callSynchronous, freezeSnapshot, isObject } from "../callbacks.js";
import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { TrustChainConstraints } from "../schemas/constraints.js";
import type {
	ConstraintCheckContext,
	ConstraintCheckDefinition,
	EntityId,
	ParsedEntityStatement,
} from "../types.js";

const standardNames = new Set(["max_path_length", "naming_constraints", "allowed_entity_types"]);
const fail = (description: string): Result<never, FederationError> =>
	err({ code: InternalErrorCode.ConstraintViolation, description });

/**
 * Check custom constraint names and synchronous callbacks before any checker runs.
 * Duplicate names and collisions with standard constraints return an error.
 */
export function validateCustomConstraintChecks(
	checks: readonly ConstraintCheckDefinition[],
): Result<void, FederationError> {
	const definitions = checks;
	if (!Array.isArray(checks)) return fail("Custom constraint checks must be an array");
	const names = new Set<string>();
	for (const definition of definitions) {
		if (
			!definition ||
			typeof definition.name !== "string" ||
			typeof definition.check !== "function"
		)
			return fail("Custom constraint checks require a name and a synchronous check function");
		if (standardNames.has(definition.name))
			return fail(`Custom constraint '${definition.name}' conflicts with a standard constraint`);
		if (names.has(definition.name))
			return fail(`Duplicate custom constraint check '${definition.name}'`);
		names.add(definition.name);
	}
	return ok(undefined);
}

function isCheckResult(value: unknown): value is Result<void, FederationError> {
	return (
		isObject(value) &&
		Object.hasOwn(value, "ok") &&
		(value.ok === true
			? Object.hasOwn(value, "value") && value.value === undefined
			: value.ok === false &&
				isObject(value.error) &&
				typeof value.error.code === "string" &&
				typeof value.error.description === "string")
	);
}

/** Capture registrations and protected evidence once, without calling any checker. */
export function createCustomConstraintRunner(
	checks: readonly ConstraintCheckDefinition[],
	chain: readonly ParsedEntityStatement[],
): Result<
	(constraints: TrustChainConstraints, position: number) => Result<void, FederationError>,
	FederationError
> {
	const valid = validateCustomConstraintChecks(checks);
	if (!valid.ok) return valid;
	if (checks.length === 0) return ok(() => ok(undefined));
	const registry = new Map(checks.map(({ name, check }) => [name, { name, check }]));
	const statements = freezeSnapshot(cloneData(chain));
	return ok((constraints, position) => {
		const statement = statements[position];
		const first = statements[0];
		const last = statements.at(-1);
		if (!statement || !first || !last)
			return fail("Custom constraint context requires a complete chain and valid position");
		const context: ConstraintCheckContext = Object.freeze({
			issuerId: statement.payload.iss as unknown as EntityId,
			subjectId: statement.payload.sub as unknown as EntityId,
			trustChainSubjectId: first.payload.sub as unknown as EntityId,
			trustAnchorId: last.payload.iss as unknown as EntityId,
			position,
			statements,
		});
		for (const [name, value] of Object.entries(constraints)) {
			const check = registry.get(name);
			if (!check) continue;
			const callback = callSynchronous(
				() => check.check(freezeSnapshot(cloneData(value)), context),
				isCheckResult,
			);
			if (!callback.ok) return fail(`Custom constraint '${name}': ${callback.error}`);
			if (!callback.value.ok)
				return fail(`Custom constraint '${name}': ${callback.value.error.description}`);
		}
		return ok(undefined);
	});
}
