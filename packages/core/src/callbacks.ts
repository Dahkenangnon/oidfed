/** Protected callback execution, immutable snapshots, and safe JSON property handling. */

import { err, ok, type Result } from "./errors.js";

/** Reject accidental asynchronous callbacks without leaving a rejected promise unhandled. */
export function callSynchronous<T>(
	callback: () => unknown,
	accepts: (value: unknown) => value is T,
): Result<T, string> {
	try {
		const result = callback();
		if (
			result &&
			(typeof result === "object" || typeof result === "function") &&
			"then" in result &&
			typeof result.then === "function"
		) {
			Promise.resolve(result).catch(() => {});
			return err("callback must return synchronously");
		}
		return accepts(result) ? ok(result) : err("callback returned an invalid result");
	} catch {
		return err("callback threw an exception");
	}
}

export function isObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Write JSON member names without invoking Object.prototype setters. */
export function setOwn(object: object, name: string, value: unknown): void {
	Object.defineProperty(object, name, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

/**
 * Freeze the reachable object graph in place, tolerating shared references and cycles.
 * Clone caller-owned data first when the caller must retain a mutable copy.
 */
export function freezeSnapshot<T>(value: T): T {
	const pending: unknown[] = [value];
	const seen = new Set<object>();
	while (pending.length) {
		const current = pending.pop();
		if (!current || typeof current !== "object" || seen.has(current)) continue;
		seen.add(current);
		for (const nested of Object.values(current)) pending.push(nested);
		Object.freeze(current);
	}
	return value;
}

/** Callback outputs must remain representable as JSON; shared objects are allowed, cycles are not. */
export function isJsonData(value: unknown): boolean {
	const ancestors = new Set<object>();
	const pending: { value: unknown; leaving?: boolean }[] = [{ value }];
	while (pending.length) {
		const entry = pending.pop() as { value: unknown; leaving?: boolean };
		const current = entry.value;
		if (entry.leaving) {
			ancestors.delete(current as object);
			continue;
		}
		if (current === null || typeof current === "string" || typeof current === "boolean") continue;
		if (typeof current === "number") {
			if (!Number.isFinite(current)) return false;
			continue;
		}
		if (!current || typeof current !== "object" || ancestors.has(current)) return false;
		if (
			!Array.isArray(current) &&
			Object.getPrototypeOf(current) !== Object.prototype &&
			Object.getPrototypeOf(current) !== null
		)
			return false;
		ancestors.add(current);
		pending.push({ value: current, leaving: true });
		for (const nested of Object.values(current)) pending.push({ value: nested });
	}
	return true;
}
