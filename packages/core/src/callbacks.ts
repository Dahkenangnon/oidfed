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

export function freezeSnapshot<T>(value: T): T {
	if (value && typeof value === "object") {
		for (const nested of Object.values(value)) freezeSnapshot(nested);
		Object.freeze(value);
	}
	return value;
}

/** Callback outputs must remain representable as JSON. */
export function isJsonData(value: unknown, ancestors = new Set<object>()): boolean {
	if (value === null || typeof value === "string" || typeof value === "boolean") return true;
	if (typeof value === "number") return Number.isFinite(value);
	if (!value || typeof value !== "object" || ancestors.has(value)) return false;
	if (
		!Array.isArray(value) &&
		Object.getPrototypeOf(value) !== Object.prototype &&
		Object.getPrototypeOf(value) !== null
	)
		return false;
	ancestors.add(value);
	const valid = Object.values(value).every((item) => isJsonData(item, ancestors));
	ancestors.delete(value);
	return valid;
}
