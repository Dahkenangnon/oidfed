/**
 * Validate a configured lifetime before publication. Entity Statement builders
 * use safe-integer durations; Trust Marks and event responses allow fractions.
 * This does not check the resulting expiration against a particular clock.
 * @throws TypeError when the duration does not satisfy the selected rule.
 */
export function assertPositiveTtlSeconds(
	value: number,
	field: string,
	mode: "safe-integer" | "finite",
): void {
	const valid = mode === "safe-integer" ? Number.isSafeInteger(value) : Number.isFinite(value);
	if (!valid || value <= 0)
		throw new TypeError(
			`${field} must be ${mode === "safe-integer" ? "positive and a safe integer" : "positive and finite"}`,
		);
}
