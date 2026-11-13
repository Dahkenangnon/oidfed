import {
	checkTrustMarkRequirements,
	err,
	FederationErrorCode,
	type FederationOptions,
	ok,
	type Result,
	type TrustMarkRequirements,
	type ValidatedTrustChain,
} from "@oidfed/core";

export interface RegistrationAccreditationContext {
	readonly chain: ValidatedTrustChain;
	readonly registrationType: "automatic" | "explicit";
}
export interface RegistrationAccreditationPolicy {
	readonly trustMarkRequirements?: TrustMarkRequirements;
	readonly beforeRegistration?: (
		context: Readonly<RegistrationAccreditationContext>,
	) => Result<void> | Promise<Result<void>>;
}
function freeze<T>(value: T): T {
	if (value !== null && typeof value === "object") {
		for (const item of Object.values(value)) freeze(item);
		Object.freeze(value);
	}
	return value;
}
export async function checkRegistrationAccreditation(
	chain: ValidatedTrustChain,
	registrationType: "automatic" | "explicit",
	policy: RegistrationAccreditationPolicy,
	options?: FederationOptions,
): Promise<Result<void>> {
	if (policy.trustMarkRequirements) {
		const checked = checkTrustMarkRequirements(chain, policy.trustMarkRequirements, options);
		if (!checked.ok)
			return err({
				code: FederationErrorCode.InvalidTrustChain,
				description: checked.error.description,
			});
	}
	if (!policy.beforeRegistration) return ok(undefined);
	try {
		const checked = await policy.beforeRegistration(
			freeze({ chain: structuredClone(chain), registrationType }),
		);
		if (checked?.ok !== true)
			return err({
				code: FederationErrorCode.InvalidTrustChain,
				description: "Registration rejected by application accreditation policy",
			});
		const current = checkTrustMarkRequirements(chain, policy.trustMarkRequirements ?? {}, options);
		if (!current.ok)
			return err({
				code: FederationErrorCode.InvalidTrustChain,
				description: current.error.description,
			});
		return ok(undefined);
	} catch {
		return err({
			code: FederationErrorCode.InvalidTrustChain,
			description: "Registration accreditation policy failed",
		});
	}
}
