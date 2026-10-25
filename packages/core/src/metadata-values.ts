/** Find forbidden null values, preserving wildcard components in wallet claim paths. */
export function findInvalidMetadataNullPaths(
	metadata: unknown,
): readonly (readonly (string | number)[])[] {
	const invalid: (string | number)[][] = [];
	const walk = (value: unknown, path: (string | number)[]) => {
		if (value === null) {
			invalid.push(path);
		} else if (Array.isArray(value)) {
			if (
				isWalletClaimPath(path) &&
				value.length > 0 &&
				value.every(
					(component) =>
						component === null ||
						typeof component === "string" ||
						(typeof component === "number" && Number.isInteger(component)),
				)
			)
				return;
			for (let index = 0; index < value.length; index++) walk(value[index], [...path, index]);
		} else if (value && typeof value === "object") {
			for (const [key, child] of Object.entries(value)) walk(child, [...path, key]);
		}
	};
	walk(metadata, []);
	return invalid;
}

function isWalletClaimPath(path: readonly (string | number)[]): boolean {
	return (
		(path.length === 7 &&
			path[0] === "openid_credential_issuer" &&
			path[1] === "credential_configurations_supported" &&
			typeof path[2] === "string" &&
			path[3] === "credential_metadata" &&
			path[4] === "claims" &&
			typeof path[5] === "number" &&
			path[6] === "path") ||
		(path.length === 8 &&
			path[0] === "openid_credential_verifier" &&
			path[1] === "dcql_queries" &&
			typeof path[2] === "number" &&
			path[3] === "credentials" &&
			typeof path[4] === "number" &&
			path[5] === "claims" &&
			typeof path[6] === "number" &&
			path[7] === "path")
	);
}
