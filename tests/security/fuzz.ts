/** Coverage-guided entrypoint for hostile JWT payloads and endpoint selectors. */

import assert from "node:assert/strict";
import {
	endpointParameterValuesMatch,
	prepareEndpointParameters,
} from "../../packages/core/src/endpoint-parameters.js";
import { validateTrustChainStructure } from "../../packages/core/src/trust-chain/validate.js";

export async function fuzz(data: Buffer): Promise<void> {
	const before = Object.getOwnPropertyDescriptors(Object.prototype);
	const text = data.toString("utf8");
	const jwt = `${Buffer.from('{"alg":"ES256","typ":"entity-statement+jwt","kid":"fuzz"}').toString("base64url")}.${data.toString("base64url")}.AA`;
	const result = await validateTrustChainStructure([jwt], new Map());
	assert.equal(typeof result.valid, "boolean");
	const params = new URLSearchParams(text);
	for (const name of params.keys()) {
		const values = params.getAll(name);
		assert.equal(endpointParameterValuesMatch(name, values, [...values].reverse(), [name]), true);
	}
	// Unknown extension names remain data, including JavaScript structural names.
	const extension = Object.fromEntries([[text.slice(0, 80), ["one", "two"]]]);
	try {
		prepareEndpointParameters(new URLSearchParams(), extension);
	} catch (error) {
		assert.ok(error instanceof Error);
	}
	assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), before);
}
