import assert from "node:assert/strict";
import { test } from "node:test";
import { assertPortableGraph } from "./check-crypto-isolation.mjs";

test("portable graph guard rejects backend and Node imports", () => {
	assert.doesNotThrow(() =>
		assertPortableGraph(["packages/crypto/dist/index.js", "packages/crypto/dist/web.js"]),
	);
	assert.throws(
		() =>
			assertPortableGraph([
				"node_modules/.pnpm/jose@6.2.13/node_modules/jose/dist/webapi/index.js",
			]),
		/JOSE/,
	);
	assert.throws(() => assertPortableGraph(["node:crypto"]), /Node/);
});
