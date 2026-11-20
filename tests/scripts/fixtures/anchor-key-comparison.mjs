import assert from "node:assert/strict";
import {
	ecCacheKey,
	entityConfigurationUrl,
	entityId,
	fetchEntityConfiguration,
	MemoryFederationStorage,
	ok,
	signEntityConfiguration,
} from "@oidfed/core";
import { createWebCryptoEngine, SoftwareSigner } from "@oidfed/crypto/web";
import { checkCampusKeys } from "./anchor-key-comparison.mjs";

const engine = createWebCryptoEngine();
const anchor = entityId("https://edugain.example");
const clock = { now: () => 1100 };

async function configuration(kid) {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	]);
	const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey);
	const signer = new SoftwareSigner({ ...privateKey, kid, alg: "ES256" });
	const jwks = { keys: [signer.publicJwk] };
	const jwt = await signEntityConfiguration({
		entityId: anchor,
		signer: { signer, publishedJwks: jwks },
		issuedAt: 1000,
		ttlSeconds: 600,
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${anchor}/fetch`,
				federation_list_endpoint: `${anchor}/list`,
			},
		},
	});
	return { jwks, jwt };
}

const old = await configuration("previous");
const current = await configuration("current");
const storage = new MemoryFederationStorage({ namespace: anchor, capabilities: ["cache"], clock });
const cacheKey = await ecCacheKey(anchor, engine);
await storage.cache.set(cacheKey, old.jwt, 400);

// Confirm the seeded entry would normally be returned before the HTTP client runs.
const cached = await fetchEntityConfiguration(anchor, {
	engine,
	clock,
	storage,
	httpClient: () => assert.fail("The seeded cache entry should be usable"),
});
assert.deepEqual(cached, ok(old.jwt));

const [protectedHeader, payload, signature] = current.jwt.split(".");
const invalidSignature = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
const invalidJwt = `${protectedHeader}.${payload}.${invalidSignature}`;

for (const { response, independent, attempts, match } of [
	{ response: current.jwt, independent: [old.jwks, current.jwks], attempts: 2, match: true },
	{ response: current.jwt, independent: [old.jwks, old.jwks], attempts: 2, match: false },
	{ response: invalidJwt, independent: [current.jwks], attempts: 1, match: undefined },
]) {
	let ecRequests = 0;
	let independentRequests = 0;
	const options = Object.freeze({
		engine,
		storage,
		clock,
		async httpClient(input) {
			assert.equal(String(input), entityConfigurationUrl(anchor));
			ecRequests++;
			return new Response(response, {
				headers: { "content-type": "application/entity-statement+jwt" },
			});
		},
	});
	const result = await checkCampusKeys(async () => {
		const keys = independent[independentRequests++];
		assert(keys, "Unexpected independent retrieval");
		return ok(keys);
	}, options);
	if (match === undefined) {
		assert.equal(result.ok, false);
		assert.equal(result.error.description, "Anchor configuration failed validation");
	} else {
		assert(result.ok, JSON.stringify(result));
		assert.equal(result.value.match, match);
	}
	assert.equal(ecRequests, attempts);
	assert.equal(independentRequests, attempts);
	assert.equal(await storage.cache.get(cacheKey), old.jwt);
}
