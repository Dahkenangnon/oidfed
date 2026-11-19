import {
	assertSigningPublicJwk,
	assertSupportedHeader,
	assertVerificationKey,
	type BuiltinJwsAlgorithm,
	CryptoError,
	CryptoUnsupportedError,
	DEFAULT_MAX_COMPACT_JWS_BYTES,
	decodeBase64url,
	decodeCompactJws,
	derToJws,
	encodeBase64url,
	isJwsAlgorithm,
	JWS_ALGORITHMS,
	type Jwk,
	jwkThumbprint,
	jwsToDer,
	MemoryRotatingKeyring,
	parseCompactJws,
	type Signer,
	StaticKeyring,
	signatureByteLength,
	signCompactJws,
	toPublicJwk,
	utf8Decode,
	utf8Encode,
} from "@oidfed/crypto";
import { createJoseEngine } from "@oidfed/crypto/jose";
import { createWebCryptoEngine, SoftwareSigner, type WebCryptoLike } from "@oidfed/crypto/web";
import * as fc from "fast-check";
import { CompactSign, calculateJwkThumbprint, compactVerify, exportJWK } from "jose";
import type QUnit from "qunit";
import { cryptoFixture, cryptoInput } from "../fixtures/crypto.js";

const payload = {
	iss: "https://issuer.example",
	sub: "https://issuer.example",
	iat: 1000,
	exp: 2000,
};
const engine = createWebCryptoEngine();
const errorCode = (code: string) => (error: unknown) =>
	error instanceof CryptoError && error.code === code;
const header = (signer: Signer) => ({
	alg: signer.publicJwk.alg,
	kid: signer.publicJwk.kid,
	typ: "entity-statement+jwt",
});

export default async (qunit: QUnit) => {
	const { module, test } = qunit;
	let edwards = true;
	try {
		await cryptoFixture("Ed25519");
	} catch (cause) {
		if (!(cause instanceof Error) || cause.name !== "NotSupportedError") throw cause;
		edwards = false;
	}
	module("crypto / engines and signing", () => {
		for (const algorithm of JWS_ALGORITHMS) {
			const register = algorithm.startsWith("Ed") && !edwards ? test.skip : test;
			register(`interoperates with JOSE using ${algorithm}`, async (a) => {
				const f = await cryptoFixture(algorithm);
				const backend = createWebCryptoEngine(undefined, { algorithms: [algorithm] });
				const jose = createJoseEngine(undefined, { algorithms: [algorithm] });
				const token = await signCompactJws(payload, header(f.signer), f.signer);
				a.equal(
					(await compactVerify(token, f.pair.publicKey, { algorithms: [algorithm] }))
						.protectedHeader.alg,
					algorithm,
				);
				const reference = await new CompactSign(utf8Encode(JSON.stringify(payload)))
					.setProtectedHeader(header(f.signer))
					.sign(f.pair.privateKey);
				for (const adapter of [backend, jose]) {
					for (const jwt of [token, reference])
						a.true(await adapter.verify(cryptoInput(jwt, f.publicJwk)));
					const parsed = parseCompactJws(token);
					const corrupted = `${encodeBase64url(utf8Encode(JSON.stringify(parsed.header)))}.${encodeBase64url(utf8Encode(JSON.stringify({ ...payload, sub: "tampered" })))}.${encodeBase64url(parsed.signature)}`;
					a.false(await adapter.verify(cryptoInput(corrupted, f.publicJwk)));
				}
				a.equal(
					encodeBase64url(await jwkThumbprint(backend, f.publicJwk)),
					await calculateJwkThumbprint(f.pair.publicKey),
				);
				a.equal(
					signatureByteLength(f.publicJwk, algorithm),
					parseCompactJws(token).signature.length,
				);
				if (algorithm.startsWith("ES")) {
					const sig = parseCompactJws(token).signature;
					a.deepEqual(derToJws(jwsToDer(sig, algorithm), algorithm), sig);
				}
			});
		}
		test("verifies authoritative bytes consistently across adapters", async (a) => {
			const f = await cryptoFixture();
			const compact = await signCompactJws(payload, header(f.signer), f.signer);
			const input = cryptoInput(compact, f.publicJwk);
			const signature = input.signature.slice();
			signature[0] = (signature[0] ?? 0) ^ 255;
			const changedPayload = utf8Encode(
				`${compact.split(".")[0]}.${encodeBase64url(utf8Encode(JSON.stringify({ ...payload, sub: "changed" })))}`,
			);
			for (const adapter of [engine, createJoseEngine()]) {
				a.true(await adapter.verify(input));
				// A stale field supplied by an older JavaScript caller must never override the bytes.
				const stale = { ...input, signature, compact };
				a.false(await adapter.verify(stale));
				a.false(await adapter.verify({ ...input, signingInput: changedPayload }));
			}
			await a.rejects(
				createJoseEngine().verify({ ...input, signingInput: new Uint8Array([255]) }),
				errorCode("MALFORMED_JWS"),
			);
			await a.rejects(
				createJoseEngine().verify({ ...input, signature: null as unknown as Uint8Array }),
				errorCode("MALFORMED_JWS"),
			);
		});
		test("accepts a protocol public key and protected header without kid", async (a) => {
			const f = await cryptoFixture();
			const key = { ...(await exportJWK(f.pair.publicKey)) } as Jwk;
			const compact = await new CompactSign(utf8Encode(JSON.stringify(payload)))
				.setProtectedHeader({ alg: "ES256" })
				.sign(f.pair.privateKey);
			a.equal(parseCompactJws(compact).header.kid, undefined);
			a.true(await engine.verify(cryptoInput(compact, key)));
			a.strictEqual(assertVerificationKey(key, "ES256"), key);
		});
		test("signs through a nonextractable host key without private-key export", async (a) => {
			const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
				"sign",
				"verify",
			]);
			const publicJwk = {
				...toPublicJwk({ ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kty: "EC" }),
				kid: "opaque",
				alg: "ES256" as const,
			};
			const signer: Signer = {
				publicJwk,
				async sign(data) {
					return new Uint8Array(
						await crypto.subtle.sign(
							{ name: "ECDSA", hash: "SHA-256" },
							pair.privateKey,
							new Uint8Array(data).buffer,
						),
					);
				},
			};
			a.false(pair.privateKey.extractable);
			a.true(
				await engine.verify(
					cryptoInput(await signCompactJws(payload, header(signer), signer), publicJwk),
				),
			);
		});
		test("imports using explicit backend algorithms after enforcing JWK agreement", async (a) => {
			const f = await cryptoFixture();
			let imports = 0;
			const implementation: WebCryptoLike<Awaited<ReturnType<typeof crypto.subtle.importKey>>> = {
				subtle: {
					async importKey(format, key, algorithm, extractable, usages) {
						imports++;
						a.false(Object.hasOwn(key, "alg"), "Do not forward JOSE labels to native JWK parsers");
						return crypto.subtle.importKey(format, key, algorithm, extractable, usages);
					},
					verify: crypto.subtle.verify.bind(crypto.subtle),
					sign: crypto.subtle.sign.bind(crypto.subtle),
					digest: crypto.subtle.digest.bind(crypto.subtle),
				},
				getRandomValues: crypto.getRandomValues.bind(crypto),
			};
			const signer = new SoftwareSigner(f.privateJwk, implementation);
			const backend = createWebCryptoEngine(implementation);
			const input = cryptoInput(await signCompactJws({}, header(signer), signer), signer.publicJwk);
			a.true(await backend.verify(input));
			a.equal(signer.publicJwk.alg, "ES256", "Keep algorithm metadata on the public identity");
			const before = imports;
			await a.rejects(
				backend.verify({ ...input, key: { ...input.key, alg: "ES384" } }),
				errorCode("MALFORMED_KEY"),
			);
			a.equal(imports, before, "Reject conflicting algorithms before reaching the backend");
		});
		test("detaches supported private import fields without retaining unknown metadata", async (a) => {
			const f = await cryptoFixture();
			const cyclic: Record<string, unknown> = {};
			cyclic.self = cyclic;
			const original = {
				...f.privateJwk,
				d: f.privateJwk.d as string,
				key_ops: ["sign"],
				x5c: ["certificate"],
				ext: false,
				oth: [{ r: "AQ", d: "Ag", t: "Aw" }],
				ignoredMetadata: cyclic,
			};
			let imported: Record<string, unknown> | undefined;
			const backend: WebCryptoLike = {
				subtle: {
					importKey: async (_format, key) => {
						imported = key as Record<string, unknown>;
						return {};
					},
					sign: async () => new ArrayBuffer(64),
					verify: async () => true,
					digest: async () => new ArrayBuffer(32),
				},
				getRandomValues: (value) => value,
			};
			const signer = new SoftwareSigner(original, backend);
			original.d = "changed";
			original.key_ops[0] = "decrypt";
			original.x5c[0] = "changed";
			original.oth[0]!.r = "changed";
			await signer.sign(new Uint8Array([97]));
			a.equal(imported?.d, f.privateJwk.d);
			a.deepEqual(imported?.key_ops, ["sign"]);
			a.deepEqual(imported?.x5c, ["certificate"]);
			a.deepEqual(imported?.oth, [{ r: "AQ", d: "Ag", t: "Aw" }]);
			a.strictEqual(imported?.ext, false);
			a.false(Object.hasOwn(imported!, "ignoredMetadata"));
			a.deepEqual(signer.publicJwk.key_ops, ["verify"]);
			for (const changes of [
				{ p: 1 },
				{ ext: "false" },
				{ oth: {} },
				{ oth: [null] },
				{ oth: [[1]] },
				{ oth: [{ r: 1, d: "Ag", t: "Aw" }] },
			])
				a.throws(
					() => new SoftwareSigner({ ...f.privateJwk, ...changes }, backend),
					errorCode("MALFORMED_KEY"),
				);
		});
		test("captures serialized input before an asynchronous signer mutates caller objects", async (a) => {
			const f = await cryptoFixture();
			const claims = { ...payload };
			const h = header(f.signer);
			const signer: Signer = {
				publicJwk: f.signer.publicJwk,
				async sign(data) {
					claims.sub = "changed";
					h.typ = "changed";
					return f.signer.sign(data);
				},
			};
			const token = await signCompactJws(claims, h, signer);
			a.equal(parseCompactJws(token).payload.sub, payload.sub);
			a.equal(parseCompactJws(token).header.typ, "entity-statement+jwt");
			a.true(await engine.verify(cryptoInput(token, f.publicJwk)));
		});
		test("rejects invalid signer output and serialized header drift", async (a) => {
			const f = await cryptoFixture();
			for (const output of [new Uint8Array(0), new Uint8Array(63), "JWT"]) {
				await a.rejects(
					signCompactJws(payload, header(f.signer), {
						publicJwk: f.signer.publicJwk,
						sign: async () => output as Uint8Array,
					}),
					errorCode("SIGNER_CONTRACT_VIOLATION"),
				);
			}
			await a.rejects(
				signCompactJws(
					payload,
					{ ...header(f.signer), toJSON: () => ({ alg: "ES256", kid: "other" }) },
					f.signer,
				),
				errorCode("SIGNER_CONTRACT_VIOLATION"),
			);
			await a.rejects(
				signCompactJws(payload, { ...header(f.signer), alg: "PS256" }, f.signer),
				errorCode("SIGNER_CONTRACT_VIOLATION"),
			);
		});
		test("bounds compact tokens before calling a signer and rejects invalid JSON shapes", async (a) => {
			const f = await cryptoFixture();
			let calls = 0;
			const signer: Signer = {
				publicJwk: f.signer.publicJwk,
				sign: async () => {
					calls++;
					return new Uint8Array(64);
				},
			};
			await a.rejects(
				signCompactJws({ x: "x".repeat(DEFAULT_MAX_COMPACT_JWS_BYTES) }, header(signer), signer),
				errorCode("MALFORMED_JWS"),
			);
			await a.rejects(
				signCompactJws({}, header(signer), signer, { maxBytes: 1 }),
				errorCode("MALFORMED_JWS"),
			);
			a.equal(calls, 0);
			for (const maxBytes of [0, -1, Infinity, 1.5]) {
				a.throws(() => parseCompactJws("a.b.c", { maxBytes }), errorCode("MALFORMED_JWS"));
			}
			await a.rejects(
				signCompactJws({ x: 1n }, header(signer), signer),
				errorCode("MALFORMED_JWS"),
			);
			await a.rejects(
				signCompactJws([] as unknown as Record<string, unknown>, header(signer), signer),
				errorCode("MALFORMED_JWS"),
			);
			const token = await signCompactJws({}, header(f.signer), f.signer);
			a.equal(parseCompactJws(token, { maxBytes: token.length }).compact, token);
			a.throws(
				() => parseCompactJws(token, { maxBytes: token.length - 1 }),
				errorCode("MALFORMED_JWS"),
			);
		});
		test("keeps capabilities immutable, validates operations, and preserves backend failures", async (a) => {
			const algorithms: BuiltinJwsAlgorithm[] = ["ES256"];
			const adapter = createWebCryptoEngine(undefined, { algorithms });
			algorithms.push("PS256");
			a.deepEqual(adapter.algorithms, ["ES256"]);
			a.true(Object.isFrozen(adapter.algorithms));
			for (const invalid of [["none"], ["ES256", "ES256"]])
				a.throws(
					() => createWebCryptoEngine(undefined, { algorithms: invalid as BuiltinJwsAlgorithm[] }),
					CryptoUnsupportedError,
				);
			const f = await cryptoFixture();
			const input = cryptoInput(await signCompactJws({}, header(f.signer), f.signer), f.publicJwk);
			await a.rejects(
				createWebCryptoEngine(undefined, { algorithms: [] }).verify(input),
				CryptoUnsupportedError,
			);
			await a.rejects(
				createJoseEngine(undefined, { algorithms: [] }).verify(input),
				CryptoUnsupportedError,
			);
			await a.rejects(engine.digest("MD5" as "SHA-256", new Uint8Array()), CryptoUnsupportedError);
			a.throws(() => createWebCryptoEngine({} as WebCryptoLike), errorCode("UNSUPPORTED_RUNTIME"));
			const cause = new Error("backend unavailable");
			const faulty = createWebCryptoEngine({
				subtle: {
					importKey: async () => {
						throw cause;
					},
					sign: crypto.subtle.sign.bind(crypto.subtle),
					verify: crypto.subtle.verify.bind(crypto.subtle),
					digest: crypto.subtle.digest.bind(crypto.subtle),
				},
				getRandomValues: crypto.getRandomValues.bind(crypto),
			});
			await a.rejects(
				faulty.verify(input),
				(error: unknown) =>
					error instanceof CryptoError &&
					error.code === "CRYPTO_OPERATION_FAILED" &&
					error.cause === cause,
			);
		});
		test("hashes and obtains secure random bytes including requests larger than 64 KiB", async (a) => {
			for (const [alg, size] of [
				["SHA-256", 32],
				["SHA-384", 48],
				["SHA-512", 64],
			] as const)
				a.equal((await engine.digest(alg, utf8Encode("abc"))).length, size);
			a.equal(
				encodeBase64url(await engine.digest("SHA-256", utf8Encode("abc"))),
				"ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
			);
			a.equal((await engine.random(70000)).length, 70000);
			a.equal((await engine.random(0)).length, 0);
			for (const count of [-1, NaN, Infinity, 0.5])
				await a.rejects(engine.random(count), errorCode("ENGINE_CONTRACT_VIOLATION"));
		});
		test("rejects malformed private material and injected backend contract violations", async (a) => {
			const f = await cryptoFixture();
			for (const d of ["", "x", "AA=", 42, undefined])
				a.throws(() => new SoftwareSigner({ ...f.privateJwk, d }), errorCode("MALFORMED_KEY"));
			a.throws(
				() => new SoftwareSigner({ ...f.privateJwk, key_ops: ["verify"] }),
				errorCode("MALFORMED_KEY"),
			);
			const implementation: WebCryptoLike = {
				subtle: {
					importKey: async () => ({}),
					verify: async () => "truthy" as unknown as boolean,
					sign: async () => new ArrayBuffer(64),
					digest: async () => new ArrayBuffer(1),
				},
				getRandomValues: () => new Uint8Array(1),
			};
			const backend = createWebCryptoEngine(implementation);
			const input = cryptoInput(await signCompactJws({}, header(f.signer), f.signer), f.publicJwk);
			await a.rejects(backend.verify(input), errorCode("ENGINE_CONTRACT_VIOLATION"));
			await a.rejects(
				backend.digest("SHA-256", new Uint8Array()),
				errorCode("ENGINE_CONTRACT_VIOLATION"),
			);
			await a.rejects(backend.random(1), errorCode("ENGINE_CONTRACT_VIOLATION"));
			for (const [name, code] of [
				["NotSupportedError", "UNSUPPORTED_ALGORITHM"],
				["DataError", "MALFORMED_KEY"],
				["SyntaxError", "MALFORMED_KEY"],
			]) {
				const cause = new Error("backend failure");
				cause.name = name!;
				const failed = createWebCryptoEngine({
					...implementation,
					subtle: {
						...implementation.subtle,
						importKey: async () => {
							throw cause;
						},
					},
				});
				await a.rejects(
					failed.verify(input),
					(error: unknown) =>
						error instanceof CryptoError && error.code === code && error.cause === cause,
				);
			}
		});
	});

	module("crypto / codecs and public keys", () => {
		test("matches native UTF-8 encoding and fatal decoding across Unicode and malformed bytes", (a) => {
			const encoder = new TextEncoder();
			const decoder = new TextDecoder("utf-8", { fatal: true });
			for (const value of [
				"",
				"ASCII\u0000",
				"é中😀",
				"\ufeffstart",
				"\ufeff\ufeff",
				"\ud800",
				"\udfff",
				"\ud800a",
				"\ud800\ud800",
				"\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff",
				"\ud800\udc00\udbff\udfff",
			]) {
				const expected = encoder.encode(value);
				a.deepEqual(utf8Encode(value), expected);
				a.equal(utf8Decode(expected), decoder.decode(expected));
			}
			fc.assert(
				fc.property(fc.array(fc.integer({ min: 0, max: 0xffff }), { maxLength: 256 }), (units) => {
					const value = String.fromCharCode(...units);
					const expected = encoder.encode(value);
					const actual = utf8Encode(value);
					return (
						actual.length === expected.length &&
						actual.every((byte, index) => byte === expected[index]) &&
						utf8Decode(actual) === decoder.decode(expected)
					);
				}),
				{ numRuns: 500 },
			);
			fc.assert(
				fc.property(fc.uint8Array({ maxLength: 128 }), (bytes) => {
					let expected: string;
					try {
						expected = decoder.decode(bytes);
					} catch {
						try {
							utf8Decode(bytes);
							return false;
						} catch (error) {
							return errorCode("MALFORMED_JWS")(error);
						}
					}
					return utf8Decode(bytes) === expected;
				}),
				{ numRuns: 1000 },
			);
			for (const bytes of [
				[0x80],
				[0xc0, 0x80],
				[0xc1, 0xbf],
				[0xe0, 0x9f, 0xbf],
				[0xed, 0xa0, 0x80],
				[0xf0, 0x8f, 0xbf, 0xbf],
				[0xf4, 0x90, 0x80, 0x80],
				[0xf5, 0x80, 0x80, 0x80],
				[0xff],
				[0xc2],
				[0xe2, 0x28, 0xa1],
				[0xf0, 0x90, 0x80],
			])
				a.throws(() => utf8Decode(new Uint8Array(bytes)), errorCode("MALFORMED_JWS"));
			a.throws(() => utf8Encode(undefined as unknown as string), errorCode("MALFORMED_JWS"));
			a.throws(() => utf8Decode("a" as unknown as Uint8Array), errorCode("MALFORMED_JWS"));
		});
		test("decodes JSON for inspection without applying signing policy or interpreting signatures", (a) => {
			const encode = (value: unknown) => encodeBase64url(utf8Encode(JSON.stringify(value)));
			for (const h of [
				{ alg: "future-alg", typ: "entity-statement+jwt" },
				{ alg: "none" },
				{ alg: 42 },
				{},
				{ alg: "ES256", crit: ["future"], future: true },
				{ alg: "ES256", b64: false },
			]) {
				for (const signature of ["", "not a signature!", "💡", "AQ="]) {
					const compact = `${encode(h)}.${encode({ message: "inspection" })}.${signature}`;
					const decoded = decodeCompactJws(compact);
					a.deepEqual(decoded.header, h);
					a.deepEqual(decoded.payload, { message: "inspection" });
					a.equal(decoded.compact, compact);
					a.throws(() => parseCompactJws(compact), CryptoError);
				}
			}
			for (const compact of [
				"a.b",
				"a.b.c.d",
				`${encode([])}.e30.`,
				`${encode({})}.${encode(null)}.`,
				"_w.e30.",
				"e30._w.",
				"a.e30.",
			])
				a.throws(() => decodeCompactJws(compact), errorCode("MALFORMED_JWS"));
			const unicodeSignature = `${encode({})}.e30.💡`;
			a.throws(
				() => decodeCompactJws(unicodeSignature, { maxBytes: unicodeSignature.length }),
				errorCode("MALFORMED_JWS"),
			);
			a.equal(
				decodeCompactJws(unicodeSignature, { maxBytes: utf8Encode(unicodeSignature).length })
					.compact,
				unicodeSignature,
			);
			a.throws(() => decodeCompactJws(1 as unknown as string), errorCode("MALFORMED_JWS"));
			a.throws(() => decodeCompactJws("e30.e30.", { maxBytes: 0 }), errorCode("MALFORMED_JWS"));
		});
		test("matches unpadded RFC 4648 vectors and generated byte round trips", (a) => {
			for (const [plain, encoded] of [
				["", ""],
				["f", "Zg"],
				["fo", "Zm8"],
				["foo", "Zm9v"],
				["foobar", "Zm9vYmFy"],
			]) {
				a.equal(encodeBase64url(utf8Encode(plain!)), encoded);
				a.equal(utf8Decode(decodeBase64url(encoded!)), plain);
			}
			fc.assert(
				fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
					const decoded = decodeBase64url(encodeBase64url(bytes));
					return decoded.length === bytes.length && decoded.every((value, i) => value === bytes[i]);
				}),
				{ numRuns: 100 },
			);
			a.true(true);
			for (const invalid of ["a", "AB", "AAB", "AA=", "AA ", "+A", "/A", "é"])
				a.throws(() => decodeBase64url(invalid), CryptoError);
			a.throws(() => decodeBase64url(1 as unknown as string), CryptoError);
			a.throws(() => encodeBase64url("x" as unknown as Uint8Array), CryptoError);
			a.throws(() => utf8Decode(new Uint8Array([255])), Error);
		});
		test("rejects malformed JWT structure, JSON, critical headers and unencoded payloads", (a) => {
			const encode = (value: unknown) => encodeBase64url(utf8Encode(JSON.stringify(value)));
			for (const h of [
				{ alg: "none" },
				{ alg: "HS256" },
				{ alg: "ES256", kid: "" },
				{ alg: "ES256", typ: 1 },
				{ alg: "ES256", crit: [] },
				{ alg: "ES256", crit: ["x"], x: true },
				{ alg: "ES256", crit: ["b64", "b64"], b64: true },
				{ alg: "ES256", b64: false },
				{ alg: "ES256", b64: true },
				{ alg: "ES256", crit: ["b64"] },
				{ alg: "ES256", b64: false, crit: ["b64"] },
			])
				a.throws(() => assertSupportedHeader(h), CryptoError);
			assertSupportedHeader({ alg: "ES256", b64: true, crit: ["b64"] });
			a.true(true);
			for (const token of [
				"",
				"a.b",
				"a.b.c.d",
				`${encode([])}.${encode({})}.AA`,
				`${encode({ alg: "ES256" })}.${encode([])}.AA`,
				`${encode({ alg: "ES256" })}..AA`,
				`${encode({ alg: "ES256" })}.${encode({})}.`,
				`__.${encode({})}.AA`,
			])
				a.throws(() => parseCompactJws(token), CryptoError);
			a.throws(() => parseCompactJws(null as unknown as string), CryptoError);
		});
		test("rejects mismatched key material, usage and private parameters", async (a) => {
			const f = await cryptoFixture();
			for (const changes of [
				{ d: undefined },
				{ d: "private" },
				{ kid: "" },
				{ use: "enc" },
				{ alg: "ES384" },
				{ key_ops: ["sign"] },
				{ key_ops: [1] },
				{ crv: "P-384" },
				{ x: "AA" },
				{ x: "!" },
				{ y: "" },
				{ x5c: [1] },
			])
				a.throws(
					() => assertVerificationKey({ ...f.publicJwk, ...changes } as Jwk, "ES256"),
					CryptoError,
				);
			a.throws(
				() => assertVerificationKey(f.publicJwk, "none" as BuiltinJwsAlgorithm),
				CryptoError,
			);
			a.throws(() => assertVerificationKey(null as unknown as Jwk, "ES256"), CryptoError);
			a.throws(() => assertSigningPublicJwk({ kty: "EC" }), CryptoError);
			a.throws(() => toPublicJwk({ kty: "oct", k: "secret" }), CryptoError);
			const extracted = toPublicJwk({
				...f.privateJwk,
				unknownSecret: "never publish",
				x5c: ["certificate"],
			});
			a.equal(extracted.d, undefined);
			a.equal(extracted.unknownSecret, undefined);
			a.deepEqual(extracted.x5c, ["certificate"]);
			const rsa = (await cryptoFixture("RS256")).publicJwk;
			for (const changes of [
				{ n: "AQ" },
				{ n: "AAE" },
				{ e: "Ag" },
				{ e: "AQ" },
				{ e: "AAE" },
				{ kty: "EC" },
			])
				a.throws(() => assertVerificationKey({ ...rsa, ...changes }, "RS256"), CryptoError);
			a.throws(() => assertVerificationKey(f.publicJwk, "RS256"), CryptoError);
		});
		test("requires valid thumbprint members and the engine's exact digest size", async (a) => {
			const f = await cryptoFixture();
			for (const key of [
				{ kty: "oct" },
				{ kty: "EC" },
				{ ...f.publicJwk, crv: "unknown" },
				{ kty: "OKP", crv: "Ed448", x: "AA" },
			])
				await a.rejects(jwkThumbprint(engine, key), CryptoError);
			await a.rejects(
				jwkThumbprint(
					{
						...engine,
						digest: async () => new Uint8Array(1),
					},
					f.publicJwk,
				),
				errorCode("ENGINE_CONTRACT_VIOLATION"),
			);
			a.true(isJwsAlgorithm("Ed25519"));
			a.false(isJwsAlgorithm("__proto__"));
			a.false(isJwsAlgorithm(undefined));
		});
		test("rejects malformed DER instead of truncating or normalizing it", (a) => {
			for (const der of [
				[],
				[0x31, 0],
				[0x30, 0x80],
				[0x30, 0x83],
				[0x30, 0x81, 1, 0],
				[0x30, 0x82, 0, 0x80],
				[0x30, 6, 2, 1, 1, 2, 1],
				[0x30, 0, 2, 1, 1, 2, 1, 1, 255],
				[0x30, 6, 2, 1, 128, 2, 1, 1],
				[0x30, 6, 2, 1, 0, 2, 1, 1],
				[0x30, 7, 2, 2, 0, 1, 2, 1, 1],
				[0x30, 6, 4, 1, 1, 2, 1, 1],
				[0x30, 5, 2, 0, 2, 1, 1],
				[0x30, 9, 2, 1, 1, 2, 1, 1, 0, 0, 0],
			])
				a.throws(() => derToJws(new Uint8Array(der), "ES256"), CryptoError);
			for (const alg of ["ES256", "ES384", "ES512"] as const) {
				const width = alg === "ES256" ? 64 : alg === "ES384" ? 96 : 132;
				fc.assert(
					fc.property(fc.uint8Array({ minLength: width, maxLength: width }), (bytes) => {
						bytes[0] = 0x80;
						bytes[width / 2] = 0x80;
						return derToJws(jwsToDer(bytes, alg), alg).every((value, i) => value === bytes[i]);
					}),
					{ numRuns: 30 },
				);
			}
			for (const alg of ["RS256", "constructor", "__proto__", "toString"])
				a.throws(
					() => derToJws(new Uint8Array(), alg as BuiltinJwsAlgorithm),
					errorCode("UNSUPPORTED_ALGORITHM"),
				);
			a.throws(() => jwsToDer(new Uint8Array(1), "ES256"), CryptoError);
			a.throws(() => jwsToDer(new Uint8Array(64), "ES256"), CryptoError);
			a.true(true);
		});
	});

	module("crypto / keyrings", () => {
		test("supports purpose-specific keys, aliases, snapshots, and hostile property names", async (a) => {
			const f = await cryptoFixture();
			const source = { ...f.signer.publicJwk, key_ops: ["verify"], x5c: ["certificate"] };
			const signers: Record<string, Signer> = {
				request_object: { publicJwk: source, sign: f.signer.sign.bind(f.signer) },
			};
			const aliases = { client_assertion: "request_object" };
			const ring = new StaticKeyring({ signers, aliases });
			source.kid = "changed";
			source.key_ops.push("encrypt");
			source.x5c.push("changed");
			delete signers.request_object;
			const snapshot = await ring.entry("client_assertion", { subject: "https://subject.example" });
			a.equal(snapshot.signer.publicJwk.kid, f.publicJwk.kid);
			a.deepEqual(snapshot.publishedJwks.keys[0]?.x5c, ["certificate"]);
			a.true(Object.isFrozen(snapshot));
			a.true(Object.isFrozen(snapshot.signer.publicJwk));
			a.true(Object.isFrozen(snapshot.publishedJwks.keys));
			const token = await signCompactJws(payload, header(snapshot.signer), snapshot.signer);
			a.true(await engine.verify(cryptoInput(token, f.publicJwk)));
			for (const purpose of ["federation", "unknown", "__proto__", "toString"])
				await a.rejects(ring.entry(purpose), errorCode("KEY_NOT_FOUND"));
			await a.rejects(new StaticKeyring({ signers: {} }).entry("anything"), CryptoError);
			a.throws(() => new StaticKeyring({ signers: {}, aliases: { x: "missing" } }), CryptoError);
			a.throws(
				() => new StaticKeyring({ signers: { x: f.signer }, aliases: { x: "x" } }),
				CryptoError,
			);
			a.throws(
				() =>
					new StaticKeyring({
						signers: { x: f.signer },
						additionalPublishedKeys: { x: [f.publicJwk] },
					}),
				CryptoError,
			);
			a.throws(
				() => new StaticKeyring({ signers: {}, additionalPublishedKeys: { x: [] } }),
				CryptoError,
			);
			a.throws(
				() =>
					new StaticKeyring({
						signers: { x: { publicJwk: f.signer.publicJwk, sign: undefined } as unknown as Signer },
					}),
				CryptoError,
			);
		});
		test("retains signer snapshots and recorded lifetimes across rotation and revocation", async (a) => {
			const f = await cryptoFixture();
			const other = new SoftwareSigner({ ...f.privateJwk, kid: "next", alg: "ES256" });
			let now = 1000.25;
			const ring = new MemoryRotatingKeyring({ federation: f.signer }, { nowSeconds: () => now });
			const before = await ring.entry("federation");
			now = 1001.5;
			await ring.publish("federation", other);
			a.equal((await ring.entry("federation")).publishedJwks.keys.length, 2);
			a.equal(
				(await ring.history("federation")).length,
				1,
				"unactivated published keys are not historical records",
			);
			now = 1002.75;
			await ring.activate("federation", "next");
			a.equal((await ring.entry("federation")).signer.publicJwk.kid, "next");
			a.true(
				await engine.verify(
					cryptoInput(
						await signCompactJws(payload, header(before.signer), before.signer),
						f.publicJwk,
					),
				),
			);
			now = 1003.5;
			await ring.retire("federation", f.signer.publicJwk.kid);
			await ring.retire("federation", f.signer.publicJwk.kid);
			a.equal((await ring.entry("federation")).publishedJwks.keys.length, 1);
			now = 1004.5;
			await ring.revoke("federation", "next", "compromised");
			await ring.revoke("federation", "next", "repeat");
			await a.rejects(ring.entry("federation"), CryptoError);
			const history = await ring.history("federation");
			a.equal(history[0]?.publishedAt, 1000.25);
			a.equal(history[0]?.activatedAt, 1000.25);
			a.equal(history[0]?.retiredAt, 1003.5);
			a.equal(history[1]?.activatedAt, 1002.75);
			a.equal(
				history[1]?.publishedAt,
				1001.5,
				"Activation preserves the earlier publication event",
			);
			a.equal(history[1]?.revokedAt, 1004.5);
			a.equal(history[1]?.revocationReason, "compromised");
			a.true(Object.isFrozen(history[0]?.publicJwk));
			await a.rejects(ring.activate("federation", f.signer.publicJwk.kid), CryptoError);
			await a.rejects(ring.retire("federation", "next"), CryptoError);
			await a.rejects(ring.publish("federation", f.signer), CryptoError);
		});
		test("rejects lifecycle failures without partial mutations and permits recovery", async (a) => {
			const f = await cryptoFixture();
			let now = 100;
			const ring = new MemoryRotatingKeyring({}, { nowSeconds: () => now });
			await a.rejects(ring.entry("unknown"), CryptoError);
			await a.rejects(ring.history("unknown"), CryptoError);
			await ring.publish("wallet_attestation", f.signer);
			await a.rejects(ring.entry("wallet_attestation"), CryptoError);
			now = NaN;
			await a.rejects(ring.activate("wallet_attestation", f.signer.publicJwk.kid), CryptoError);
			a.deepEqual(await ring.history("wallet_attestation"), []);
			now = 101;
			await ring.activate("wallet_attestation", f.signer.publicJwk.kid);
			a.equal((await ring.history("wallet_attestation"))[0]?.publishedAt, 100);
			now = 99;
			await a.rejects(ring.revoke("wallet_attestation", f.signer.publicJwk.kid, "x"), CryptoError);
			a.equal(
				(await ring.entry("wallet_attestation")).signer.publicJwk.kid,
				f.signer.publicJwk.kid,
			);
			now = 102;
			await ring.revoke("wallet_attestation", f.signer.publicJwk.kid, "x");
			const replacement = new SoftwareSigner({ ...f.privateJwk, kid: "replacement", alg: "ES256" });
			now = NaN;
			await a.rejects(ring.publish("wallet_attestation", replacement), CryptoError);
			now = 102;
			await ring.publish("wallet_attestation", replacement);
			await ring.activate("wallet_attestation", "replacement");
			a.equal((await ring.entry("wallet_attestation")).signer.publicJwk.kid, "replacement");
			await a.rejects(ring.retire("wallet_attestation", "replacement"), CryptoError);
			await a.rejects(ring.activate("wallet_attestation", "missing"), CryptoError);
			const unused = new SoftwareSigner({ ...f.privateJwk, kid: "unused", alg: "ES256" });
			await ring.publish("wallet_attestation", unused);
			await ring.retire("wallet_attestation", "unused");
			a.equal(
				(await ring.history("wallet_attestation")).find(
					(record) => record.publicJwk.kid === "unused",
				)?.publishedAt,
				102,
			);
			a.equal(
				(await ring.history("wallet_attestation")).find(
					(record) => record.publicJwk.kid === "unused",
				)?.activatedAt,
				undefined,
			);
			a.throws(() => new MemoryRotatingKeyring({}, { nowSeconds: () => Infinity }), CryptoError);
		});
	});
};
