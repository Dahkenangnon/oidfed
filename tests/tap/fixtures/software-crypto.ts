import {
	type CryptoContext,
	cloneData,
	historicalKeysFromKeyring,
	type JWKSchema,
	validateFederationKeySet,
} from "@oidfed/core";
/** Explicit software custody and malformed-token signing used by test fixtures. */
import {
	type BuiltinJwsAlgorithm,
	decodeBase64url,
	encodeBase64url,
	type Jwk,
	jwkThumbprint,
	type KeyringEntry,
	MemoryRotatingKeyring,
	StaticKeyring,
	utf8Decode,
	utf8Encode,
} from "@oidfed/crypto";
import { createWebCryptoEngine, SoftwareSigner } from "@oidfed/crypto/web";
import { exportJWK, generateKeyPair } from "jose";

export const testEngine = createWebCryptoEngine();

export async function generateSigningKey(alg: BuiltinJwsAlgorithm = "ES256"): Promise<{
	publicKey: ReturnType<typeof JWKSchema.parse>;
	privateKey: ReturnType<typeof JWKSchema.parse>;
}> {
	const pair = await generateKeyPair(alg, { extractable: true });
	const pub = await exportJWK(pair.publicKey);
	const kid = encodeBase64url(await jwkThumbprint(testEngine, pub as Jwk));
	return {
		publicKey: { ...pub, kty: pub.kty as string, kid, alg, use: "sig" },
		privateKey: {
			...(await exportJWK(pair.privateKey)),
			kty: pub.kty as string,
			kid,
			alg,
			use: "sig",
		},
	};
}

/** A real captured entry, plus raw signing for intentionally invalid protected headers. */
export class SigningEntryFixture implements KeyringEntry {
	readonly signer: SoftwareSigner;
	readonly publishedJwks;
	constructor(key: Jwk, options?: { alg?: BuiltinJwsAlgorithm }) {
		this.signer = new SoftwareSigner({
			...key,
			kid: key.kid as string,
			alg: options?.alg ?? (key.alg as BuiltinJwsAlgorithm),
		});
		this.publishedJwks = { keys: [this.signer.publicJwk] };
	}
	get alg() {
		return this.signer.publicJwk.alg;
	}
	get kid() {
		return this.signer.publicJwk.kid;
	}
	async signJwt(payload: Uint8Array, header: Readonly<Record<string, unknown>>): Promise<string> {
		const input = `${encodeBase64url(utf8Encode(JSON.stringify(header)))}.${encodeBase64url(payload)}`;
		return `${input}.${encodeBase64url(await this.signer.sign(utf8Encode(input)))}`;
	}
}

/** Test setup; application policies such as scheduled retirement stay in each test. */
export class FixtureCrypto implements CryptoContext {
	readonly engine = testEngine;
	readonly keyring: MemoryRotatingKeyring;
	readonly history;
	constructor(
		initial: { signer: KeyringEntry; publicJwk?: Jwk; jwks?: { keys: readonly Jwk[] } },
		options?: { nowMs?: () => number },
	) {
		if (initial.publicJwk)
			validateFederationKeySet({
				signer: initial.signer.signer,
				publishedJwks: { keys: [initial.publicJwk] },
			});
		this.keyring = new MemoryRotatingKeyring(
			{ federation: initial.signer.signer },
			options?.nowMs ? { nowSeconds: () => options.nowMs!() / 1000 } : undefined,
		);
		this.history = historicalKeysFromKeyring(this.keyring);
	}
	static fromJWK(key: Jwk, options?: { nowMs?: () => number }) {
		return new FixtureCrypto({ signer: new SigningEntryFixture(key) }, options);
	}
}

export class FixedCryptoFixture implements CryptoContext {
	readonly engine = testEngine;
	readonly keyring: StaticKeyring;
	constructor(initial: { signer: KeyringEntry; jwks: { keys: readonly Jwk[] } }) {
		validateFederationKeySet({ signer: initial.signer.signer, publishedJwks: initial.jwks });
		this.keyring = new StaticKeyring({
			signers: { federation: initial.signer.signer },
			additionalPublishedKeys: {
				federation: initial.jwks.keys.filter(
					(key) => key.kid !== initial.signer.signer.publicJwk.kid,
				),
			},
		});
	}
}

/** Translate a fixture's publication tuple into its host-owned raw signing binding. */
export function fixtureSigner(value: KeyringEntry | { signer: KeyringEntry; publicJwk?: Jwk }) {
	return "publishedJwks" in value ? value.signer : value.signer.signer;
}

/** Fixture-owned purpose bindings are installed into the host keyring during setup. */
type ProtocolFixtureInput = {
	requestObjectSigner?: KeyringEntry;
	clientAssertionSigner?: KeyringEntry;
	walletAttestationSigner?: KeyringEntry;
	authorizationRequestSigner?: KeyringEntry;
	getRequestObjectSigner?: () => Promise<KeyringEntry>;
	getClientAssertionSigner?: () => Promise<KeyringEntry>;
};
const protocolBindings = new WeakMap<object, ReadonlyMap<string, () => Promise<KeyringEntry>>>();
const fixturePublications = new WeakMap<object, readonly Jwk[]>();
export class PurposeBindingsFixture {
	readonly [operation: string]: string | undefined;
	declare readonly requestObject?: string;
	declare readonly clientAssertion?: string;
	declare readonly walletAttestation?: string;
	declare readonly authorizationRequest?: string;
	constructor(input: ProtocolFixtureInput) {
		const bindings = new Map<string, () => Promise<KeyringEntry>>();
		const known: Jwk[] = [];
		if (input.requestObjectSigner || input.getRequestObjectSigner) {
			this.requestObject = "request_object";
			this.clientAssertion = "client_assertion";
			const request =
				input.getRequestObjectSigner ?? (() => Promise.resolve(input.requestObjectSigner!));
			const assertion =
				input.getClientAssertionSigner ??
				(input.clientAssertionSigner
					? () => Promise.resolve(input.clientAssertionSigner!)
					: request);
			bindings.set(this.requestObject, request);
			bindings.set(this.clientAssertion, assertion);
		}
		if (input.walletAttestationSigner) {
			this.walletAttestation = "wallet_attestation";
			bindings.set(this.walletAttestation, () => Promise.resolve(input.walletAttestationSigner!));
		}
		if (input.authorizationRequestSigner) {
			this.authorizationRequest = "authorization_request";
			bindings.set(this.authorizationRequest, () =>
				Promise.resolve(input.authorizationRequestSigner!),
			);
		}
		for (const entry of [
			input.requestObjectSigner,
			input.clientAssertionSigner,
			input.walletAttestationSigner,
			input.authorizationRequestSigner,
		])
			if (entry) known.push(...entry.publishedJwks.keys);
		protocolBindings.set(this, bindings);
		fixturePublications.set(this, [...new Map(known.map((key) => [key.kid, key])).values()]);
	}
}
function fixtureBindings(crypto: CryptoContext, purposes: readonly object[]): CryptoContext {
	const bindings = new Map(
		purposes.flatMap((purpose) => [...(protocolBindings.get(purpose) ?? [])]),
	);
	if (!bindings.size) return crypto;
	return {
		...crypto,
		keyring: {
			entry(purpose, context) {
				const selected = bindings.get(purpose);
				return selected ? selected() : crypto.keyring.entry(purpose, context);
			},
		},
	};
}
/** Assemble actual library configuration; the production APIs receive only crypto contracts. */
export function fixtureHostConfig<T extends { crypto: CryptoContext }>(config: T): T;
export function fixtureHostConfig(
	config: import("@oidfed/authority").AuthorityConfig & { authorityHints?: never },
): import("@oidfed/authority").AuthorityConfig;
export function fixtureHostConfig(
	config: import("@oidfed/leaf").LeafConfig,
): import("@oidfed/leaf").LeafConfig;

export function fixtureHostConfig(config: {
	crypto: CryptoContext;
	roles?: readonly import("@oidfed/core").EntityRole[];
	signing?: object;
}) {
	const purposes = [
		...(config.signing ? [config.signing] : []),
		...(config.roles ?? []).flatMap((role) => {
			const signing = (role as { config?: { signing?: object } }).config?.signing;
			return signing ? [signing] : [];
		}),
	];
	// Existing fixtures supply the same keys as inline metadata. Managed publication now owns
	// that field. Remove a matching fixture copy, retaining conflicting copies for rejection tests.
	const metadata =
		"metadata" in config
			? (cloneData(config.metadata) as Record<string, Record<string, unknown>>)
			: undefined;
	const sameKeys = (value: unknown, keys: readonly Jwk[]) => {
		const published = (value as { keys?: readonly Jwk[] } | undefined)?.keys;
		return (
			published?.length === keys.length &&
			keys.every((key) =>
				published.some((candidate) =>
					["kid", "kty", "crv", "x", "y", "n", "e", "alg"].every(
						(name) => key[name] === candidate[name],
					),
				),
			)
		);
	};
	for (const role of config.roles ?? []) {
		const signing = (role as { config?: { signing?: object } }).config?.signing;
		const keys = signing && fixturePublications.get(signing);
		if (!keys?.length) continue;
		if (sameKeys(role.metadata.jwks, keys)) delete role.metadata.jwks;
		const block = metadata?.[role.type];
		if (block && sameKeys(block.jwks, keys)) delete block.jwks;
	}
	return {
		...config,
		...(metadata ? { metadata } : {}),
		crypto: fixtureBindings(config.crypto, purposes),
	};
}

const roleContexts = new WeakMap<object, WeakMap<object, import("@oidfed/core").EntityContext>>();
/** Direct role tests use the same explicit dependency setup as host factories. */
export function fixtureRoleContext(
	role: import("@oidfed/core").EntityRole,
	context: Omit<import("@oidfed/core").EntityContext, "options"> & {
		options?: import("@oidfed/core").FederationOptions;
	},
): import("@oidfed/core").EntityContext {
	const contexts =
		roleContexts.get(role) ?? new WeakMap<object, import("@oidfed/core").EntityContext>();
	roleContexts.set(role, contexts);
	const existing = contexts.get(context);
	if (existing) return existing;
	const prepared = {
		...context,
		crypto: fixtureBindings(
			context.crypto,
			(role as { config?: { signing?: object } }).config?.signing
				? [(role as unknown as { config: { signing: object } }).config.signing]
				: [],
		),
		options: { ...context.options, engine: context.crypto.engine },
	};
	contexts.set(context, prepared);
	return prepared;
}

export function signingKeyFixture(key: Jwk) {
	const signer = new SigningEntryFixture(key);
	return { signer, publicJwk: signer.signer.publicJwk };
}

/** Build a host keyring around a test-controlled publication read. */
export function fixtureCryptoFromRead(
	read: () => Promise<KeyringEntry | { signer: KeyringEntry; jwks: { keys: readonly Jwk[] } }>,
	history?: () => Promise<readonly import("@oidfed/core").HistoricalKeyEntry[]>,
): CryptoContext {
	return {
		engine: testEngine,
		keyring: {
			async entry() {
				const snapshot = await read();
				if ("publishedJwks" in snapshot) return snapshot;
				return { signer: snapshot.signer.signer, publishedJwks: snapshot.jwks };
			},
		},
		...(history ? { history: { getHistoricalKeys: history } } : {}),
	};
}

/** Instrument a real binding while allowing tests to inspect or corrupt its token result. */
export function instrumentSigningEntry(
	base: KeyringEntry | import("@oidfed/crypto").Signer,
	signJwt: (payload: Uint8Array, header: Readonly<Record<string, unknown>>) => Promise<string>,
): KeyringEntry {
	const entry =
		"publishedJwks" in base ? base : { signer: base, publishedJwks: { keys: [base.publicJwk] } };
	return {
		...entry,
		signer: {
			publicJwk: entry.signer.publicJwk,
			async sign(input) {
				const [header, payload] = utf8Decode(input).split(".");
				const token = await signJwt(
					decodeBase64url(payload!),
					JSON.parse(utf8Decode(decodeBase64url(header!))),
				);
				return decodeBase64url(token.split(".")[2]!);
			},
		},
	};
}

/** Sign arbitrary encoded fixture payloads without imposing a production token profile. */
export async function rawFixtureJwt(
	base: KeyringEntry | import("@oidfed/crypto").Signer,
	payload: Uint8Array,
	header: Readonly<Record<string, unknown>>,
): Promise<string> {
	const signer = "publishedJwks" in base ? base.signer : base;
	const input = `${encodeBase64url(utf8Encode(JSON.stringify(header)))}.${encodeBase64url(payload)}`;
	return `${input}.${encodeBase64url(await signer.sign(utf8Encode(input)))}`;
}

/** Publish all initial fixture keys and activate the requested last key explicitly. */
export async function fixtureCryptoFromKeys(
	initial: readonly { signer: KeyringEntry; publicJwk?: Jwk }[],
	options?: { nowMs?: () => number },
): Promise<FixtureCrypto> {
	if (!initial.length) throw new TypeError("At least one fixture key is required");
	const crypto = new FixtureCrypto(initial[0]!, options);
	for (const key of initial.slice(1)) {
		await crypto.keyring.publish("federation", key.signer.signer);
		await crypto.keyring.activate("federation", key.signer.signer.publicJwk.kid);
	}
	return crypto;
}

/** A backend outage begins after readiness validation, before the first publication. */
export async function fixtureCryptoFailureAfterStartup(error: Error): Promise<CryptoContext> {
	const key = await generateSigningKey();
	const entry = new SigningEntryFixture(key.privateKey);
	let reads = 0;
	return fixtureCryptoFromRead(async () => {
		if (reads++ === 0) return entry;
		throw error;
	});
}
