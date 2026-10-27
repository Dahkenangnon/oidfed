/** Disposable HTTPS applications exercised by the external Foundation suite. */
import { readFileSync, writeFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { Intermediate, MemoryStorageAdapter, TrustAnchor } from "@oidfed/authority";
import {
	discoverEntity,
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	resolveEntityKeys,
	type TrustAnchorSet,
} from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { OidcRelyingPartyRole, StaticProtocolSigningKeyProvider } from "@oidfed/oidc";
import { rateLimit } from "express-rate-limit";
import { importJWK, type JWK as JoseJWK } from "jose";
import * as oidc from "openid-client";
import { createAuthorityApp } from "../e2e/participants/authority-app.js";
import { createLeafApp } from "../e2e/participants/leaf-app.js";
import { createOpenIDProviderApp } from "../e2e/participants/openid-provider-app.js";

const state = "/run/oidfed";
const settings = JSON.parse(readFileSync(join(state, "settings.json"), "utf8")) as {
	runId: string;
};
const base = (name: string) => `https://${name}.ofed.test:8443`;
const suite = base("suite");
const suiteAuthority = (role: string) => `${suite}/test/a/${settings.runId}-${role}/trust-anchor`;
const pairs = await Promise.all(Array.from({ length: 11 }, () => generateSigningKey("RS256")));
const key = (index: number) => {
	const value = pairs[index];
	if (!value) throw new Error("Missing fixture key");
	return value;
};
const provider = (index: number) => MemoryFederationKeyProvider.fromJWK(key(index).privateKey);
const anchors: TrustAnchorSet = new Map([
	[entityId(base("ta")), { jwks: { keys: [key(0).publicKey] } }],
	[entityId(suiteAuthority("op")), { jwks: { keys: [key(6).publicKey] } }],
	[entityId(suiteAuthority("rp")), { jwks: { keys: [key(6).publicKey] } }],
]);
const fed = (id: string) => ({
	federation_fetch_endpoint: `${id}/fetch`,
	federation_list_endpoint: `${id}/list`,
	federation_resolve_endpoint: `${id}/resolve`,
});
const ta = new TrustAnchor({
	entityId: base("ta"),
	metadata: { federation_entity: fed(base("ta")) },
	storage: new MemoryStorageAdapter(),
	keyProvider: provider(0),
	trustAnchors: anchors,
});
const ia = new Intermediate({
	entityId: base("ia"),
	authorityHints: [base("ta")],
	metadata: { federation_entity: fed(base("ia")) },
	storage: new MemoryStorageAdapter(),
	keyProvider: provider(1),
	trustAnchors: anchors,
});
const leaf = new Leaf({
	entityId: base("leaf"),
	authorityHints: [base("ia")],
	metadata: { federation_entity: { display_name: "Conformance Leaf" } },
	keyProvider: provider(2),
});
await ta.registerSubordinate({
	entityId: entityId(base("ia")),
	jwks: { keys: [key(1).publicKey] },
	isIntermediate: true,
});
await ia.registerSubordinate({
	entityId: entityId(base("leaf")),
	jwks: { keys: [key(2).publicKey] },
});
const opKeys = provider(3);
const opLeaf = new Leaf({
	entityId: base("op"),
	authorityHints: [suiteAuthority("op")],
	keyProvider: opKeys,
	metadata: {
		federation_entity: {},
		openid_provider: {
			issuer: base("op"),
			authorization_endpoint: `${base("op")}/auth`,
			token_endpoint: `${base("op")}/token`,
			userinfo_endpoint: `${base("op")}/me`,
			jwks_uri: `${base("op")}/jwks`,
			pushed_authorization_request_endpoint: `${base("op")}/request`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
			request_object_signing_alg_values_supported: ["RS256"],
			token_endpoint_auth_methods_supported: ["private_key_jwt"],
			token_endpoint_auth_signing_alg_values_supported: ["RS256"],
			scopes_supported: ["openid"],
			claims_supported: ["sub"],
			client_registration_types_supported: ["automatic"],
			request_parameter_supported: true,
			request_uri_parameter_supported: true,
		},
	},
});
const rpRole = new OidcRelyingPartyRole({
	protocolKeyProvider: new StaticProtocolSigningKeyProvider({
		requestObjectSigner: new JwkSigner(key(5).privateKey),
	}),
	metadata: {
		redirect_uris: [`${base("rp")}/callback`],
		response_types: ["code"],
		grant_types: ["authorization_code"],
		client_registration_types: ["automatic"],
		token_endpoint_auth_method: "private_key_jwt",
		jwks: { keys: [key(5).publicKey] },
	},
});
const rpLeaf = new Leaf({
	entityId: base("rp"),
	authorityHints: [suiteAuthority("rp")],
	keyProvider: provider(4),
	metadata: { federation_entity: {} },
	roles: [rpRole],
	trustAnchors: anchors,
});
const rpProtocolKey = await importJWK(
	JSON.parse(JSON.stringify(key(5).privateKey)) as JoseJWK,
	"RS256",
);
if (rpProtocolKey instanceof Uint8Array) throw new Error("Expected an asymmetric fixture key");
const sessions = new Map<
	string,
	{ configuration: oidc.Configuration; verifier: string; nonce: string; expires: number }
>();
const rpApp = createLeafApp(rpLeaf, base("rp"));
rpApp.use(
	rateLimit({
		windowMs: 60_000,
		limit: 1_000,
		keyGenerator: () => "fixture",
		standardHeaders: "draft-8",
		legacyHeaders: false,
	}),
);
rpApp.get("/login", async (_req, res) => {
	for (const [id, session] of sessions) if (session.expires < Date.now()) sessions.delete(id);
	if (sessions.size >= 100) {
		res.status(503).end();
		return;
	}
	// Only the fixed suite RP-plan issuer is an allowed login target.
	const issuer = `${suite}/test/a/${settings.runId}-rp`;
	const discovered = await discoverEntity(entityId(issuer), anchors);
	if (!discovered.ok) {
		res.status(400).json({ accepted: false, stage: "federation" });
		return;
	}
	const metadata = discovered.value.resolvedMetadata.openid_provider;
	const federationKeys = discovered.value.trustChain.statements[0]?.payload.jwks;
	if (!metadata || !federationKeys) throw new Error("Missing trusted OP metadata");
	const keys = await resolveEntityKeys(metadata, federationKeys);
	if (!keys.ok) throw new Error("Protocol key resolution failed");
	// Supply the authenticated key material, including inline/superior replacements,
	// through the protocol engine's JWKS transport. No second discovery is performed.
	const keyUri = new URL("/validated-protocol-keys", base("rp")).href;
	const engineMetadata = { ...metadata, jwks_uri: keyUri } as unknown as oidc.ServerMetadata;
	const bound = new oidc.Configuration(
		engineMetadata,
		base("rp"),
		{ token_endpoint_auth_signing_alg: "RS256" },
		oidc.PrivateKeyJwt(rpProtocolKey),
	);
	bound[oidc.customFetch] = (input, init) =>
		String(input) === keyUri
			? Promise.resolve(Response.json({ keys: keys.value.keys }))
			: fetch(input, init as RequestInit);
	const verifier = oidc.randomPKCECodeVerifier();
	const nonce = oidc.randomNonce();
	const session = oidc.randomState();
	sessions.set(session, { configuration: bound, verifier, nonce, expires: Date.now() + 300_000 });
	const authorization = await rpRole.createAuthorizationRequest(
		discovered.value,
		{
			response_type: "code",
			redirect_uri: `${base("rp")}/callback`,
			scope: "openid",
			state: session,
			nonce,
			code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
			code_challenge_method: "S256",
		},
		anchors,
		{ requestDelivery: "query" },
	);
	if (!authorization.ok || authorization.value.delivery !== "query") {
		sessions.delete(session);
		res.status(400).json({ accepted: false, stage: "registration" });
		return;
	}
	res.redirect(authorization.value.authorizationUrl);
});
rpApp.get("/callback", async (req, res) => {
	const session = typeof req.query.state === "string" ? sessions.get(req.query.state) : undefined;
	if (typeof req.query.state === "string") sessions.delete(req.query.state);
	if (!session || session.expires < Date.now()) {
		res.status(400).json({ accepted: false, stage: "session" });
		return;
	}
	try {
		const tokens = await oidc.authorizationCodeGrant(
			session.configuration,
			new URL(req.originalUrl, base("rp")),
			{
				pkceCodeVerifier: session.verifier,
				expectedNonce: session.nonce,
				expectedState: String(req.query.state),
				idTokenExpected: true,
			},
		);
		res.json({ accepted: Boolean(tokens.claims()?.sub), stage: "protocol" });
	} catch {
		res.status(400).json({ accepted: false, stage: "protocol" });
	}
});
const taApp = createAuthorityApp(ta, base("ta"));
const iaApp = createAuthorityApp(ia, base("ia"));
const leafApp = createLeafApp(leaf, base("leaf"));
const opApp = createOpenIDProviderApp({
	leaf: opLeaf,
	entityId: base("op"),
	trustAnchors: anchors,
	federationKeyProvider: opKeys,
	oidcSigningKey: key(7).privateKey,
	allowedRequestUriHosts: new Set(["suite.ofed.test"]),
	automaticInteractions: true,
	authorizationErrorRedirect: `${suite}/test/a/${settings.runId}-op/callback`,
});
writeFileSync(
	join(state, "suite-keys.json"),
	JSON.stringify({
		authority: key(6).privateKey,
		entity: key(8).privateKey,
		protocol: key(9).privateKey,
		encryption: { ...key(10).privateKey, use: "enc", alg: "RSA-OAEP-256" },
		anchorPublic: key(0).publicKey,
	}),
	{ mode: 0o600 },
);
const server = https.createServer(
	{
		cert: readFileSync(join(state, "tls.pem")),
		key: readFileSync(join(state, "tls-key.pem")),
		maxHeaderSize: 65_536,
	},
	(req, res) => {
		if (req.url === "/health") {
			res.writeHead(200).end("ready");
			return;
		}
		switch ((req.headers.host ?? "").split(":")[0]) {
			case "ta.ofed.test":
				taApp(req, res);
				break;
			case "ia.ofed.test":
				iaApp(req, res);
				break;
			case "leaf.ofed.test":
				leafApp(req, res);
				break;
			case "op.ofed.test":
				opApp(req, res);
				break;
			case "rp.ofed.test":
				rpApp(req, res);
				break;
			default:
				res.writeHead(404).end();
		}
	},
);
server.listen(8443, "0.0.0.0");
for (const signal of ["SIGINT", "SIGTERM"] as const)
	process.once(signal, () => server.close(() => process.exit(0)));
