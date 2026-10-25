import {
	type AuthorityConfig,
	Intermediate,
	MemoryStorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	entityId,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	MemoryFederationKeyProvider,
} from "../../../packages/core/src/index.js";

export const issuer = entityId("https://authority.example/tenant");

export const subject = entityId("https://subordinate.example:8443/client%20one");

export const endpoint = "https://history.example:8443/events?version=1";

export async function fixture(intermediate = false, authenticated = false) {
	const key = await generateSigningKey("ES256");
	const clientKey = await generateSigningKey("ES256");
	let now = 1500;
	const clock = { now: () => now };
	const storage = new MemoryStorageAdapter({ subordinateEvents: true, clock });
	const keyProvider = new MemoryFederationKeyProvider({
		signer: new JwkSigner(key.privateKey),
		publicJwk: key.publicKey,
	});
	const config: AuthorityConfig = {
		entityId: issuer,
		storage,
		keyProvider,
		options: { clock },
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${issuer}/fetch`,
				federation_list_endpoint: `${issuer}/list`,
				federation_subordinate_events_endpoint: endpoint,
				...(authenticated
					? { federation_subordinate_events_endpoint_auth_methods: ["private_key_jwt"] }
					: {}),
			},
		},
		...(intermediate ? { authorityHints: [entityId("https://superior.example")] } : {}),
	};
	const authority = intermediate ? new Intermediate(config) : new TrustAnchor(config);
	const record = {
		entityId: subject,
		jwks: { keys: [clientKey.publicKey] },
		metadata: { openid_relying_party: { organization_name: "Client" } },
	};
	const httpClient: HttpClient = async (input, init) =>
		authority.handleRequest(new Request(String(input), init));
	const options = { issuer, issuerJwks: { keys: [key.publicKey] }, clock, httpClient };
	return {
		authority,
		storage,
		keyProvider,
		key,
		clientKey,
		record,
		config,
		options,
		clock,
		setNow: (value: number) => {
			now = value;
		},
	};
}
