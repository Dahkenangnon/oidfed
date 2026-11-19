/** Compile the complete crypto surface under exact optional-property checking. */
import type {
	CryptoEngine,
	HistoricalKeyRecord,
	Jwk,
	JwsAlgorithm,
	JwsVerifyInput,
	Keyring,
	PublicJwk,
	Signer,
	SigningPublicJwk,
} from "@oidfed/crypto";
import { decodeCompactJws, StaticKeyring } from "@oidfed/crypto";
import { createWebCryptoEngine } from "@oidfed/crypto/web";
import { OidcRelyingPartyRole } from "@oidfed/oidc";
import { WalletProviderRole } from "@oidfed/wallet";

const wire: Jwk = { kty: "EC", crv: "P-256" };
const publicKey: PublicJwk = wire;
// @ts-expect-error Signing identities require an explicit identifier and algorithm.
const signing: SigningPublicJwk = publicKey;
const engine: CryptoEngine = createWebCryptoEngine(globalThis.crypto);
const keyring: Keyring = new StaticKeyring({ signers: {} });
declare const signer: Signer;
declare const input: JwsVerifyInput;
// @ts-expect-error Verification consumes bytes, not a second compact representation.
engine.verify({ ...input, compact: "stale" });
const decoded = decodeCompactJws("e30.e30.");
// @ts-expect-error Inspection does not establish a supported algorithm.
const inspectedAlgorithm: JwsAlgorithm = decoded.header.alg;
const customHistory: HistoricalKeyRecord = { publicJwk: signer.publicJwk };
// @ts-expect-error Signing callbacks return bytes, not JWT strings.
const wrong: Signer = { publicJwk: signer.publicJwk, sign: async () => "JWT" };
void [signing, engine, keyring, wrong, inspectedAlgorithm, customHistory];

// @ts-expect-error The RP defines operation names, and the host selects purpose values.
new OidcRelyingPartyRole({ signing: { requestObjects: "kms-rp" } });
// @ts-expect-error The wallet role defines operation names.
new WalletProviderRole({ signing: { attestation: "native-wallet" } });
