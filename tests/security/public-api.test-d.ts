import type { CryptoEngine } from "@oidfed/crypto";

declare const engine: CryptoEngine;

import {
	type AuthorityConfig,
	Intermediate,
	type IntermediateConfig,
	TrustAnchor,
} from "@oidfed/authority";
import {
	type assessEntity,
	type discoverEntity,
	type EntityId,
	entityId,
	err,
	type FederationOptions,
	ok,
	type Result,
} from "@oidfed/core";
import type { Leaf } from "@oidfed/leaf";
import { OAuthClientRole, OidcProviderRole } from "@oidfed/oidc";
import { CredentialIssuerRole, WalletProviderRole } from "@oidfed/wallet";
import { expectAssignable, expectError, expectType } from "tsd";

const result: Result<number, string> = Math.random() ? ok(1) : err("invalid");
if (result.ok) {
	expectType<number>(result.value);
	expectError(result.error);
} else {
	expectType<string>(result.error);
	expectError(result.value);
}
expectType<EntityId>(entityId("https://entity.example"));
expectAssignable<FederationOptions>({
	engine,
	maxTotalFetches: 0,
	logger: {
		debug: async () => {},
		info: async () => {},
		warn: async () => {},
		error: async () => {},
	},
});
expectError(entityId(123));
expectError(OidcProviderRole.parseMetadata({}, "extra"));
expectType<boolean>(OAuthClientRole.parsePublicationMetadata({}).success);
expectType<boolean>(WalletProviderRole.parsePublicationMetadata({}).success);
expectType<boolean>(CredentialIssuerRole.parsePublicationMetadata({}).success);
expectType<Leaf>(null as unknown as Awaited<ReturnType<typeof Leaf.create>>);
expectType<TrustAnchor>(null as unknown as Awaited<ReturnType<typeof TrustAnchor.create>>);
expectType<Intermediate>(null as unknown as Awaited<ReturnType<typeof Intermediate.create>>);

const anchor = null as unknown as TrustAnchor;
const intermediate = null as unknown as Intermediate;
expectError<TrustAnchor>(intermediate);
expectError<Intermediate>(anchor);
expectType<EntityId>(anchor.entityId);
expectError(() => {
	anchor.entityId = entityId("https://other.example");
});
expectError(TrustAnchor.assessEntity);
expectError(Intermediate.discoverEntity);
expectError(intermediate.setTrustMarkIssuers);
expectError(intermediate.setTrustMarkOwners);
expectType<Promise<string>>(
	anchor.resolveEntity(entityId("https://subject.example"), undefined, { clockSkewSeconds: 5 }),
);
expectError(anchor.resolveEntity(entityId("https://subject.example"), undefined, { engine }));
const config = null as unknown as AuthorityConfig;
const intermediateConfig = null as unknown as IntermediateConfig;
expectType<Promise<Intermediate>>(Intermediate.create(intermediateConfig));
expectError(Intermediate.create(config));
expectError(Intermediate.create({ ...intermediateConfig, authorityHints: [] }));
expectError(Intermediate.create({ ...intermediateConfig, trustMarkIssuers: {} }));
const provider = null as unknown as OidcProviderRole;
expectError(provider.processAutomaticRegistration("request", { engine }));
expectError(
	provider.processPushedAuthorizationRequest(new Request("https://provider.example/par"), {
		algorithmRegistry: undefined,
	}),
);
expectType<Promise<string>>(anchor.getEntityConfiguration());
expectType<Promise<Response>>(intermediate.handleRequest(new Request("https://authority.example")));

expectType<ReturnType<typeof assessEntity>>(
	anchor.assessEntity(entityId("https://subject.example")),
);
expectType<ReturnType<typeof discoverEntity>>(
	intermediate.discoverEntity(entityId("https://subject.example")),
);

expectError<FederationOptions>({ maxTotalFetches: 0 });
