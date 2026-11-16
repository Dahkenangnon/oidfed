import { type Intermediate, TrustAnchor } from "@oidfed/authority";
import {
	type assessEntity,
	type discoverEntity,
	type discoverEntityFromChain,
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
expectType<Leaf>(null as unknown as InstanceType<typeof Leaf>);
expectType<TrustAnchor>(null as unknown as InstanceType<typeof TrustAnchor>);
expectType<Intermediate>(null as unknown as InstanceType<typeof Intermediate>);

const anchor = null as unknown as TrustAnchor;
const intermediate = null as unknown as Intermediate;
expectError<TrustAnchor>(intermediate);
expectError<Intermediate>(anchor);
expectType<EntityId>(anchor.entityId);
expectError(() => {
	anchor.entityId = entityId("https://other.example");
});
expectType<typeof Intermediate.assessEntity>(TrustAnchor.assessEntity);
expectType<typeof Intermediate.discoverEntity>(TrustAnchor.discoverEntity);
expectType<typeof Intermediate.discoverEntityFromChain>(TrustAnchor.discoverEntityFromChain);
expectType<typeof Intermediate.sanitizeSubordinateMetadata>(
	TrustAnchor.sanitizeSubordinateMetadata,
);
expectType<Promise<string>>(anchor.getEntityConfiguration());
expectType<Promise<Response>>(intermediate.handleRequest(new Request("https://authority.example")));

expectType<typeof assessEntity>(TrustAnchor.assessEntity);
expectType<typeof discoverEntity>(TrustAnchor.discoverEntity);
expectType<typeof discoverEntityFromChain>(TrustAnchor.discoverEntityFromChain);
expectType<ReturnType<typeof assessEntity>>(
	anchor.assessEntity(entityId("https://subject.example")),
);
expectType<ReturnType<typeof discoverEntity>>(
	intermediate.discoverEntity(entityId("https://subject.example")),
);
