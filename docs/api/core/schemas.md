# Schemas and wire types

[`@oidfed/core`](README.md)

Schemas check data shape and local claim relationships. A successful parse does not verify a signature, establish an anchor, or authorize an operation. Publication metadata may be partial; effective protocol metadata is checked after superior completion and policy.

Field tables describe parsed output. A Zod-branded Entity Identifier is written as `z.output<typeof EntityIdSchema>`; it has a different TypeScript brand from the core `EntityId` factory type. `z.infer` and `z.output` refer to Zod's type helpers, not additional core exports. Loose object schemas preserve unknown fields; plain object schemas strip them, and strict object schemas reject them. Use the parser's returned data when those distinctions matter.

## `BaseEntityStatementSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L29)

Parse the common Entity Statement fields and require `exp > iat`. The schema preserves extension claims. It does not enforce all EC/SS-specific claim placement, critical-claim semantics, signature, or trust rules.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `metadata?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata blocks indexed by Entity Type. This base shape does not apply the specialized EC/SS claim restrictions. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `COLLECTION_INFO_CLAIMS`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L8)

Informational metadata claim names recognized by the Entity Collection schemas.

```typescript signature
const COLLECTION_INFO_CLAIMS: readonly ["organization_name", "display_name", "description", "keywords", "contacts", "logo_uri", "policy_uri", "information_uri", "organization_uri"];
```

## `createCollectionSchemas`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L21)

Create informational, entity-entry, and collection-response schemas using the standard informational claims plus the supplied declaration names. Informational values retain unknown fields; standard and language-tagged claim values are checked. The returned schemas parse data only, without validating Federation or Trust Mark evidence.

```typescript signature
createCollectionSchemas(infoClaims?: readonly string[]): {
	info: z.ZodRecord<z.ZodString, z.ZodUnknown>;
	entity: z.ZodObject<{
		entity_id: z.core.$ZodBranded<z.ZodURL, "EntityId", "out">;
		entity_types: z.ZodOptional<z.ZodArray<z.ZodString>>;
		entity_infos: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodRecord<z.ZodString, z.ZodUnknown>>>;
		trust_marks: z.ZodOptional<z.ZodArray<z.ZodObject<{
			trust_mark_type: z.ZodString;
			trust_mark: z.ZodString;
		}, z.core.$strip>>>;
	}, z.core.$loose>;
	response: z.ZodObject<{
		entities: z.ZodArray<z.ZodObject<{
			entity_id: z.core.$ZodBranded<z.ZodURL, "EntityId", "out">;
			entity_types: z.ZodOptional<z.ZodArray<z.ZodString>>;
			entity_infos: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodRecord<z.ZodString, z.ZodUnknown>>>;
			trust_marks: z.ZodOptional<z.ZodArray<z.ZodObject<{
				trust_mark_type: z.ZodString;
				trust_mark: z.ZodString;
			}, z.core.$strip>>>;
		}, z.core.$loose>>;
		next: z.ZodOptional<z.ZodString>;
		last_updated: z.ZodOptional<z.ZodNumber>;
	}, z.core.$loose>;
};
```

## `DecodedFederationJwtPayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L83)

Decoded federation tokens still need profile-specific claim validation.

```typescript signature
type DecodedFederationJwtPayload = {
	[key: string]: unknown;
	iss: z.output<typeof EntityIdSchema>;
	sub: z.output<typeof EntityIdSchema>;
	iat: number;
	exp: number;
	jwks?: undefined | JWKSet;
	authority_hints?: undefined | Array<z.output<typeof EntityIdSchema>>;
	trust_anchor_hints?: undefined | Array<z.output<typeof EntityIdSchema>>;
	source_endpoint?: undefined | string;
	trust_anchor?: undefined | string;
	metadata?: undefined | Record<string, Record<string, unknown>>;
	metadata_policy?: undefined | Record<string, Record<string, unknown>>;
	constraints?: undefined | TrustChainConstraints;
	crit?: undefined | Array<string>;
	metadata_policy_crit?: undefined | Array<string>;
	trust_marks?: undefined | Array<TrustMarkRef>;
	trust_mark_issuers?: undefined | Record<string, Array<z.output<typeof EntityIdSchema>>>;
	trust_mark_owners?: undefined | Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>;
	aud?: undefined | string | Array<string>;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jwks?` | `undefined \| JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `authority_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `trust_anchor_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Hints about reachable Trust Anchors; permitted only when the Entity Configuration has Superiors. |
| `source_endpoint?` | `undefined \| string` | Fetch endpoint from which the Subordinate Statement was obtained. |
| `trust_anchor?` | `undefined \| string` | Trust Anchor identifier carried by this request or statement. |
| `metadata?` | `undefined \| Record<string, Record<string, unknown>>` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `EntityCollectionEntity`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L71)

An informational entity entry returned by an Entity Collection endpoint.

```typescript signature
type EntityCollectionEntity = z.infer<typeof EntityCollectionEntitySchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entity_id` | `z.output<typeof EntityIdSchema>` | Exact Federation Entity Identifier of this collection entry. |
| `entity_types?` | `undefined \| Array<string>` | Entity Types advertised for this collection entry. |
| `entity_infos?` | `undefined \| Record<string, Record<string, unknown>>` | Informational metadata indexed by Entity Type Identifier; these values are not independently trusted. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |

## `EntityCollectionEntitySchema`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L56)

Validates the `EntityCollectionEntity` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entity_id` | `z.output<typeof EntityIdSchema>` | Exact Federation Entity Identifier of this collection entry. |
| `entity_types?` | `undefined \| Array<string>` | Entity Types advertised for this collection entry. |
| `entity_infos?` | `undefined \| Record<string, Record<string, unknown>>` | Informational metadata indexed by Entity Type Identifier; these values are not independently trusted. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |

## `EntityCollectionRequestParams`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L74)

Filters, selected claims, locales, and pagination parameters for a collection request.

```typescript signature
type EntityCollectionRequestParams = z.input<typeof EntityCollectionRequestSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `from?` | `undefined \| string` | Opaque continuation cursor returned by a previous listing response. |
| `limit?` | `undefined \| number` | Requested maximum number of entries on a page. |
| `trustAnchor?` | `undefined \| string` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `entityType?` | `undefined \| Array<string>` | Entity Type Identifier used to select a metadata block or filter entries. |
| `trustMarkType?` | `undefined \| Array<string>` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `query?` | `undefined \| string` | Text query interpreted by the collection's configured matcher. |
| `entityClaims?` | `undefined \| Array<string>` | Entity-level claims selected or supported by the collection API. |
| `infoClaims?` | `undefined \| Array<string>` | Informational metadata claims selected or supported by the collection API. |
| `locale?` | `undefined \| Array<string>` | Preferred BCP 47 language tags for informational metadata. |

## `EntityCollectionRequestSchema`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L58)

Parse the library's camelCase collection request parameters, including nonempty selector values and BCP 47 locale syntax. Unknown top-level parameters are rejected. Use `EntityCollectionRequestParams` for its public input type; these are not the raw HTTP query names.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `from?` | `undefined \| string` | Opaque continuation cursor returned by a previous listing response. |
| `limit?` | `undefined \| number` | Requested maximum number of entries on a page. |
| `trustAnchor?` | `undefined \| z.output<typeof EntityIdSchema>` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `entityType?` | `undefined \| Array<string>` | Entity Type Identifier used to select a metadata block or filter entries. |
| `trustMarkType?` | `undefined \| Array<string>` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `query?` | `undefined \| string` | Text query interpreted by the collection's configured matcher. |
| `entityClaims?` | `undefined \| Array<string>` | Entity-level claims selected or supported by the collection API. |
| `infoClaims?` | `undefined \| Array<string>` | Informational metadata claims selected or supported by the collection API. |
| `locale?` | `undefined \| Array<string>` | Preferred BCP 47 language tags for informational metadata. |

## `EntityCollectionResponse`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L73)

A page of informational entity entries and an optional continuation cursor.

```typescript signature
type EntityCollectionResponse = z.infer<typeof EntityCollectionResponseSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entities` | `Array<EntityCollectionEntity>` | Entity Collection entries returned on this page. |
| `next?` | `undefined \| string` | Continuation value for the next response page, when one exists. |
| `last_updated?` | `undefined \| number` | NumericDate of the most recent collection update. |

## `EntityCollectionResponseSchema`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L57)

Validates the `EntityCollectionResponse` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entities` | `Array<EntityCollectionEntity>` | Entity Collection entries returned on this page. |
| `next?` | `undefined \| string` | Continuation value for the next response page, when one exists. |
| `last_updated?` | `undefined \| number` | NumericDate of the most recent collection update. |

## `EntityConfigurationPayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L185)

Claims in an entity's self-issued Entity Configuration.

```typescript signature
type EntityConfigurationPayload = z.infer<typeof EntityConfigurationSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata?` | `undefined \| FederationMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `authority_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `trust_anchor_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Hints about reachable Trust Anchors; permitted only when the Entity Configuration has Superiors. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `EntityConfigurationSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L37)

Parse Entity Configuration claims, require `iss === sub` and `exp > iat`, and retain extension fields. This is a shape check, not verification of the claimed self-signature or complete Federation claim placement.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata?` | `undefined \| FederationMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `authority_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `trust_anchor_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Hints about reachable Trust Anchors; permitted only when the Entity Configuration has Superiors. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `EntityIdSchema`

[Source](../../../packages/core/src/schemas/entity-id.ts#L5)

Validates an HTTPS Entity Identifier with no credentials, query, or fragment.

## `EntityStatementPayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L184)

Claims shared by Entity Configurations and Subordinate Statements.

```typescript signature
type EntityStatementPayload = z.infer<typeof EntityStatementPayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `authority_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `trust_anchor_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Hints about reachable Trust Anchors; permitted only when the Entity Configuration has Superiors. |
| `source_endpoint?` | `undefined \| string` | Fetch endpoint from which the Subordinate Statement was obtained. |
| `trust_anchor?` | `undefined \| string` | Trust Anchor identifier carried by this request or statement. |
| `metadata?` | `undefined \| Record<string, Record<string, unknown>>` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `EntityStatementPayloadSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L86)

Combined Entity Statement schema accepting both ECs and SSs.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `authority_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `trust_anchor_hints?` | `undefined \| Array<z.output<typeof EntityIdSchema>>` | Hints about reachable Trust Anchors; permitted only when the Entity Configuration has Superiors. |
| `source_endpoint?` | `undefined \| string` | Fetch endpoint from which the Subordinate Statement was obtained. |
| `trust_anchor?` | `undefined \| string` | Trust Anchor identifier carried by this request or statement. |
| `metadata?` | `undefined \| Record<string, Record<string, unknown>>` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `EntityTypeInfo`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L72)

Informational metadata for an entity type in a collection entry.

```typescript signature
type EntityTypeInfo = z.infer<typeof EntityTypeInfoSchema>;
```

## `EntityTypeInfoSchema`

[Source](../../../packages/core/src/schemas/entity-collection.ts#L55)

Validates the `EntityTypeInfo` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

## `EntityTypeMetadataMap`

[Source](../../../packages/core/src/schemas/metadata.ts#L121)

Metadata indexed by Entity Type Identifier.

```typescript signature
type EntityTypeMetadataMap = {
	readonly [EntityType.OpenIDWalletProvider]: Record<string, unknown>;
	readonly [EntityType.OpenIDCredentialIssuer]: Record<string, unknown>;
	readonly [EntityType.OpenIDCredentialVerifier]: Record<string, unknown>;
	readonly [EntityType.FederationEntity]: FederationEntityMetadata;
	readonly [EntityType.OpenIDRelyingParty]: OpenIDRelyingPartyMetadata;
	readonly [EntityType.OpenIDProvider]: OpenIDProviderMetadata;
	readonly [EntityType.OAuthAuthorizationServer]: Record<string, unknown>;
	readonly [EntityType.OAuthClient]: Record<string, unknown>;
	readonly [EntityType.OAuthResource]: Record<string, unknown>;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `openid_wallet_provider` | `Record<string, unknown>` | Wallet Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_issuer` | `Record<string, unknown>` | Credential Issuer metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_verifier` | `Record<string, unknown>` | Credential Verifier metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `federation_entity` | `FederationEntityMetadata` | Federation entity metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_relying_party` | `OpenIDRelyingPartyMetadata` | OpenID Relying Party metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_provider` | `OpenIDProviderMetadata` | OpenID Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_authorization_server` | `Record<string, unknown>` | OAuth authorization server metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_client` | `Record<string, unknown>` | OAuth client metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_resource` | `Record<string, unknown>` | OAuth protected resource metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |

The core-local `OpenIDRelyingPartyMetadata` and `OpenIDProviderMetadata` aliases in this declaration both mean `Record<string, unknown>`; they are not root exports or the protocol-conformance types from `@oidfed/oidc`.

## `EntityTypeMetadataPolicy`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L30)

Policy declarations for the metadata parameters of one entity type.

```typescript signature
type EntityTypeMetadataPolicy = z.infer<typeof EntityTypeMetadataPolicySchema>;
```

## `EntityTypeMetadataPolicySchema`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L25)

Validates the `EntityTypeMetadataPolicy` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

## `EXTENDED_LIST_SUPPORTED_CLAIMS`

[Source](../../../packages/core/src/schemas/extended-list.ts#L23)

Built-in claims supported by Extended Listing claim selection.

```typescript signature
const EXTENDED_LIST_SUPPORTED_CLAIMS: ReadonlySet<ExtendedListClaim>;
```

## `ExtendedListClaim`

[Source](../../../packages/core/src/schemas/extended-list.ts#L6)

Top-level Entity Statement claims that the extended listing endpoint can return per entity.

```typescript signature
const ExtendedListClaim: {
	readonly SubordinateStatement: "subordinate_statement";
	readonly Iss: "iss";
	readonly Sub: "sub";
	readonly Iat: "iat";
	readonly Exp: "exp";
	readonly Jwks: "jwks";
	readonly Metadata: "metadata";
	readonly MetadataPolicy: "metadata_policy";
	readonly Constraints: "constraints";
	readonly Crit: "crit";
	readonly MetadataPolicyCrit: "metadata_policy_crit";
	readonly TrustMarks: "trust_marks";
	readonly SourceEndpoint: "source_endpoint";
};
type ExtendedListClaim = (typeof ExtendedListClaim)[keyof typeof ExtendedListClaim];
```

## `ExtendedListEntity`

[Source](../../../packages/core/src/schemas/extended-list.ts#L77)

A subordinate entry with any requested audit timestamps and selected claims.

```typescript signature
type ExtendedListEntity = z.infer<typeof ExtendedListEntitySchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `id` | `z.output<typeof EntityIdSchema>` | Identifier of the key, subordinate, or snapshot described by this entry. |
| `subordinate_statement?` | `undefined \| string` | Compact Subordinate Statement JWT requested through Extended Listing. |
| `registered?` | `undefined \| number` | Initial subordinate registration NumericDate. |
| `updated?` | `undefined \| number` | Most recent update NumericDate for this subordinate record. |

## `ExtendedListEntitySchema`

[Source](../../../packages/core/src/schemas/extended-list.ts#L63)

Per-entity object inside `immediate_subordinate_entities`. Loose so custom claims may be present.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `id` | `z.output<typeof EntityIdSchema>` | Identifier of the key, subordinate, or snapshot described by this entry. |
| `subordinate_statement?` | `undefined \| string` | Compact Subordinate Statement JWT requested through Extended Listing. |
| `registered?` | `undefined \| number` | Initial subordinate registration NumericDate. |
| `updated?` | `undefined \| number` | Most recent update NumericDate for this subordinate record. |

## `ExtendedListQuery`

[Source](../../../packages/core/src/schemas/extended-list.ts#L76)

Filters, pagination, and claim-selection parameters for Extended Listing.

```typescript signature
type ExtendedListQuery = z.infer<typeof ExtendedListQuerySchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `from?` | `undefined \| string` | Opaque continuation cursor returned by a previous listing response. |
| `limit?` | `undefined \| number` | Requested maximum number of entries on a page. |
| `updated_after?` | `undefined \| number` | Inclusive lower update-time filter as a NumericDate. |
| `updated_before?` | `undefined \| number` | Inclusive upper update-time filter as a NumericDate. |
| `audit_timestamps?` | `undefined \| false \| true` | Explicit audit timestamp selector after server-side coercion. |
| `claims?` | `undefined \| Array<string>` | Claims associated with the artifact or selected for this operation. |
| `entity_type?` | `undefined \| Array<string>` | Requested Entity Types; interpretation follows this endpoint's selector rules. |
| `trust_marked?` | `undefined \| false \| true` | Whether to restrict a listing to entities with eligible Trust Marks. |
| `trust_mark_type?` | `undefined \| string \| Array<string>` | Trust Mark type identifier carried in this artifact or request. |
| `intermediate?` | `undefined \| false \| true` | Whether a Listing request is restricted to Intermediate Entities. |

## `ExtendedListQuerySchema`

[Source](../../../packages/core/src/schemas/extended-list.ts#L49)

Server-side query schema. Accepts raw HTTP query strings and coerces them into typed values.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `from?` | `undefined \| string` | Opaque continuation cursor returned by a previous listing response. |
| `limit?` | `undefined \| number` | Requested maximum number of entries on a page. |
| `updated_after?` | `undefined \| number` | Inclusive lower update-time filter as a NumericDate. |
| `updated_before?` | `undefined \| number` | Inclusive upper update-time filter as a NumericDate. |
| `audit_timestamps?` | `undefined \| false \| true` | Explicit audit timestamp selector after server-side coercion. |
| `claims?` | `undefined \| Array<string>` | Claims associated with the artifact or selected for this operation. |
| `entity_type?` | `undefined \| Array<string>` | Requested Entity Types; interpretation follows this endpoint's selector rules. |
| `trust_marked?` | `undefined \| false \| true` | Whether to restrict a listing to entities with eligible Trust Marks. |
| `trust_mark_type?` | `undefined \| string \| Array<string>` | Trust Mark type identifier carried in this artifact or request. |
| `intermediate?` | `undefined \| false \| true` | Whether a Listing request is restricted to Intermediate Entities. |

## `ExtendedListRequestParams`

[Source](../../../packages/core/src/schemas/extended-list.ts#L81)

Client-facing request parameters; serialised into URL query string by the fetch helper.

```typescript signature
interface ExtendedListRequestParams {
	/** Opaque continuation value returned as `next` by the server. */
	from?: string;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
	auditTimestamps?: boolean;
	claims?: ReadonlyArray<ExtendedListClaim | string>;
	entityType?: string | ReadonlyArray<string>;
	trustMarked?: boolean;
	trustMarkType?: string | ReadonlyArray<string>;
	intermediate?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `from?` | `string` | Opaque continuation cursor returned by a previous listing response. |
| `limit?` | `number` | Requested maximum number of entries on a page. |
| `updatedAfter?` | `number` | Inclusive lower update-time filter, converted to updated_after on the wire. |
| `updatedBefore?` | `number` | Inclusive upper update-time filter, converted to updated_before on the wire. |
| `auditTimestamps?` | `boolean` | Request audit timestamps explicitly; omitted values leave timestamp selection to endpoint defaults. |
| `claims?` | `ReadonlyArray<ExtendedListClaim \| string>` | Claims associated with the artifact or selected for this operation. |
| `entityType?` | `string \| ReadonlyArray<string>` | Entity Type Identifier used to select a metadata block or filter entries. |
| `trustMarked?` | `boolean` | Whether to filter a listing by the presence of eligible Trust Marks. |
| `trustMarkType?` | `string \| ReadonlyArray<string>` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `intermediate?` | `boolean` | Whether a Listing request is restricted to Intermediate Entities. |

## `ExtendedListResponse`

[Source](../../../packages/core/src/schemas/extended-list.ts#L78)

A page of Extended Listing results and its continuation information.

```typescript signature
type ExtendedListResponse = z.infer<typeof ExtendedListResponseSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `immediate_subordinate_entities` | `Array<{ [key: string]: unknown; id: z.output<typeof EntityIdSchema>; subordinate_statement?: undefined \| string; registered?: undefined \| number; updated?: undefined \| number; }>` | Immediate Subordinate entries returned by the Extended Listing endpoint. |
| `next?` | `undefined \| string` | Continuation value for the next response page, when one exists. |

## `ExtendedListResponseSchema`

[Source](../../../packages/core/src/schemas/extended-list.ts#L71)

Top-level response shape.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `immediate_subordinate_entities` | `Array<{ [key: string]: unknown; id: z.output<typeof EntityIdSchema>; subordinate_statement?: undefined \| string; registered?: undefined \| number; updated?: undefined \| number; }>` | Immediate Subordinate entries returned by the Extended Listing endpoint. |
| `next?` | `undefined \| string` | Continuation value for the next response page, when one exists. |

## `FederationEntityMetadata`

[Source](../../../packages/core/src/schemas/metadata.ts#L109)

Federation endpoints, authentication methods, and informational metadata published by an entity.

```typescript signature
type FederationEntityMetadata = z.infer<typeof FederationEntityMetadataSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_fetch_endpoint?` | `undefined \| string` | HTTPS Fetch endpoint URL, without a fragment. |
| `federation_list_endpoint?` | `undefined \| string` | HTTPS Subordinate Listing endpoint URL, without a fragment. |
| `federation_extended_list_endpoint?` | `undefined \| string` | HTTPS Extended Subordinate Listing endpoint URL, without a fragment. |
| `federation_subordinate_events_endpoint?` | `undefined \| string` | HTTPS Subordinate Events endpoint URL, without a fragment. |
| `federation_resolve_endpoint?` | `undefined \| string` | HTTPS Resolve endpoint URL, without a fragment. |
| `federation_collection_endpoint?` | `undefined \| string` | HTTPS Entity Collection endpoint URL, without a fragment. |
| `federation_trust_mark_status_endpoint?` | `undefined \| string` | HTTPS Trust Mark Status endpoint URL, without a fragment. |
| `federation_trust_mark_list_endpoint?` | `undefined \| string` | HTTPS Trust Marked Entities Listing endpoint URL, without a fragment. |
| `federation_trust_mark_endpoint?` | `undefined \| string` | HTTPS Trust Mark issuance endpoint URL, without a fragment. |
| `federation_historical_keys_endpoint?` | `undefined \| string` | HTTPS Historical Keys endpoint URL, without a fragment. |
| `federation_fetch_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Fetch endpoint; omission means none. |
| `federation_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Subordinate Listing endpoint; omission means none. |
| `federation_extended_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Extended Subordinate Listing endpoint; omission means none. |
| `federation_subordinate_events_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Subordinate Events endpoint; omission means none. |
| `federation_resolve_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Resolve endpoint; omission means none. |
| `federation_collection_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Entity Collection endpoint; omission means none. |
| `federation_trust_mark_status_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Mark Status endpoint; omission means none. |
| `federation_trust_mark_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Marked Entities Listing endpoint; omission means none. |
| `federation_trust_mark_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Mark issuance endpoint; omission means none. |
| `federation_historical_keys_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Historical Keys endpoint; omission means none. |
| `endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Signing algorithms accepted for Federation endpoint authentication; none is rejected. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |

## `FederationEntityMetadataSchema`

[Source](../../../packages/core/src/schemas/metadata.ts#L20)

Validates the `FederationEntityMetadata` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_fetch_endpoint?` | `undefined \| string` | HTTPS Fetch endpoint URL, without a fragment. |
| `federation_list_endpoint?` | `undefined \| string` | HTTPS Subordinate Listing endpoint URL, without a fragment. |
| `federation_extended_list_endpoint?` | `undefined \| string` | HTTPS Extended Subordinate Listing endpoint URL, without a fragment. |
| `federation_subordinate_events_endpoint?` | `undefined \| string` | HTTPS Subordinate Events endpoint URL, without a fragment. |
| `federation_resolve_endpoint?` | `undefined \| string` | HTTPS Resolve endpoint URL, without a fragment. |
| `federation_collection_endpoint?` | `undefined \| string` | HTTPS Entity Collection endpoint URL, without a fragment. |
| `federation_trust_mark_status_endpoint?` | `undefined \| string` | HTTPS Trust Mark Status endpoint URL, without a fragment. |
| `federation_trust_mark_list_endpoint?` | `undefined \| string` | HTTPS Trust Marked Entities Listing endpoint URL, without a fragment. |
| `federation_trust_mark_endpoint?` | `undefined \| string` | HTTPS Trust Mark issuance endpoint URL, without a fragment. |
| `federation_historical_keys_endpoint?` | `undefined \| string` | HTTPS Historical Keys endpoint URL, without a fragment. |
| `federation_fetch_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Fetch endpoint; omission means none. |
| `federation_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Subordinate Listing endpoint; omission means none. |
| `federation_extended_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Extended Subordinate Listing endpoint; omission means none. |
| `federation_subordinate_events_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Subordinate Events endpoint; omission means none. |
| `federation_resolve_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Resolve endpoint; omission means none. |
| `federation_collection_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Entity Collection endpoint; omission means none. |
| `federation_trust_mark_status_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Mark Status endpoint; omission means none. |
| `federation_trust_mark_list_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Marked Entities Listing endpoint; omission means none. |
| `federation_trust_mark_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Trust Mark issuance endpoint; omission means none. |
| `federation_historical_keys_endpoint_auth_methods?` | `undefined \| Array<string>` | Authentication methods advertised for the Historical Keys endpoint; omission means none. |
| `endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Signing algorithms accepted for Federation endpoint authentication; none is rejected. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |

## `FederationMetadata`

[Source](../../../packages/core/src/schemas/metadata.ts#L114)

Metadata blocks indexed by Entity Type Identifier.

```typescript signature
type FederationMetadata = z.infer<typeof FederationMetadataSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_entity?` | `undefined \| FederationEntityMetadata` | Federation entity metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_relying_party?` | `undefined \| Record<string, unknown>` | OpenID Relying Party metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_provider?` | `undefined \| Record<string, unknown>` | OpenID Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_authorization_server?` | `undefined \| Record<string, unknown>` | OAuth authorization server metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_client?` | `undefined \| Record<string, unknown>` | OAuth client metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_resource?` | `undefined \| Record<string, unknown>` | OAuth protected resource metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_wallet_provider?` | `undefined \| Record<string, unknown>` | Wallet Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_issuer?` | `undefined \| Record<string, unknown>` | Credential Issuer metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_verifier?` | `undefined \| Record<string, unknown>` | Credential Verifier metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |

## `FederationMetadataPolicy`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L31)

Metadata-policy declarations indexed by entity type and parameter name.

```typescript signature
type FederationMetadataPolicy = z.infer<typeof FederationMetadataPolicySchema>;
```

## `FederationMetadataPolicySchema`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L27)

Validates the `FederationMetadataPolicy` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

## `FederationMetadataSchema`

[Source](../../../packages/core/src/schemas/metadata.ts#L98)

Validates the `FederationMetadata` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_entity?` | `undefined \| FederationEntityMetadata` | Federation entity metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_relying_party?` | `undefined \| Record<string, unknown>` | OpenID Relying Party metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_provider?` | `undefined \| Record<string, unknown>` | OpenID Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_authorization_server?` | `undefined \| Record<string, unknown>` | OAuth authorization server metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_client?` | `undefined \| Record<string, unknown>` | OAuth client metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `oauth_resource?` | `undefined \| Record<string, unknown>` | OAuth protected resource metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_wallet_provider?` | `undefined \| Record<string, unknown>` | Wallet Provider metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_issuer?` | `undefined \| Record<string, unknown>` | Credential Issuer metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |
| `openid_credential_verifier?` | `undefined \| Record<string, unknown>` | Credential Verifier metadata block. Core shape parsing does not replace the protocol package's effective metadata validation. |

## `FetchQuerySchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L156)

Validates the `FetchQuery` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iss?` | `undefined \| z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |

## `getEntityTypes`

[Source](../../../packages/core/src/schemas/metadata.ts#L117)

Return the own metadata block names whose values are not `undefined`, including framework-defined Entity Type Identifiers. This helper does not validate the blocks or establish protocol conformance.

```typescript signature
getEntityTypes(metadata: FederationMetadata): ReadonlyArray<EntityTypeIdentifier>;
```

## `HistoricalKeyEntry`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L187)

A federation key and its historical validity or revocation information.

```typescript signature
type HistoricalKeyEntry = z.infer<typeof HistoricalKeyEntrySchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kty` | `string` | JWK key type. Schema acceptance does not prove the key is usable by the cryptographic backend. |
| `kid` | `string` | Key identifier used to select a public verification key. |
| `exp` | `number` | Upper lifetime bound for this historical key; selection requires validAt to precede it. |
| `use?` | `undefined \| string` | Intended key use, such as sig, enc, or an extension value. |
| `alg?` | `undefined \| string` | Algorithm associated with the signer or JWK. |
| `key_ops?` | `undefined \| Array<string>` | Operations for which the key may be used. |
| `n?` | `undefined \| string` | RSA modulus encoded as a base64url unsigned integer. |
| `e?` | `undefined \| string` | RSA public exponent encoded as a base64url unsigned integer. |
| `crv?` | `undefined \| string` | Named curve for an elliptic-curve or OKP key. |
| `x?` | `undefined \| string` | Public elliptic-curve coordinate or OKP public key value. |
| `y?` | `undefined \| string` | Public elliptic-curve y coordinate when required by the key type. |
| `iat?` | `undefined \| number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `nbf?` | `undefined \| number` | NumericDate before which the JWT must not be accepted. |
| `revoked?` | `undefined \| { [key: string]: unknown; revoked_at: number; reason?: undefined \| string; }` | Optional revocation timestamp and reason; historical verification applies the configured revocation policy. |

## `HistoricalKeyEntrySchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L91)

Historical key entry for the federation_historical_keys endpoint.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kty` | `string` | JWK key type. Schema acceptance does not prove the key is usable by the cryptographic backend. |
| `kid` | `string` | Key identifier used to select a public verification key. |
| `exp` | `number` | Upper lifetime bound for this historical key; selection requires validAt to precede it. |
| `use?` | `undefined \| string` | Intended key use, such as sig, enc, or an extension value. |
| `alg?` | `undefined \| string` | Algorithm associated with the signer or JWK. |
| `key_ops?` | `undefined \| Array<string>` | Operations for which the key may be used. |
| `n?` | `undefined \| string` | RSA modulus encoded as a base64url unsigned integer. |
| `e?` | `undefined \| string` | RSA public exponent encoded as a base64url unsigned integer. |
| `crv?` | `undefined \| string` | Named curve for an elliptic-curve or OKP key. |
| `x?` | `undefined \| string` | Public elliptic-curve coordinate or OKP public key value. |
| `y?` | `undefined \| string` | Public elliptic-curve y coordinate when required by the key type. |
| `iat?` | `undefined \| number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `nbf?` | `undefined \| number` | NumericDate before which the JWT must not be accepted. |
| `revoked?` | `undefined \| { [key: string]: unknown; revoked_at: number; reason?: undefined \| string; }` | Optional revocation timestamp and reason; historical verification applies the configured revocation policy. |

## `HistoricalKeysPayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L188)

Claims and key history carried by a signed Historical Keys response.

```typescript signature
type HistoricalKeysPayload = z.infer<typeof HistoricalKeysPayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `keys` | `Array<HistoricalKeyEntry>` | Historical public keys and their recorded validity and revocation information; this array may be empty. |

## `HistoricalKeysPayloadSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L104)

Validates the `HistoricalKeysPayload` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `keys` | `Array<HistoricalKeyEntry>` | Historical public keys and their recorded validity and revocation information; this array may be empty. |

## `JWK`

[Source](../../../packages/core/src/schemas/jwk.ts#L56)

A JSON Web Key, including its algorithm and intended-use metadata where supplied.

```typescript signature
type JWK = z.infer<typeof JWKSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kty` | `string` | JWK key type. Schema acceptance does not prove the key is usable by the cryptographic backend. |
| `kid?` | `undefined \| string` | Key identifier used to select a public verification key. |
| `use?` | `undefined \| string` | Intended key use, such as sig, enc, or an extension value. |
| `alg?` | `undefined \| string` | Algorithm associated with the signer or JWK. |
| `key_ops?` | `undefined \| Array<string>` | Operations for which the key may be used. |
| `n?` | `undefined \| string` | RSA modulus encoded as a base64url unsigned integer. |
| `e?` | `undefined \| string` | RSA public exponent encoded as a base64url unsigned integer. |
| `crv?` | `undefined \| string` | Named curve for an elliptic-curve or OKP key. |
| `x?` | `undefined \| string` | Public elliptic-curve coordinate or OKP public key value. |
| `y?` | `undefined \| string` | Public elliptic-curve y coordinate when required by the key type. |

## `JWKSchema`

[Source](../../../packages/core/src/schemas/jwk.ts#L7)

Parse public JWK fields and preserve extensions and unsupported key types for later selection. Known private-key parameters are rejected. Parsing does not prove key material is complete, usable, trusted, or supported by the active cryptographic backend.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kty` | `string` | JWK key type. Schema acceptance does not prove the key is usable by the cryptographic backend. |
| `kid?` | `undefined \| string` | Key identifier used to select a public verification key. |
| `use?` | `undefined \| string` | Intended key use, such as sig, enc, or an extension value. |
| `alg?` | `undefined \| string` | Algorithm associated with the signer or JWK. |
| `key_ops?` | `undefined \| Array<string>` | Operations for which the key may be used. |
| `n?` | `undefined \| string` | RSA modulus encoded as a base64url unsigned integer. |
| `e?` | `undefined \| string` | RSA public exponent encoded as a base64url unsigned integer. |
| `crv?` | `undefined \| string` | Named curve for an elliptic-curve or OKP key. |
| `x?` | `undefined \| string` | Public elliptic-curve coordinate or OKP public key value. |
| `y?` | `undefined \| string` | Public elliptic-curve y coordinate when required by the key type. |

## `JWKSet`

[Source](../../../packages/core/src/schemas/jwk.ts#L57)

A set of public federation signing keys.

```typescript signature
type JWKSet = z.infer<typeof JWKSetSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `keys` | `Array<JWK>` | Public keys in the set; metadata sets may be empty, while Federation signing-key sets require at least one key. |

## `JWKSetSchema`

[Source](../../../packages/core/src/schemas/jwk.ts#L41)

Parse a nonempty public Federation signing-key set with a nonempty, distinct `kid` on every key. Unknown key types can remain for selection. This schema does not prove possession or cryptographic usability of a key.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `keys` | `Array<JWK>` | Public keys in the set; metadata sets may be empty, while Federation signing-key sets require at least one key. |

## `ListQuerySchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L161)

Validates the `ListQuery` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entity_type?` | `undefined \| string` | Requested Entity Types; interpretation follows this endpoint's selector rules. |
| `trust_marked?` | `undefined \| false \| true` | Whether to restrict a listing to entities with eligible Trust Marks. |
| `trust_mark_type?` | `undefined \| string` | Trust Mark type identifier carried in this artifact or request. |
| `intermediate?` | `undefined \| false \| true` | Whether a Listing request is restricted to Intermediate Entities. |

## `MetadataJWKSetSchema`

[Source](../../../packages/core/src/schemas/jwk.ts#L36)

Parse public protocol keys. The array may be empty; key identifiers are optional and may repeat. This shape check does not enforce mixed signing/encryption `use` requirements—`validateJwkSetUseRequirement` and the protocol workflows perform that check. `JWKSetSchema` adds the Federation signing-key rules.

```ts
import { JWKSchema, JWKSetSchema, MetadataJWKSetSchema } from "@oidfed/core";

export function inspectImportedKeys(rawKey: unknown, rawSet: unknown) {
  return {
    publicKeyShape: JWKSchema.safeParse(rawKey),
    protocolSetShape: MetadataJWKSetSchema.safeParse(rawSet),
    federationSetShape: JWKSetSchema.safeParse(rawSet),
  };
}
```

Other exported schemas use the same `safeParse` contract. Select the schema for the artifact being checked, then complete its signature and trust verification before using the result.

## `MetadataParameterPolicy`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L29)

The operator declarations applied to one metadata parameter.

```typescript signature
type MetadataParameterPolicy = z.infer<typeof MetadataParameterPolicySchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `value?` | `undefined \| null \| string \| number \| false \| true \| Array<unknown> \| Record<string, unknown>` | Value imposed by a metadata-policy value operator. |
| `add?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Values added to an array metadata parameter. |
| `default?` | `undefined \| string \| number \| false \| true \| Array<unknown> \| Record<string, unknown>` | Fallback value used when this metadata parameter is absent. |
| `one_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Permitted alternatives for a single-valued parameter; an empty merged intersection is an error. |
| `subset_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Permitted members of an array parameter; merging may produce an empty intersection. |
| `superset_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Members that an array parameter must contain. |
| `essential?` | `undefined \| false \| true` | Whether the parameter must exist after policy application. |

## `MetadataParameterPolicySchema`

[Source](../../../packages/core/src/schemas/metadata-policy.ts#L15)

Validates the `MetadataParameterPolicy` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `value?` | `undefined \| null \| string \| number \| false \| true \| Array<unknown> \| Record<string, unknown>` | Value imposed by a metadata-policy value operator. |
| `add?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Values added to an array metadata parameter. |
| `default?` | `undefined \| string \| number \| false \| true \| Array<unknown> \| Record<string, unknown>` | Fallback value used when this metadata parameter is absent. |
| `one_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Permitted alternatives for a single-valued parameter; an empty merged intersection is an error. |
| `subset_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Permitted members of an array parameter; merging may produce an empty intersection. |
| `superset_of?` | `undefined \| Array<string \| number \| Record<string, unknown>>` | Members that an array parameter must contain. |
| `essential?` | `undefined \| false \| true` | Whether the parameter must exist after policy application. |

## `NamingConstraints`

[Source](../../../packages/core/src/schemas/constraints.ts#L39)

Permitted or excluded host patterns for subordinate Entity Identifiers.

```typescript signature
type NamingConstraints = z.infer<typeof NamingConstraintsSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `permitted?` | `undefined \| Array<string>` | Allowed hostname patterns; a leading dot matches subdomains rather than the bare domain. |
| `excluded?` | `undefined \| Array<string>` | Forbidden hostname patterns, taking precedence over permitted patterns. |

## `NamingConstraintsSchema`

[Source](../../../packages/core/src/schemas/constraints.ts#L18)

Validates the `NamingConstraints` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `permitted?` | `undefined \| Array<string>` | Allowed hostname patterns; a leading dot matches subdomains rather than the bare domain. |
| `excluded?` | `undefined \| Array<string>` | Forbidden hostname patterns, taking precedence over permitted patterns. |

## `OAuthAuthorizationServerMetadata`

[Source](../../../packages/core/src/oauth-metadata.ts#L239)

Effective OAuth authorization-server metadata, checked after Superior metadata and policy have been applied.

```typescript signature
type OAuthAuthorizationServerMetadata = {
	[key: string]: unknown;
	issuer: string;
	response_types_supported: Array<string>;
	authorization_endpoint?: undefined | string;
	token_endpoint?: undefined | string;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_endpoint?: undefined | string;
	acr_values_supported?: undefined | Array<string>;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	claims_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | false | true;
	request_parameter_supported?: undefined | false | true;
	request_uri_parameter_supported?: undefined | false | true;
	require_request_uri_registration?: undefined | false | true;
	check_session_iframe?: undefined | string;
	frontchannel_logout_supported?: undefined | false | true;
	frontchannel_logout_session_supported?: undefined | false | true;
	backchannel_logout_supported?: undefined | false | true;
	backchannel_logout_session_supported?: undefined | false | true;
	end_session_endpoint?: undefined | string;
	backchannel_token_delivery_modes_supported?: undefined | Array<"push" | "poll" | "ping">;
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_user_code_parameter_supported?: undefined | false | true;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | false | true;
	require_signed_request_object?: undefined | false | true;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | false | true;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | false | true;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
	service_documentation?: undefined | string;
	ui_locales_supported?: undefined | Array<string>;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	organization_identifier?: undefined | string;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `response_types_supported` | `Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `authorization_endpoint?` | `undefined \| string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the token endpoint. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported client attestation signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported client attestation pop signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported token endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported revocation endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported introspection encryption content-encryption methods. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported id token signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported id token encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported userinfo signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported userinfo encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported request object signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported request object encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported request object encryption content-encryption methods. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `claims_parameter_supported?` | `undefined \| false \| true` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| false \| true` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| false \| true` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| false \| true` | Whether Request Object URIs must be registered in advance. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `frontchannel_logout_supported?` | `undefined \| false \| true` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| false \| true` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| false \| true` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| false \| true` | Whether back-channel logout supports session identifiers. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| Array<"push" \| "poll" \| "ping">` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported backchannel authentication request signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `backchannel_user_code_parameter_supported?` | `undefined \| false \| true` | Whether CIBA requests support the user_code parameter. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported authorization signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported authorization encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported authorization encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported nfv token signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported nfv token encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| false \| true` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| false \| true` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| false \| true` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| false \| true` | Whether the server supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |

## `OAuthAuthorizationServerPublicationMetadata`

[Source](../../../packages/core/src/oauth-metadata.ts#L240)

OAuth authorization-server metadata suitable for publication before a Superior completes missing fields.

```typescript signature
type OAuthAuthorizationServerPublicationMetadata = {
	[key: string]: unknown;
	issuer?: undefined | string;
	authorization_endpoint?: undefined | string;
	token_endpoint?: undefined | string;
	response_types_supported?: undefined | Array<string>;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_endpoint?: undefined | string;
	acr_values_supported?: undefined | Array<string>;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	claims_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | false | true;
	request_parameter_supported?: undefined | false | true;
	request_uri_parameter_supported?: undefined | false | true;
	require_request_uri_registration?: undefined | false | true;
	check_session_iframe?: undefined | string;
	frontchannel_logout_supported?: undefined | false | true;
	frontchannel_logout_session_supported?: undefined | false | true;
	backchannel_logout_supported?: undefined | false | true;
	backchannel_logout_session_supported?: undefined | false | true;
	end_session_endpoint?: undefined | string;
	backchannel_token_delivery_modes_supported?: undefined | Array<"push" | "poll" | "ping">;
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_user_code_parameter_supported?: undefined | false | true;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | false | true;
	require_signed_request_object?: undefined | false | true;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | false | true;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | false | true;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
	service_documentation?: undefined | string;
	ui_locales_supported?: undefined | Array<string>;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	organization_identifier?: undefined | string;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer?` | `undefined \| string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `authorization_endpoint?` | `undefined \| string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `response_types_supported?` | `undefined \| Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the token endpoint. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported client attestation signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported client attestation pop signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported token endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported revocation endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Authentication methods supported by the introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection endpoint auth signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported introspection encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported introspection encryption content-encryption methods. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported id token signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported id token encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported userinfo signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported userinfo encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported request object signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported request object encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported request object encryption content-encryption methods. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `claims_parameter_supported?` | `undefined \| false \| true` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| false \| true` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| false \| true` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| false \| true` | Whether Request Object URIs must be registered in advance. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `frontchannel_logout_supported?` | `undefined \| false \| true` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| false \| true` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| false \| true` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| false \| true` | Whether back-channel logout supports session identifiers. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| Array<"push" \| "poll" \| "ping">` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported backchannel authentication request signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `backchannel_user_code_parameter_supported?` | `undefined \| false \| true` | Whether CIBA requests support the user_code parameter. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported authorization signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported authorization encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported authorization encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported nfv token signing algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Supported nfv token encryption algorithm identifiers. Use the parser to enforce this field's algorithm restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Supported nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| false \| true` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| false \| true` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| false \| true` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| false \| true` | Whether the server supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |

## `parseOAuthAuthorizationServerMetadata`

[Source](../../../packages/core/src/oauth-metadata.ts#L243)

Parse effective OAuth authorization-server metadata with protocol-specific field and cross-field checks. The default `oauth` profile requires `issuer` and `response_types_supported`; `openid4vci` permits the latter to be absent only for a pre-authorized-code-only server. Conditional endpoint and attestation requirements still apply. Unknown metadata is preserved. Parsing does not authenticate the issuer or `signed_metadata`.

```typescript signature
parseOAuthAuthorizationServerMetadata(metadata: unknown, options?: { profile?: "oauth" }): z.ZodSafeParseResult<OAuthAuthorizationServerMetadata>;
parseOAuthAuthorizationServerMetadata(metadata: unknown, options: { profile: "openid4vci" }): z.ZodSafeParseResult<OAuthAuthorizationServerPublicationMetadata & { issuer: string }>;
parseOAuthAuthorizationServerMetadata(metadata: unknown, options: { profile?: "oauth" | "openid4vci" }): z.ZodSafeParseResult<OAuthAuthorizationServerMetadata> | z.ZodSafeParseResult<OAuthAuthorizationServerPublicationMetadata & { issuer: string }>;
```

## `parseOAuthAuthorizationServerPublicationMetadata`

[Source](../../../packages/core/src/oauth-metadata.ts#L265)

Check supplied authorization-server publication fields while allowing a Superior to complete missing fields later. Supplied values and applicable cross-field consistency rules are still checked; unknown metadata is preserved.

```typescript signature
parseOAuthAuthorizationServerPublicationMetadata(metadata: unknown): z.ZodSafeParseResult<OAuthAuthorizationServerPublicationMetadata>;
```

## `ResolveQuerySchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L174)

Validates the `ResolveQuery` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `trust_anchor` | `z.output<typeof EntityIdSchema> \| Array<z.output<typeof EntityIdSchema>>` | Trust Anchor identifier carried by this request or statement. |
| `entity_type?` | `undefined \| string \| Array<string>` | Requested Entity Types; interpretation follows this endpoint's selector rules. |

## `ResolveResponsePayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L189)

The subject's resolved metadata and chain evidence carried in a signed Resolve response.

```typescript signature
type ResolveResponsePayload = z.infer<typeof ResolveResponsePayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata` | `FederationMetadata` | Resolver-reported effective metadata; schema parsing alone does not authorize or trust the resolver. |
| `trust_chain` | `Array<string>` | Leaf-first compact Entity Statements carrying the subject's Trust Chain. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `ResolveResponsePayloadSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L137)

Resolve Response payload for the federation_resolve endpoint.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata` | `FederationMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `trust_chain` | `Array<string>` | Leaf-first compact Entity Statements carrying the subject's Trust Chain. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `SubordinateEvent`

[Source](../../../packages/core/src/schemas/subordinate-events.ts#L30)

A recorded subordinate lifecycle event and any associated extension data.

```typescript signature
type SubordinateEvent = z.infer<typeof SubordinateEventSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `event` | `string` | Standard or extension event name. |
| `event_description?` | `undefined \| string` | Optional human-readable explanation of this event. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |

## `SubordinateEventSchema`

[Source](../../../packages/core/src/schemas/subordinate-events.ts#L14)

Validates the `SubordinateEvent` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `event` | `string` | Standard or extension event name. |
| `event_description?` | `undefined \| string` | Optional human-readable explanation of this event. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |

## `SubordinateEventsResponse`

[Source](../../../packages/core/src/schemas/subordinate-events.ts#L31)

Claims and event history carried in a signed Subordinate Events response.

```typescript signature
type SubordinateEventsResponse = z.infer<typeof SubordinateEventsResponseSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `federation_registration_events` | `Array<SubordinateEvent>` | Ordered recorded events about the requested Immediate Subordinate. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |

## `SubordinateEventsResponseSchema`

[Source](../../../packages/core/src/schemas/subordinate-events.ts#L22)

Validates the `SubordinateEventsResponse` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `federation_registration_events` | `Array<SubordinateEvent>` | Ordered recorded events about the requested Immediate Subordinate. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |

## `SubordinateEventType`

[Source](../../../packages/core/src/schemas/subordinate-events.ts#L5)

Standard subordinate lifecycle event names. Extension events use the extension-preserving event schema.

```typescript signature
const SubordinateEventType: {
	readonly Registration: "registration";
	readonly Revocation: "revocation";
	readonly Suspension: "suspension";
	readonly MetadataUpdate: "metadata_update";
	readonly MetadataPolicyUpdate: "metadata_policy_update";
	readonly JwksUpdate: "jwks_update";
};
```

## `SubordinateStatementPayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L186)

Claims in a Superior's statement about a specific subordinate.

```typescript signature
type SubordinateStatementPayload = z.infer<typeof SubordinateStatementSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata?` | `undefined \| FederationMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `source_endpoint?` | `undefined \| string` | Fetch endpoint from which the Subordinate Statement was obtained. |
| `trust_anchor?` | `undefined \| string` | Trust Anchor identifier carried by this request or statement. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `SubordinateStatementSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L54)

Parse a Superior's statement about a different subject, require `iss !== sub` and `exp > iat`, and retain extension fields. Complete publication, signature, chain, and critical-claim validation are separate checks.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `z.output<typeof EntityIdSchema>` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata?` | `undefined \| FederationMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `source_endpoint?` | `undefined \| string` | Fetch endpoint from which the Subordinate Statement was obtained. |
| `trust_anchor?` | `undefined \| string` | Trust Anchor identifier carried by this request or statement. |
| `metadata_policy?` | `undefined \| Record<string, Record<string, unknown>>` | Metadata-policy declarations indexed by Entity Type and parameter; substantive operator checks are separate from shape parsing. |
| `constraints?` | `undefined \| TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `crit?` | `undefined \| Array<string>` | Extension claim names recipients must understand and process; each named claim must be present. |
| `metadata_policy_crit?` | `undefined \| Array<string>` | Nonstandard metadata-policy operator names that recipients must understand. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |
| `trust_mark_issuers?` | `undefined \| Record<string, Array<z.output<typeof EntityIdSchema>>>` | Issuer identities permitted by the anchor for each Trust Mark type; an empty array allows any issuer. |
| `trust_mark_owners?` | `undefined \| Record<string, { [key: string]: unknown; sub: z.output<typeof EntityIdSchema>; jwks: JWKSet; }>` | Owner identity and public keys indexed by Trust Mark type, declared in anchor policy. |
| `aud?` | `undefined \| string \| Array<string>` | Optional JWT recipient value. A verifier must bind any present audience to the expected recipient under the artifact's own rules. |

## `TrustChainConstraints`

[Source](../../../packages/core/src/schemas/constraints.ts#L40)

Path length, naming, entity-type, and extension constraints declared on a chain.

```typescript signature
type TrustChainConstraints = z.infer<typeof TrustChainConstraintsSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `max_path_length?` | `undefined \| number` | Maximum number of Intermediate Entities permitted below the authority carrying this constraint. |
| `naming_constraints?` | `undefined \| NamingConstraints` | Permitted and excluded subordinate hostname patterns. |
| `allowed_entity_types?` | `undefined \| Array<string>` | Entity Types allowed to remain in subordinate metadata; federation_entity is retained. |

## `TrustChainConstraintsSchema`

[Source](../../../packages/core/src/schemas/constraints.ts#L23)

Validates the `TrustChainConstraints` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `max_path_length?` | `undefined \| number` | Maximum number of Intermediate Entities permitted below the authority carrying this constraint. |
| `naming_constraints?` | `undefined \| NamingConstraints` | Permitted and excluded subordinate hostname patterns. |
| `allowed_entity_types?` | `undefined \| Array<string>` | Entity Types allowed to remain in subordinate metadata; federation_entity is retained. |

## `TrustMarkDelegationPayload`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L44)

Claims in an owner's JWT authorizing an issuer for a Trust Mark type.

```typescript signature
type TrustMarkDelegationPayload = z.infer<typeof TrustMarkDelegationPayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Trust Mark Owner signing this issuance delegation. |
| `sub` | `z.output<typeof EntityIdSchema>` | Trust Mark Issuer authorized by the owner delegation. |
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `ref?` | `undefined \| string` | Reference URL for the Trust Mark or its delegation. |

## `TrustMarkDelegationPayloadSchema`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L28)

Validates the `TrustMarkDelegationPayload` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Trust Mark Owner signing this issuance delegation. |
| `sub` | `z.output<typeof EntityIdSchema>` | Trust Mark Issuer authorized by the owner delegation. |
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `ref?` | `undefined \| string` | Reference URL for the Trust Mark or its delegation. |

## `TrustMarkOwner`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L38)

The owner identity and public keys configured for a Trust Mark type.

```typescript signature
type TrustMarkOwner = {
	sub: string;
	jwks: JWKSet;
	[key: string]: unknown;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `sub` | `string` | Trust Mark Owner identity whose keys validate delegations for this type. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |

## `TrustMarkOwnerSchema`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L12)

Validates the `TrustMarkOwner` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `sub` | `z.output<typeof EntityIdSchema>` | Trust Mark Owner identity whose keys validate delegations for this type. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |

## `TrustMarkPayload`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L43)

Claims in a signed Trust Mark, including its issuer, subject, and type.

```typescript signature
type TrustMarkPayload = z.infer<typeof TrustMarkPayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Trust Mark Issuer signing this accreditation. |
| `sub` | `z.output<typeof EntityIdSchema>` | Accredited holder of this Trust Mark. |
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `ref?` | `undefined \| string` | Reference URL for the Trust Mark or its delegation. |
| `delegation?` | `undefined \| string` | Owner-signed delegation JWT authorizing the Trust Mark Issuer. |

## `TrustMarkPayloadSchema`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L17)

Validates the `TrustMarkPayload` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Trust Mark Issuer signing this accreditation. |
| `sub` | `z.output<typeof EntityIdSchema>` | Accredited holder of this Trust Mark. |
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp?` | `undefined \| number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `ref?` | `undefined \| string` | Reference URL for the Trust Mark or its delegation. |
| `delegation?` | `undefined \| string` | Owner-signed delegation JWT authorizing the Trust Mark Issuer. |

## `TrustMarkRef`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L37)

A published Trust Mark reference containing its type and compact JWT.

```typescript signature
type TrustMarkRef = z.infer<typeof TrustMarkRefSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `trust_mark` | `string` | Compact Trust Mark JWT, not merely its type identifier. |

## `TrustMarkRefSchema`

[Source](../../../packages/core/src/schemas/trust-mark.ts#L7)

Validates the `TrustMarkRef` data shape. Use `safeParse` to receive a success/error result, or `parse` when a thrown validation error is appropriate.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trust_mark_type` | `string` | Trust Mark type identifier carried in this artifact or request. |
| `trust_mark` | `string` | Compact Trust Mark JWT, not merely its type identifier. |

## `TrustMarkStatusBodySchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L180)

Parse a Status request body with a nonempty `trust_mark` string. This object schema strips unknown fields; signature, issuer, and active-state checks occur in the Status workflow.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trust_mark` | `string` | Nonempty compact Trust Mark JWT submitted to the Status endpoint. |

## `TrustMarkStatusResponsePayload`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L190)

Claims in the issuer's signed response about a mark's status.

```typescript signature
type TrustMarkStatusResponsePayload = z.infer<typeof TrustMarkStatusResponsePayloadSchema>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `trust_mark` | `string` | Compact Trust Mark JWT, not merely its type identifier. |
| `status` | `string` | Reported mark status; active is the interoperable positive value, while other strings may be profile-defined. |

## `TrustMarkStatusResponsePayloadSchema`

[Source](../../../packages/core/src/schemas/entity-statement.ts#L149)

Trust Mark Status Response payload.

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `trust_mark` | `string` | Compact Trust Mark JWT, not merely its type identifier. |
| `status` | `string` | Reported mark status; active is the interoperable positive value, while other strings may be profile-defined. |

