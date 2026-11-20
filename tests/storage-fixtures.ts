import {
	type CacheStore,
	type EntityCollectionStore,
	type FederationOptions,
	type FederationStorage,
	MemoryFederationStorage,
	type MemoryFederationStorageOptions,
	type ReadSnapshotView,
	type ReplayStore,
	type StorageCapability,
	type SubordinateEventStore,
	type SubordinateReadStore,
	type SubordinateStore,
	type TransactionView,
	type TrustMarkRecord,
	type TrustMarkStore,
} from "@oidfed/core";
import { encodeBase64url, utf8Encode } from "@oidfed/crypto";

type TestTransaction = TransactionView & { subordinate: SubordinateStore };
type TestSnapshot = ReadSnapshotView & { subordinate: SubordinateReadStore };
type TestStorage = Omit<MemoryFederationStorage, "transaction" | "readSnapshot" | "subordinate"> & {
	subordinate: SubordinateStore;
	cache: CacheStore;
	replay: ReplayStore;
	transaction<T>(op: (tx: TestTransaction) => Promise<T>): Promise<T>;
	readSnapshot<T>(op: (tx: TestSnapshot) => Promise<T>): Promise<T>;
};

type TestMemoryFlags = Omit<MemoryFederationStorageOptions, "namespace" | "capabilities"> & {
	readonly namespace?: string;
	readonly trustMarks?: boolean;
	readonly subordinateEvents?: boolean;
	readonly collections?: boolean;
};

export function memoryStorage<const Options extends TestMemoryFlags>(
	options?: Options,
): TestStorage &
	(Options extends { readonly trustMarks: true }
		? { trustMark: TrustMarkStore }
		: Record<never, never>) &
	(Options extends { readonly subordinateEvents: true }
		? { subordinateEvent: SubordinateEventStore }
		: Record<never, never>) &
	(Options extends { readonly collections: true }
		? { entityCollection: EntityCollectionStore }
		: Record<never, never>);
export function memoryStorage({
	namespace = "test",
	trustMarks,
	subordinateEvents,
	collections,
	...options
}: TestMemoryFlags = {}): TestStorage {
	const capabilities: StorageCapability[] = [
		"subordinate:read",
		"subordinate:write",
		"transaction",
		"snapshot",
		"replay",
		"cache",
	];
	if (trustMarks) capabilities.push("trustMark:read", "trustMark:write");
	if (subordinateEvents) capabilities.push("subordinateEvent:read", "subordinateEvent:write");
	if (collections) capabilities.push("entityCollection");
	return new MemoryFederationStorage({ ...options, namespace, capabilities }) as TestStorage;
}

export function replayStorage(
	replay: ReplayStore,
): FederationStorage & { readonly replay: ReplayStore } {
	return { namespace: "test", capabilities: ["replay"], replay };
}
export function cacheStorage(cache: CacheStore | undefined): FederationStorage | undefined {
	return cache ? { namespace: "test", capabilities: ["cache"], cache } : undefined;
}

export function collectionOptions<T extends FederationOptions>(
	options: T,
	entityCollection?: EntityCollectionStore,
	replay?: ReplayStore,
): T {
	const base = options.storage;
	const repository =
		entityCollection ??
		base?.entityCollection ??
		new MemoryFederationStorage({
			namespace: "test",
			capabilities: ["entityCollection"],
			...(options.clock ? { clock: options.clock } : {}),
		}).entityCollection;
	if (!repository) throw new Error("Expected a collection repository");
	return {
		...options,
		storage: {
			...base,
			namespace: base?.namespace ?? "test",
			capabilities: [
				...new Set([
					...(base?.capabilities ?? []),
					"entityCollection" as const,
					...(replay ? ["replay" as const] : []),
				]),
			],
			entityCollection: repository,
			...(replay ? { replay } : {}),
		},
	};
}

/** Public key material for storage fixtures that do not exercise signing. */
export const STORED_PUBLIC_JWK = {
	kty: "EC",
	crv: "P-256",
	kid: "storage-test",
	x: "OUdYsCLIbES6cmG2MHFuXamZ60fem7Tkk7LPO3nX9QY",
	y: "7TjTIz97de-2yxmBudZuhUS-eP6egZSw3ZV_n4URxHQ",
};

/** Structurally valid compact fixture. Use a signed token when testing protocol verification. */
export function storedTrustMarkToken(
	record: Pick<TrustMarkRecord, "subject" | "trustMarkType" | "issuedAt" | "expiresAt">,
	issuer = "https://issuer.example",
	variant = "fixture",
): string {
	const json = (data: unknown) => encodeBase64url(utf8Encode(JSON.stringify(data)));
	return [
		json({ alg: "ES256", typ: "trust-mark+jwt", kid: "storage-test" }),
		json({
			iss: issuer,
			sub: record.subject,
			trust_mark_type: record.trustMarkType,
			iat: record.issuedAt,
			exp: record.expiresAt,
			fixture: variant,
		}),
		encodeBase64url(new Uint8Array(64)),
	].join(".");
}
