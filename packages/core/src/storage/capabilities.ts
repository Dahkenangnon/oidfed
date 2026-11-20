import { cloneData } from "../data-copy.js";
import type { EntityCollectionStore } from "./collection.js";
import type {
	FederationStorage,
	ReadSnapshotView,
	StorageCapability,
	TransactionView,
} from "./contracts.js";
import { InvalidStorageRecordError } from "./errors.js";
import {
	CacheWriteSchema,
	JtiReplayClaimSchema,
	parseStorageRecord,
	StorageJsonSchema,
	type StorageValidationOptions,
} from "./record-schemas.js";
import type { ReplayStore } from "./replay-store.js";
import type {
	SubordinateEventReadStore,
	SubordinateEventStore,
	SubordinateReadStore,
	SubordinateStore,
} from "./subordinates.js";
import type {
	TrustMarkReadStore,
	TrustMarkStore,
	TrustMarkTransactionStore,
} from "./trust-mark.js";
import { callValidatedRepository } from "./validated-records.js";

const methods = {
	"subordinate:read": ["subordinate", "fetch", "list"],
	"subordinate:write": ["subordinate", "register", "update", "remove"],
	"trustMark:read": [
		"trustMark",
		"candidates",
		"status",
		"valid",
		"listSubjects",
		"forSubject",
		"hasAny",
		"revision",
	],
	"trustMark:write": ["trustMark", "issue", "revoke"],
	"subordinateEvent:read": ["subordinateEvent", "history"],
	"subordinateEvent:write": ["subordinateEvent", "append"],
	entityCollection: ["entityCollection", "publish", "current", "snapshot", "saveCursor", "cursor"],
	replay: ["replay", "useJti"],
	cache: ["cache", "get", "set", "delete", "clear"],
	transaction: ["", "transaction"],
	snapshot: ["", "readSnapshot"],
	namespace: ["", "withNamespace"],
} as const satisfies Record<StorageCapability, readonly string[]>;

export class StorageCapabilityError extends Error {
	constructor(
		readonly operation: string,
		readonly capability: StorageCapability,
		detail?: string,
	) {
		super(`${operation} requires storage capability ${capability}${detail ? ` (${detail})` : ""}`);
		this.name = "StorageCapabilityError";
	}
}

export type StorageFeature =
	| "authority"
	| "subordinateLifecycle"
	| "eventHistory"
	| "eventCapture"
	| "trustMarkRead"
	| "trustMarkWrite"
	| "collection"
	| "oneTimeAuthentication";

const requirements = {
	authority: ["subordinate:read"],
	subordinateLifecycle: ["subordinate:read", "subordinate:write", "transaction"],
	eventHistory: ["subordinate:read", "subordinateEvent:read"],
	eventCapture: ["subordinateEvent:read", "subordinateEvent:write", "transaction"],
	trustMarkRead: ["trustMark:read", "snapshot"],
	trustMarkWrite: ["trustMark:read", "trustMark:write", "snapshot", "transaction"],
	collection: ["entityCollection"],
	oneTimeAuthentication: ["replay"],
} as const satisfies Record<StorageFeature, readonly StorageCapability[]>;

/** List the capabilities enabled features require. History also needs a snapshot or transaction. */
export function describeStorageRequirements(
	...features: readonly StorageFeature[]
): readonly StorageCapability[] {
	return [...new Set(features.flatMap((feature) => requirements[feature]))];
}

function assertMethods(view: object, capability: StorageCapability, operation: string): void {
	const [repository, ...names] = methods[capability];
	const target: unknown = repository ? Reflect.get(view, repository) : view;
	for (const name of names)
		if (target == null || typeof Reflect.get(Object(target), name) !== "function")
			throw new StorageCapabilityError(
				operation,
				capability,
				[repository, name].filter(Boolean).join("."),
			);
}

type CapabilityShape = {
	"subordinate:read": { readonly subordinate: SubordinateReadStore };
	"subordinate:write": { readonly subordinate: SubordinateStore };
	"trustMark:read": { readonly trustMark: TrustMarkReadStore };
	"trustMark:write": { readonly trustMark: TrustMarkStore };
	"subordinateEvent:read": { readonly subordinateEvent: SubordinateEventReadStore };
	"subordinateEvent:write": { readonly subordinateEvent: SubordinateEventStore };
	transaction: Required<Pick<FederationStorage, "transaction" | "isolation">>;
	snapshot: Required<Pick<FederationStorage, "readSnapshot">>;
	namespace: Required<Pick<FederationStorage, "withNamespace">>;
	entityCollection: { readonly entityCollection: EntityCollectionStore };
	replay: { readonly replay: ReplayStore };
	cache: Required<Pick<FederationStorage, "cache">>;
};
type UnionToIntersection<T> = (T extends unknown ? (value: T) => void : never) extends (
	value: infer I,
) => void
	? I
	: never;
type RequiredMembers<C extends StorageCapability> = StorageCapability extends C
	? unknown
	: UnionToIntersection<CapabilityShape[C]>;

/** Validate declarations and method groups before enabling features. */
export function assertStorageCapabilities<const C extends StorageCapability>(
	storage: FederationStorage | undefined,
	required: readonly C[],
	operation = "Federation storage",
): asserts storage is FederationStorage & RequiredMembers<C> {
	if (!storage) {
		if (required[0]) throw new StorageCapabilityError(operation, required[0]);
		throw new TypeError(`${operation} requires a storage handle`);
	}
	{
		if (
			typeof storage.namespace !== "string" ||
			storage.namespace.trim() !== storage.namespace ||
			!storage.namespace ||
			!Array.isArray(storage.capabilities)
		)
			throw new TypeError(
				`${operation} requires a named storage namespace and declared capabilities`,
			);
		const declared = new Set<StorageCapability>(storage.capabilities);
		if (declared.size !== storage.capabilities.length)
			throw new TypeError(`${operation} has duplicate storage capabilities`);
		for (const capability of declared) {
			if (!Object.hasOwn(methods, capability))
				throw new TypeError(`${operation} has an unknown storage capability`);
			assertMethods(storage, capability, operation);
		}
		if (declared.has("transaction") !== (storage.isolation === "serializable"))
			throw new StorageCapabilityError(operation, "transaction", "serializable isolation");
		for (const capability of ["subordinate", "subordinateEvent", "trustMark"] as const)
			if (declared.has(`${capability}:write`) && !declared.has(`${capability}:read`))
				throw new StorageCapabilityError(operation, `${capability}:read`);
	}
	for (const capability of required)
		if (!storage.capabilities.includes(capability))
			throw new StorageCapabilityError(operation, capability);
}

type RepositoryCapability = Exclude<
	StorageCapability,
	"cache" | "replay" | "entityCollection" | "snapshot" | "transaction" | "namespace"
>;

type ScopedCapabilityShape = Omit<CapabilityShape, "trustMark:write"> & {
	"trustMark:write": { readonly trustMark: TrustMarkTransactionStore };
};

function assertRevisionGuard(view: ReadSnapshotView, operation: string): void {
	if (
		!view.trustMark ||
		!("checkRevision" in view.trustMark) ||
		typeof view.trustMark.checkRevision !== "function"
	)
		throw new StorageCapabilityError(operation, "trustMark:write", "trustMark.checkRevision");
}

/** Narrow a scoped view to the repository methods needed for the current operation. */
export function assertStorageView<const C extends RepositoryCapability>(
	view: TransactionView | ReadSnapshotView,
	required: readonly C[],
	operation: string,
): asserts view is TransactionView & UnionToIntersection<ScopedCapabilityShape[C]> {
	for (const capability of required) {
		assertMethods(view, capability, operation);
		const [repository] = methods[capability];
		const readCapability = `${repository}:read` as const;
		if (readCapability !== capability) assertMethods(view, readCapability, operation);
		if (capability === "trustMark:write") assertRevisionGuard(view, operation);
	}
}

const scopedRepositories = ["subordinate", "trustMark", "subordinateEvent"] as const;

export async function runScoped<T, V extends ReadSnapshotView | TransactionView>(
	storage: FederationStorage,
	view: V,
	write: boolean,
	callback: (value: V) => Promise<T>,
	options?: StorageValidationOptions,
	validateRecords = true,
): Promise<T> {
	const scope = write ? "Storage transaction" : "Storage snapshot";
	const pending = new Set<Promise<unknown>>();
	let open = true;
	const guard = (repository: (typeof scopedRepositories)[number], target: object, name: string) => {
		return (...args: unknown[]) => {
			if (!open) return Promise.reject(new Error(`${scope} has closed`));
			let operation: Promise<unknown>;
			try {
				operation = validateRecords
					? callValidatedRepository(repository, name, target, args, options)
					: Promise.resolve(
							(Reflect.get(target, name) as (...values: unknown[]) => unknown).apply(target, args),
						);
			} catch (error) {
				operation = Promise.reject(error);
			}
			pending.add(operation);
			const settled = () => pending.delete(operation);
			void operation.then(settled, settled);
			return operation;
		};
	};
	const result: Record<string, unknown> = {};
	for (const repository of scopedRepositories) {
		const read = `${repository}:read` as const;
		const mutation = `${repository}:write` as const;
		if (!storage.capabilities.includes(read)) continue;
		assertMethods(view, read, scope);
		const target = view[repository] as object;
		const names: string[] = methods[read].slice(1);
		if (write && storage.capabilities.includes(mutation)) {
			assertMethods(view, mutation, scope);
			names.push(...methods[mutation].slice(1));
			if (repository === "trustMark") {
				assertRevisionGuard(view, scope);
				names.push("checkRevision");
			}
		}
		result[repository] = Object.freeze(
			Object.fromEntries(names.map((name) => [name, guard(repository, target, name)])),
		);
	}
	try {
		const value = await callback(Object.freeze(result) as V);
		if (pending.size > 0) throw new Error(`${scope} callback must await its repository operations`);
		return value;
	} finally {
		open = false;
		await Promise.allSettled(pending);
	}
}

/** Run a serializable write callback with repositories scoped to that attempt. */
export function storageTransaction<T>(
	storage: FederationStorage,
	callback: (view: TransactionView) => Promise<T>,
	options?: StorageValidationOptions,
): Promise<T> {
	assertStorageCapabilities(storage, ["transaction"], "Storage transaction");
	return storage.transaction((view) => runScoped(storage, view, true, callback, options));
}

/** Run a read-only callback against one consistent view, optionally using a serializable transaction. */
export function storageSnapshot<T>(
	storage: FederationStorage,
	callback: (view: ReadSnapshotView) => Promise<T>,
	options?: StorageValidationOptions & { readonly allowTransaction?: boolean },
): Promise<T> {
	const { allowTransaction, ...validation } = options ?? {};
	const checks = Object.keys(validation).length > 0 ? validation : undefined;
	if (allowTransaction && !storage.capabilities.includes("snapshot")) {
		assertStorageCapabilities(storage, ["transaction"], "Storage snapshot");
		return storage.transaction((view) => runScoped(storage, view, false, callback, checks));
	}
	assertStorageCapabilities(storage, ["snapshot"], "Storage snapshot");
	return storage.readSnapshot((view) => runScoped(storage, view, false, callback, checks));
}

/** Obtain replay protection only from a handle that declares the capability. */
export function requireReplayStorage(
	storage: FederationStorage | undefined,
	operation: string,
): ReplayStore {
	assertStorageCapabilities(storage, ["replay"], operation);
	const store = storage.replay;
	return {
		async useJti(claim) {
			const result = await store.useJti(
				parseStorageRecord(JtiReplayClaimSchema, claim, "replay", "claim"),
			);
			if (typeof result !== "boolean")
				throw new InvalidStorageRecordError("replay", "claim", "Expected a boolean result");
			return result;
		},
	};
}

/** Resolve a cache from its declaration, or leave caching to the caller's local policy. */
export function getCacheStorage(
	storage: FederationStorage | undefined,
): FederationStorage["cache"] {
	if (!storage?.capabilities.includes("cache")) return undefined;
	assertMethods(storage, "cache", "Federation cache");
	const cache = storage.cache;
	if (!cache) return undefined;
	return {
		async get<T>(key: string) {
			const value = await cache.get<T>(key);
			return StorageJsonSchema.safeParse(value).success ? cloneData(value) : undefined;
		},
		async set<T>(key: string, value: T, ttlSeconds: number) {
			const parsed = parseStorageRecord(
				CacheWriteSchema,
				{ key, value, ttlSeconds },
				"cache",
				"set",
			);
			return cache.set(parsed.key, parsed.value, parsed.ttlSeconds);
		},
		delete: cache.delete.bind(cache),
		clear: cache.clear.bind(cache),
	};
}
