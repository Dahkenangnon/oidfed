import { FederationErrorCode, InternalErrorCode } from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { decodeEntityConfiguration, decodeEntityStatement } from "../jose/verify.js";
import type { EntityConfigurationPayload } from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { fetchEntityConfiguration } from "../trust-chain/fetch.js";
import { resolveTrustChains } from "../trust-chain/resolve.js";
import {
	validateEntityConfigurationPublication,
	validateTrustChainStructure,
} from "../trust-chain/validate.js";
import { validateTrustMark } from "../trust-marks/index.js";
import {
	type EntityId,
	type FederationOptions,
	isValidEntityId,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "../types.js";
import type { CollectionEntry } from "./types.js";

type Root = { jwt: string; payload: EntityConfigurationPayload; expiresAt: number };
type IssuerProof = { keys: JWKSet; expiresAt: number };
type IssuerResolution = { incomplete: boolean; proof: IssuerProof | undefined };

/** Refresh-local chain and mark evidence; self-published keys never become issuer proofs. */
export function createCollectionEvidence(
	anchor: EntityId,
	anchors: TrustAnchorSet,
	options: FederationOptions,
	configuration: (id: EntityId) => ReturnType<typeof fetchEntityConfiguration>,
	openIssuerOptions: () => FederationOptions,
) {
	const proofs = new Map<string, IssuerProof>();
	const resolutions = new Map<string, Promise<IssuerResolution>>();
	let rootPending: Promise<Result<Root>> | undefined;

	async function validatePath(chain: readonly string[]): Promise<ValidatedTrustChain | undefined> {
		const checked = await validateTrustChainStructure(chain, anchors, {
			...options,
			verboseErrors: true,
		});
		if (!checked.valid) {
			options.logger?.debug("Excluded collection entity with an invalid chain", {
				errors: checked.errors,
			});
			return undefined;
		}
		const ec = decodeEntityConfiguration(chain[0] ?? "");
		if (!ec.ok) return undefined;
		const id = checked.chain.entityId;
		proofs.set(id, {
			keys: ec.value.payload.jwks,
			expiresAt: Math.max(proofs.get(id)?.expiresAt ?? -Infinity, checked.chain.expiresAt),
		});
		return checked.chain;
	}

	function root(): Promise<Result<Root>> {
		rootPending ??= (async () => {
			const fetched = await configuration(anchor);
			if (!fetched.ok) return fetched;
			const verified = await validatePath([fetched.value]);
			const ec = decodeEntityConfiguration(fetched.value);
			return verified && ec.ok
				? ok({ jwt: fetched.value, payload: ec.value.payload, expiresAt: verified.expiresAt })
				: err({
						code: FederationErrorCode.InvalidTrustChain,
						description: "Invalid collection Trust Anchor configuration",
					});
		})();
		return rootPending;
	}

	async function issuerProof(issuer: string, explicitlyListed: boolean) {
		if (options.signal?.aborted) throw new DOMException("Refresh aborted", "AbortError");
		const existing = proofs.get(issuer);
		if (existing) return existing;
		let pending = resolutions.get(issuer);
		if (!pending) {
			// Cache resolution facts once; each mark type applies its own failure policy below.
			pending = (async () => {
				const paths = await resolveTrustChains(
					issuer as EntityId,
					anchors,
					explicitlyListed ? options : openIssuerOptions(),
				);
				const incomplete =
					paths.incomplete === true ||
					paths.errors.some(
						(error) =>
							error.code === InternalErrorCode.Network || error.code === InternalErrorCode.Timeout,
					);
				if (!incomplete) {
					for (const path of paths.chains) await validatePath(path.statements);
				}
				return { incomplete, proof: incomplete ? undefined : proofs.get(issuer) };
			})();
			resolutions.set(issuer, pending);
		}
		const resolved = await pending;
		if (options.signal?.aborted) throw new DOMException("Refresh aborted", "AbortError");
		if (resolved.incomplete) {
			if (explicitlyListed) throw new Error("Unable to resolve Trust Mark issuer");
			options.logger?.debug("Skipped Trust Mark from an unresolved open issuer", { issuer });
			return undefined;
		}
		return resolved.proof;
	}

	async function verifyMarks(
		entry: CollectionEntry,
		publication?: EntityConfigurationPayload,
		openOnly = false,
	) {
		if (!entry.entity.trust_marks?.length) return;
		const trustedRoot = await root();
		if (!trustedRoot.ok) throw new Error(trustedRoot.error.description);
		let publicationExpiresAt = entry.chainExpiresAt ?? Infinity;
		if (!publication) {
			const id = entry.entity.entity_id as unknown as EntityId;
			const fetched = await configuration(id);
			if (!fetched.ok) {
				if (
					fetched.error.code === InternalErrorCode.Network ||
					fetched.error.code === InternalErrorCode.Timeout
				)
					throw new Error("Unable to confirm Trust Mark publication");
				return;
			}
			const ec = decodeEntityConfiguration(fetched.value);
			if (!ec.ok || ec.value.payload.sub !== entry.entity.entity_id) return;
			const self = await validateEntityConfigurationPublication(fetched.value, options);
			if (!self.valid) return;
			publication = ec.value.payload;
			publicationExpiresAt = self.statement.payload.exp;
		}
		for (const ref of entry.entity.trust_marks) {
			if (
				!publication.trust_marks?.some(
					(published) =>
						published.trust_mark_type === ref.trust_mark_type &&
						published.trust_mark === ref.trust_mark,
				)
			)
				continue;
			const authorized = trustedRoot.value.payload.trust_mark_issuers?.[ref.trust_mark_type];
			if (!authorized || (authorized.length === 0) !== openOnly) continue;
			const mark = decodeEntityStatement(ref.trust_mark);
			if (!mark.ok || !isValidEntityId(mark.value.payload.iss)) continue;
			if (authorized.length && !authorized.includes(mark.value.payload.iss)) continue;
			const proof = await issuerProof(mark.value.payload.iss, authorized.length > 0);
			if (!proof) continue;
			const checked = await validateTrustMark(
				ref.trust_mark,
				trustedRoot.value.payload.trust_mark_issuers ?? {},
				proof.keys,
				{
					...options,
					expectedSubject: entry.entity.entity_id,
					...(trustedRoot.value.payload.trust_mark_owners
						? { trustMarkOwners: trustedRoot.value.payload.trust_mark_owners }
						: {}),
				},
			);
			if (!checked.ok) continue;
			entry.verifiedMarks = [
				...entry.verifiedMarks,
				{
					type: ref.trust_mark_type,
					expiresAt: Math.min(
						entry.expiresAt,
						entry.chainExpiresAt ?? Infinity,
						publicationExpiresAt,
						trustedRoot.value.expiresAt,
						proof.expiresAt,
						checked.value.expiresAt ?? Infinity,
						checked.value.delegation?.expiresAt ?? Infinity,
					),
				},
			];
		}
	}
	return { root, validatePath, verifyMarks };
}
