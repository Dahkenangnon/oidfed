/** Serialized, validated updates to a holder's published Trust Mark references. */

import { decodeEntityStatement } from "../jose/verify.js";
import type { TrustMarkRef } from "../schemas/trust-mark.js";
import { entityId, type FederationOptions, type TrustAnchorSet } from "../types.js";
import {
	establishTrustMarkIssuerTrust,
	type TrustMarkIssuerContext,
	trustMarkIssuerContext,
	type ValidateTrustMarkWithIssuerOptions,
	validateTrustMarkWithIssuer,
} from "./evidence.js";
import { fetchTrustMarkForIssuer } from "./fetch.js";
import { trustMarkOperation } from "./operation.js";

export interface AttachTrustMarkOptions
	extends Omit<ValidateTrustMarkWithIssuerOptions, "expectedSubject"> {
	readonly issuerEvidence: TrustMarkIssuerContext;
	readonly replacement?: "same-issuer-and-type";
}
export type RemoveTrustMarkSelector =
	| { readonly jwt: string }
	| { readonly issuer: string; readonly trustMarkType: string };
export interface FetchAndAttachTrustMarkOptions {
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchors: TrustAnchorSet;
	readonly replacement?: "same-issuer-and-type";
	readonly options?: FederationOptions;
}
/** Serializes publication mutations; a failed publisher leaves the prior references intact. */
export class TrustMarkHolder {
	private refs: TrustMarkRef[];
	private tail: Promise<void> = Promise.resolve();
	/** Detach initial publication references and retain the host's publication callback. */
	constructor(
		private readonly subject: string,
		refs: readonly TrustMarkRef[],
		private readonly publish: (references: readonly TrustMarkRef[]) => Promise<void>,
	) {
		entityId(subject);
		this.refs = structuredClone([...refs]);
	}
	/** Return detached publication references; this does not revalidate existing marks. */
	getTrustMarks(): TrustMarkRef[] {
		return structuredClone(this.refs);
	}
	/**
	 * Serialize an operation with other holder publication changes, releasing the queue on failure.
	 */
	async updatePublication<T>(operation: () => Promise<T>): Promise<T> {
		const prior = this.tail;
		let release!: () => void;
		this.tail = new Promise<void>((resolve) => {
			release = resolve;
		});
		await prior;
		try {
			return await operation();
		} finally {
			release();
		}
	}
	/**
	 * Validate issuer evidence and holder binding before publishing the updated references.
	 * A failed validation or publisher leaves the previous references unchanged.
	 */
	async attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void> {
		if (options.replacement !== undefined && options.replacement !== "same-issuer-and-type")
			throw new TypeError("Invalid Trust Mark replacement mode");
		return this.updatePublication(async () => {
			const checked = await validateTrustMarkWithIssuer(jwt, options.issuerEvidence, {
				...options,
				expectedSubject: this.subject,
			});
			if (!checked.ok) throw new Error(checked.error.description);
			if (!options.replacement && this.refs.some((ref) => ref.trust_mark === jwt)) return;
			const refs = options.replacement
				? this.refs.filter((ref) => {
						const decoded = decodeEntityStatement(ref.trust_mark);
						return (
							!decoded.ok ||
							decoded.value.payload.iss !== checked.value.issuer ||
							ref.trust_mark_type !== checked.value.trustMarkType
						);
					})
				: [...this.refs];
			refs.push({ trust_mark: jwt, trust_mark_type: checked.value.trustMarkType });
			if (
				refs.length === this.refs.length &&
				refs.every(
					(ref, i) =>
						ref.trust_mark === this.refs[i]?.trust_mark &&
						ref.trust_mark_type === this.refs[i]?.trust_mark_type,
				)
			)
				return;
			await this.publish(structuredClone(refs));
			this.refs = refs;
		});
	}
	/** Establish issuer trust, retrieve the holder's mark, and validate it before publication. */
	async fetchAndAttachTrustMark(input: FetchAndAttachTrustMarkOptions): Promise<void> {
		const options = trustMarkOperation(input.options ?? {});
		const evidence = await establishTrustMarkIssuerTrust({
			issuer: input.issuer,
			trustMarkType: input.trustMarkType,
			trustAnchors: input.trustAnchors,
			options,
		});
		if (!evidence.ok) throw new Error(evidence.error.description);
		const trusted = trustMarkIssuerContext(evidence.value, input.trustMarkType, options);
		if (!trusted.ok) throw new Error(trusted.error.description);
		const endpoint = trusted.value.metadata?.federation_trust_mark_endpoint;
		if (!endpoint) throw new Error("Issuer does not publish a Trust Mark endpoint");
		const jwt = await fetchTrustMarkForIssuer(
			endpoint,
			{ trustMarkType: input.trustMarkType, sub: entityId(this.subject) },
			trusted.value.issuer,
			options,
		);
		if (!jwt.ok) throw new Error(jwt.error.description);
		return this.attachTrustMark(jwt.value, {
			...options,
			issuerEvidence: evidence.value,
			expectedTrustMarkType: input.trustMarkType,
			...(input.replacement ? { replacement: input.replacement } : {}),
		});
	}
	/** Remove matching publication references without revoking the issuer's stored mark. */
	async removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void> {
		return this.updatePublication(async () => {
			const refs = this.refs.filter((ref) => {
				if ("jwt" in selector) return ref.trust_mark !== selector.jwt;
				const decoded = decodeEntityStatement(ref.trust_mark);
				return (
					!decoded.ok ||
					decoded.value.payload.iss !== selector.issuer ||
					ref.trust_mark_type !== selector.trustMarkType
				);
			});
			if (refs.length === this.refs.length) return;
			await this.publish(structuredClone(refs));
			this.refs = refs;
		});
	}
}
