import { generateSigningKey, JwkSigner, JwtTyp, signEntityStatement } from "@oidfed/core";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useResolveQuery } from "@/features/resolve/hooks/use-resolve-query";

const resolver = "https://resolver.example.com";
const subject = "https://subject.example.com";
const anchor = "https://anchor.example.com";

beforeEach(() => {
	// Match Node's TextEncoder and Web Crypto byte arrays inside jsdom.
	vi.stubGlobal("Uint8Array", new TextEncoder().encode("").constructor);
});

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

describe("useResolveQuery audience binding", () => {
	for (const restricted of [false, true]) {
		it(
			restricted
				? "reports an audience-bound response as a verification error"
				: "accepts an audience-free response",
			async () => {
				const { privateKey, publicKey } = await generateSigningKey("ES256");
				const signer = new JwkSigner(privateKey);
				const now = Math.floor(Date.now() / 1000);
				const configuration = await signEntityStatement(
					{
						iss: resolver,
						sub: resolver,
						iat: now,
						exp: now + 3600,
						jwks: { keys: [publicKey] },
						metadata: { federation_entity: { federation_resolve_endpoint: `${resolver}/resolve` } },
					},
					signer,
					{ typ: JwtTyp.EntityStatement },
				);
				const responseJwt = await signEntityStatement(
					{
						iss: resolver,
						sub: subject,
						iat: now,
						exp: now + 3600,
						metadata: { federation_entity: { organization_name: "Subject" } },
						trust_chain: ["fixture"],
						...(restricted ? { aud: "https://client.example.com" } : {}),
					},
					signer,
					{ typ: JwtTyp.ResolveResponse },
				);
				const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
					const url = new URL(input instanceof Request ? input.url : String(input));
					if (url.href === `${resolver}/.well-known/openid-federation`) {
						return new Response(configuration, {
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					}
					if (
						url.origin === resolver &&
						url.pathname === "/resolve" &&
						url.searchParams.get("sub") === subject &&
						url.searchParams.get("trust_anchor") === anchor
					) {
						return new Response(responseJwt, {
							headers: { "Content-Type": "application/resolve-response+jwt" },
						});
					}
					throw new Error(`Unexpected fixture URL: ${url.href}`);
				});
				const { result } = renderHook(() => useResolveQuery());
				act(() =>
					result.current.query({ resolverEntityId: resolver, subject, trustAnchors: [anchor] }),
				);
				await waitFor(() => expect(result.current.loading).toBe(false));
				expect(result.current.error).toBeNull();
				expect(fetchSpy).toHaveBeenCalledTimes(2);
				const outcome = result.current.result?.results[0];
				expect(outcome).toBeDefined();
				if (restricted) {
					expect(outcome?.error).toMatch(/Response verification failed:.*audience/);
					expect(outcome?.responsePayload).toBeUndefined();
				} else {
					expect(outcome?.error).toBeUndefined();
					expect(outcome?.responsePayload?.sub).toBe(subject);
				}
			},
		);
	}
});
