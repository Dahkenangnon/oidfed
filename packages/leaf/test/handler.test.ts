import type { Logger } from "@oidfed/core";
import { MediaType, WELL_KNOWN_OPENID_FEDERATION } from "@oidfed/core";
import { describe, expect, it, vi } from "vitest";
import { createLeafEntity } from "../src/entity-configuration.js";
import { createLeafHandler } from "../src/handler.js";
import { createLeafConfig, LEAF_ID } from "./test-helpers.js";

async function createHandler() {
	const { config } = await createLeafConfig();
	const entity = createLeafEntity(config);
	return { handler: createLeafHandler(entity), entity };
}

describe("createLeafHandler", () => {
	it("returns 200 with correct Content-Type for well-known path", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);

		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe(MediaType.EntityStatement);
	});

	it("response body is valid JWT", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);
		const body = await response.text();

		expect(body.split(".")).toHaveLength(3);
	});

	it("returns 405 for POST to well-known path", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" });
		const response = await handler(request);

		expect(response.status).toBe(405);
		expect(response.headers.get("Allow")).toBe("GET");
	});

	it("returns 404 for unknown paths", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}/unknown-path`);
		const response = await handler(request);

		expect(response.status).toBe(404);
	});

	it("includes security headers on 200 response", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);

		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(response.headers.get("Strict-Transport-Security")).toContain("max-age=");
	});

	it("includes security headers on 404 response", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}/unknown`);
		const response = await handler(request);

		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("includes security headers on 405 response", async () => {
		const { handler } = await createHandler();
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "DELETE" });
		const response = await handler(request);

		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("returns 500 when getEntityConfiguration throws", async () => {
		const faultyEntity = {
			getEntityConfiguration: () => {
				throw new Error("signing failure");
			},
		} as unknown as import("../src/entity-configuration.js").LeafEntity;
		const handler = createLeafHandler(faultyEntity);
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);

		expect(response.status).toBe(500);
		const body = await response.json();
		expect(body.error).toBe("server_error");
		expect(response.headers.get("Cache-Control")).toBe("no-store");
	});

	it("500 body does NOT contain internal error message (no info leak)", async () => {
		const secretMessage = "database password is hunter2";
		const faultyEntity = {
			getEntityConfiguration: () => {
				throw new Error(secretMessage);
			},
		} as unknown as import("../src/entity-configuration.js").LeafEntity;
		const handler = createLeafHandler(faultyEntity);
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);

		const text = await response.text();
		expect(text).not.toContain(secretMessage);
	});

	it("logger error() is called with original error on 500", async () => {
		const originalError = new Error("signing failure");
		const faultyEntity = {
			getEntityConfiguration: () => {
				throw originalError;
			},
		} as unknown as import("../src/entity-configuration.js").LeafEntity;

		const logger: Logger = {
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		};

		const handler = createLeafHandler(faultyEntity, { logger });
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		await handler(request);

		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			"Failed to serve entity configuration",
			expect.objectContaining({ error: originalError }),
		);
	});

	describe("response body structure", () => {
		it("404 response has error and error_description fields", async () => {
			const { handler } = await createHandler();
			const request = new Request(`${LEAF_ID}/unknown`);
			const response = await handler(request);
			const body = await response.json();

			expect(body.error).toBe("not_found");
			expect(body.error_description).toBe("Unknown endpoint");
		});

		it("405 response has error field", async () => {
			const { handler } = await createHandler();
			const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" });
			const response = await handler(request);
			const body = await response.json();

			expect(body.error).toBe("method_not_allowed");
		});

		it("500 response has error and error_description fields", async () => {
			const faultyEntity = {
				getEntityConfiguration: () => {
					throw new Error("fail");
				},
			} as unknown as import("../src/entity-configuration.js").LeafEntity;
			const handler = createLeafHandler(faultyEntity);
			const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
			const response = await handler(request);
			const body = await response.json();

			expect(body.error).toBe("server_error");
			expect(body.error_description).toBe("An internal error occurred");
		});
	});
});
