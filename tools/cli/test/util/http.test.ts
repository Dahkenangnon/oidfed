import { describe, expect, it } from "vitest";
import { createHttpClient } from "../../src/util/http.js";

describe("createHttpClient", () => {
	it("returns plain fetch when no timeout is given", () => {
		expect(createHttpClient()).toBe(fetch);
	});

	it("aborts requests that exceed timeout", async () => {
		const client = createHttpClient(1);
		await expect(client("https://httpbin.org/delay/10")).rejects.toThrow();
	});
});
