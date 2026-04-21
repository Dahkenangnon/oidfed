import { describe, expect, it } from "vitest";
import { compose, type Middleware } from "../src/handler.js";

describe("compose", () => {
	const dummyNext = async (_req: Request) => new Response("final", { status: 200 });

	it("passes through with no middlewares", async () => {
		const mw = compose();
		const req = new Request("https://example.com");
		const res = await mw(req, dummyNext);
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("final");
	});

	it("single middleware wraps the handler", async () => {
		const mw: Middleware = async (req, next) => {
			const res = await next(req);
			return new Response(await res.text(), {
				status: res.status,
				headers: { "X-Added": "true" },
			});
		};
		const composed = compose(mw);
		const res = await composed(new Request("https://example.com"), dummyNext);
		expect(res.headers.get("X-Added")).toBe("true");
		expect(await res.text()).toBe("final");
	});

	it("multiple middlewares execute in order", async () => {
		const order: number[] = [];
		const mw1: Middleware = async (req, next) => {
			order.push(1);
			const res = await next(req);
			order.push(4);
			return res;
		};
		const mw2: Middleware = async (req, next) => {
			order.push(2);
			const res = await next(req);
			order.push(3);
			return res;
		};
		const composed = compose(mw1, mw2);
		await composed(new Request("https://example.com"), dummyNext);
		expect(order).toEqual([1, 2, 3, 4]);
	});

	it("middleware can short-circuit (skip next)", async () => {
		const blocker: Middleware = async (_req, _next) => {
			return new Response("blocked", { status: 403 });
		};
		const neverCalled: Middleware = async (_req, _next) => {
			throw new Error("Should not be called");
		};
		const composed = compose(blocker, neverCalled);
		const res = await composed(new Request("https://example.com"), dummyNext);
		expect(res.status).toBe(403);
		expect(await res.text()).toBe("blocked");
	});
});
