import { MemoryReplayStore } from "../../packages/core/src/storage/replay-memory.js";
import { testEngine } from "./fixtures/software-crypto.js";
/** Generated security invariants shared by every supported runtime. */

import { applyMetadataPolicy } from "@oidfed/core";
import * as fc from "fast-check";
import type QUnit from "qunit";
import { endpointParameterValuesMatch } from "../../packages/core/src/endpoint-parameters.js";
import { readResponseBody } from "../../packages/core/src/http/response-body.js";

const options = { seed: 20261116, numRuns: 100 };
const key = fc.oneof(
	fc.constantFrom("__proto__", "constructor", "prototype", "toString", "hasOwnProperty"),
	fc.string({ minLength: 1, maxLength: 40 }),
);

export default function securityProperties(QUnit: QUnit) {
	QUnit.module("generated security invariants", () => {
		QUnit.test("the bounded reader rejects non-byte response chunks", async (assert) => {
			const response = new Response();
			Object.defineProperty(response, "body", {
				value: new ReadableStream({
					start(controller) {
						controller.enqueue("untrusted string chunk");
						controller.close();
					},
				}),
			});
			await assert.rejects(
				readResponseBody(response, 1024, new AbortController().signal),
				TypeError,
			);
		});
		QUnit.test("policy writes preserve prototypes and caller-owned input", (assert) => {
			fc.assert(
				fc.property(key, key, fc.jsonValue(), (entityType, parameter, value) => {
					const before = Object.getOwnPropertyDescriptors(Object.prototype);
					const input = JSON.parse(`{${JSON.stringify(entityType)}:{}}`);
					const policy = JSON.parse(
						`{${JSON.stringify(entityType)}:{${JSON.stringify(parameter)}:{"value":${JSON.stringify(value)}}}}`,
					);
					const original = JSON.stringify(input);
					const result = applyMetadataPolicy(input, policy);
					const after = Object.getOwnPropertyDescriptors(Object.prototype);
					assert.deepEqual(Reflect.ownKeys(after), Reflect.ownKeys(before));
					for (const name of Object.keys(before)) {
						const previous = before[name]!;
						const current = after[name]!;
						assert.true(
							["value", "get", "set", "enumerable", "configurable", "writable"].every(
								(field) => Reflect.get(current, field) === Reflect.get(previous, field),
							),
						);
					}
					assert.strictEqual(JSON.stringify(input), original);
					if (result.ok) {
						assert.ok(Object.hasOwn(result.value, entityType));
						if (value !== null) assert.ok(Object.hasOwn(result.value[entityType]!, parameter));
					}
				}),
				options,
			);
		});
		QUnit.test(
			"membership selectors ignore ordering and repeated values only when declared",
			(assert) => {
				fc.assert(
					fc.property(fc.array(fc.string(), { maxLength: 20 }), (values) => {
						const permuted = [...values].reverse().flatMap((value) => [value, value]);
						assert.true(
							endpointParameterValuesMatch("entity_type", values, permuted, ["entity_type"]),
						);
						assert.strictEqual(
							endpointParameterValuesMatch("extension", values, permuted, []),
							values.length === permuted.length &&
								values.every((value, index) => value === permuted[index]),
						);
					}),
					options,
				);
			},
		);
		QUnit.test("concurrent replay claims have exactly one winner", async (assert) => {
			await fc.assert(
				fc.asyncProperty(
					fc.scheduler(),
					fc.string({ minLength: 1, maxLength: 100 }),
					async (scheduler, jti) => {
						const store = new MemoryReplayStore({ engine: testEngine, clock: { now: () => 1000 } });
						const claim = {
							issuer: "https://issuer.example",
							audience: "https://receiver.example",
							jti,
							expiresAt: 2000,
						};
						const pending = Array.from({ length: 4 }, () =>
							scheduler.schedule(store.useJti(claim)),
						);
						await scheduler.waitAll();
						assert.strictEqual((await Promise.all(pending)).filter(Boolean).length, 1);
					},
				),
				{ ...options, numRuns: 30 },
			);
		});
	});
}
