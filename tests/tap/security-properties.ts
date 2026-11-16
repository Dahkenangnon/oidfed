/** Security regressions shared by every supported runtime. */

import type QUnit from "qunit";
import { readResponseBody } from "../../packages/core/src/http-response.js";

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
	});
}
