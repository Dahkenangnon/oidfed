import { utf8Decode } from "@oidfed/crypto";
/** Internal bounded response reader shared by federation HTTP clients. */

export async function readResponseBody(
	response: Response,
	maxBytes: number,
	signal: AbortSignal,
): Promise<string> {
	if (!response.body) return "";
	const contentLength = response.headers.get("content-length");
	if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
		void response.body.cancel().catch(() => {});
		throw new RangeError(`Response exceeds maximum size of ${maxBytes} bytes`);
	}
	const reader = response.body.getReader();
	// Cancel pending reads even when an injected HTTP client ignores the signal.
	const onAbort = () => {
		void reader.cancel().catch(() => {});
	};
	signal.addEventListener("abort", onAbort, { once: true });
	let finished = false;
	try {
		const chunks: Uint8Array[] = [];
		let received = 0;

		while (true) {
			if (signal.aborted) throw new DOMException("Request aborted", "AbortError");
			const chunk: { done: boolean; value?: unknown } = await reader.read();
			const { done, value } = chunk;
			if (signal.aborted) throw new DOMException("Request aborted", "AbortError");
			if (done) {
				finished = true;
				const bytes = new Uint8Array(received);
				let offset = 0;
				for (const bytesChunk of chunks) {
					bytes.set(bytesChunk, offset);
					offset += bytesChunk.length;
				}
				return utf8Decode(bytes, { fatal: false });
			}
			if (!ArrayBuffer.isView(value)) throw new TypeError("Response body must contain byte chunks");
			received += value.byteLength;
			if (received > maxBytes) {
				throw new RangeError(`Response exceeds maximum size of ${maxBytes} bytes`);
			}
			chunks.push(new Uint8Array(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)));
		}
	} finally {
		signal.removeEventListener("abort", onAbort);
		if (!finished) void reader.cancel().catch(() => {});
		reader.releaseLock();
	}
}
