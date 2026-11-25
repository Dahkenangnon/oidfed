/** Read exact bytes from a Web stream with a hard limit and prompt cancellation. */

/** The stream exceeded the configured byte limit. */
export class BodyLimitExceeded extends RangeError {
	constructor(maxBytes: number) {
		super(`Body exceeds maximum size of ${maxBytes} bytes`);
		this.name = "BodyLimitExceeded";
	}
}

/** Return null for an absent body. Preserve transport errors and the caller's abort reason. */
export async function readBytesWithLimit(
	body: ReadableStream<Uint8Array> | null,
	maxBytes: number,
	signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer> | null> {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
		throw new RangeError("Body byte limit must be a nonnegative safe integer");
	if (body === null) {
		signal?.throwIfAborted();
		return null;
	}
	return readStreamBytes(body, maxBytes, signal);
}

/** Read a stream while preserving the numeric comparison used by legacy text readers. */
export async function readStreamBytes(
	body: ReadableStream<Uint8Array>,
	maxBytes: number,
	signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
	const reader = body.getReader();
	/** Cancellation also wakes a pending read when the underlying transport ignores the signal. */
	const cancel = () => {
		void reader.cancel().catch(() => undefined);
	};
	signal?.addEventListener("abort", cancel, { once: true });
	const chunks: Uint8Array[] = [];
	let received = 0;
	let finished = false;
	try {
		for (;;) {
			signal?.throwIfAborted();
			const { done, value }: { done: boolean; value?: unknown } = await reader.read();
			signal?.throwIfAborted();
			if (done) {
				finished = true;
				break;
			}
			if (!ArrayBuffer.isView(value)) throw new TypeError("Body must contain byte chunks");
			if (received + value.byteLength > maxBytes) throw new BodyLimitExceeded(maxBytes);
			if (value.byteLength === 0) continue;
			received += value.byteLength;
			// Own the retained bytes before allowing the producer to supply another chunk.
			chunks.push(new Uint8Array(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)));
		}
		const bytes = new Uint8Array(received);
		let offset = 0;
		for (const chunk of chunks) {
			bytes.set(chunk, offset);
			offset += chunk.byteLength;
		}
		return bytes;
	} finally {
		signal?.removeEventListener("abort", cancel);
		if (!finished) cancel();
		reader.releaseLock();
	}
}
