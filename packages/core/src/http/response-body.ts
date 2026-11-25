/** Internal bounded response reader shared by federation HTTP clients. */
import { utf8Decode } from "@oidfed/crypto";
import { BodyLimitExceeded, readStreamBytes } from "./body-bytes.js";

export async function readResponseBody(
	response: Response,
	maxBytes: number,
	signal: AbortSignal,
): Promise<string> {
	if (!response.body) return "";
	const contentLength = response.headers.get("content-length");
	if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
		void response.body.cancel().catch(() => {});
		throw new BodyLimitExceeded(maxBytes);
	}
	const bytes = await readStreamBytes(response.body, maxBytes, signal);
	return utf8Decode(bytes, { fatal: false });
}
