/** Inspect suite exports without extracting archive paths onto the filesystem. */
import { isDeepStrictEqual } from "node:util";
import { crc32 } from "node:zlib";
import { openPromise } from "yauzl";
import { MAX_ENTRY_BYTES } from "./api.js";
import { HarnessError } from "./policy.js";

export async function checkExport(
	path: string,
	expected: Map<string, [string | undefined, string | undefined]>,
): Promise<void> {
	const found = new Map<string, [string | undefined, string | undefined]>();
	try {
		const archive = await openPromise(path, { validateEntrySizes: true, strictFileNames: true });
		try {
			for await (const entry of archive.eachEntry()) {
				if (!entry.fileName.endsWith(".json")) continue;
				if (entry.uncompressedSize > MAX_ENTRY_BYTES) throw new HarnessError("oversized_export");
				const stream = await archive.openReadStreamPromise(entry);
				const chunks: Buffer[] = [];
				let size = 0;
				let checksum = 0;
				for await (const chunk of stream) {
					size += chunk.length;
					if (size > MAX_ENTRY_BYTES) {
						stream.destroy();
						throw new HarnessError("oversized_export");
					}
					chunks.push(chunk);
					checksum = crc32(chunk, checksum);
				}
				if (checksum !== entry.crc32) throw new HarnessError("invalid_export");
				const data: unknown = JSON.parse(Buffer.concat(chunks).toString());
				if (
					!data ||
					typeof data !== "object" ||
					!("testInfo" in data) ||
					!data.testInfo ||
					typeof data.testInfo !== "object"
				)
					throw new HarnessError("export_result_mismatch");
				const info = data.testInfo as {
					id?: string;
					_id?: string;
					status?: string;
					result?: string;
				};
				const id = info.id ?? info._id;
				if (typeof id !== "string") throw new HarnessError("export_result_mismatch");
				if (found.has(id)) throw new HarnessError("duplicate_export_instance");
				found.set(id, [info.status, info.result]);
			}
		} finally {
			archive.close();
		}
	} catch (error) {
		if (error instanceof HarnessError) throw error;
		throw new HarnessError("invalid_export");
	}
	if (!isDeepStrictEqual(found, expected)) throw new HarnessError("export_result_mismatch");
}
