import { describe, expect, it } from "vitest";
import { createLogger } from "../../src/util/logger.js";

function makeStream() {
	const lines: string[] = [];
	return {
		write(data: string) {
			lines.push(data);
			return true;
		},
		lines,
	};
}

describe("createLogger", () => {
	it("writes info to stderr when not quiet", () => {
		const stream = makeStream();
		const log = createLogger({ quiet: false, verbose: false, stderr: stream });
		log.info("hello");
		expect(stream.lines).toHaveLength(1);
		expect(stream.lines[0]).toContain("hello");
	});

	it("suppresses info when quiet", () => {
		const stream = makeStream();
		const log = createLogger({ quiet: true, verbose: false, stderr: stream });
		log.info("hello");
		expect(stream.lines).toHaveLength(0);
	});

	it("writes error even when quiet", () => {
		const stream = makeStream();
		const log = createLogger({ quiet: true, verbose: false, stderr: stream });
		log.error("oops");
		expect(stream.lines).toHaveLength(1);
	});

	it("writes debug only when verbose", () => {
		const stream = makeStream();
		const log = createLogger({ quiet: false, verbose: false, stderr: stream });
		log.debug("detail");
		expect(stream.lines).toHaveLength(0);

		const log2 = createLogger({ quiet: false, verbose: true, stderr: stream });
		log2.debug("detail");
		expect(stream.lines).toHaveLength(1);
	});

	it("suppresses warn when quiet", () => {
		const stream = makeStream();
		const log = createLogger({ quiet: true, verbose: false, stderr: stream });
		log.warn("caution");
		expect(stream.lines).toHaveLength(0);
	});
});
