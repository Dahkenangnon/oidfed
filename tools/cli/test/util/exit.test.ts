import { err, FederationErrorCode, federationError, ok } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { ExitCode, resultToExitCode } from "../../src/util/exit.js";

describe("ExitCode", () => {
	it("defines expected exit codes", () => {
		expect(ExitCode.OK).toBe(0);
		expect(ExitCode.FEDERATION_ERROR).toBe(1);
		expect(ExitCode.USAGE_ERROR).toBe(2);
	});
});

describe("resultToExitCode", () => {
	it("returns 0 for ok result", () => {
		expect(resultToExitCode(ok("fine"))).toBe(0);
	});

	it("returns 1 for err result", () => {
		const error = federationError(FederationErrorCode.SIGNATURE_INVALID, "bad");
		expect(resultToExitCode(err(error))).toBe(1);
	});
});
