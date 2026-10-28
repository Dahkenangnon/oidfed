/** A named Vitest case for every module in the unchanged OpenID Federation conformance baseline. */
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { Session } from "./driver.js";
import { BASELINE, HarnessError, type PlanInfo, type Profile } from "./policy.js";

// biome-ignore lint/suspicious/noUndeclaredEnvVars: Docker runs this project directly, outside Turbo.
const profile = process.env.OIDF_PROFILE ?? "deployed";
if (!Object.hasOwn(BASELINE.profiles, profile)) throw new HarnessError("invalid_profile");
const session = new Session(profile as Profile);
beforeAll(() => session.start(), 365_000);
afterAll(() => session.finish(), 30_000);

for (const role of BASELINE.profiles[session.profile]) {
	for (const target of role === "deployed" ? ["ta", "ia", "leaf"] : [role]) {
		describe(`${role}: ${target}`, () => {
			let plan: PlanInfo;
			const executed = new Map<string, string>();
			const expected = new Map<string, [string | undefined, string | undefined]>();
			beforeAll(async () => {
				if (session.halted) return;
				try {
					plan = await session.createPlan(role, target);
				} catch (error) {
					await session.fail(error);
					throw session.publicError(error);
				}
			});
			for (const module of BASELINE.plans[role].modules) {
				test(module.name, async (context) => {
					// These are unexecuted cases after a fatal error, not accepted upstream skips.
					if (session.halted) {
						context.skip("Blocked by an earlier application or infrastructure failure");
						return;
					}
					const record = await session.module(
						role,
						target,
						plan,
						module.name,
						executed,
						expected,
						context.signal,
					);
					expect(
						record.accepted,
						"OpenID Federation test module did not satisfy the acceptance policy",
					).toBe(true);
					if (record.result === "SKIPPED")
						context.skip("Accepted optional capability skip; see summary.json");
				}, 190_000);
			}
			afterAll(async () => {
				if (!session.halted) await session.verifyPlan(role, plan, executed, expected);
			}, 180_000);
		});
	}
}
