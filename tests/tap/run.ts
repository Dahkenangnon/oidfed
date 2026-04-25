import type QUnit from "qunit";

export default async (QUnit: QUnit, done: (stats: QUnit.DoneDetails) => void) => {
	// `reporters` is a runtime extension on QUnit 2.x not yet exposed by @types/qunit.
	(QUnit as unknown as { reporters: { tap: { init(q: QUnit): void } } }).reporters.tap.init(QUnit);
	QUnit.config.autostart = false;
	QUnit.config.testTimeout = 10_000;

	const modules = await Promise.all([
		import("./packages/leaf.js"),
		import("./packages/oidc.js"),
		import("./packages/authority.js"),
		import("./packages/core.js"),
	]);
	for (const { default: module } of modules) {
		await module(QUnit);
	}
	QUnit.start();
	QUnit.done(done);
};
