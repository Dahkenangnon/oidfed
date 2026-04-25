import QUnit from "qunit";
import run from "./run.js";

run(QUnit, (stats) => {
	(globalThis as unknown as { stats: unknown }).stats = stats;
});
