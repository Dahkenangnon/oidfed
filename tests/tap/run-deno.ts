import QUnit from "qunit";
import run from "./run.js";

declare const Deno: { exit(code?: number): never };

run(QUnit, (stats) => {
	if (stats?.failed !== 0) Deno.exit(1);
});
