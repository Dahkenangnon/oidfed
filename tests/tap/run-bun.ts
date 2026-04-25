import QUnit from "qunit";
import run from "./run.js";

const stats = await new Promise<QUnit.DoneDetails>((resolve) => {
	run(QUnit, resolve);
});
if (stats?.failed !== 0) process.exit(1);
