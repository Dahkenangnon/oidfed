import { app } from "electron";
import QUnit from "qunit";
import run from "./run.js";

app.on("ready", () => {
	run(QUnit, (stats) => {
		app.exit(stats?.failed !== 0 ? 1 : 0);
	});
});
