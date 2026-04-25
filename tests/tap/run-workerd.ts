import QUnit from "qunit";
import run from "./run.js";

export default {
	async test() {
		await new Promise((resolve, reject) => {
			run(QUnit, (results) => {
				results?.failed !== 0 ? reject() : resolve(undefined);
			});
		});
	},
};
