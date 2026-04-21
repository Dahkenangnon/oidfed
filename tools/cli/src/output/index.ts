export interface OutputFormatter {
	format(data: unknown): string;
}

export { HumanFormatter } from "./human.js";
export { JsonFormatter } from "./json.js";

import { HumanFormatter } from "./human.js";
import { JsonFormatter } from "./json.js";

export function createFormatter(options: { json?: boolean | undefined }): OutputFormatter {
	return options.json ? new JsonFormatter() : new HumanFormatter();
}
