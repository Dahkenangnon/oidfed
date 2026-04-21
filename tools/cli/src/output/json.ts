import type { OutputFormatter } from "./index.js";

export class JsonFormatter implements OutputFormatter {
	format(data: unknown): string {
		return JSON.stringify(data, null, 2);
	}
}
