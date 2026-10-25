import {
	type EntityCollectionRequestParams,
	err,
	fetchEntityCollection,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";
import type { Command } from "commander";
import type { OutputFormatter } from "../output/index.js";
import type { Logger } from "../util/logger.js";

export interface CollectionDeps {
	httpClient: HttpClient;
	formatter: OutputFormatter;
	logger: Logger;
	readFile: (path: string) => Promise<string>;
}
export interface CollectionArgs extends EntityCollectionRequestParams {
	endpoint: string;
	post?: boolean;
	clientAssertionFile?: string;
}
export async function handler(args: CollectionArgs, deps: CollectionDeps): Promise<Result<string>> {
	const { endpoint, post, clientAssertionFile, ...params } = args;
	let clientAssertion: string | undefined;
	if (clientAssertionFile !== undefined) {
		try {
			clientAssertion = (await deps.readFile(clientAssertionFile)).trim();
		} catch {
			return err({ code: "invalid_request", description: "Cannot read client assertion file" });
		}
	}
	const response = await fetchEntityCollection(endpoint, params, {
		httpClient: deps.httpClient,
		...(post ? { method: "POST" } : {}),
		...(clientAssertion !== undefined ? { clientAssertion } : {}),
	});
	return response.ok ? ok(deps.formatter.format(response.value)) : response;
}

export function register(program: Command, deps: CollectionDeps): void {
	const append = (value: string, previous: string[] = []) => [...previous, value];
	program
		.command("collection")
		.description(
			"Query informational entity collection data; validate selected entities separately",
		)
		.argument("<endpoint>", "HTTPS collection endpoint, including independent providers")
		.option("--trust-anchor <id>", "Collection Trust Anchor")
		.option("--entity-type <type>", "Entity Type Identifier; repeat for OR matching", append)
		.option("--trust-mark-type <id>", "Trust Mark Type Identifier; repeat for AND matching", append)
		.option("--entity-claims <claim>", "Entity claim; repeat to select several", append)
		.option("--info-claims <claim>", "Informational claim; repeat to select several", append)
		.option("--locale <tag>", "BCP47 language tag; repeat for several languages", append)
		.option("--query <text>", "Responder-defined text query")
		.option("--from <cursor>", "Opaque continuation value from a previous response")
		.option("--limit <number>", "Maximum entities in the response", (raw: string) => {
			if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(Number(raw)))
				throw new Error("Expected a nonnegative safe integer");
			return Number(raw);
		})
		.option("--post", "Use anonymous form POST instead of GET")
		.option("--client-assertion-file <path>", "Client assertion JWT; implies POST")
		.action(async (endpoint: string, options: Omit<CollectionArgs, "endpoint">) => {
			const response = await handler({ endpoint, ...options }, deps);
			if (response.ok) process.stdout.write(`${response.value}\n`);
			else {
				deps.logger.error(response.error.description);
				process.exitCode = 1;
			}
		});
}
