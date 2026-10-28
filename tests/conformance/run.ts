/** Build the pinned suite and manage its disposable Docker environment. */
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { BASELINE, ensureComplete, HarnessError, type Profile } from "./policy.js";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const MAVEN =
	"maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237";
type Options = { env?: NodeJS.ProcessEnv; quiet?: boolean; signal?: AbortSignal; timeout?: number };
export type Command = (args: string[], options?: Options) => Promise<void>;

export const command: Command = async (args, options = {}) => {
	const executable = args[0];
	if (!executable) throw new HarnessError("empty_command");
	const signals = [
		...(options.signal ? [options.signal] : []),
		...(options.timeout ? [AbortSignal.timeout(options.timeout)] : []),
	];
	await new Promise<void>((done, reject) => {
		const child = spawn(executable, args.slice(1), {
			cwd: ROOT,
			env: options.env ?? process.env,
			stdio: options.quiet ? "ignore" : "inherit",
			...(signals.length ? { signal: AbortSignal.any(signals) } : {}),
		});
		let failed = false;
		let forced: NodeJS.Timeout | undefined;
		child.once("error", () => {
			failed = true;
			// Wait for the child to stop before cleaning up its Docker resources.
			if (child.pid) forced = setTimeout(() => child.kill("SIGKILL"), 5000).unref();
		});
		child.once("close", (code) => {
			clearTimeout(forced);
			if (code === 0 && !failed) done();
			else reject(new HarnessError("command_failed"));
		});
	});
};

async function gitOutput(args: string[]): Promise<string> {
	return new Promise((done, reject) => {
		const child = spawn("git", args, { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] });
		const chunks: Buffer[] = [];
		child.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
		child.once("error", () => reject(new HarnessError("git_failed")));
		child.once("close", (code) =>
			code === 0
				? done(Buffer.concat(chunks).toString().trim())
				: reject(new HarnessError("git_failed")),
		);
	});
}

async function exists(path: string): Promise<boolean> {
	try {
		await stat(path);
		return true;
	} catch {
		return false;
	}
}

export async function checkout(source: string, signal?: AbortSignal): Promise<void> {
	if (!(await exists(join(source, ".git")))) {
		await mkdir(source, { recursive: true });
		await command(["git", "init", source]);
		await command(["git", "-C", source, "remote", "add", "origin", BASELINE.repository]);
		await command(
			["git", "-C", source, "fetch", "--depth=1", "origin", BASELINE.revision],
			signal ? { signal } : {},
		);
		await command(["git", "-C", source, "checkout", "--detach", "FETCH_HEAD"]);
	}
	if ((await gitOutput(["-C", source, "rev-parse", "HEAD"])) !== BASELINE.revision)
		throw new HarnessError("suite_revision_mismatch");
	if (await gitOutput(["-C", source, "status", "--porcelain", "--untracked-files=all"]))
		throw new HarnessError("suite_checkout_dirty");
	for (const plan of Object.values(BASELINE.plans)) {
		const text = (await readFile(join(source, plan.source), "utf8"))
			.split("\n")
			.filter((line) => !line.trimStart().startsWith("//"))
			.join("\n");
		const classes = [...text.matchAll(/\b(OpenIDFederation\w+)\.class/g)].map((match) => match[1]);
		const wanted = plan.modules.map((module) =>
			module.source
				.split("/")
				.at(-1)
				?.replace(/\.java$/, ""),
		);
		if (JSON.stringify(classes) !== JSON.stringify(wanted))
			throw new HarnessError("suite_source_inventory_mismatch");
	}
}

async function certificates(state: string): Promise<void> {
	await command(
		[
			"openssl",
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-days",
			"2",
			"-subj",
			"/CN=oidfed disposable conformance CA",
			"-keyout",
			join(state, "ca-key.pem"),
			"-out",
			join(state, "ca.pem"),
		],
		{ quiet: true },
	);
	await command(
		[
			"openssl",
			"req",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-subj",
			"/CN=suite.ofed.test",
			"-keyout",
			join(state, "tls-key.pem"),
			"-out",
			join(state, "tls.csr"),
		],
		{ quiet: true },
	);
	const extensions = join(state, "tls.ext");
	await writeFile(
		extensions,
		"subjectAltName=DNS:suite.ofed.test,DNS:ta.ofed.test,DNS:ia.ofed.test,DNS:leaf.ofed.test,DNS:op.ofed.test,DNS:rp.ofed.test\nextendedKeyUsage=serverAuth\n",
	);
	await command(
		[
			"openssl",
			"x509",
			"-req",
			"-days",
			"2",
			"-in",
			join(state, "tls.csr"),
			"-CA",
			join(state, "ca.pem"),
			"-CAkey",
			join(state, "ca-key.pem"),
			"-CAcreateserial",
			"-extfile",
			extensions,
			"-out",
			join(state, "tls.pem"),
		],
		{ quiet: true },
	);
}

export async function withEnvironment(
	compose: string[],
	env: NodeJS.ProcessEnv,
	state: string,
	keepPrivate: boolean,
	work: () => Promise<void>,
	runCommand: Command = command,
): Promise<void> {
	try {
		await work();
	} finally {
		try {
			await runCommand([...compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"], {
				env,
				quiet: true,
				timeout: 45_000,
			});
		} finally {
			if (!keepPrivate) await rm(state, { recursive: true, force: true });
		}
	}
}

async function hashFile(path: string): Promise<string> {
	const hash = createHash("sha256");
	for await (const chunk of createReadStream(path)) hash.update(chunk);
	return hash.digest("hex");
}

export function validateOptions(profile: string, keepPrivate: boolean): asserts profile is Profile {
	if (!Object.hasOwn(BASELINE.profiles, profile)) throw new HarnessError("invalid_profile");
	if (keepPrivate && process.env.CI) throw new HarnessError("private_diagnostics_in_ci");
}

export async function main(
	profile: string,
	sourceOverride?: string,
	keepPrivate = false,
	signal?: AbortSignal,
): Promise<void> {
	validateOptions(profile, keepPrivate);
	const cache = join(ROOT, ".conformance");
	const source = sourceOverride ? resolve(sourceOverride) : join(cache, "suite", BASELINE.revision);
	await checkout(source, signal);
	const maven = join(cache, "maven");
	await mkdir(maven, { recursive: true });
	await command(
		[
			"docker",
			"run",
			"--rm",
			"--user",
			`${process.getuid?.()}:${process.getgid?.()}`,
			"-v",
			`${source}:/src`,
			"-v",
			`${maven}:/tmp/maven`,
			"-w",
			"/src",
			MAVEN,
			"mvn",
			"-B",
			"-Dmaven.repo.local=/tmp/maven",
			"-Dmaven.test.skip=true",
			"-Dpmd.skip=true",
			"package",
		],
		signal ? { signal } : {},
	);
	const jar = join(source, "target/fapi-test-suite.jar");
	if (!(await exists(jar))) throw new HarnessError("suite_jar_missing");
	const definition = join(ROOT, "tests/conformance");
	const digest = await hashFile(join(definition, "Dockerfile"));
	const runner = `oidfed-conformance-runner:${digest.slice(0, 16)}`;
	await command(["docker", "build", "-t", runner, definition], signal ? { signal } : {});
	const runId = `oidfed-${randomUUID().replaceAll("-", "").slice(0, 16)}`;
	const run = join(cache, "runs", runId);
	const state = join(run, "private");
	const results = join(run, "results");
	await mkdir(state, { recursive: true, mode: 0o700 });
	await mkdir(results);
	const env = {
		...process.env,
		OIDF_ROOT: ROOT,
		OIDF_SOURCE: source,
		OIDF_STATE: state,
		OIDF_RESULTS: results,
		OIDF_PROFILE: profile,
		OIDF_UID: String(process.getuid?.()),
		OIDF_GID: String(process.getgid?.()),
		OIDF_RUNNER: runner,
	};
	const compose = ["docker", "compose", "-p", runId, "-f", join(definition, "compose.yml")];
	await withEnvironment(compose, env, state, keepPrivate, async () => {
		await certificates(state);
		await writeFile(join(state, "settings.json"), JSON.stringify({ runId }));
		const fixtureHash = createHash("sha256");
		for (const name of (await readdir(definition)).sort()) {
			const path = join(definition, name);
			if ((await stat(path)).isFile())
				fixtureHash
					.update(name)
					.update("\0")
					.update(await readFile(path));
		}
		await writeFile(
			join(results, "build.json"),
			`${JSON.stringify({ revision: BASELINE.revision, jarSha256: await hashFile(jar), profile, oidfedCommit: await gitOutput(["rev-parse", "HEAD"]), dirty: Boolean(await gitOutput(["status", "--porcelain"])), fixtureSha256: fixtureHash.digest("hex"), runnerImage: runner }, null, 2)}\n`,
		);
		console.log(`Compose project: ${runId}\nReports: ${results}`);
		await command([...compose, "up", "-d", "mongo", "suite", "proxy", "fixtures"], {
			env,
			...(signal ? { signal } : {}),
		});
		await command([...compose, "run", "--rm", "driver"], { env, ...(signal ? { signal } : {}) });
		ensureComplete(JSON.parse(await readFile(join(results, "summary.json"), "utf8")), profile);
	});
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const controller = new AbortController();
	process.once("SIGTERM", () => controller.abort());
	process.once("SIGINT", () => controller.abort());
	try {
		const { values } = parseArgs({
			options: {
				profile: { type: "string", default: "deployed" },
				source: { type: "string" },
				"keep-private": { type: "boolean", default: false },
				help: { type: "boolean", default: false },
			},
		});
		if (values.help)
			console.log(
				"Usage: run.ts [--profile deployed|rp|op|full] [--source PATH] [--keep-private]\n\nRun the pinned OpenID Federation conformance test plans. --keep-private retains sensitive local diagnostics and is forbidden in CI.",
			);
		else await main(values.profile, values.source, values["keep-private"], controller.signal);
	} catch (error) {
		console.error(
			`Conformance run failed: ${error instanceof HarnessError ? error.message : "launcher_failed"}`,
		);
		process.exitCode = controller.signal.aborted ? 143 : 1;
	}
}
