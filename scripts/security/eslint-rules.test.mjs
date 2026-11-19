/** Detection and safe cases for each local rule, including dispatch data flow and guards. */

import test from "node:test";
import assert from "node:assert/strict";
import { Linter } from "eslint";
import tseslint from "typescript-eslint";
import protocol from "./eslint-rules.mjs";

const config = {
	files: ["**/*.{ts,js}"],
	languageOptions: { parser: tseslint.parser },
	plugins: { protocol },
	rules: {
		"no-eval": "error",
		"no-new-func": "error",
		...Object.fromEntries(Object.keys(protocol.rules).map((name) => [`protocol/${name}`, "error"])),
	},
};
const fixtures = [
	["crypto.getRandomValues(bytes)", "no-host-crypto-globals"],
	["globalThis.crypto.subtle.verify(input)", "no-host-crypto-globals"],
	["new TextEncoder().encode(text)", "no-host-crypto-globals"],
	["structuredClone(value)", "no-host-crypto-globals"],
	["function host(crypto) { return crypto.engine.random(8); }"],
	["context.crypto.engine.digest('SHA-256', bytes)"],
	[
		"const box={}; box.method=parameters.get('method'); registry[box['method']]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const box={}; box['method']=parameters.get('method'); registry[box.method]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const box={}; box[0]=parameters.get('method'); registry[box['0']]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const box={}; box.method=parameters.get('method'); if(Object.hasOwn(registry,box.method)) registry[box['method']]()",
	],
	[
		"const box={}; box['method']=parameters.get('method'); if(Object.hasOwn(registry,box['method'])) registry[box.method]()",
	],
	[
		"const key=parameters.get('method'); if(Object.hasOwn(context.registry,key)) context['registry'][key]()",
	],
	[
		"const key=parameters.get('method'); if(Object.hasOwn(context.registry,key)) context[other][key]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const key=parameters.get('method'); if(Object.hasOwn(context[property],key)) context.other[key]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const names = JSON.parse(raw); let index = 0; if (Object.hasOwn(registry, names[index])) { index = 1; registry[names[index]]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"const parsed = {}; parsed.method = parameters.get('method'); registry[parsed.method]()",
		"no-inherited-auth-dispatch",
	],
	[
		"function run() { let name = parameters.get('method'); if (!Object.hasOwn(registry, name)) return; while (flag) { registry[name](); name = parameters.get('other'); } }",
		"no-inherited-auth-dispatch",
	],
	[
		"function run() { let name = parameters.get('method'); while (flag) { if (!Object.hasOwn(registry, name)) return; registry[name](); name = parameters.get('other'); } }",
	],
	["eval(input)", "no-eval"],
	["new Function(input)", "no-new-func"],
	["Function(input)", "no-new-func"],
	["const name = parameters.get('method') ?? ''; registry[name]()", "no-inherited-auth-dispatch"],
	[
		"const parsed = JSON.parse(raw); const {method} = parsed; registry[method]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); const alias = name; registry[alias]()",
		"no-inherited-auth-dispatch",
	],
	["let name; name = parameters.get('method'); registry[name]()", "no-inherited-auth-dispatch"],
	["let name; ({method: name} = JSON.parse(raw)); registry[name]()", "no-inherited-auth-dispatch"],
	[
		"let name = 'safe'; while (flag) { registry[name](); name = parameters.get('method'); }",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = flag ? JSON.parse(raw).method : 'safe'; registry[name]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(other, name)) registry[name]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, other)) registry[name]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name) || flag) registry[name]()",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name)) {} registry[name]()",
		"no-inherited-auth-dispatch",
	],
	[
		"let name = parameters.get('method'); if (Object.hasOwn(registry, name)) { name = parameters.get('other'); registry[name]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name)) { registry = other; registry[name]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"function run() { let name = parameters.get('method'); if (!Object.hasOwn(registry, name)) return; name = 'toString'; registry[name]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name)) { delete registry[name]; registry[name]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name)) { const name = JSON.parse(raw).method; registry[name]() }",
		"no-inherited-auth-dispatch",
	],
	[
		"const Object = fake; const name = parameters.get('method'); if (Object.hasOwn(registry, name)) registry[name]()",
		"no-inherited-auth-dispatch",
	],
	["Object.assign({}, JSON.parse(raw))", "no-prototype-assign-from-json"],
	["fetch(url)", "no-unbounded-fetch"],
	["globalThis.fetch(url)", "no-unbounded-fetch"],
	["logger.warn(clientSecret)", "no-secret-logging"],
	["logger.warn('context', privateKey)", "no-secret-logging"],
	["logger.warn('context', clientSecret, 'other')", "no-secret-logging"],
	["logger.warn('context', 'other', clientAssertion)", "no-secret-logging"],
	["logger.error(client_secret)", "no-secret-logging"],
	["logger.info(client_assertion)", "no-secret-logging"],
	["const name = parameters.get('method'); if (Object.hasOwn(registry, name)) registry[name]()"],
	[
		"function run() { const name = parameters.get('method'); if (!Object.hasOwn(registry, name)) return; registry[name]() }",
	],
	[
		"const name = parameters.get('method'); if (!Object.hasOwn(registry, name)) throw Error(); registry[name]()",
	],
	[
		"const name = parameters.get('method'); if (Object.hasOwn(registry, name) && flag) registry[name]()",
	],
	["const name = parameters.get('method'); Object.hasOwn(registry, name) && registry[name]()"],
	[
		"const name = parameters.get('method'); if (!Object.hasOwn(registry, name)) {} else registry[name]()",
	],
	["const name = parameters.get('method'); handlers.get(name)?.()"],
	["const name = 'known'; registry[name]()"],
	["const name = parameters.get('method'); function safe(name) { registry[name]() }"],
	["Object.assign(Object.create(null), JSON.parse(raw))"],
	["safeTransport(url)"],
	["const client = options.httpClient ?? fetch"],
	["logger.warn('Public signing key', publicKey)"],
	["logger.warn('Client authentication failed')"],
];

for (const [index, [code, rule]] of fixtures.entries()) {
	for (const extension of ["ts", "js"]) {
		test(`${extension} fixture ${index + 1}: ${rule ?? "safe"}`, () => {
			const messages = new Linter().verify(code, [config], { filename: `fixture.${extension}` });
			const expected = rule
				? [rule.startsWith("no-eval") || rule === "no-new-func" ? rule : `protocol/${rule}`]
				: [];
			assert.deepEqual(
				messages.map((message) => message.ruleId),
				expected,
				JSON.stringify(messages),
			);
			for (const message of messages) assert.equal(message.line, 1);
		});
	}
}

test("TypeScript casts and non-null assertions retain request-derived dispatch keys", () => {
	for (const expression of ["name as string", "name!", "name satisfies string", "<string>name"]) {
		const code = `const name = parameters.get('method'); registry[${expression}]()`;
		const messages = new Linter().verify(code, [config], { filename: "fixture.ts" });
		assert.deepEqual(
			messages.map((message) => message.ruleId),
			["protocol/no-inherited-auth-dispatch"],
		);
	}
});

test("wrapped request getters remain taint sources", () => {
	for (const getter of [
		"parameters.get as Getter",
		"parameters.get!",
		"parameters.get satisfies Getter",
		"<Getter>parameters.get",
	]) {
		const code = `const key = (${getter})('method'); registry[key]()`;
		const messages = new Linter().verify(code, [config], { filename: "fixture.ts" });
		assert.deepEqual(
			messages.map((message) => message.ruleId),
			["protocol/no-inherited-auth-dispatch"],
		);
		const guarded = `const key = (${getter})('method'); if(Object.hasOwn(registry,key)) registry[key]()`;
		assert.deepEqual(new Linter().verify(guarded, [config], { filename: "fixture.ts" }), []);
	}
});

test("wrapped JSON sources and membership owners preserve detection and binding checks", () => {
	for (const owner of ["JSON as Parser", "JSON!", "JSON satisfies Parser", "<Parser>JSON"]) {
		const code = `const value = (${owner}).parse(raw); registry[value.method]()`;
		const messages = new Linter().verify(code, [config], { filename: "fixture.ts" });
		assert.deepEqual(
			messages.map((message) => message.ruleId),
			["protocol/no-inherited-auth-dispatch"],
		);
	}
	const guarded =
		"const key = parameters.get('method'); if((Object as Membership).hasOwn(registry,key)) registry[key]()";
	assert.deepEqual(new Linter().verify(guarded, [config], { filename: "fixture.ts" }), []);
	const shadowed = `const Object = fake; ${guarded}`;
	assert.deepEqual(
		new Linter()
			.verify(shadowed, [config], { filename: "fixture.ts" })
			.map((message) => message.ruleId),
		["protocol/no-inherited-auth-dispatch"],
	);
});

test("wrapped global Function constructors are rejected without duplicate or shadowed-binding reports", () => {
	for (const constructor of [
		"Function as Factory",
		"Function!",
		"Function satisfies Factory",
		"<Factory>Function",
	]) {
		for (const prefix of ["", "new "]) {
			const code = `${prefix}(${constructor})(input)`;
			const messages = new Linter().verify(code, [config], { filename: "fixture.ts" });
			assert.deepEqual(
				messages.map((message) => message.ruleId),
				["protocol/no-wrapped-function-constructor"],
			);
			const shadowed = `function safe(Function) { return ${code}; }`;
			assert.deepEqual(new Linter().verify(shadowed, [config], { filename: "fixture.ts" }), []);
		}
	}
	assert.deepEqual(
		new Linter().verify("(SafeFactory as Factory)(input)", [config], { filename: "fixture.ts" }),
		[],
	);
});

test("both direct transport spellings report their exact source locations", () => {
	const messages = new Linter().verify("fetch(url);\nglobalThis.fetch(url);", [config]);
	assert.deepEqual(
		messages.map(({ ruleId, line, column }) => ({ ruleId, line, column })),
		[
			{ ruleId: "protocol/no-unbounded-fetch", line: 1, column: 1 },
			{ ruleId: "protocol/no-unbounded-fetch", line: 2, column: 1 },
		],
	);
});
