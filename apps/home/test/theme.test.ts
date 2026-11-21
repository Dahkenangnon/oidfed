import assert from "node:assert/strict";
import { test } from "node:test";
import {
	parseStoredTheme,
	readStoredTheme,
	resolveTheme,
	storeTheme,
	THEME_COLORS,
	themeBootstrapScript,
} from "../app/lib/theme";

/** Installs a `localStorage` that fails the way a hardened browser does. */
function withDeniedStorage(body: () => void) {
	const descriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
	Object.defineProperty(globalThis, "localStorage", {
		configurable: true,
		get() {
			throw new Error("SecurityError: access to storage is denied");
		},
	});
	try {
		body();
	} finally {
		if (descriptor) Object.defineProperty(globalThis, "localStorage", descriptor);
		else Reflect.deleteProperty(globalThis, "localStorage");
	}
}

test("a stored choice wins over the operating system preference", () => {
	assert.equal(resolveTheme("light", true), "light");
	assert.equal(resolveTheme("dark", false), "dark");
});

test("the operating system preference decides when nothing is stored", () => {
	assert.equal(resolveTheme(null, true), "dark");
	assert.equal(resolveTheme(null, false), "light");
});

test("only the two known values count as a stored choice", () => {
	assert.equal(parseStoredTheme("dark"), "dark");
	assert.equal(parseStoredTheme("light"), "light");
	assert.equal(parseStoredTheme(null), null);
	assert.equal(parseStoredTheme(""), null);
	assert.equal(parseStoredTheme("DARK"), null);
	assert.equal(parseStoredTheme("system"), null);
});

test("a browser that denies storage reports no stored choice instead of throwing", () => {
	withDeniedStorage(() => {
		assert.equal(readStoredTheme(), null);
	});
});

test("a browser that denies storage drops the write instead of throwing", () => {
	withDeniedStorage(() => {
		assert.doesNotThrow(() => storeTheme("dark"));
	});
});

test("the bootstrap script resolves the theme before first paint", () => {
	const script = themeBootstrapScript();
	assert.match(script, /try\{/, "must tolerate browsers that deny storage");
	assert.match(script, /catch/, "must tolerate browsers that deny storage");
	assert.ok(script.includes("prefers-color-scheme: dark"), "must consult the system preference");
	assert.ok(script.includes(THEME_COLORS.dark), "must set the dark browser chrome");
	assert.doesNotMatch(script, /\n/, "must stay a single inline statement");
});

/**
 * Runs the inline bootstrap against the globals a browser would supply and
 * reports what it did to the document.
 */
function runBootstrap(stored: string | null, systemDark: boolean) {
	const classes = new Set<string>();
	let chrome = "#fcfdff";
	const globals = {
		localStorage: { getItem: (key: string) => (key === "theme" ? stored : null) },
		matchMedia: (query: string) => ({ matches: systemDark && query.includes("dark") }),
		document: {
			documentElement: { classList: { add: (name: string) => classes.add(name) } },
			querySelector: (selector: string) =>
				selector === 'meta[name="theme-color"]'
					? { setAttribute: (_: string, value: string) => (chrome = value) }
					: null,
		},
	};
	const run = new Function(
		...Object.keys(globals),
		`"use strict";${themeBootstrapScript()}`,
	) as (...args: unknown[]) => void;
	run(...Object.values(globals));
	return { dark: classes.has("dark"), chrome };
}

test("the bootstrap script applies a stored dark choice", () => {
	assert.deepEqual(runBootstrap("dark", false), { dark: true, chrome: THEME_COLORS.dark });
});

test("the bootstrap script honours a stored light choice on a dark system", () => {
	assert.deepEqual(runBootstrap("light", true), { dark: false, chrome: THEME_COLORS.light });
});

test("the bootstrap script follows a dark system when nothing is stored", () => {
	assert.deepEqual(runBootstrap(null, true), { dark: true, chrome: THEME_COLORS.dark });
});

test("the bootstrap script leaves a light system alone when nothing is stored", () => {
	assert.deepEqual(runBootstrap(null, false), { dark: false, chrome: THEME_COLORS.light });
});
