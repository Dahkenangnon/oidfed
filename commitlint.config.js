export default {
	extends: ["@commitlint/config-conventional"],
	plugins: [
		{
			rules: {
				"reference-position": ({ subject = "" }) => {
					const description = subject.replace(/^(?:#\d+\s+)+(?=\S)/, "");
					const withoutUrls = description.replace(/\b[a-z][a-z\d+.-]*:\/\/\S+/gi, "");
					return [
						!/(?:^|\W)#\d+\b/.test(withoutUrls),
						"put numbered references immediately after type(scope):, before the description",
					];
				},
			},
		},
	],
	rules: {
		"reference-position": [2, "always"],
		"type-enum": [
			2,
			"always",
			[
				"feat",
				"fix",
				"perf",
				"refactor",
				"test",
				"docs",
				"build",
				"ci",
				"chore",
				"style",
				"revert",
			],
		],
		"scope-enum": [
			2,
			"always",
			[
				"core",
				"authority",
				"leaf",
				"oidc",
				"cli",
				"explorer",
				"home",
				"learn",
				"ui",
				"release",
				"ci",
				"deps",
				"deps-dev",
				"tests",
				"e2e",
				"scripts",
				"repo",
				"docs",
				"guide"
			],
		],
		"scope-empty": [2, "never"],
		"subject-case": [2, "never", ["upper-case", "pascal-case", "start-case"]],
		"subject-full-stop": [2, "never", "."],
		"header-max-length": [2, "always", 72],
		"body-max-line-length": [2, "always", 120],
	},
};
