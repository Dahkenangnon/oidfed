export default {
	extends: ["@commitlint/config-conventional"],
	plugins: [
		{
			rules: {
				"reference-position": ({ subject = "" }) => {
					const description = subject.replace(/\s+\(#\d+\)$/, "");
					const withoutUrls = description.replace(/\b[a-z][a-z\d+.-]*:\/\/\S+/gi, "");
					return [
						(description === subject || description.trim().length > 0) &&
							!/(?:^|\W|[\w.-]+\/[\w.-]+)#\d+\b/.test(withoutUrls),
						"put one numbered reference at the end of the subject as (#123)",
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
