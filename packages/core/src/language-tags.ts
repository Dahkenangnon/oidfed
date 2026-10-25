// RFC 5646 includes private-use and grandfathered tags that Intl may reject.
const grandfathered = new Set([
	"en-gb-oed",
	"i-ami",
	"i-bnn",
	"i-default",
	"i-enochian",
	"i-hak",
	"i-klingon",
	"i-lux",
	"i-mingo",
	"i-navajo",
	"i-pwn",
	"i-tao",
	"i-tay",
	"i-tsu",
	"sgn-be-fr",
	"sgn-be-nl",
	"sgn-ch-de",
	"art-lojban",
	"cel-gaulish",
	"no-bok",
	"no-nyn",
	"zh-guoyu",
	"zh-hakka",
	"zh-min",
	"zh-min-nan",
	"zh-xiang",
]);
const languageTag =
	/^(?:(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})(?:-[a-z]{4})?(?:-(?:[a-z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(?:-[0-9a-wy-z](?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?|x(?:-[a-z0-9]{1,8})+)$/i;
export function isLanguageTag(tag: string): boolean {
	if (grandfathered.has(tag.toLowerCase())) return true;
	if (!languageTag.test(tag)) return false;
	const seen = new Set<string>();
	let extension = false;
	const parts = tag.toLowerCase().split("-");
	if (parts[0] === "x") return true;
	for (const part of parts.slice(1)) {
		if (part === "x") break;
		if (part.length === 1) {
			if (seen.has(part)) return false;
			seen.add(part);
			extension = true;
		} else if (!extension && (part.length >= 5 || /^[0-9][a-z0-9]{3}$/.test(part))) {
			if (seen.has(part)) return false;
			seen.add(part);
		}
	}
	return true;
}

/** Exact registered names take precedence over interpreting a language suffix. */
export function splitInformationalClaim(
	name: string,
	declared: ReadonlySet<string>,
): { base: string; tag?: string } {
	if (declared.has(name)) return { base: name };
	const candidates = [...declared]
		.filter((base) => name.startsWith(`${base}#`))
		.sort((a, b) => b.length - a.length);
	for (const base of candidates) {
		const tag = name.slice(base.length + 1);
		if (isLanguageTag(tag)) return { base, tag };
	}
	return { base: name };
}
