const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

/** Returns whether an untrusted dictionary key can access JavaScript prototype state. */
export function isPrototypeKey(key: string): boolean {
	return PROTOTYPE_KEYS.has(key);
}

/** Own-property lookup for dictionaries whose keys can originate in federation data. */
export function hasOwn(record: object, key: string): boolean {
	return Object.hasOwn(record, key);
}
