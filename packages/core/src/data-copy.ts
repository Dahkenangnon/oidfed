/** Portable copies of application data. Service objects and key handles are never copyable data. */

/**
 * Detach a data graph, preserving cycles, shared references, maps and binary views.
 * Like structured cloning, custom object prototypes and property descriptors are not retained.
 * Functions, symbols, weak collections and opaque platform objects reject with TypeError.
 */
export function cloneData<T>(value: T): T {
	const seen = new Map<object, unknown>();
	const pending: (() => void)[] = [];
	const copy = (source: unknown): unknown => {
		if (typeof source === "function" || typeof source === "symbol")
			throw new TypeError("Only data values can be copied");
		if (source === null || typeof source !== "object") return source;
		if (seen.has(source)) return seen.get(source);
		let result: unknown;
		if (source instanceof Date) result = new Date(source.getTime());
		else if (source instanceof RegExp) result = new RegExp(source.source, source.flags);
		else if (source instanceof ArrayBuffer) result = source.slice(0);
		else if (ArrayBuffer.isView(source)) {
			const buffer = copy(source.buffer) as ArrayBuffer;
			if (source instanceof DataView)
				result = new DataView(buffer, source.byteOffset, source.byteLength);
			else {
				const constructors = {
					Int8Array,
					Uint8Array,
					Uint8ClampedArray,
					Int16Array,
					Uint16Array,
					Int32Array,
					Uint32Array,
					Float32Array,
					Float64Array,
					BigInt64Array,
					BigUint64Array,
				};
				const name = Object.prototype.toString.call(source).slice(8, -1);
				const Constructor = constructors[name as keyof typeof constructors];
				if (!Constructor) throw new TypeError("Unsupported binary view");
				result = new Constructor(
					buffer,
					source.byteOffset,
					source.byteLength / Constructor.BYTES_PER_ELEMENT,
				);
			}
		} else if (source instanceof Map) {
			const target = new Map();
			result = target;
			pending.push(() => {
				for (const [key, item] of source) target.set(copy(key), copy(item));
			});
		} else if (source instanceof Set) {
			const target = new Set();
			result = target;
			pending.push(() => {
				for (const item of source) target.add(copy(item));
			});
		} else if (source instanceof Error) {
			const target = new Error(source.message);
			target.name = source.name;
			result = target;
			if (source.stack !== undefined) target.stack = source.stack;
			if (Object.hasOwn(source, "cause"))
				pending.push(() => {
					target.cause = copy(source.cause);
				});
		} else if (
			Array.isArray(source) ||
			Object.prototype.toString.call(source) === "[object Object]"
		) {
			const target: Record<string, unknown> | unknown[] = Array.isArray(source)
				? new Array(source.length)
				: {};
			result = target;
			pending.push(() => {
				for (const name of Object.keys(source))
					Object.defineProperty(target, name, {
						value: copy((source as Record<string, unknown>)[name]),
						enumerable: true,
						writable: true,
						configurable: true,
					});
			});
		} else
			throw new TypeError(
				"Unsupported data object; retain service objects and key handles by reference",
			);
		seen.set(source, result);
		return result;
	};
	const result = copy(value);
	while (pending.length) pending.pop()?.();
	return result as T;
}
