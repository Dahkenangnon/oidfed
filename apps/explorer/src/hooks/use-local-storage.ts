import { useCallback, useState } from "react";

/**
 * A `useState`-like hook backed by localStorage.
 * Reads from localStorage on mount; writes on every `set`.
 *
 * Key convention: `oidfed-explorer-<feature>-<field>`.
 */
export function useLocalStorage<T>(key: string, initialValue: T): [T, (value: T) => void] {
	const [stored, setStored] = useState<T>(() => {
		try {
			const item = localStorage.getItem(key);
			return item !== null ? (JSON.parse(item) as T) : initialValue;
		} catch {
			return initialValue;
		}
	});

	const setValue = useCallback(
		(value: T) => {
			setStored(value);
			try {
				localStorage.setItem(key, JSON.stringify(value));
			} catch {
				// Storage full or blocked — ignore
			}
		},
		[key],
	);

	return [stored, setValue];
}
