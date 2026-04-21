import { useCallback, useSyncExternalStore } from "react";
import { loadSettings, type Settings, saveSettings } from "@/lib/settings";

const listeners = new Set<() => void>();
let currentSettings = loadSettings();

function subscribe(listener: () => void): () => void {
	listeners.add(listener);
	return () => listeners.delete(listener);
}

function getSnapshot(): Settings {
	return currentSettings;
}

function notify(): void {
	for (const listener of listeners) {
		listener();
	}
}

export function useSettings(): readonly [Settings, (update: Partial<Settings>) => void] {
	const settings = useSyncExternalStore(subscribe, getSnapshot);

	const update = useCallback((partial: Partial<Settings>) => {
		currentSettings = { ...currentSettings, ...partial };
		saveSettings(currentSettings);
		notify();
	}, []);

	return [settings, update] as const;
}
