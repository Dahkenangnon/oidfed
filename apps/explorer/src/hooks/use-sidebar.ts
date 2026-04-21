import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "oidfed-explorer-sidebar";

function getInitialCollapsed(): boolean {
	try {
		return localStorage.getItem(STORAGE_KEY) === "collapsed";
	} catch {
		return false;
	}
}

export function useSidebar() {
	const [collapsed, setCollapsed] = useState(getInitialCollapsed);
	const [mobileOpen, setMobileOpen] = useState(false);

	const toggle = useCallback(() => {
		setCollapsed((prev) => {
			const next = !prev;
			localStorage.setItem(STORAGE_KEY, next ? "collapsed" : "expanded");
			return next;
		});
	}, []);

	const openMobile = useCallback(() => setMobileOpen(true), []);
	const closeMobile = useCallback(() => setMobileOpen(false), []);

	// Close mobile drawer on route change (resize beyond mobile)
	useEffect(() => {
		const mq = window.matchMedia("(min-width: 768px)");
		const handler = () => {
			if (mq.matches) setMobileOpen(false);
		};
		mq.addEventListener("change", handler);
		return () => mq.removeEventListener("change", handler);
	}, []);

	return { collapsed, toggle, mobileOpen, openMobile, closeMobile } as const;
}
