import type { ReactNode } from "react";

export function SiteHero({
	title,
	description,
	children,
	variant,
}: {
	title: ReactNode;
	description: string;
	children?: ReactNode;
	variant?: "home";
}) {
	return (
		<header className={variant === "home" ? "site-hero site-hero-home" : "site-hero"}>
			<div className="site-hero-shapes" aria-hidden="true" />
			<div className="relative mx-auto max-w-6xl px-5 py-14 text-center sm:px-8 sm:py-20">
				<h1 className="mx-auto max-w-5xl text-balance font-heading text-[clamp(2.25rem,6.25vw,5.25rem)] leading-[1.04] font-bold tracking-[-0.04em]">
					{title}
				</h1>
				<p className="mx-auto mt-5 max-w-[58ch] text-pretty text-base leading-relaxed text-muted-foreground sm:mt-6 sm:text-lg">
					{description}
				</p>
				{children}
			</div>
		</header>
	);
}
