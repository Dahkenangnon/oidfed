import type { HTMLAttributes, SVGProps } from "react";
import { cn } from "../lib/utils";

export function OidfedLogoMark({ className, ...props }: SVGProps<SVGSVGElement>) {
	return (
		<svg
			viewBox="0 0 64 64"
			className={cn("size-8 shrink-0", className)}
			aria-hidden="true"
			role="presentation"
			{...props}
		>
			<rect x="4" y="4" width="56" height="56" rx="14" className="fill-neutral-950" />
			<path
				d="M32 14.5 19.5 29v12L32 49.5 44.5 41V29L32 14.5Z"
				className="fill-brand-500/10 stroke-brand-300"
				strokeWidth="2.25"
				strokeLinejoin="round"
			/>
			<path
				d="M32 19.5v24M22 30.5h20M22 40.5h20"
				className="stroke-brand-200/75"
				strokeWidth="1.75"
				strokeLinecap="round"
			/>
			<circle cx="32" cy="14.5" r="5" className="fill-brand-300" />
			<circle cx="19.5" cy="29" r="4.5" className="fill-brand-400" />
			<circle cx="44.5" cy="29" r="4.5" className="fill-brand-400" />
			<circle cx="32" cy="49.5" r="4.5" className="fill-brand-500" />
			<circle cx="32" cy="32" r="7" className="fill-neutral-950 stroke-brand-100" strokeWidth="2" />
			<text
				x="32"
				y="37.6"
				textAnchor="middle"
				fontFamily="Inter, ui-sans-serif, system-ui, sans-serif"
				fontSize="15.5"
				fontWeight="800"
				className="fill-brand-50"
			>
				@
			</text>
		</svg>
	);
}

export interface OidfedLogoProps extends HTMLAttributes<HTMLDivElement> {
	readonly label?: string;
	readonly sublabel?: string;
	readonly markClassName?: string;
	readonly labelClassName?: string;
	readonly sublabelClassName?: string;
}

export function OidfedLogo({
	label = "oidfed",
	sublabel,
	className,
	markClassName,
	labelClassName,
	sublabelClassName,
	...props
}: OidfedLogoProps) {
	return (
		<div className={cn("flex min-w-0 items-center gap-2", className)} {...props}>
			<OidfedLogoMark className={markClassName} />
			<div className="min-w-0 leading-none">
				<span
					className={cn("block truncate font-heading text-[15px] font-semibold", labelClassName)}
				>
					{label}
				</span>
				{sublabel ? (
					<span
						className={cn(
							"mt-1 block truncate font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground",
							sublabelClassName,
						)}
					>
						{sublabel}
					</span>
				) : null}
			</div>
		</div>
	);
}
