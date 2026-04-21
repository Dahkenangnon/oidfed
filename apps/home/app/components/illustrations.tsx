export function HeroBackground() {
	return (
		<svg
			className="pointer-events-none absolute inset-0 h-full w-full"
			aria-hidden="true"
			xmlns="http://www.w3.org/2000/svg"
		>
			<defs>
				<radialGradient id="hero-fade" cx="50%" cy="40%" r="60%">
					<stop offset="0%" stopColor="currentColor" stopOpacity="0.08" />
					<stop offset="100%" stopColor="currentColor" stopOpacity="0" />
				</radialGradient>
			</defs>
			<rect width="100%" height="100%" fill="url(#hero-fade)" className="text-primary" />
			{/* Network nodes */}
			<g className="text-primary" fill="currentColor" opacity="0.12">
				<circle cx="15%" cy="25%" r="3" />
				<circle cx="30%" cy="60%" r="2.5" />
				<circle cx="50%" cy="20%" r="4" />
				<circle cx="70%" cy="45%" r="3" />
				<circle cx="85%" cy="30%" r="2.5" />
				<circle cx="40%" cy="75%" r="2" />
				<circle cx="75%" cy="70%" r="3" />
				<circle cx="20%" cy="45%" r="2" />
				<circle cx="60%" cy="65%" r="2.5" />
			</g>
			{/* Connection lines */}
			<g
				className="text-primary"
				stroke="currentColor"
				strokeWidth="0.5"
				opacity="0.06"
				fill="none"
			>
				<line x1="15%" y1="25%" x2="50%" y2="20%" />
				<line x1="50%" y1="20%" x2="85%" y2="30%" />
				<line x1="50%" y1="20%" x2="70%" y2="45%" />
				<line x1="15%" y1="25%" x2="30%" y2="60%" />
				<line x1="30%" y1="60%" x2="40%" y2="75%" />
				<line x1="70%" y1="45%" x2="75%" y2="70%" />
				<line x1="70%" y1="45%" x2="85%" y2="30%" />
				<line x1="20%" y1="45%" x2="30%" y2="60%" />
				<line x1="60%" y1="65%" x2="75%" y2="70%" />
			</g>
		</svg>
	);
}

export function SectionDivider() {
	return (
		<div className="pointer-events-none -my-px overflow-hidden" aria-hidden="true">
			<svg
				className="h-8 w-full text-primary"
				viewBox="0 0 1200 32"
				preserveAspectRatio="none"
				xmlns="http://www.w3.org/2000/svg"
				aria-hidden="true"
			>
				<path
					d="M0 32 C300 0, 600 28, 900 8 C1050 0, 1150 16, 1200 12 L1200 32Z"
					fill="currentColor"
					opacity="0.03"
				/>
			</svg>
		</div>
	);
}

export function FederationGraph() {
	return (
		<svg
			className="h-32 w-40 text-primary"
			viewBox="0 0 160 128"
			xmlns="http://www.w3.org/2000/svg"
			aria-hidden="true"
		>
			{/* Trust Anchor */}
			<circle cx="80" cy="20" r="8" fill="currentColor" opacity="0.2" />
			{/* Intermediates */}
			<circle cx="45" cy="60" r="6" fill="currentColor" opacity="0.15" />
			<circle cx="115" cy="60" r="6" fill="currentColor" opacity="0.15" />
			{/* Leaves */}
			<circle cx="25" cy="100" r="4" fill="currentColor" opacity="0.1" />
			<circle cx="65" cy="100" r="4" fill="currentColor" opacity="0.1" />
			<circle cx="95" cy="100" r="4" fill="currentColor" opacity="0.1" />
			<circle cx="135" cy="100" r="4" fill="currentColor" opacity="0.1" />
			{/* Lines */}
			<g stroke="currentColor" strokeWidth="1" opacity="0.12" fill="none">
				<line x1="80" y1="28" x2="45" y2="54" />
				<line x1="80" y1="28" x2="115" y2="54" />
				<line x1="45" y1="66" x2="25" y2="96" />
				<line x1="45" y1="66" x2="65" y2="96" />
				<line x1="115" y1="66" x2="95" y2="96" />
				<line x1="115" y1="66" x2="135" y2="96" />
			</g>
		</svg>
	);
}

export function NetworkPattern() {
	return (
		<svg
			className="pointer-events-none absolute inset-0 h-full w-full text-primary"
			aria-hidden="true"
			xmlns="http://www.w3.org/2000/svg"
		>
			<defs>
				<pattern id="dot-grid" x="0" y="0" width="32" height="32" patternUnits="userSpaceOnUse">
					<circle cx="16" cy="16" r="1" fill="currentColor" opacity="0.07" />
				</pattern>
			</defs>
			<rect width="100%" height="100%" fill="url(#dot-grid)" />
		</svg>
	);
}
