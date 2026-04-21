export type Phase = "foundation" | "core" | "advanced" | "capstone" | "deeper";

export interface PhaseInfo {
	id: Phase;
	label: string;
	color: string;
}

export const phases: Record<Phase, PhaseInfo> = {
	foundation: { id: "foundation", label: "Foundation", color: "text-brand-500" },
	core: { id: "core", label: "Core Mechanics", color: "text-emerald-600" },
	advanced: { id: "advanced", label: "Advanced", color: "text-purple-600" },
	capstone: { id: "capstone", label: "Capstone", color: "text-orange-600" },
	deeper: { id: "deeper", label: "Going Deeper", color: "text-teal-600" },
};

export const phaseOrder: Phase[] = ["foundation", "core", "advanced", "capstone", "deeper"];

export interface Lesson {
	number: number;
	slug: string;
	title: string;
	subtitle: string;
	phase: Phase;
	emoji: string;
}

export const lessons: Lesson[] = [
	{
		number: 1,
		slug: "what-is-federation",
		title: "What is Federation?",
		subtitle: "Why federation exists and what problem it solves",
		phase: "foundation",
		emoji: "🌐",
	},
	{
		number: 2,
		slug: "entities-and-roles",
		title: "Entities & Roles",
		subtitle: "The hierarchy of players in a federation",
		phase: "foundation",
		emoji: "🏛️",
	},
	{
		number: 3,
		slug: "entity-statements",
		title: "Entity Statements",
		subtitle: "Signed documents that carry trust — cracking open a JWT",
		phase: "foundation",
		emoji: "📜",
	},
	{
		number: 4,
		slug: "trust-chains",
		title: "Trust Chains",
		subtitle: "How linked, signed statements form an unbreakable chain",
		phase: "core",
		emoji: "🔗",
	},
	{
		number: 5,
		slug: "trust-chain-resolution",
		title: "Trust Chain Resolution",
		subtitle: "The algorithm that fetches, assembles, and verifies a chain",
		phase: "core",
		emoji: "🔍",
	},
	{
		number: 6,
		slug: "metadata-and-policy",
		title: "Metadata & Policy",
		subtitle: "How entities describe capabilities and superiors constrain them",
		phase: "core",
		emoji: "📋",
	},
	{
		number: 7,
		slug: "trust-marks",
		title: "Trust Marks",
		subtitle: "Certified badges that prove an entity meets requirements",
		phase: "advanced",
		emoji: "🏅",
	},
	{
		number: 8,
		slug: "federation-endpoints",
		title: "Federation Endpoints",
		subtitle: "The HTTP APIs that federation entities expose",
		phase: "advanced",
		emoji: "🔌",
	},
	{
		number: 9,
		slug: "client-registration",
		title: "Client Registration",
		subtitle: "How an app introduces itself to an OpenID Provider",
		phase: "advanced",
		emoji: "🤝",
	},
	{
		number: 10,
		slug: "putting-it-together",
		title: "Putting It All Together",
		subtitle: "A complete real-world scenario using every concept",
		phase: "capstone",
		emoji: "🎓",
	},
	{
		number: 11,
		slug: "topology-design",
		title: "Federation Topology Design",
		subtitle: "Choosing the right shape for your federation",
		phase: "deeper",
		emoji: "🗺️",
	},
	{
		number: 12,
		slug: "faq",
		title: "Frequently Asked Questions",
		subtitle: "Common questions from basics to operations",
		phase: "deeper",
		emoji: "❓",
	},
	{
		number: 13,
		slug: "glossary",
		title: "Glossary",
		subtitle: "Every key term defined, linked, and cross-referenced",
		phase: "deeper",
		emoji: "📖",
	},
	{
		number: 14,
		slug: "real-use-cases",
		title: "Real-World Use Cases",
		subtitle: "How diverse industries use federation to solve trust problems",
		phase: "deeper",
		emoji: "🏭",
	},
	{
		number: 15,
		slug: "hands-on-objects",
		title: "Hands-On Object Lab",
		subtitle: "Build physical objects that map to federation concepts",
		phase: "deeper",
		emoji: "🧪",
	},
];

/** Get a lesson by 1-based number. Throws if not found. */
export function getLesson(number: number): Lesson {
	const lesson = lessons[number - 1];
	if (!lesson) throw new Error(`Lesson ${number} not found`);
	return lesson;
}

export function getLessonsByPhase(phase: Phase): Lesson[] {
	return lessons.filter((l) => l.phase === phase);
}

export function getLessonNav(number: number): {
	prev: Lesson | undefined;
	next: Lesson | undefined;
} {
	const idx = lessons.findIndex((l) => l.number === number);
	return {
		prev: idx > 0 ? lessons[idx - 1] : undefined,
		next: idx < lessons.length - 1 ? lessons[idx + 1] : undefined,
	};
}
