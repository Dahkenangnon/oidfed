import { ArrowLeft } from "lucide-react";
import { Link } from "react-router";
import { SiteHero } from "../components/site-hero";
import { buildMeta } from "../lib/seo";

export function meta() {
	return buildMeta({
		title: "Page not found",
		description: "The address may have changed. Browse the documentation or the ecosystem instead.",
		path: "/404",
		noindex: true,
	});
}

export default function NotFound() {
	return (
		<SiteHero title="Page not found" description="The address may have changed.">
			<div className="mt-7 flex flex-wrap justify-center gap-3">
				<Link to="/" className="site-button">
					<ArrowLeft aria-hidden className="size-4" /> Back to home
				</Link>
				<Link to="/ecosystem" className="site-button site-button-outline">
					Browse the ecosystem
				</Link>
			</div>
		</SiteHero>
	);
}
