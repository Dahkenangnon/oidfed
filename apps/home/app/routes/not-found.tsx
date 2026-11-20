import { ArrowLeft } from "lucide-react";
import { Link } from "react-router";
import { SiteHero } from "../components/site-hero";

export function meta() {
	return [{ title: "Page not found | OidFed" }, { name: "robots", content: "noindex,nofollow" }];
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
