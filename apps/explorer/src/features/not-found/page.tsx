import { Button } from "@oidfed/ui";
import { useNavigate } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";

export function NotFoundPage() {
	usePageTitle("404 — Page Not Found");
	const navigate = useNavigate();

	return (
		<div className="flex min-h-screen flex-col items-center justify-center gap-6 p-8 text-center">
			<p className="font-mono text-5xl font-bold text-muted-foreground/40">404</p>
			<div className="space-y-2">
				<h1 className="text-2xl font-semibold">Page not found</h1>
				<p className="text-sm text-muted-foreground">
					The page you're looking for doesn't exist or has been moved.
				</p>
			</div>
			<Button variant="outline" size="sm" onClick={() => navigate("/")}>
				Back to explorer
			</Button>
		</div>
	);
}
