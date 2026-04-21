import { buttonVariants } from "@oidfed/ui";
import { Link } from "react-router";

export function meta() {
	return [{ title: "404 — Page Not Found | @oidfed" }];
}

export default function NotFound() {
	return (
		<div className="flex min-h-screen flex-col items-center justify-center gap-6 p-8 text-center">
			<p className="font-mono text-5xl font-bold text-muted-foreground/40">404</p>
			<div className="space-y-2">
				<h1 className="text-2xl font-semibold">Page not found</h1>
				<p className="text-sm text-muted-foreground">
					The page you're looking for doesn't exist or has been moved.
				</p>
			</div>
			<Link to="/" className={buttonVariants({ variant: "outline", size: "sm" })}>
				Back to home
			</Link>
		</div>
	);
}
