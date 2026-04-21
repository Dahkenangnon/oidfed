import { Separator, SidebarInset, SidebarProvider, SidebarTrigger } from "@oidfed/ui";
import { Outlet } from "react-router";
import { AppSidebar } from "./app-sidebar";
import { ThemeToggle } from "./theme-toggle";

function getSidebarDefault(): boolean {
	const match = document.cookie.match(/(?:^|; )sidebar_state=([^;]*)/);
	return match?.[1] ? decodeURIComponent(match[1]) !== "false" : true;
}

export function RootLayout() {
	return (
		<SidebarProvider defaultOpen={getSidebarDefault()} className="h-svh overflow-hidden">
			<AppSidebar />
			<SidebarInset className="flex h-full flex-col overflow-hidden">
				<header className="flex h-12 shrink-0 items-center gap-2 px-4 md:px-6 lg:px-8">
					<SidebarTrigger className="md:hidden" />
					<Separator orientation="vertical" className="h-4 md:hidden" />
					<div className="flex-1" />
					<ThemeToggle />
				</header>
				<main className="flex-1 overflow-auto px-4 pb-8 md:px-6 lg:px-8">
					<div className="mx-auto max-w-6xl">
						<Outlet />
					</div>
				</main>
				<footer className="shrink-0 border-t px-4 py-2 md:px-6 lg:px-8">
					<p className="text-center text-xs text-muted-foreground">
						Provided as-is with no guarantees. Self-hostable —{" "}
						<a
							href="https://github.com/Dahkenangnon/oidfed"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-2 hover:text-foreground"
						>
							view source on GitHub
						</a>
						{" · "}By{" "}
						<a
							href="https://github.com/Dahkenangnon"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-2 hover:text-foreground"
						>
							Justin Dah-kenangnon
						</a>
					</p>
				</footer>
			</SidebarInset>
		</SidebarProvider>
	);
}
