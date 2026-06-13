import {
	Separator,
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupContent,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarInset,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarProvider,
	SidebarTrigger,
	Tooltip,
	TooltipPopup,
	TooltipTrigger,
	useSidebar,
} from "@oidfed/ui";
import {
	BookOpen,
	ExternalLink,
	Globe,
	Network,
	PanelLeftClose,
	PanelLeftOpen,
	Telescope,
} from "lucide-react";
import { GitHubIcon } from "@oidfed/ui";
import { Link, Outlet, useLocation } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";
import { getLessonsByPhase, phaseOrder, phases } from "~/data/lessons";

function getSidebarDefault(): boolean {
	if (typeof document === "undefined") return true;
	const match = document.cookie.match(/(?:^|; )sidebar_state=([^;]*)/);
	return match?.[1] ? decodeURIComponent(match[1]) !== "false" : true;
}

function SidebarLayout() {
	const location = useLocation();
	const { state, toggleSidebar } = useSidebar();
	const isCollapsed = state === "collapsed";
	const currentSlug = location.pathname.split("/").pop();

	return (
		<>
			<Sidebar collapsible="icon">
				<SidebarHeader>
					<SidebarMenu>
						<SidebarMenuItem>
							<div className="flex items-center gap-1">
								<SidebarMenuButton size="lg" render={<Link to="/" />} className="flex-1">
									<div className="flex size-8 items-center justify-center rounded-lg bg-brand-500 text-white shrink-0">
										<BookOpen className="size-4" />
									</div>
									<div className="flex flex-col gap-0.5 leading-none">
										<span className="font-semibold">OidFed Learn</span>
									</div>
								</SidebarMenuButton>
								{!isCollapsed && (
									<Tooltip>
										<TooltipTrigger
											render={
												<button
													type="button"
													onClick={toggleSidebar}
													className="flex size-8 items-center justify-center rounded-md text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground shrink-0"
												/>
											}
										>
											<PanelLeftClose className="size-4" />
										</TooltipTrigger>
										<TooltipPopup>Collapse sidebar</TooltipPopup>
									</Tooltip>
								)}
							</div>
						</SidebarMenuItem>
						{isCollapsed && (
							<SidebarMenuItem>
								<Tooltip>
									<TooltipTrigger
										render={
											<button
												type="button"
												onClick={toggleSidebar}
												className="flex size-8 items-center justify-center rounded-md text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground w-full"
											/>
										}
									>
										<PanelLeftOpen className="size-4" />
									</TooltipTrigger>
									<TooltipPopup side="right">Expand sidebar</TooltipPopup>
								</Tooltip>
							</SidebarMenuItem>
						)}
					</SidebarMenu>
				</SidebarHeader>
				<SidebarContent>
					{phaseOrder.map((phaseId) => {
						const phase = phases[phaseId];
						const phaseLessons = getLessonsByPhase(phaseId);
						return (
							<SidebarGroup key={phaseId}>
								<SidebarGroupLabel className={phase.color}>{phase.label}</SidebarGroupLabel>
								<SidebarGroupContent>
									<SidebarMenu>
										{phaseLessons.map((lesson) => (
											<SidebarMenuItem key={lesson.slug}>
												<SidebarMenuButton
													isActive={currentSlug === lesson.slug}
													render={<Link to={`/lessons/${lesson.slug}`} />}
													size="sm"
												>
													<span
														className="mr-0.5 shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground"
														aria-hidden
													>
														{String(lesson.number).padStart(2, "0")}
													</span>
													<span className="truncate">{lesson.title}</span>
												</SidebarMenuButton>
											</SidebarMenuItem>
										))}
									</SidebarMenu>
								</SidebarGroupContent>
							</SidebarGroup>
						);
					})}
				</SidebarContent>
				<SidebarFooter>
					<SidebarMenu>
						<SidebarMenuItem>
							<SidebarMenuButton
								render={
									<a
										href="https://oidfed.com"
										target="_blank"
										rel="noopener noreferrer"
										aria-label="oidfed.com — project home"
									/>
								}
							>
								<Globe className="size-4" />
								<span>Home Page</span>
								<ExternalLink className="size-3 ml-auto opacity-50" />
							</SidebarMenuButton>
						</SidebarMenuItem>
						<SidebarMenuItem>
							<SidebarMenuButton
								render={
									<a
										href="https://fed.oidfed.com"
										target="_blank"
										rel="noopener noreferrer"
										aria-label="fed.oidfed.com"
									/>
								}
							>
								<Network className="size-4" />
								<span>fed.oidfed.com</span>
								<ExternalLink className="size-3 ml-auto opacity-50" />
							</SidebarMenuButton>
						</SidebarMenuItem>
						<SidebarMenuItem>
							<SidebarMenuButton
								render={
									<a
										href="https://explore.oidfed.com"
										target="_blank"
										rel="noopener noreferrer"
										aria-label="OidFed Explorer"
									/>
								}
							>
								<Telescope className="size-4" />
								<span>Explorer</span>
								<ExternalLink className="size-3 ml-auto opacity-50" />
							</SidebarMenuButton>
						</SidebarMenuItem>
						<SidebarMenuItem>
							<SidebarMenuButton
								render={
									<a
										href="https://github.com/Dahkenangnon/oidfed"
										target="_blank"
										rel="noopener noreferrer"
										aria-label="OidFed on GitHub"
									/>
								}
							>
								<GitHubIcon />
								<span>GitHub</span>
								<ExternalLink className="size-3 ml-auto opacity-50" />
							</SidebarMenuButton>
						</SidebarMenuItem>
					</SidebarMenu>
				</SidebarFooter>
			</Sidebar>
			<SidebarInset className="flex h-full flex-col overflow-hidden">
				<header className="flex h-12 shrink-0 items-center gap-2 px-4 md:px-6 lg:px-8">
					<SidebarTrigger className="md:hidden" />
					<Separator orientation="vertical" className="h-4 md:hidden" />
					<div className="flex-1" />
					<ThemeToggle />
				</header>
				<main className="flex-1 overflow-auto">
					<Outlet />
				</main>
			</SidebarInset>
		</>
	);
}

export default function LessonsLayout() {
	return (
		<SidebarProvider defaultOpen={getSidebarDefault()} className="h-svh overflow-hidden">
			<SidebarLayout />
		</SidebarProvider>
	);
}
