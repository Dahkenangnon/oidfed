import {
	GitHubIcon,
	Menu,
	MenuItem,
	MenuPopup,
	MenuTrigger,
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
	ChevronUp,
	ExternalLink,
	Globe,
	MoreHorizontal,
	Network,
	PanelLeftClose,
	PanelLeftOpen,
	Telescope,
} from "lucide-react";
import { Link, Outlet, useLocation } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";
import { getLessonsByPhase, phaseOrder, phases } from "~/data/lessons";

const externalLinks = [
	{ label: "Home Page", href: "https://oidfed.com", icon: Globe },
	{ label: "fed.oidfed.com", href: "https://fed.oidfed.com", icon: Network },
	{ label: "Explorer", href: "https://explore.oidfed.com", icon: Telescope },
	{ label: "GitHub", href: "https://github.com/Dahkenangnon/oidfed", icon: GitHubIcon },
] as const;

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
							<Menu>
								<MenuTrigger
									render={
										<SidebarMenuButton aria-label="More OidFed links" className="cursor-pointer" />
									}
								>
									<MoreHorizontal aria-hidden="true" className="size-4" />
									<span>More</span>
									<ChevronUp
										aria-hidden="true"
										className="ml-auto size-3 opacity-50 group-data-[collapsible=icon]:hidden"
									/>
								</MenuTrigger>
								<MenuPopup
									align="start"
									className="w-56"
									side={isCollapsed ? "right" : "top"}
									sideOffset={8}
								>
									{externalLinks.map((item) => (
										<MenuItem
											closeOnClick
											key={item.href}
											render={
												<a
													href={item.href}
													target="_blank"
													rel="noopener noreferrer"
												/>
											}
										>
											<item.icon aria-hidden="true" />
											<span>{item.label}</span>
											<ExternalLink
												aria-hidden="true"
												className="ml-auto size-3 opacity-50"
											/>
										</MenuItem>
									))}
								</MenuPopup>
							</Menu>
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
