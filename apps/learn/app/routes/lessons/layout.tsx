import {
	Progress,
	Separator,
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarInset,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarProvider,
	SidebarRail,
	SidebarTrigger,
	Tooltip,
	TooltipPopup,
	TooltipTrigger,
	useSidebar,
} from "@oidfed/ui";
import { BookOpen, ExternalLink, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { Link, Outlet, useLocation } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";
import { getLessonsByPhase, lessons, phaseOrder, phases } from "~/data/lessons";

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
	const currentLesson = lessons.find((l) => l.slug === currentSlug);
	const progress = currentLesson ? Math.round((currentLesson.number / lessons.length) * 100) : 0;

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
										<span className="font-semibold">Learn</span>
										<span className="text-xs text-muted-foreground">OpenID Federation</span>
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
					{!isCollapsed && (
						<div className="px-2 mt-1">
							<div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
								<span>Progress</span>
								<span>{progress}%</span>
							</div>
							<Progress value={progress} />
						</div>
					)}
				</SidebarHeader>
				<SidebarContent>
					{phaseOrder.map((phaseId) => {
						const phase = phases[phaseId];
						const phaseLessons = getLessonsByPhase(phaseId);
						return (
							<SidebarGroup key={phaseId}>
								<SidebarGroupLabel className={phase.color}>{phase.label}</SidebarGroupLabel>
								<SidebarMenu>
									{phaseLessons.map((lesson) => (
										<SidebarMenuItem key={lesson.slug}>
											<SidebarMenuButton
												isActive={currentSlug === lesson.slug}
												render={<Link to={`/lessons/${lesson.slug}`} />}
												size="sm"
											>
												<span className="mr-1.5">{lesson.emoji}</span>
												<span className="truncate">{lesson.title}</span>
											</SidebarMenuButton>
										</SidebarMenuItem>
									))}
								</SidebarMenu>
							</SidebarGroup>
						);
					})}
				</SidebarContent>
				<SidebarFooter className="p-2 space-y-1">
					<div className="flex items-center gap-1 text-xs">
						<a
							href="https://oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
						>
							oidfed.com
							<ExternalLink className="size-3" />
						</a>
						<span className="text-muted-foreground">·</span>
						<a
							href="https://explore.oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
						>
							Explorer
							<ExternalLink className="size-3" />
						</a>
					</div>
					<ThemeToggle />
				</SidebarFooter>
				<SidebarRail />
			</Sidebar>
			<SidebarInset className="flex h-full flex-col overflow-hidden">
				<header className="shrink-0 flex items-center gap-2 border-b border-border px-4 h-12">
					<SidebarTrigger />
					<Separator orientation="vertical" className="h-4" />
					<span className="text-sm text-muted-foreground">
						{currentLesson ? `Lesson ${currentLesson.number} of ${lessons.length}` : "Lessons"}
					</span>
				</header>
				<main className="flex-1 overflow-y-auto">
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
