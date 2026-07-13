import {
	GitHubIcon,
	Menu,
	MenuItem,
	MenuPopup,
	MenuTrigger,
	OidfedLogo,
	Separator,
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupContent,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	Tooltip,
	TooltipPopup,
	TooltipTrigger,
	useSidebar,
} from "@oidfed/ui";
import {
	BadgeCheck,
	BookOpen,
	ChevronUp,
	Clock,
	ExternalLink,
	FileSearch,
	FlaskConical,
	GitCompare,
	Globe,
	HeartPulse,
	Link,
	List,
	MoreHorizontal,
	PanelLeftClose,
	PanelLeftOpen,
	Route,
	Settings,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router";

interface NavItem {
	readonly label: string;
	readonly path: string;
	readonly icon: React.ComponentType<{ className?: string }>;
	readonly disabled: boolean;
}

const navItems: readonly NavItem[] = [
	{ label: "Entity Inspector", path: "/entity", icon: FileSearch, disabled: false },
	{ label: "Trust Chain", path: "/chain", icon: Link, disabled: false },
	{ label: "Topology Graph", path: "/topology", icon: Globe, disabled: false },
	{ label: "Subordinates", path: "/subordinates", icon: List, disabled: false },
	{ label: "Expiration", path: "/expiry", icon: Clock, disabled: false },
	{ label: "Trust Marks", path: "/trust-marks", icon: BadgeCheck, disabled: false },
	{ label: "Policy Simulator", path: "/policy", icon: FlaskConical, disabled: false },
	{ label: "Health Check", path: "/health", icon: HeartPulse, disabled: false },
	{ label: "Resolve Proxy", path: "/resolve", icon: Route, disabled: false },
	{ label: "Metadata Diff", path: "/diff", icon: GitCompare, disabled: false },
];

const externalLinks = [
	{ label: "Home Page", href: "https://oidfed.com", icon: Globe },
	{ label: "fed.oidfed.com", href: "https://fed.oidfed.com", icon: Globe },
	{ label: "Learn OpenID Federation", href: "https://learn.oidfed.com", icon: BookOpen },
	{ label: "GitHub Repos", href: "https://github.com/Dahkenangnon/oidfed", icon: GitHubIcon },
] as const;

export function AppSidebar() {
	const location = useLocation();
	const navigate = useNavigate();
	const { state, toggleSidebar } = useSidebar();
	const isCollapsed = state === "collapsed";

	return (
		<Sidebar collapsible="icon">
			<SidebarHeader>
				<SidebarMenu>
					<SidebarMenuItem>
						<div className="flex items-center gap-1">
							<SidebarMenuButton
								size="lg"
								onClick={() => navigate("/")}
								className="cursor-pointer flex-1"
							>
								<OidfedLogo label="OidFed Explorer" markClassName="size-8" />
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
				<SidebarGroup>
					<SidebarGroupLabel>Tools</SidebarGroupLabel>
					<SidebarGroupContent>
						<SidebarMenu>
							{navItems.map((item) => {
								const isActive = location.pathname.startsWith(item.path);
								const button = (
									<SidebarMenuButton
										data-active={isActive}
										onClick={() => {
											if (!item.disabled) navigate(item.path);
										}}
										className={item.disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
									>
										<item.icon className="size-4" />
										<span>{item.label}</span>
									</SidebarMenuButton>
								);

								return (
									<SidebarMenuItem key={item.path}>
										{item.disabled && isCollapsed ? (
											<Tooltip>
												<TooltipTrigger render={button} />
												<TooltipPopup side="right">{item.label}</TooltipPopup>
											</Tooltip>
										) : (
											button
										)}
									</SidebarMenuItem>
								);
							})}
						</SidebarMenu>
					</SidebarGroupContent>
				</SidebarGroup>
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
								className="w-60"
								side={isCollapsed ? "right" : "top"}
								sideOffset={8}
							>
								{externalLinks.map((item) => (
									<MenuItem
										closeOnClick
										key={item.href}
										render={<a href={item.href} target="_blank" rel="noopener noreferrer" />}
									>
										<item.icon aria-hidden="true" />
										<span>{item.label}</span>
										<ExternalLink aria-hidden="true" className="ml-auto size-3 opacity-50" />
									</MenuItem>
								))}
							</MenuPopup>
						</Menu>
					</SidebarMenuItem>
					<Separator className="my-1" />
					<SidebarMenuItem>
						<SidebarMenuButton
							data-active={location.pathname === "/settings"}
							onClick={() => navigate("/settings")}
							className="cursor-pointer border border-brand-500/25 bg-brand-500/10 text-brand-700 shadow-xs hover:bg-brand-500/15 hover:text-brand-800 dark:border-brand-400/25 dark:bg-brand-400/10 dark:text-brand-300 dark:hover:bg-brand-400/15 dark:hover:text-brand-200"
						>
							<Settings className="size-4 text-brand-600 dark:text-brand-300" />
							<span className="font-medium">Settings</span>
							<span className="ml-auto rounded-sm bg-brand-500 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-white group-data-[collapsible=icon]:hidden dark:bg-brand-400 dark:text-neutral-950">
								Setup
							</span>
						</SidebarMenuButton>
					</SidebarMenuItem>
				</SidebarMenu>
			</SidebarFooter>
		</Sidebar>
	);
}
