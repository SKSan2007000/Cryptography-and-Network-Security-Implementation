import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  BellRing,
  FileClock,
  FlaskConical,
  Gauge,
  Globe,
  Inbox,
  LayoutDashboard,
  LogOut,
  Menu,
  Search,
  Send,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud,
  UserCog,
  Users,
} from "lucide-react";
import { useState, type ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { useAuth } from "@/hooks/useAuth";
import { useNotifications } from "@/lib/queries";
import { getTrustStatus } from "@/lib/security-rules";
import { cn } from "@/lib/utils";

type NavItem = { to: string; label: string; icon: typeof Shield };

const MAIN: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/send", label: "Secure Transfer", icon: UploadCloud },
  { to: "/inbox", label: "Inbox", icon: Inbox },
  { to: "/sent", label: "Sent Files", icon: Send },
  { to: "/digital-twin", label: "Security Digital Twin", icon: Globe },
  { to: "/security", label: "Security Center", icon: ShieldCheck },
  { to: "/audit", label: "Audit Logs", icon: FileClock },
  { to: "/security-lab", label: "Security Lab", icon: FlaskConical },
  { to: "/demo", label: "Threat Simulator", icon: Shield },
  { to: "/profile", label: "Profile", icon: UserCog },
  { to: "/settings", label: "Settings", icon: Settings },
];

const ADMIN: NavItem[] = [
  { to: "/admin", label: "Admin Dashboard", icon: Gauge },
  { to: "/admin/users", label: "Users", icon: Users },
  { to: "/admin/transfers", label: "Transfers", icon: Send },
  { to: "/admin/threats", label: "Threat Incidents", icon: Shield },
  { to: "/admin/audit", label: "System Audit", icon: FileClock },
  { to: "/admin/performance", label: "Performance", icon: Activity },
];

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-4 py-4">
      <span className="rounded-md bg-primary/15 p-2 text-primary">
        <ShieldCheck className="size-5" />
      </span>
      <div className="leading-tight">
        <p className="text-sm font-semibold tracking-tight">SentinelCrypt</p>
        <p className="text-[11px] text-muted-foreground">Trust-aware transfer</p>
      </div>
    </div>
  );
}

function NavLinks({ items, onNavigate }: { items: NavItem[]; onNavigate?: () => void }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <nav className="space-y-0.5 px-2">
      {items.map((item) => {
        const active = pathname === item.to || pathname.startsWith(`${item.to}/`);
        return (
          <Link
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
              active
                ? "bg-primary/12 text-primary"
                : "text-sidebar-foreground/75 hover:bg-accent/50 hover:text-foreground",
            )}
          >
            <item.icon className="size-4" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function SidebarBody({ isAdmin, onNavigate }: { isAdmin: boolean; onNavigate?: () => void }) {
  return (
    <ScrollArea className="h-full">
      <Brand />
      <p className="px-5 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        Workspace
      </p>
      <NavLinks items={MAIN} {...(onNavigate ? { onNavigate } : {})} />
      {isAdmin ? (
        <>
          <p className="px-5 pb-1 pt-5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Administration
          </p>
          <NavLinks items={ADMIN} {...(onNavigate ? { onNavigate } : {})} />
        </>
      ) : null}
      <div className="p-4 pt-6">
        <p className="rounded-md border border-border bg-surface/50 p-3 text-[11px] leading-relaxed text-muted-foreground">
          AES-256-GCM · RSA-OAEP 2048 · SHA-256 · TLS. All cryptography runs in your browser via the
          Web Crypto API.
        </p>
      </div>
    </ScrollArea>
  );
}

function NotificationBell() {
  const { user } = useAuth();
  const { data } = useNotifications(user?.id);
  const items = data ?? [];
  const unread = items.filter((n) => !n.read).length;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
          <BellRing className="size-4" />
          {unread > 0 ? (
            <span className="absolute right-1 top-1 size-2 rounded-full bg-critical" />
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <p className="border-b border-border px-3 py-2 text-sm font-medium">Notifications</p>
        <ScrollArea className="max-h-80">
          {items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No notifications yet.</p>
          ) : (
            items.map((n) => (
              <div key={n.id} className="border-b border-border/60 p-3 last:border-0">
                <p className="text-sm font-medium">{n.title}</p>
                <p className="text-xs text-muted-foreground">{n.body}</p>
              </div>
            ))
          )}
        </ScrollArea>
      </PopoverContent>
    </Popover>
  );
}

export function AppShell({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { profile, isAdmin, signOut, sessionInfo } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const score = profile?.trust_score ?? 100;

  const handleSearch = (event: React.FormEvent) => {
    event.preventDefault();
    const value = query.trim();
    if (!value) return;
    if (/^[0-9a-f-]{36}$/i.test(value)) {
      void navigate({ to: "/transfer/$id", params: { id: value } });
    } else {
      void navigate({ to: "/audit" });
    }
  };

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden w-64 shrink-0 border-r border-sidebar-border bg-sidebar lg:block">
        <div className="sticky top-0 h-screen">
          <SidebarBody isAdmin={isAdmin} />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-2 border-b border-border bg-background/85 px-3 py-2.5 backdrop-blur sm:px-5">
          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                aria-label="Open navigation"
              >
                <Menu className="size-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-72 bg-sidebar p-0">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <SidebarBody isAdmin={isAdmin} onNavigate={() => setOpen(false)} />
            </SheetContent>
          </Sheet>

          <form onSubmit={handleSearch} className="relative hidden max-w-xs flex-1 sm:block">
            <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search transfer ID or audit events"
              className="pl-8"
              aria-label="Search"
            />
          </form>

          <div className="ml-auto flex items-center gap-1.5 sm:gap-3">
            <Badge
              variant="outline"
              className="hidden items-center gap-1.5 border-secure/40 text-secure sm:flex"
            >
              <ShieldCheck className="size-3.5" /> Secure TLS
            </Badge>
            <Badge
              variant="outline"
              className={cn(
                "mono hidden gap-1.5 font-medium md:flex",
                score >= 90
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                  : score >= 75
                    ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                    : score >= 60
                      ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                      : "border-destructive/40 bg-destructive/10 text-destructive",
              )}
            >
              Trust {score}/100 · {getTrustStatus(score)}
            </Badge>
            <NotificationBell />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="gap-2">
                  <span className="grid size-6 place-items-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary">
                    {(profile?.full_name ?? profile?.email ?? "?").slice(0, 1).toUpperCase()}
                  </span>
                  <span className="hidden max-w-32 truncate text-sm sm:inline">
                    {profile?.full_name ?? profile?.email ?? "Account"}
                  </span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-60">
                <DropdownMenuLabel className="space-y-0.5">
                  <p className="truncate text-sm">{profile?.email}</p>
                  <p className="mono text-[11px] font-normal text-muted-foreground">
                    {isAdmin ? "administrator" : "user"} · session{" "}
                    {sessionInfo?.sessionId ? "monitored" : "starting"}
                  </p>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => void navigate({ to: "/profile" })}>
                  <UserCog className="mr-2 size-4" /> Profile
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => void navigate({ to: "/settings" })}>
                  <SlidersHorizontal className="mr-2 size-4" /> Settings
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={async () => {
                    await signOut();
                    void navigate({ to: "/auth", replace: true });
                  }}
                >
                  <LogOut className="mr-2 size-4" /> Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-3 py-5 sm:px-6 sm:py-6">
          <div className="mx-auto w-full max-w-7xl space-y-6">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
                {description ? (
                  <p className="mt-1 text-sm text-muted-foreground">{description}</p>
                ) : null}
              </div>
              {actions}
            </div>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
