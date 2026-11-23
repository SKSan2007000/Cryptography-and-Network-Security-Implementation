import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/$")({
  head: () => ({
    meta: [{ title: "Page Not Found — SentinelCrypt" }, { name: "robots", content: "noindex" }],
  }),
  component: NotFoundPage,
});

function NotFoundPage() {
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="text-center">
        <ShieldAlert className="mx-auto size-10 text-warning" />
        <h1 className="mt-4 text-2xl font-semibold tracking-tight">404 — Page not found</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          The page you requested does not exist or has moved.
        </p>
        <Button asChild className="mt-6">
          <Link to="/">Return home</Link>
        </Button>
      </div>
    </div>
  );
}
