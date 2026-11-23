import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/login")({
  head: () => ({
    meta: [{ title: "Sign in — SentinelCrypt" }],
  }),
  beforeLoad: () => {
    throw redirect({ to: "/auth" });
  },
  component: () => null,
});
