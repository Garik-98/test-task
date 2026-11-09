import { createFileRoute, Link } from "@tanstack/react-router"

import { Button } from "@/components/ui/button"

export const Route = createFileRoute("/_layout/forbidden")({
  component: Forbidden,
  head: () => ({
    meta: [
      {
        title: "Access Denied",
      },
    ],
  }),
})

function Forbidden() {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-24 text-center">
      <h1 className="text-2xl font-bold tracking-tight">Access Denied</h1>
      <p className="mt-2 max-w-md text-muted-foreground">
        You do not have permission to view this page.
      </p>
      <Button asChild className="mt-6">
        <Link to="/">Back to dashboard</Link>
      </Button>
    </div>
  )
}
