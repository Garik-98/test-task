import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute, redirect } from "@tanstack/react-router"
import { Suspense } from "react"

import { MetricsService, UsersService } from "@/client"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { can } from "@/lib/permissions"

function getMetricsQueryOptions() {
  return {
    queryFn: async () => (await MetricsService.readMetrics()).data,
    queryKey: ["metrics"],
  }
}

export const Route = createFileRoute("/_layout/metrics")({
  component: Metrics,
  beforeLoad: async () => {
    const { data: user } = await UsersService.readUserMe()
    if (!can(user.role, "viewMetrics")) {
      throw redirect({
        to: "/forbidden",
      })
    }
  },
  head: () => ({
    meta: [
      {
        title: "Metrics - FastAPI Template",
      },
    ],
  }),
})

function MetricsContent() {
  const { data: metrics } = useSuspenseQuery(getMetricsQueryOptions())

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-3xl font-bold">{metrics.user_count}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Items</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-3xl font-bold">{metrics.item_count}</p>
        </CardContent>
      </Card>
    </div>
  )
}

function Metrics() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Metrics</h1>
        <p className="text-muted-foreground">
          A simple snapshot of users and items.
        </p>
      </div>
      <Suspense
        fallback={<p className="text-muted-foreground">Loading metrics...</p>}
      >
        <MetricsContent />
      </Suspense>
    </div>
  )
}
