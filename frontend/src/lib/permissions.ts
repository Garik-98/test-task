import type { UserRole } from "@/client"

export type Action =
  | "listUsers"
  | "createUser"
  | "viewMetrics"
  | "updateOwnProfile"
  | "updateAnyProfile"

const allowedRoles: Record<Action, readonly UserRole[]> = {
  listUsers: ["admin", "manager"],
  createUser: ["admin"],
  viewMetrics: ["admin", "manager"],
  updateOwnProfile: ["admin", "manager", "member"],
  updateAnyProfile: ["admin"],
}

export function can(
  role: UserRole | null | undefined,
  action: Action,
): boolean {
  if (!role) {
    return false
  }
  return allowedRoles[action].includes(role)
}

export function roleLabel(role: UserRole | null | undefined): string {
  if (role === "admin") return "Admin"
  if (role === "manager") return "Manager"
  if (role === "member") return "Member"
  return "User"
}
