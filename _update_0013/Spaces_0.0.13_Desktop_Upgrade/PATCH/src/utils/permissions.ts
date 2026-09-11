import type {
  WorkspaceBootstrap,
  WorkspaceCustomPermission,
  WorkspacePlatformRole,
  WorkspaceRole,
} from '../types/spaces'

export type WorkspacePermission =
  | 'read'
  | 'edit_notes'
  | 'delete_notes'
  | 'send_chat'
  | 'create_channels'
  | 'manage_members'
  | 'manage_workspace'
  | 'view_logs'

const rolePermissions: Record<WorkspaceRole, ReadonlySet<WorkspacePermission>> = {
  owner: new Set(['read', 'edit_notes', 'delete_notes', 'send_chat', 'create_channels', 'manage_members', 'manage_workspace', 'view_logs']),
  admin: new Set(['read', 'edit_notes', 'delete_notes', 'send_chat', 'create_channels', 'manage_members', 'manage_workspace', 'view_logs']),
  contributor: new Set(['read', 'edit_notes', 'delete_notes', 'send_chat', 'view_logs']),
  viewer: new Set(['read', 'view_logs']),
}

const contributorCustomPermissions = new Set<WorkspaceCustomPermission>([
  'send_messages',
  'attach_files',
  'edit_notes',
  'delete_notes',
  'view_audit_log',
])

export function canWorkspace(role: WorkspaceRole, permission: WorkspacePermission): boolean {
  return rolePermissions[role].has(permission)
}

/** Mirrors the Worker access model: legacy role permissions + stackable custom roles. */
export function hasWorkspacePermission(
  data: WorkspaceBootstrap | null,
  userId: string | undefined,
  permission: WorkspaceCustomPermission,
): boolean {
  if (!data || !userId) return false
  // Ownership is absolute and immutable: the Space owner always has every permission.
  if (data.workspace.ownerId === userId) return true
  const member = data.members.find(item => item.profileId === userId)
  if (!member) return false

  if (member.role === 'owner' || member.role === 'admin') return true
  if (member.role === 'contributor' && contributorCustomPermissions.has(permission)) return true
  if (member.role === 'viewer' && permission === 'view_audit_log') return true

  return data.roles.some(role =>
    member.customRoleIds.includes(role.id) && role.permissions.includes(permission),
  )
}

export function workspaceRoleLabel(role: WorkspaceRole): string {
  switch (role) {
    case 'owner': return 'Owner'
    case 'admin': return 'Administrator'
    case 'contributor': return 'Contributor'
    case 'viewer': return 'Viewer'
  }
}


export function platformRoleLabel(role: WorkspacePlatformRole): string {
  switch (role) {
    case 'founder': return 'Founder'
    case 'staff': return 'Staff'
    default: return ''
  }
}
