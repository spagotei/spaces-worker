import { useEffect, useMemo, useState } from 'react'
import { Icon } from '../../components/Icon'
import { WorkspaceApi } from '../../api/workspace-api'
import { useSpaces } from '../../state/SpacesContext'
import type { WorkspaceInvite } from '../../types/spaces'
import { timeAgo } from '../../utils/format'
import { hasWorkspacePermission } from '../../utils/permissions'

export function InvitesView() {
  const { activeWorkspaceId, activeWorkspace, apiUrl, session, data, profile, pushToast } = useSpaces()
  const [invites, setInvites] = useState<WorkspaceInvite[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)

  const api = useMemo(() => new WorkspaceApi({ baseUrl: apiUrl, getToken: () => session?.token ?? '' }), [apiUrl, session?.token])
  const canManage = hasWorkspacePermission(data, profile?.id, 'create_invites')

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!activeWorkspaceId) return
      setLoading(true)
      try {
        const items = await api.listInvites(activeWorkspaceId)
        if (!cancelled) setInvites(items)
      } catch (error) {
        if (!cancelled) pushToast(error instanceof Error ? error.message : 'Could not load invites.', 'danger')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void load()
    return () => { cancelled = true }
  }, [activeWorkspaceId, api, pushToast])

  async function createInvite() {
    if (!activeWorkspaceId || creating) return
    setCreating(true)
    try {
      const invite = await api.createInvite(activeWorkspaceId)
      setInvites(current => [invite, ...current])
      await navigator.clipboard?.writeText(invite.code).catch(() => undefined)
      pushToast('Invite created and copied.', 'success')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not create invite.', 'danger')
    } finally { setCreating(false) }
  }

  async function copy(code: string) {
    try {
      await navigator.clipboard.writeText(code)
      pushToast('Invite copied.', 'success')
    } catch {
      pushToast(`Invite code: ${code}`, 'info')
    }
  }

  async function revoke(invite: WorkspaceInvite) {
    if (!activeWorkspaceId) return
    try {
      await api.revokeInvite(activeWorkspaceId, invite.id)
      setInvites(current => current.filter(item => item.id !== invite.id))
      pushToast('Invite revoked.', 'success')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not revoke invite.', 'danger')
    }
  }

  return (
    <div className="view-scroll invites-view page-enter">
      <div className="content-heading invites-heading">
        <div><span className="eyebrow">ACCESS</span><h1>Invites</h1><p>Bring approved people into {activeWorkspace?.name ?? 'this Space'}.</p></div>
        {canManage && <button className="primary-button" disabled={creating} onClick={() => void createInvite()}><Icon name="plus" size={15} />{creating ? 'Creating…' : 'Create invite'}</button>}
      </div>

      <section className="invite-security-card">
        <span className="invite-security-icon"><Icon name="lock" /></span>
        <div><strong>Private beta still applies</strong><p>An invite grants Space membership only. The account must already have Spaces beta access.</p></div>
      </section>

      <section className="invite-list-card">
        <header><span>Active invites</span><small>{invites.length}</small></header>
        {loading ? <div className="mini-loading"><span className="spinner" /> Loading invites…</div> : (
          <div className="invite-list">
            {invites.map(invite => {
              const expired = Boolean(invite.expiresAt && invite.expiresAt < Date.now())
              return (
                <article className={`invite-row ${expired ? 'expired' : ''}`} key={invite.id}>
                  <div className="invite-code-block"><code>{invite.code}</code><button onClick={() => void copy(invite.code)} title="Copy invite"><Icon name="download" size={14} /></button></div>
                  <div className="invite-meta"><span>{expired ? 'Expired' : invite.expiresAt ? `Expires ${timeAgo(invite.expiresAt)}` : 'No expiry'}</span><span>{invite.uses}{invite.maxUses ? ` / ${invite.maxUses}` : ''} uses</span></div>
                  {canManage && <button className="ghost-danger compact" onClick={() => void revoke(invite)}><Icon name="trash" size={14} /> Revoke</button>}
                </article>
              )
            })}
            {!invites.length && <div className="center-empty inline-empty"><Icon name="plus" /><h2>No active invites</h2><p>Create one when you are ready to bring someone in.</p></div>}
          </div>
        )}
      </section>
    </div>
  )
}
