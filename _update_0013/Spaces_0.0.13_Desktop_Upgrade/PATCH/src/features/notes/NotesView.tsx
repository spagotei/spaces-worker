import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Avatar } from '../../components/Avatar'
import { ContextMenu, useContextMenu, type ContextAction } from '../../components/ContextMenu'
import { Icon } from '../../components/Icon'
import { renderRichText } from '../../components/RichText'
import { usePreferences } from '../../state/PreferencesContext'
import { useSpaces } from '../../state/SpacesContext'
import type { WorkspaceNote } from '../../types/spaces'
import { timeAgo } from '../../utils/format'
import { filterContent } from '../../utils/content-filter'
import { hasWorkspacePermission } from '../../utils/permissions'

const MAX_TXT_BYTES = 256 * 1024

export function NotesView() {
  const { data, activeChannel, activeChannelId, profile, saveNote, deleteNote, addComment, deleteComment, pushToast } = useSpaces()
  const { preferences } = usePreferences()
  const contextMenu = useContextMenu()
  const importInput = useRef<HTMLInputElement>(null)
  const replaceInput = useRef<HTMLInputElement>(null)
  const [replaceTargetId, setReplaceTargetId] = useState('')
  const notes = useMemo(() => (data?.notes ?? []).filter(note => note.channelId === activeChannelId).sort((a, b) => b.updatedAt - a.updatedAt), [activeChannelId, data?.notes])
  const [selectedId, setSelectedId] = useState('')
  const selected = notes.find(note => note.id === selectedId) ?? null
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [comment, setComment] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!selectedId && notes[0]) setSelectedId(notes[0].id)
    if (selectedId && !notes.some(note => note.id === selectedId)) setSelectedId(notes[0]?.id ?? '')
  }, [notes, selectedId])

  useEffect(() => {
    setTitle(selected?.title ?? '')
    setBody(selected?.body ?? '')
  }, [selected?.body, selected?.id, selected?.title])

  const comments = useMemo(() => (data?.comments ?? []).filter(item => item.noteId === selectedId && !item.deletedAt).sort((a, b) => a.createdAt - b.createdAt), [data?.comments, selectedId])
  const canCreate = activeChannel?.effectivePermissions?.create_notes ?? hasWorkspacePermission(data, profile?.id, 'edit_notes')
  const canEdit = activeChannel?.effectivePermissions?.edit_notes ?? hasWorkspacePermission(data, profile?.id, 'edit_notes')
  const canDelete = activeChannel?.effectivePermissions?.delete_notes ?? hasWorkspacePermission(data, profile?.id, 'delete_notes')
  const canModerate = hasWorkspacePermission(data, profile?.id, 'moderate_comments')
  const dirty = Boolean(selected ? title !== selected.title || body !== selected.body : title || body)

  async function save(reason?: string) {
    if (!(selected ? canEdit : canCreate) || !activeChannelId || !title.trim()) return
    setSaving(true)
    try {
      const saved = await saveNote({ id: selected?.id ?? '', channelId: activeChannelId, title: title.trim(), body }, reason ?? (selected ? 'Updated from Spaces' : 'Created from Spaces'))
      if (saved) setSelectedId(saved.id)
    } finally { setSaving(false) }
  }

  function newNote() {
    if (!canCreate) return
    setSelectedId('')
    setTitle('')
    setBody('')
  }

  async function removeNote(note: WorkspaceNote) {
    if (!canDelete || !window.confirm(`Delete “${note.title}”?`)) return
    await deleteNote(note.id)
    setSelectedId('')
  }

  async function readTxt(file: File) {
    if (!file.name.toLowerCase().endsWith('.txt') && file.type !== 'text/plain') throw new Error('Choose a plain .txt file.')
    if (file.size > MAX_TXT_BYTES) throw new Error('Text imports are limited to 256 KB.')
    return file.text()
  }

  async function importTxt(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file || !canCreate || !activeChannelId) return
    try {
      const text = await readTxt(file)
      const nextTitle = file.name.replace(/\.txt$/i, '').trim().slice(0, 80) || 'Imported note'
      const saved = await saveNote({ id: '', channelId: activeChannelId, title: nextTitle, body: text }, `Imported from ${file.name}`)
      if (saved) setSelectedId(saved.id)
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not import that text file.', 'danger')
    }
  }

  async function replaceFromTxt(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    const target = notes.find(note => note.id === replaceTargetId)
    setReplaceTargetId('')
    if (!file || !target || !canEdit) return
    try {
      const text = await readTxt(file)
      const saved = await saveNote({ id: target.id, channelId: target.channelId, title: target.title, body: text }, `Updated from ${file.name}`)
      if (saved) setSelectedId(saved.id)
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not update that note.', 'danger')
    }
  }

  function beginReplace(note: WorkspaceNote) {
    if (!canEdit) return
    setReplaceTargetId(note.id)
    window.setTimeout(() => replaceInput.current?.click(), 0)
  }

  function exportTxt(note: WorkspaceNote) {
    const safeName = note.title.replace(/[\/:*?"<>|]/g, '-').trim() || 'Spaces note'
    const blob = new Blob([note.body], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${safeName}.txt`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    pushToast('Note exported as .txt.', 'success')
  }

  function noteActions(note: WorkspaceNote): ContextAction[] {
    return [
      { id: 'open', label: 'Open note', note: `Edited ${timeAgo(note.updatedAt)}`, icon: 'notes', onSelect: () => setSelectedId(note.id) },
      { id: 'copy', label: 'Copy note text', note: note.title, icon: 'copy', onSelect: async () => { await navigator.clipboard.writeText(`${note.title}\n\n${note.body}`); pushToast('Note copied.', 'success') } },
      { id: 'export', label: 'Export .txt', note: 'Download this note as plain text', icon: 'download', onSelect: () => exportTxt(note) },
      ...(canEdit ? [{ id: 'replace-txt', label: 'Update from .txt', note: 'Replace this note body from a text file', icon: 'upload' as const, onSelect: () => beginReplace(note) }] : []),
      ...(canCreate ? [{ id: 'duplicate', label: 'Duplicate note', note: 'Create a copy in this channel', icon: 'copy' as const, onSelect: async () => { const duplicate = await saveNote({ id: '', channelId: note.channelId, title: `${note.title} copy`, body: note.body }, 'Duplicated note'); if (duplicate) setSelectedId(duplicate.id) } }] : []),
      ...(canDelete ? [{ id: 'delete', label: 'Delete note', note: 'Remove this shared note', icon: 'trash' as const, danger: true, onSelect: () => removeNote(note) }] : []),
    ]
  }

  if (!activeChannel) return <div className="center-empty"><Icon name="notes" /><h2>Select a note channel</h2></div>

  return (
    <div className="notes-view page-enter notes-view-v9">
      <aside className="note-list-panel">
        <header>
          <div><span className="eyebrow">SHARED NOTES</span><h2>#{activeChannel.name}</h2></div>
          <div className="note-header-actions">
            {canCreate && <button className="icon-button" title="Import .txt" onClick={() => importInput.current?.click()}><Icon name="upload" size={15}/></button>}
            <button className="icon-button emphasized" disabled={!canCreate} title={canCreate ? 'New note' : 'Your roles cannot create notes'} onClick={newNote}><Icon name="plus" /></button>
          </div>
          <input ref={importInput} hidden type="file" accept=".txt,text/plain" onChange={event => void importTxt(event)} />
          <input ref={replaceInput} hidden type="file" accept=".txt,text/plain" onChange={event => void replaceFromTxt(event)} />
        </header>
        {canCreate && <div className="note-import-hint"><Icon name="paperclip" size={13}/><span>New note or import a .txt file</span></div>}
        <div className="note-list">
          {notes.map(note => <button {...contextMenu.bind(note.title, noteActions(note), 'Right-click or hold for note actions')} className={`note-list-item ${selected?.id === note.id ? 'active' : ''}`} key={note.id} onClick={() => setSelectedId(note.id)}><strong>{note.title}</strong><p>{filterContent(note.body, preferences.contentFilter).slice(0, 90) || 'Empty note'}</p><span>Edited {timeAgo(note.updatedAt)}</span></button>)}
          {!notes.length && <div className="mini-empty"><Icon name="notes" /><span>No notes in this channel.</span></div>}
        </div>
      </aside>

      <section className="note-editor-panel">
        <div className="note-editor-toolbar">
          <span>{selected ? `v${selected.version}` : 'NEW NOTE'}</span>
          <div className="note-editor-actions">{selected && <button className="secondary-button compact" onClick={() => exportTxt(selected)}><Icon name="download" size={14}/> Export</button>}{selected && canEdit && <button className="secondary-button compact" onClick={() => beginReplace(selected)}><Icon name="upload" size={14}/> Import update</button>}{selected && canDelete && <button className="ghost-danger" onClick={() => void removeNote(selected)}><Icon name="trash" size={15} /> Delete</button>}<button className="primary-button compact" disabled={!(selected ? canEdit : canCreate) || saving || !title.trim() || !dirty} onClick={() => void save()}>{saving ? 'Saving…' : dirty ? 'Save note' : 'Saved'}</button></div>
        </div>
        <input className="note-title-input" disabled={!canEdit} value={title} onChange={e => setTitle(e.target.value)} placeholder="Untitled note" />
        <textarea className="note-body-input" disabled={!canEdit} value={canEdit ? body : filterContent(body, preferences.contentFilter)} onChange={e => setBody(e.target.value)} placeholder="Start writing…" />
      </section>

      <aside className="comments-panel">
        <header><div><span className="eyebrow">DISCUSSION</span><h3>Comments</h3></div><span className="section-count">{comments.length}</span></header>
        {selected ? <>
          <div className="comment-list">
            {comments.map(item => {
              const own = item.authorId === profile?.id
              const postOwner = selected.createdBy === profile?.id
              return <article className="comment" key={item.id}><Avatar name={item.authorName} initials={item.authorInitials} src={item.authorAvatarUrl} size={30} /><div><div className="comment-meta"><strong>{item.authorName}</strong><span>{timeAgo(item.createdAt)}</span></div><p>{renderRichText(item.body, data?.emojis ?? [], preferences.contentFilter)}</p></div>{(own || postOwner || canModerate) && <button title="Remove comment" onClick={() => void deleteComment(item.id)}><Icon name="x" size={13} /></button>}</article>
            })}
            {!comments.length && <div className="mini-empty"><Icon name="chat" /><span>No comments yet.</span></div>}
          </div>
          <form className="comment-composer" onSubmit={async e => { e.preventDefault(); if (!comment.trim()) return; try { await addComment(selected.id, comment.trim()); setComment('') } catch (error) { pushToast(error instanceof Error ? error.message : 'Comment failed.', 'danger') } }}><input value={comment} onChange={e => setComment(e.target.value)} placeholder="Add a comment…" /><button disabled={!comment.trim()}><Icon name="send" size={15} /></button></form>
        </> : <div className="mini-empty tall"><Icon name="reply" /><span>Select a note to open its discussion.</span></div>}
      </aside>
      <ContextMenu menu={contextMenu.menu} onClose={contextMenu.close}/>
    </div>
  )
}
