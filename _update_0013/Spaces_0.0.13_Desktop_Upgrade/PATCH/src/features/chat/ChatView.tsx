import { useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent, type KeyboardEvent } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon } from '../../components/Icon'
import { ImagePreview } from '../../components/ImagePreview'
import { EmojiPicker } from '../../components/EmojiPicker'
import { renderRichText } from '../../components/RichText'
import { usePreferences } from '../../state/PreferencesContext'
import { useSpaces } from '../../state/SpacesContext'
import type { WorkspaceChatMessage, WorkspaceMessageAttachment } from '../../types/spaces'
import { formatBytes, formatTime } from '../../utils/format'
import { filterContent } from '../../utils/content-filter'
import { hasWorkspacePermission } from '../../utils/permissions'

const MAX_FILE_BYTES = 180 * 1024
const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'text/plain'])

function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error ?? new Error('Could not read file.'))
    reader.readAsDataURL(file)
  })
}

function runSlashCommand(input: string): string {
  const trimmed = input.trim()
  if (trimmed.startsWith('/shrug')) return `${trimmed.slice(6).trim()} ¯\\_(ツ)_/¯`.trim()
  if (trimmed.startsWith('/spoiler ')) return `||${trimmed.slice(9).trim()}||`
  if (trimmed.startsWith('/me ')) return `**${trimmed.slice(4).trim()}**`
  return trimmed
}

export function ChatView() {
  const { data, activeChannel, activeChannelId, profile, sendMessage, editMessage, deleteMessage, pushToast } = useSpaces()
  const { preferences } = usePreferences()
  const [body, setBody] = useState('')
  const [attachment, setAttachment] = useState<WorkspaceMessageAttachment | null>(null)
  const [sending, setSending] = useState(false)
  const [emojiOpen, setEmojiOpen] = useState(false)
  const [editingId, setEditingId] = useState('')
  const [editBody, setEditBody] = useState('')
  const [dragging, setDragging] = useState(false)
  const [replyTarget, setReplyTarget] = useState<WorkspaceChatMessage | null>(null)
  const [previewImage, setPreviewImage] = useState<{ src: string; name: string } | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const previousChannel = useRef('')

  const messages = useMemo(
    () => (data?.messages ?? []).filter(message => message.channelId === activeChannelId && !message.deletedAt).sort((a, b) => a.createdAt - b.createdAt),
    [activeChannelId, data?.messages],
  )
  const emojis = data?.emojis ?? []
  const canSend = activeChannel?.effectivePermissions?.send_messages ?? hasWorkspacePermission(data, profile?.id, 'send_messages')
  const canAttach = activeChannel?.effectivePermissions?.attach_files ?? hasWorkspacePermission(data, profile?.id, 'attach_files')
  const canModerate = hasWorkspacePermission(data, profile?.id, 'moderate_messages')
  const draftKey = activeChannelId ? `spaces.draft.${activeChannelId}` : ''
  const mentionMatch = /(?:^|\s)@([^@\n]{0,32})$/u.exec(body)
  const mentionQuery = mentionMatch?.[1].toLowerCase() ?? ''
  const canMentionEveryone = hasWorkspacePermission(data, profile?.id, 'mention_everyone')
  const mentionSuggestions = useMemo(() => {
    if (!mentionMatch || !data) return []
    const items = [
      ...(canMentionEveryone ? [
        { value: '@everyone', label: '@everyone', note: 'Notify everyone in this Space', icon: 'members' as const },
        { value: '@here', label: '@here', note: 'Notify people currently using Spaces', icon: 'bell' as const },
      ] : []),
      ...data.roles.filter(role => role.mentionable).map(role => ({ value: `@${role.name}`, label: `@${role.name}`, note: 'Mention role', icon: 'roles' as const })),
      ...data.members.map(member => ({ value: `@${member.username}`, label: `@${member.username}`, note: member.displayName, icon: 'user' as const })),
    ]
    return items.filter(item => item.label.slice(1).toLowerCase().includes(mentionQuery)).slice(0, 8)
  }, [canMentionEveryone, data, mentionMatch, mentionQuery])

  function insertMention(value: string) {
    if (!mentionMatch) return
    const start = mentionMatch.index + mentionMatch[0].lastIndexOf('@')
    setBody(current => `${current.slice(0, start)}${value} ${current.slice(start + mentionMatch[0].slice(mentionMatch[0].lastIndexOf('@')).length)}`)
  }

  const currentMember = data?.members.find(member => member.profileId === profile?.id)
  const personalPingTokens = useMemo(() => {
    const tokens = new Set<string>()
    if (profile?.username) tokens.add(`@${profile.username.toLowerCase()}`)
    for (const role of data?.roles ?? []) {
      if (role.mentionable && currentMember?.customRoleIds.includes(role.id)) tokens.add(`@${role.name.toLowerCase()}`)
    }
    return [...tokens]
  }, [currentMember?.customRoleIds, data?.roles, profile?.username])

  function authorCanMentionEveryone(authorId: string) {
    const member = data?.members.find(item => item.profileId === authorId)
    if (!member) return false
    if (member.role === 'owner' || member.role === 'admin') return true
    return (data?.roles ?? []).some(role => member.customRoleIds.includes(role.id) && role.permissions.includes('mention_everyone'))
  }

  function messagePingsMe(message: WorkspaceChatMessage) {
    if (message.authorId === profile?.id) return false
    const bodyLower = message.body.toLowerCase()
    if (personalPingTokens.some(token => bodyLower.includes(token))) return true
    return authorCanMentionEveryone(message.authorId) && (bodyLower.includes('@everyone') || bodyLower.includes('@here'))
  }
  useEffect(() => {
    setBody(draftKey ? localStorage.getItem(draftKey) ?? '' : '')
    setReplyTarget(null)
    setEmojiOpen(false)
  }, [draftKey])

  useEffect(() => {
    if (!draftKey) return
    if (body) localStorage.setItem(draftKey, body)
    else localStorage.removeItem(draftKey)
  }, [body, draftKey])

  useEffect(() => {
    const channelChanged = previousChannel.current !== activeChannelId
    previousChannel.current = activeChannelId
    const timer = window.setTimeout(() => endRef.current?.scrollIntoView({ behavior: channelChanged || preferences.reducedMotion ? 'auto' : 'smooth', block: 'end' }), channelChanged ? 0 : 30)
    return () => window.clearTimeout(timer)
  }, [activeChannelId, messages.length, preferences.reducedMotion])

  async function loadFile(file: File) {
    if (!canAttach) { pushToast('Your roles do not allow chat attachments.', 'danger'); return }
    if (file.size > MAX_FILE_BYTES) { pushToast('Chat files are limited to 180 KB.', 'danger'); return }
    if (!ALLOWED_TYPES.has(file.type) && !/\.txt$/i.test(file.name)) { pushToast('Chats only accept PNG, JPEG, WebP, or plain .txt files.', 'danger'); return }
    try {
      const dataUrl = await fileToDataUrl(file)
      setAttachment({ name: file.name, type: file.type || 'text/plain', size: file.size, dataUrl })
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not read that file.', 'danger')
    }
  }

  async function pickFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (file) await loadFile(file)
  }

  async function dropFile(event: DragEvent<HTMLFormElement>) {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files?.[0]
    if (file) await loadFile(file)
  }

  async function submit(event?: FormEvent) {
    event?.preventDefault()
    if (!canSend || (!body.trim() && !attachment) || sending) return
    setSending(true)
    try {
      const transformed = runSlashCommand(body)
      const replyPrefix = replyTarget
        ? `↳ @${replyTarget.authorName}: ${replyTarget.body.replace(/\s+/g, ' ').slice(0, 72)}${replyTarget.body.length > 72 ? '…' : ''}\n`
        : ''
      await sendMessage(`${replyPrefix}${transformed}`.trim(), attachment)
      setBody('')
      setAttachment(null)
      setEmojiOpen(false)
      setReplyTarget(null)
      if (draftKey) localStorage.removeItem(draftKey)
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Message failed to send.', 'danger')
    } finally { setSending(false) }
  }

  async function saveEdit(messageId: string) {
    if (!editBody.trim()) return
    try {
      await editMessage(messageId, editBody.trim())
      setEditingId('')
      setEditBody('')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not edit message.', 'danger')
    }
  }

  function editKeyDown(event: KeyboardEvent<HTMLTextAreaElement>, messageId: string) {
    if (event.key === 'Escape') { setEditingId(''); setEditBody(''); return }
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void saveEdit(messageId) }
  }

  async function copyMessage(message: WorkspaceChatMessage) {
    try {
      await navigator.clipboard.writeText(message.body)
      pushToast('Message copied.', 'success')
    } catch {
      pushToast('Could not copy message.', 'danger')
    }
  }

  if (!activeChannel) return <div className="center-empty"><Icon name="chat" size={26} /><h2>Select a channel</h2><p>Pick a conversation from the sidebar.</p></div>

  return (
    <div className={`chat-view page-enter density-${preferences.messageDensity}`}>
      <div className="message-list">
        <div className="channel-welcome">
          <div className="channel-welcome-icon"><Icon name={activeChannel.kind === 'announcement' ? 'bell' : 'hash'} size={24} /></div>
          <h1>{activeChannel.kind === 'announcement' ? '' : '#'}{activeChannel.name}</h1>
          <p>{activeChannel.description || `This is the beginning of #${activeChannel.name}.`}</p>
          <span className="channel-welcome-rule" />
        </div>

        {messages.map((message, index) => {
          const previous = messages[index - 1]
          const grouped = Boolean(previous && previous.authorId === message.authorId && message.createdAt - previous.createdAt < 5 * 60 * 1000)
          const own = message.authorId === profile?.id
          const isImage = Boolean(message.attachment?.dataUrl && message.attachment.type.startsWith('image/'))
          return (
            <article className={`message ${grouped ? 'message-grouped' : ''} ${messagePingsMe(message) ? 'message-pinged' : ''}`} key={message.id}>
              {!grouped && <Avatar name={message.authorName} initials={message.authorInitials} size={38} />}
              <div className="message-main">
                {!grouped && <div className="message-meta"><strong>{message.authorName}</strong>{own && <span className="you-chip">YOU</span>}<time>{formatTime(message.createdAt)}</time></div>}
                {editingId === message.id ? (
                  <div className="message-edit"><textarea value={editBody} onChange={event => setEditBody(event.target.value)} onKeyDown={event => editKeyDown(event, message.id)} autoFocus /><div><span>Enter to save · Shift+Enter for a line · Esc to cancel</span><button onClick={() => void saveEdit(message.id)}>Save</button></div></div>
                ) : (
                  <div className="message-body">{renderRichText(message.body, emojis, preferences.contentFilter)}{message.editedAt && <small>(edited)</small>}</div>
                )}
                {message.attachment && (
                  <div className={`attachment-card ${isImage ? 'attachment-image-card' : ''}`}>
                    {isImage && message.attachment.dataUrl ? <button type="button" className="attachment-preview" onClick={() => setPreviewImage({ src: message.attachment!.dataUrl!, name: message.attachment!.name })} title="Preview image"><img src={message.attachment.dataUrl} alt={message.attachment.name} /></button> : <Icon name="paperclip" />}
                    <div><strong>{message.attachment.name}</strong><span>{formatBytes(message.attachment.size)} · {message.attachment.type || 'file'}</span></div>
                    {message.attachment.dataUrl && <a className="attachment-download" href={message.attachment.dataUrl} download={message.attachment.name} title="Download"><Icon name="download" size={16} /></a>}
                  </div>
                )}
              </div>
              {editingId !== message.id && (
                <div className="message-actions">
                  <button title="Reply" onClick={() => setReplyTarget(message)}><Icon name="reply" size={15} /></button>
                  <button title="Copy text" onClick={() => void copyMessage(message)}><Icon name="copy" size={15} /></button>
                  {own && <button title="Edit" onClick={() => { setEditingId(message.id); setEditBody(message.body) }}><Icon name="edit" size={15} /></button>}
                  {(own || canModerate) && <button title={own ? 'Delete' : 'Remove as moderator'} onClick={() => void deleteMessage(message.id)}><Icon name="trash" size={15} /></button>}
                </div>
              )}
            </article>
          )
        })}
        <div ref={endRef} className="message-end-anchor" />
      </div>

      <form className={`composer ${dragging ? 'composer-dragging' : ''} ${!canSend ? 'composer-locked' : ''}`} onSubmit={submit} onDragEnter={event => { event.preventDefault(); setDragging(true) }} onDragOver={event => { event.preventDefault(); setDragging(true) }} onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false) }} onDrop={event => void dropFile(event)}>
        {dragging && <div className="composer-drop-hint"><Icon name="paperclip" /><span>Drop to attach to chat</span></div>}
        {replyTarget && <div className="composer-reply"><Icon name="reply" size={14} /><div><span>Replying to <strong>{replyTarget.authorName}</strong></span><p>{filterContent(replyTarget.body, preferences.contentFilter).slice(0, 110)}</p></div><button type="button" onClick={() => setReplyTarget(null)}><Icon name="x" size={14} /></button></div>}
        {attachment && <div className={`composer-attachment ${attachment.type.startsWith('image/') ? 'has-image' : ''}`}>{attachment.type.startsWith('image/') && attachment.dataUrl ? <button type="button" className="composer-attachment-thumb" onClick={() => setPreviewImage({ src: attachment.dataUrl!, name: attachment.name })}><img src={attachment.dataUrl} alt="" /></button> : <Icon name="paperclip" />}<div><strong>{attachment.name}</strong><span>{formatBytes(attachment.size)} · images/plain text only</span></div><button type="button" onClick={() => setAttachment(null)}><Icon name="x" size={14} /></button></div>}
        {emojiOpen && <EmojiPicker emojis={emojis} onClose={() => setEmojiOpen(false)} onPick={value => { setBody(current => `${current}${current && !current.endsWith(' ') && value.startsWith(':') ? ' ' : ''}${value}`); setEmojiOpen(false) }} />}
        {mentionSuggestions.length > 0 && <div className="mention-suggestions" role="listbox" aria-label="Mention suggestions">{mentionSuggestions.map(item => <button type="button" key={item.value} onClick={() => insertMention(item.value)}><span className="mention-suggestion-icon"><Icon name={item.icon} size={14}/></span><span><strong>{item.label}</strong><small>{item.note}</small></span></button>)}</div>}
        <div className="composer-row">
          <button type="button" className="composer-icon" disabled={!canAttach} title={canAttach ? 'Attach file' : 'Attachments are not allowed for your roles'} onClick={() => fileInput.current?.click()}><Icon name="plus" /></button>
          <input ref={fileInput} type="file" hidden onChange={event => void pickFile(event)} accept=".png,.jpg,.jpeg,.webp,.txt,image/png,image/jpeg,image/webp,text/plain" />
          <textarea disabled={!canSend} value={body} onChange={event => setBody(event.target.value)} onKeyDown={event => { if (preferences.enterToSend && event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void submit() } }} placeholder={canSend ? `Message #${activeChannel.name}` : 'You can read this channel, but cannot send messages.'} rows={1} />
          <button type="button" className={`composer-icon ${emojiOpen ? 'active' : ''}`} title="Emoji" onClick={() => setEmojiOpen(value => !value)}><Icon name="emoji" /></button>
          <button className="send-button" disabled={!canSend || sending || (!body.trim() && !attachment)} title="Send"><Icon name="send" size={17} /></button>
        </div>
      </form>
      {previewImage && <ImagePreview src={previewImage.src} name={previewImage.name} onClose={() => setPreviewImage(null)} />}
    </div>
  )
}
