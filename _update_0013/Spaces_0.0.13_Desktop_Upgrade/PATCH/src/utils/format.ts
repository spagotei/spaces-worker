export function timeAgo(timestamp: number): string {
  const delta = Date.now() - timestamp
  const future = delta < 0
  const seconds = Math.floor(Math.abs(delta) / 1000)

  if (seconds < 45) return future ? 'in a moment' : 'just now'

  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return future ? `in ${minutes}m` : `${minutes}m ago`

  const hours = Math.floor(minutes / 60)
  if (hours < 24) return future ? `in ${hours}h` : `${hours}h ago`

  const days = Math.floor(hours / 24)
  if (days < 7) return future ? `in ${days}d` : `${days}d ago`

  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(new Date(timestamp))
}

export function formatTime(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(new Date(timestamp))
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  return `${Math.round(bytes / 1024)} KB`
}

export function normalizeChannelName(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9-_ ]+/g, '').replace(/\s+/g, '-').slice(0, 32)
}
