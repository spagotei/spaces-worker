-- Spaces v63: Discord-like direct message pins.
CREATE TABLE IF NOT EXISTS direct_message_pins (
  thread_kind TEXT NOT NULL CHECK(thread_kind IN ('dm', 'group')),
  thread_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  pinned_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pinned_at INTEGER NOT NULL,
  PRIMARY KEY (thread_kind, thread_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_direct_message_pins_thread
ON direct_message_pins(thread_kind, thread_id, pinned_at DESC);
