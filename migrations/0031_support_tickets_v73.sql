-- Spaces V73: first-class Support ticketing

CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  ticket_number TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  topic TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'waiting',
  assigned_to TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resolved_at INTEGER,
  resolved_by TEXT,
  last_activity_at INTEGER NOT NULL,
  delete_after INTEGER,
  reopened_at INTEGER,
  transcript_deleted_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_user
  ON support_tickets(user_id, last_activity_at DESC);

CREATE INDEX IF NOT EXISTS idx_support_tickets_status
  ON support_tickets(status, last_activity_at DESC);

CREATE INDEX IF NOT EXISTS idx_support_tickets_assigned
  ON support_tickets(assigned_to, status, last_activity_at DESC);

CREATE TABLE IF NOT EXISTS support_ticket_collaborators (
  ticket_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  added_by TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  PRIMARY KEY (ticket_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_support_ticket_collaborators_user
  ON support_ticket_collaborators(user_id, added_at DESC);

CREATE TABLE IF NOT EXISTS support_ticket_events (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL,
  actor_user_id TEXT,
  event_type TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_support_ticket_events_ticket
  ON support_ticket_events(ticket_id, created_at ASC);

ALTER TABLE support_messages ADD COLUMN ticket_id TEXT;

CREATE INDEX IF NOT EXISTS idx_support_messages_ticket_v73
  ON support_messages(ticket_id, created_at ASC);
