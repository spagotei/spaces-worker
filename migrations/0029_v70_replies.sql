-- Spaces V70 structured replies and threaded note comments
ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT;
CREATE INDEX IF NOT EXISTS idx_messages_reply_to_v70 ON messages(reply_to_message_id);
ALTER TABLE note_comments ADD COLUMN parent_comment_id TEXT;
CREATE INDEX IF NOT EXISTS idx_note_comments_parent_v70 ON note_comments(parent_comment_id);
