-- Shared, permission-checked folders inside each existing Notes channel.
CREATE TABLE IF NOT EXISTS notes_folders_v89 (
 id TEXT PRIMARY KEY, space_id TEXT NOT NULL, channel_id TEXT NOT NULL,
 name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0,
 created_by TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_folders_v89_space_channel ON notes_folders_v89(space_id,channel_id,sort_order);
CREATE TABLE IF NOT EXISTS note_folder_links_v89 (
 space_id TEXT NOT NULL,note_id TEXT NOT NULL,folder_id TEXT NOT NULL,updated_at INTEGER NOT NULL,
 PRIMARY KEY(space_id,note_id)
);
CREATE INDEX IF NOT EXISTS idx_note_folder_links_v89_folder ON note_folder_links_v89(space_id,folder_id);
