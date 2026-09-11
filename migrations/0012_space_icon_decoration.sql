-- Spaces 0.0.11
-- Persist the non-destructive decorative frame around each Space icon.
ALTER TABLE spaces ADD COLUMN icon_decoration TEXT NOT NULL DEFAULT 'ring';
