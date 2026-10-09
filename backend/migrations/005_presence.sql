-- Presence: the status a user chose for themselves. "auto" shows them Active while they are
-- connected and using the app (Away after a period of inactivity); "away" and "offline" (appear
-- offline) override that.
ALTER TABLE users ADD COLUMN IF NOT EXISTS presence_preference VARCHAR(10) NOT NULL DEFAULT 'auto'
    CHECK (presence_preference IN ('auto', 'away', 'offline'));
