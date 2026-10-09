-- Session generations: changing or resetting a password, or suspending an account, increments
-- users.session_generation. Access and refresh tokens record the generation they were issued
-- under and stop working once it changes, even if they were issued concurrently with the change.
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_generation BIGINT NOT NULL DEFAULT 0;

-- Idempotent sends: the client generates client_id once per composed message and reuses it when
-- retrying, so a retried send returns the original message instead of a duplicate.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS client_id UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_client_id
    ON messages(sender_id, client_id) WHERE client_id IS NOT NULL;

-- History and sidebar queries filter by conversation and order by creation time.
CREATE INDEX IF NOT EXISTS idx_messages_group_history
    ON messages(group_id, created_at DESC, id)
    WHERE parent_id IS NULL AND NOT COALESCE(is_deleted, false);
CREATE INDEX IF NOT EXISTS idx_messages_direct_history
    ON messages(LEAST(sender_id, receiver_id), GREATEST(sender_id, receiver_id), created_at DESC)
    WHERE receiver_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);
