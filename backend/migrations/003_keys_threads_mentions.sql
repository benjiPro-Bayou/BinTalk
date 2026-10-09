-- Versioned data keys: each version's AES key is stored wrapped (encrypted) by the Vault
-- Transit key, so keys survive restarts and old versions stay readable after rotation.
ALTER TABLE encryption_key_versions ADD COLUMN IF NOT EXISTS wrapped_key TEXT;

-- Which data key version encrypted each message / phone number.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_key_version INT;

-- Threads: replies to a group message point at the top-level message they belong to.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES messages(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_messages_parent ON messages(parent_id);

-- @mentions (user IDs only; the message text stays encrypted).
CREATE TABLE IF NOT EXISTS message_mentions (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_message_mentions_user ON message_mentions(user_id);
