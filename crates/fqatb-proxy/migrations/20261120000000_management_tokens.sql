-- Management tokens, which authenticate the management API.
-- Like access tokens, the token itself is never stored: `secret_hash` is the SHA-256 of its random part, and its ID is
-- embedded in it.
CREATE TABLE management_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
    created_at TEXT NOT NULL
        CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'),
    expires_at TEXT NOT NULL
        CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z')
) STRICT;
