-- Access tokens issued by the proxy.
-- The token itself is never stored: `secret_hash` is the SHA-256 of its random part, and its ID is embedded in it.
-- `permissions` is the policy JSON, encrypted with AES-256-GCM using the database cipher and bound to the row ID.
CREATE TABLE access_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
    permissions BLOB NOT NULL,
    created_at TEXT NOT NULL
        CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'),
    expires_at TEXT NOT NULL
        CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z')
) STRICT;

-- Which Bitbucket tokens each access token's policy uses.
-- The policy is encrypted, so this table, written together with it, is what finds the access tokens that depend on a Bitbucket token.
CREATE TABLE access_token_bitbucket_tokens (
    access_token_id TEXT NOT NULL REFERENCES access_tokens (id) ON DELETE CASCADE,
    bitbucket_token_id TEXT NOT NULL REFERENCES bitbucket_tokens (id) ON DELETE CASCADE,
    PRIMARY KEY (access_token_id, bitbucket_token_id)
) STRICT;

CREATE INDEX access_token_bitbucket_tokens_by_bitbucket_token
    ON access_token_bitbucket_tokens (bitbucket_token_id);
