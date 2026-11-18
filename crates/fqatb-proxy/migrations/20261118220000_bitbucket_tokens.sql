-- Bitbucket access tokens managed in the admin panel.
-- The name identifies a token, is unique, and cannot be changed after creation.
-- The token value is encrypted with AES-256-GCM using the database cipher, bound to the row ID.
CREATE TABLE bitbucket_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    token BLOB NOT NULL
) STRICT;
