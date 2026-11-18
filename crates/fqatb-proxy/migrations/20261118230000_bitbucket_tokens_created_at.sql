-- Records when each Bitbucket token was added, as an RFC 3339 UTC timestamp with whole seconds.
-- Tokens added before this migration get 2026-11-18T20:00:00Z.
-- SQLite cannot drop a column default, so the table is rebuilt to keep `created_at` without one.
CREATE TABLE bitbucket_tokens_new (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    token BLOB NOT NULL,
    created_at TEXT NOT NULL
        CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z')
) STRICT;

INSERT INTO bitbucket_tokens_new (id, name, token, created_at)
SELECT id, name, token, '2026-11-18T20:00:00Z' FROM bitbucket_tokens;

DROP TABLE bitbucket_tokens;

ALTER TABLE bitbucket_tokens_new RENAME TO bitbucket_tokens;
