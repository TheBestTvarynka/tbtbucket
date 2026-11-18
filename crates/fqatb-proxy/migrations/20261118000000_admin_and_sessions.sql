-- The proxy has exactly one administrator, identified by a random UUID and authenticated by a passphrase.
-- The Argon2 PHC string is not encrypted: it is already a one-way, salted hash.
CREATE TABLE admin (
    id TEXT PRIMARY KEY NOT NULL,
    password_hash TEXT NOT NULL
) STRICT;

-- An index on a constant expression allows at most one row.
CREATE UNIQUE INDEX admin_singleton ON admin ((0));

-- The session payload is JSON encrypted with AES-256-CBC and authenticated with HMAC-SHA256.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    ciphertext BLOB NOT NULL
) STRICT;
