# Management API

The management API manages Bitbucket tokens and access tokens over JSON, for scripts and automation that do not use the admin panel.
It can do what the `/webapp/bitbucket_tokens` and `/webapp/access_tokens` pages do, and nothing else: management tokens themselves are only managed in the admin panel.

## Management tokens

The admin issues management tokens on `/webapp/management_tokens`, the admin panel's home page, with a name and a lifetime of 1, 7, 30 or 90 days.
A token is shown once, right after it is issued, and cannot be recovered afterwards.
Removing it on the same page revokes it immediately.

A management token looks like an access token with a different prefix: `fgatbm_` followed by unpadded URL-safe base64 of `id (16) ‖ secret (32) ‖ HMAC-SHA256(id ‖ secret) (32)`.
It is signed with its own key, derived from `FQATB_ENCRYPTION_KEY` with a salt of its own, so a management token never passes for an access token and the other way round.
Like access tokens, only the SHA-256 of the secret is stored, in the `management_tokens` table, so the database alone never yields a working token.

## Authentication

Every request needs the token as a bearer token:

```http
Authorization: Bearer fgatbm_…
```

The admin session cookie is not accepted, so that a page open in the admin's browser cannot call the API on their behalf.
A missing, malformed, removed or expired token gets `401 Unauthorized` with `WWW-Authenticate: Bearer`.

## Errors

Errors use the same JSON format as the proxy's Bitbucket-compatible API:

```json
{ "errors": [{ "context": null, "message": "expires_in_days must be one of 1, 7, 30, 90", "exceptionName": null }] }
```

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | The body is not valid JSON. |
| `401 Unauthorized` | The management token is missing or not valid. |
| `404 Not Found` | The token to remove does not exist. |
| `409 Conflict` | The Bitbucket token to remove is used by access tokens; see below. |
| `415 Unsupported Media Type` | The body is not sent as `Content-Type: application/json`. |
| `422 Unprocessable Entity` | The body has the wrong shape, an unknown field, or values that are not accepted, such as a taken name. |

Timestamps are RFC 3339 in UTC with whole seconds, such as `2026-11-20T10:35:04Z`.

## Endpoints

Paths are relative to the proxy's base URL.

### List Bitbucket tokens

`GET /fgatbapi/v1/bitbucket_tokens` returns every Bitbucket token, ordered by name, never with its value:

```json
[{ "id": "a9940e18-bc62-4a9c-bfd9-18a18361ecbf", "name": "read", "created_at": "2026-11-20T10:35:04Z" }]
```

### Add a Bitbucket token

`POST /fgatbapi/v1/bitbucket_tokens` stores a Bitbucket HTTP access token, encrypted:

```json
{ "name": "read", "token": "ATBB…" }
```

It answers `201 Created` with the new token's ID, which access token rules refer to:

```json
{ "id": "a9940e18-bc62-4a9c-bfd9-18a18361ecbf", "name": "read" }
```

### Remove a Bitbucket token

`DELETE /fgatbapi/v1/bitbucket_tokens/{id}` removes the token and answers `204 No Content`.

Access tokens whose rules use the Bitbucket token stop working without it, so they are removed with it.
Because that is easy to do by accident, the request fails with `409 Conflict` when such access tokens exist, naming them in `access_tokens`:

```json
{
  "access_tokens": ["ci"],
  "errors": [{ "context": null, "message": "Bitbucket token is used by access tokens ci; repeat the request with remove_access_tokens=true to remove them too", "exceptionName": null }]
}
```

`DELETE /fgatbapi/v1/bitbucket_tokens/{id}?remove_access_tokens=true` removes the Bitbucket token together with those access tokens, and answers `200 OK` naming them:

```json
{ "removed_access_tokens": ["ci"] }
```

### List access tokens

`GET /fgatbapi/v1/access_tokens` returns every access token, ordered by name, never with the token itself or its permissions:

```json
[{
  "id": "33dce598-7541-4d61-8946-7cc05f60dc42",
  "name": "ci",
  "created_at": "2026-11-20T10:35:04Z",
  "expires_at": "2026-11-27T10:35:04Z",
  "expired": false
}]
```

### Create an access token

`POST /fgatbapi/v1/access_tokens` issues an access token.
`expires_in_days` is one of `1`, `7`, `30` and `90`, and `policy` is the permission format described in [`access-model.md`](access-model.md#policy-document):

```json
{
  "name": "ci",
  "expires_in_days": 7,
  "policy": {
    "version": 1,
    "rules": [
      { "bitbucket_token": "a9940e18-bc62-4a9c-bfd9-18a18361ecbf", "actions": ["repo:read"], "project": "PROJ", "repository": "api" }
    ]
  }
}
```

It answers `201 Created` with the token.
This response is the only time the token is available:

```json
{
  "id": "33dce598-7541-4d61-8946-7cc05f60dc42",
  "name": "ci",
  "token": "fgatb_…",
  "expires_at": "2026-11-27T10:35:04Z"
}
```

An invalid policy is explained by rule, for example `rule 1: source branches only limit pull request and comment actions; select one of them or clear the field`.

### Remove an access token

`DELETE /fgatbapi/v1/access_tokens/{id}` revokes the token immediately and answers `204 No Content`.

## Example

```bash
PROXY=https://tbtbucket.com:8443
AUTH="Authorization: Bearer $FGATB_MANAGEMENT_TOKEN"

bitbucket_token=$(curl -sf -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name": "read", "token": "'"$BITBUCKET_TOKEN"'"}' \
  "$PROXY/fgatbapi/v1/bitbucket_tokens" | jq -r .id)

curl -sf -H "$AUTH" -H 'Content-Type: application/json' -d @- "$PROXY/fgatbapi/v1/access_tokens" <<EOF | jq -r .token
{"name": "ci", "expires_in_days": 7, "policy": {"version": 1, "rules": [
  {"bitbucket_token": "$bitbucket_token", "actions": ["repo:read"], "project": "PROJ", "repository": "api"}
]}}
EOF
```
