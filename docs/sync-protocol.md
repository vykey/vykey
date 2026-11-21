# vykey sync protocol

Version 1. Server: `crates/vykey-server`; wire types:
`crates/vykey-sync-proto` (the source of truth for field names and limits).

The server is zero-knowledge: it stores opaque encrypted records and hands
them out by revision. It never sees vault contents and cannot merge them;
clients resolve conflicts.

## Accounts and tokens

An account is anonymous. `POST /v1/account` creates one and returns its
**token**, the only credential:

```
vy1-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567
```

160 random bits, base32 (RFC 4648 alphabet, no padding), shown as `vy1-`
and eight groups of four. Parsing ignores case, spaces and dashes; the `vy1`
prefix is required (`1` is not a base32 digit, so it cannot be confused with
the body).

The server stores only `SHA-256(token bytes)` and finds the account by it.
There is no recovery: a lost token is a lost account (the vaults stay on
the devices). A leaked token lets its holder download every vault's salt
and verifier, and so try master passwords offline, and overwrite or delete
records; treat it as a secret.

Every other endpoint needs `Authorization: Bearer <token>`.

## Records

Everything synced is a record:

| Field      | Type    | Notes |
|------------|---------|-------|
| `id`       | UUID    | the client's id of the vault, folder or entry |
| `kind`     | string  | `vault`, `folder` or `entry` |
| `vault_id` | UUID    | the vault it belongs to; a vault record's own `id` |
| `rev`      | integer | revision of its last change, assigned by the server |
| `deleted`  | bool    | tombstone; `blob` is empty |
| `blob`     | base64  | opaque client data, at most 64 KiB decoded |

A record's `kind` and `vault_id` never change.

**Revisions.** Each account has one counter. Every stored change takes the
next value, so revisions are unique per account and increase in commit
order. The account revision is the last one assigned (0 when empty).
Client clocks play no part.

## Endpoints

HTTP/1.1; bodies are JSON (`Content-Type: application/json`). Responses
carry `Cache-Control: no-store`.

### `POST /v1/account` → 201

```json
{"token": "vy1-..."}
```

No body needed, unless the server asks for proof of work (next section).
Limited per client address (10 per hour).

Registration is closed by default: the request needs the header
`X-Vykey-Invite: <invite key>` (the server's `VYKEY_SERVER_INVITE_KEY`),
otherwise 403 `registration_closed`. A server started with
`--open-registration` lets anyone create an account.

### `GET /v1/account/challenge` → 200

Only on servers that ask for proof of work for open registration (others
answer 404; with registration closed, 403 `registration_closed`).

```json
{"challenge": "AQ…", "difficulty": 24, "expires_in": 600}
```

The client finds a `nonce` (unsigned 64-bit) such that
`SHA-256(challenge bytes ‖ nonce as 8 little-endian bytes)` starts with
`difficulty` zero bits (`vykey_sync_proto::pow::solve`), and sends

```json
{"challenge": "AQ…", "nonce": 13371337}
```

as the body of `POST /v1/account`. A challenge is valid for 10 minutes and
once; on 403 `challenge_failed` (missing, wrong, expired, already used, or
issued before a server restart) the client gets a new one. Clients should
refuse a difficulty above 32 (`pow::MAX_DIFFICULTY`). Invited clients skip
the proof of work.

The challenge is signed by the server (HMAC-SHA256 with a key made at
start-up), so it cannot be altered or forged and the server keeps no state
for challenges it hands out, only for used ones until they expire. Layout:
version (1) ‖ issued at (8) ‖ difficulty (1) ‖ random (16) ‖ tag (16).

The difficulty is the configured base plus one bit for each doubling of the
registration rate over the last hour above a target (default 100 per hour),
at most 8 bits more: ordinary sign-ups pay about a second once, a flood gets
exponentially more expensive.

### `GET /v1/account` → 200

```json
{"rev": 42, "bytes": 18210, "records": 37,
 "quota_bytes": 10485760, "quota_records": 20000, "created": 1795001721}
```

### `DELETE /v1/account` → 204

Deletes the account and every record at once.

### `GET /v1/changes?since=N&limit=M` → 200

Records whose `rev > since`, by ascending `rev`, at most `limit` (default
500, at most 1000).

```json
{"records": [{"id": "…", "kind": "entry", "vault_id": "…", "rev": 41,
              "deleted": false, "blob": "…"}],
 "until": 41, "more": true, "poll_after": 300}
```

- `until`: the client is now up to date to this revision; pass it as the
  next `since`. Without `more` it is the account revision.
- `more`: ask again right away.
- `poll_after`: seconds to wait before the next poll when idle. Clients must
  honour it: it is how the server sheds load.
- A record changed several times appears once, with its latest version.
- `since=0` returns every record the server keeps: a full snapshot.

**410 `resync_required`** when `since` is ahead of the account revision (the
server was restored from a backup) or below the account's garbage-collection
floor (a tombstone the client never saw was removed). The client then pulls
from `since=0`, treats the result as complete, deletes local records missing
from it unless they have unpushed local changes, and pushes everything it
has changed or created (their `base_rev` is what the snapshot says, or 0 for
records missing from it).

### `POST /v1/push` → 200

```json
{"records": [
  {"id": "…", "kind": "entry", "vault_id": "…", "base_rev": 41, "blob": "…"},
  {"id": "…", "kind": "folder", "vault_id": "…", "base_rev": 12, "deleted": true}
]}
```

`base_rev` is the `rev` the client's version is based on, 0 for a record the
server has never had. At most 500 records, unique ids.

```json
{"results": [
  {"status": "ok", "id": "…", "rev": 43},
  {"status": "conflict", "id": "…", "current": {"id": "…", "rev": 44, …}}
 ],
 "rev": 43}
```

Per record, in request order:

- `ok`: `base_rev` equalled the stored revision (0: no such record); stored
  under the new `rev`.
- `conflict`: it did not; nothing stored for that record. `current` is the
  server's version, or `null` if the server has no such record (it was
  removed by garbage collection after being deleted).

Records without conflict are stored even when others conflict. The push is
one transaction: on any error below nothing is stored.

| Status | `error` | Cause |
|---|---|---|
| 400 | `bad_request` | malformed JSON or id; duplicate id; tombstone with a blob; live record with an empty blob; vault record whose `vault_id` is not its `id`; a stored record's `kind` or `vault_id` changed |
| 413 | `payload_too_large` | body over 8 MiB, blob over 64 KiB, more than 500 records |
| 507 | `quota_exceeded` | the push would grow the account past its quota |

A push that does not grow usage passes even over quota, so an account above
a lowered quota can still delete.

### `GET /v1/health` → 200

`{"status": "ok"}`, no token.

## Errors

Every error has the body

```json
{"error": "<code>", "message": "<text for humans>"}
```

| Status | `error` |
|---|---|
| 400, 408 | `bad_request` (408: the body did not arrive within 30 s) |
| 401 | `unauthorized`: missing, malformed or unknown token |
| 403 | `registration_closed`, `challenge_failed` |
| 404 | `not_found` |
| 405 | `method_not_allowed` |
| 410 | `resync_required` |
| 413 | `payload_too_large` |
| 429 | `rate_limited`; wait `Retry-After` seconds |
| 500 | `internal` |
| 507 | `quota_exceeded` |

Requests the HTTP layer rejects before the API sees them (malformed
request line or headers, headers over 16 KiB: 400, 431) get the status
without a JSON body.

After 30 failed authentications in 10 minutes an address gets 429 for every
authenticated request until the window ends. Addresses are counted per IPv4
address and per IPv6 /64.

## Tombstones and garbage collection

Deleting a record is a push with `deleted: true`: the blob is dropped, the
record keeps a revision so other devices learn about the deletion. Pushing
a live version on top of a tombstone (with its `rev` as `base_rev`)
restores the record.

Tombstones older than 90 days (configurable) are removed for good. The
highest revision removed becomes the account's floor; a client whose
`since` is below it gets 410 and resyncs.

## Client behaviour

Not enforced by the server, but assumed by it:

- **Sync loop.** Pull until `more` is false, apply, push local changes in
  batches, handle conflicts, repeat (at most a few rounds). Sync on unlock,
  a few seconds after a local change, and every `poll_after` seconds while
  a vault is open.
- **Backoff.** On network errors and 5xx, retry with exponential backoff
  and jitter; on 429/503 wait `Retry-After`.
- **Conflicts** are the client's: it decrypts `current` and merges (for
  entries: the later edit wins, the losing version is kept as a copy if a
  secret differs). A vault record (salt, wrapped key, verifier) is never
  merged: the server's version wins and the user is told the master
  password was changed elsewhere.

## Blob format (client side)

The server does not look inside blobs. Version 1 of the client format, for
folder and entry records:

```
version (1 byte) || nonce (12) || AES-256-GCM(JSON of the whole record, padded) || tag (16)
AAD = "vykey-sync-v1" || kind || vault_id || id
```

The AAD binds a blob to its record: a server that moves blobs between
records or vaults makes decryption fail. The JSON carries every field of
the record, timestamps included, plus a per-record edit counter so a
client can refuse an older version than one it has seen; it is padded to a
multiple of 256 bytes so the size does not reveal field lengths.

A vault record must be readable before the vault is unlocked, so its blob
is plain JSON: name, salt, wrapped key, verifier. The server sees vault
names.

## What the server knows

| Knows | Does not know |
|---|---|
| hash of the token | the token |
| number of vaults, folders, entries per account | titles, logins, passwords, URLs, notes, TOTP secrets |
| record sizes (to 256 bytes) | field lengths |
| when records change (from requests) | timestamps inside records |
| which vault a record belongs to | which folder an entry is in |
| vault names, salts, wrapped keys, verifiers | master passwords |
| the day an account was last used | client addresses (not stored; used in memory for rate limits) |

## Storage on the server

One redb file. Tables (byte layout in `crates/vykey-server/src/codec.rs`):

| Table       | Key                              | Value |
|-------------|----------------------------------|-------|
| `meta`      | `"schema"`                       | layout version (1) |
| `accounts`  | account (32)                     | rev, bytes, records, created, last seen day, gc floor |
| `records`   | account ‖ id (48)                | rev, kind, vault id, deleted, deleted at, blob |
| `changes`   | account ‖ rev big-endian (40)    | id |
| `graveyard` | deleted at ‖ account ‖ id (56)   | — |

Each record has one `changes` row, under its latest revision; a pull is a
range scan. `graveyard` orders tombstones by age for garbage collection.
