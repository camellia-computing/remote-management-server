# Address book read and edit boundary

The pre-release read contract uses Bearer-authenticated **POST**, with
`Content-Type: application/json` and a correctly framed zero-length body or `{}`.
Selectors belong in the query string. Nonempty JSON selectors are rejected, not
ignored; GET is not a compatibility route.

`/api/ab/personal` returns `guid`, `name`, `address_book_snapshot_version: 1` and
`authorization_generation`. `/api/ab/shared/profiles` is a versioned paginated
catalog; every row includes the same identity/version fields. Catalog rows are
metadata, not proof that an editor's cached content is current. Ordering is
`(name, guid)`; identity is GUID, never the display name.

`/api/ab/peers?ab=<guid>&current=1&pageSize=100` returns a page with the identity,
generation, pagination contract, `total` and `data`. `/api/ab/tags/<guid>` returns
an object with the same identity/generation, `total` and `data` (not a bare list).
Each content response reads its generation and content under the profile
authority lock and rechecks authorization. Separate requests are **not** one
database snapshot: consumers must require identical GUID/generation across
every peer page and the tags response, and reject incomplete or duplicate data.

Only a complete snapshot may become editable. Failed pulls retain the previous
display cache without granting it a newer version; a catalog refresh or receipt
alone must not relabel stale visible contents. Account/endpoint changes and
late responses invalidate the read attempt. Consumers on JavaScript must reject
generations they cannot represent exactly rather than round `If-Match`.

Content writes require `Idempotency-Key: v2:<uuidv4>`, observed `If-Match`, a
frozen public request digest and receipt version 2. The operation ID stored in
the journal and used in receipt GET remains the bare UUIDv4. Mandatory-v1/v2
key parsers reject the other's wire format before applying a mutation. A
successful write invalidates the displayed snapshot until reconciled. An unknown
result is recovered by GET of the original operation ID, never a new-ID retry.
Native/CLI write consumers are being coordinated in STATE-044/COMPAT-011; this
document and the local read tests do not certify a complete deployable combination.

The public digest covers canonical parsed JSON, presence of a body, non-secret
fields and `keep`/`clear`/`set` secret markers. It contains no password-derived
hash or secret length. Secret field names include the personal peer's wire
`hash`, stored `rhash`, `password`, `default_password`, `address_book_password`
and `token`. The provider privately binds the complete intent using
HMAC and a random per-operation key inside its context-authenticated encrypted
receipt. Encryption-key rotation rewraps that container without invalidating
replay. Changing only a secret under the same operation ID still conflicts.

Migration 0035 removes the old plaintext response column and retires unsafe v1
receipts as version-0 tombstones. Their IDs remain reserved within normal
receipt retention: recovery returns
410 and callers must reconcile resources before creating a new operation.
Rollback also retires v2 containers before restoring the old schema so an old
reader cannot expose private binding keys. It does not restore old results or
weak digests. Old exports/backups are not securely erased by a schema migration.
