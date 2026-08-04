# Camellia Remote Management Server

Production management plane for Camellia Remote: accounts, devices, address books, policy, auditing, and a commit-pinned Web client. Production supports PostgreSQL only; SQLite is restricted to explicit `CAMELLIA_REMOTE_DEBUG=true` development. Online plugin signing remains disabled until the repositories provide a versioned artifact envelope, a real verification consumer, and an approval-backed signing workflow.

The service listens on port 21114 behind a TLS reverse proxy. Keep PostgreSQL and the backend network private. The initial single-region target is 99.9% availability, RPO at most one hour, and RTO at most four hours.

## Development

Use Python 3.13+, uv 0.12.0, and PostgreSQL 18. For an isolated SQLite development run:

```bash
uv sync --locked --all-groups
CAMELLIA_REMOTE_DEBUG=true CAMELLIA_REMOTE_SECRET_KEY=dev-only-insecure-secret-key \
  CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN=development-device-token-00000000 \
  uv run python manage.py migrate
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Production

Copy `.env.example` to a mode-`0600` secret file and set every required value, especially `CAMELLIA_REMOTE_SECRET_KEY`, the stable lowercase `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID`, its canonical 32-byte Base64 `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY`, `CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`, `CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN`, PostgreSQL connection parameters, explicit public HTTPS origins, WSS rendezvous endpoints with ports, and the canonical 32-byte Base64 `CAMELLIA_REMOTE_RS_PUB_KEY`. Configure PostgreSQL with either `CAMELLIA_REMOTE_DATABASE_URL` or the complete `HOST/PORT/NAME/USER/PASSWORD` settings, never both. Compose uses discrete parameters, so URL-reserved characters in strong passwords need no encoding. Production requires TLS. Invalid booleans, integers, log levels, and time zones stop startup rather than silently falling back. Never place secrets in images, Git, or shell history. Configure all OIDC values together.

Gunicorn access logs contain only the method, fixed route pattern, status, byte count, duration, and a server-generated request ID. They never include a raw URL/query, Referer, User-Agent, or client address. Reverse proxies must enforce the same boundary and must not log OIDC code/state values, share tokens, audit/session/device parameters, or recording filenames.

Address-book and pending-OIDC secrets use authenticated `secretbox:v2` envelopes with explicit key IDs. The database key inventory stores only encrypted non-business canaries and key fingerprints; readiness rejects wrong keys and replica key-state splits. Connection credentials are returned only by authenticated, access-scoped runtime APIs. Django admin treats them as write-only values, and CSV/Excel exports omit them.

For rotation, configure the new ID/key as primary, retain the old key as an `old-id:Base64` entry in `CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS`, and keep `CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID` on the key that produced legacy v1 rows. Run `python manage.py rotate_data_encryption --dry-run`, then run bounded batches; `--max-batches` supports deliberate interruption and resume. After all batches, run the command once without `--max-batches` to authenticate every primary envelope. Use `--retire-key-id OLD_ID` only after that full validation and readiness pass and retained backup inventory no longer requires the key. When deleting the old secret, also move `CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID` to a key that remains configured.

Install `docker-compose.yaml`, `deploy/backup-postgres.sh`, and `deploy/systemd/*` as documented in the Chinese README. Pin `CAMELLIA_REMOTE_MANAGEMENT_IMAGE` to a published `sha256` digest. The systemd stack performs the one-shot migration before starting the application; the hourly timer produces atomic PostgreSQL custom-format backups. A five-minute timer removes expired login attempts, OIDC sessions and access tokens, marks expired share links, and deletes consumed or expired links after the configured retention period. The operations units may reach Docker only through the local Unix socket. That socket is equivalent to host root access, so keep it root-only and prevent unprivileged changes to the deployment directory and environment file.

The Compose default uses `sslmode=disable` only for PostgreSQL on its non-routable, same-host `backend` bridge. External or cross-host databases are required to use `verify-full`, a trusted CA, and a hostname covered by the certificate. Private CA, client certificate, and client key paths can be supplied with `CAMELLIA_REMOTE_DATABASE_SSLROOTCERT`, `CAMELLIA_REMOTE_DATABASE_SSLCERT`, and `CAMELLIA_REMOTE_DATABASE_SSLKEY`; the client certificate and key must be configured together.

Store backups on encrypted independent storage, copy them off-site daily, and run quarterly restore drills. Restore into an empty database with the same PostgreSQL major version, run migrations and deployment checks, verify `/health/ready`, then restore traffic.

`web-client.lock` identifies the only Web source accepted by CI. A formal
Management release also requires that exact commit to be a completed immutable
Remote Client release with valid evidence, then reuses the Web artifact from
the exact successful Management push CI. Release Manager creates a reviewed
version PR and exact tag. The workflow freezes and scans one multi-architecture
OCI layout before protected approval, publishes the identical digest only to
configured GHCR/Docker Hub targets, signs and publicly reads back all evidence,
and completes an immutable GitHub Release. Deployments use digests; `latest` is
only reconciled discovery metadata.

This repository is licensed under GNU AGPL-3.0-only. See `SOURCE_PROVENANCE.json`, `NOTICE`, and `SECURITY.md`.
