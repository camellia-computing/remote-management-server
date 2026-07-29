# Camellia Remote Management Server

Production management plane for Camellia Remote: accounts, devices, address books, policy, auditing, plugin signing, and a commit-pinned Web client. Production supports PostgreSQL only; SQLite is restricted to explicit `CAMELLIA_REMOTE_DEBUG=true` development.

The service listens on port 21114 behind a TLS reverse proxy. Keep PostgreSQL and the backend network private. The initial single-region target is 99.9% availability, RPO at most one hour, and RTO at most four hours.

## Development

Use Python 3.13+, uv 0.11.30+, and PostgreSQL 18. For an isolated SQLite development run:

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

Copy `.env.example` to a mode-`0600` secret file and set every required value, especially `CAMELLIA_REMOTE_SECRET_KEY`, `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY`, `CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN`, PostgreSQL connection parameters, explicit public HTTPS origins, WSS rendezvous endpoints with ports, and the canonical 32-byte Base64 `CAMELLIA_REMOTE_RS_PUB_KEY`. Configure PostgreSQL with either `CAMELLIA_REMOTE_DATABASE_URL` or the complete `HOST/PORT/NAME/USER/PASSWORD` settings, never both. Compose uses discrete parameters, so URL-reserved characters in strong passwords need no encoding. Production requires TLS. Invalid booleans, integers, log levels, and time zones stop startup rather than silently falling back. Never place secrets in images, Git, or shell history. Configure all OIDC values together.

Address-book connection credentials are authenticated-encrypted at rest and returned only by authenticated, access-scoped runtime APIs. Django admin treats them as write-only values, and CSV/Excel exports omit them.

Install `docker-compose.yaml`, `deploy/backup-postgres.sh`, and `deploy/systemd/*` as documented in the Chinese README. Pin `CAMELLIA_REMOTE_MANAGEMENT_IMAGE` to a published `sha256` digest. The systemd stack performs the one-shot migration before starting the application; the hourly timer produces atomic PostgreSQL custom-format backups. A five-minute timer removes expired login attempts, OIDC sessions and access tokens, marks expired share links, and deletes consumed or expired links after the configured retention period.

The Compose default uses `sslmode=disable` only for PostgreSQL on its non-routable, same-host `backend` bridge. External or cross-host databases are required to use `verify-full`, a trusted CA, and a hostname covered by the certificate. Private CA, client certificate, and client key paths can be supplied with `CAMELLIA_REMOTE_DATABASE_SSLROOTCERT`, `CAMELLIA_REMOTE_DATABASE_SSLCERT`, and `CAMELLIA_REMOTE_DATABASE_SSLKEY`; the client certificate and key must be configured together.

Store backups on encrypted independent storage, copy them off-site daily, and run quarterly restore drills. Restore into an empty database with the same PostgreSQL major version, run migrations and deployment checks, verify `/health/ready`, then restore traffic.

`web-client.lock` identifies the only Web source accepted by CI. Releases require a successful push CI for the exact reachable commit and the `release` environment approval. Published OCI images are multi-architecture, SBOM/provenance enabled, and keylessly signed by digest; no floating `latest` tag is produced.

This repository is licensed under GNU AGPL-3.0-only. See `SOURCE_PROVENANCE.json`, `NOTICE`, and `SECURITY.md`.
