# Repository instructions

- Production uses PostgreSQL. SQLite code and tests are development-only and must
  remain gated by `CAMELLIA_REMOTE_DEBUG=true`.
- Treat authentication, device verification, encryption, upload bounds, proxy
  trust, and Web artifact provenance as security boundaries. Fail closed.
- Keep migrations reproducible from an empty database. Never edit an already
  published migration; before the first release, prefer a clean baseline.
- Use locked dependencies. Run Ruff, Django deployment checks, migrations, tests,
  release-metadata tests, workflow lint, and the hardened container smoke test.
- Release only exact successful-CI commits, pin production images by digest, and
  preserve SBOM, provenance, signature, approval, and immutable-tag gates.
