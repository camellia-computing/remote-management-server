# Release policy

Camellia Remote Management follows the organization
[CI/CD baseline](https://github.com/camellia-computing/.github/blob/main/docs/CI_CD_BASELINE.md).
The management version, source commit, pinned Remote Web commit and successful
exact-SHA push CI run form one immutable release input.

## Publication flow

1. A candidate must be reachable from the default branch and have one
   successful push CI run containing the exact unexpired Web artifact.
2. `publish=false` builds a non-mutating candidate and does not receive the
   Release App secret.
3. `publish=true` must execute the default-branch workflow definition. A scoped
   Release App token verifies its own slug/login, squash-only repository policy
   and immutable Releases.
4. A non-self reviewer approves the protected `release` environment.
5. The image is built once for the selected architectures, published only by
   immutable digest, and receives BuildKit SBOM/provenance plus keyless Cosign
   signing.
6. The App creates a draft GitHub Release containing the exact image digest,
   source/Web commits, CI run, release notes and checksums.
7. Automation downloads every draft asset, compares exact bytes and verifies
   checksums before publishing. It waits for immutable state and repeats the
   public readback.

No `latest` deployment input is trusted. Deploy the digest recorded by
`release-metadata.json`.

## GitHub App and review contract

Formal publication requires variable `RELEASE_APP_CLIENT_ID`, variable
`RELEASE_APP_LOGIN`, secret `RELEASE_APP_PRIVATE_KEY`, and selected App
installation access to `remote-management-server`. The App needs
Administration read, Contents read/write and Metadata read; it must not have
Actions or Workflows permission.

Normal code changes still require the stable `CI / Required` check and
CODEOWNERS/current-head review. Formal publication adds the protected
environment approval. A retry may update only an App-authored compatible draft;
conflicting author, commit, title, tag or assets fail closed. Published
Releases, tags and assets are never replaced.

Server-only repositories do not receive desktop/mobile PFX, P12, keystore or
private signing keys. Their trust evidence is the immutable image digest,
SBOM/provenance, keyless signature and attested Release manifest.
