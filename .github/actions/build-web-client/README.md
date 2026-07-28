# Build pinned Camellia Remote Web client

This repository-local composite action restores or builds the exact Camellia
Remote Web runtime selected by Remote Management's `web-client.lock`. It is not
a GitHub App and has no separate organization installation. It executes with
the permissions of its calling workflow.

## Location and caller

- Definition:
  `remote-management-server/.github/actions/build-web-client/action.yml`
- Current caller: `.github/workflows/ci.yml`
- Invocation: `uses: ./.github/actions/build-web-client`

The action must be checked out from the same immutable Remote Management commit
as its caller.

## Inputs and output

| Name | Default | Meaning |
| --- | --- | --- |
| `repository-name` | `remote-client` | One unqualified repository name under `github.repository_owner` |
| `flutter-version` | `3.44.5` | Exact Flutter SDK version used for the Web build |
| `node-version` | `24.18.0` | Exact Node.js version used for the bridge build |

Output `revision` is the full Remote Client commit read from
`web-client.lock`.

Owner-qualified repository names, path components, and `.`/`..` are rejected.

## Required workflow permissions

The calling job needs only:

```yaml
permissions:
  contents: read
  actions: read
```

`contents: read` checks repository/default-branch state and checks out the
locked source. `actions: read` inspects push CI runs for the selected Remote
Client revision. No write permission, long-lived PAT, or GitHub App credential
is required while the source repository is public and readable by the workflow
token.

If Remote Client later becomes private, use a separately reviewed
cross-repository read GitHub App with only `Contents: Read-only` and
`Metadata: Read-only`; do not broaden the default workflow token.

## Trust boundary

Before executing source from Remote Client, the action:

1. reads one full commit from `scripts/web_client_revision.sh`;
2. confirms the commit is reachable from the source default branch;
3. finds a successful push workflow for that exact commit;
4. requires the run to contain exactly one successful `CI / Required` job;
5. checks out that immutable commit with persisted credentials disabled;
6. verifies the checked-out revision before building;
7. records `<revision> clean` in
   `static/web_client/.source_revision` and checks required output files and
   symlink absence.

The compiled-runtime cache key includes the source revision, Flutter and Node
versions, synchronization script, and action definition. A cache hit is still
subject to the final provenance/content checks.

The nested Remote Client `setup-flutter` action is pinned to a full commit SHA.
Third-party setup/cache actions are also pinned to full SHAs.

## Updating the action

1. Merge and obtain a green required push CI run for the intended Remote Client
   commit.
2. Update `web-client.lock` through the repository's lock update command or
   documented script; never type an abbreviated SHA.
3. If the Remote Client setup action changed, update the full SHA in
   `action.yml` to the same reviewed source line.
4. If Flutter or Node changes, update the action defaults, calling workflow, and
   lock/build evidence together.
5. Run actionlint, ShellCheck, the full Remote Management CI path, and the
   hardened container/deployment checks before merge.

Do not weaken the reachability or exact-CI checks to work around a missing
source run. Produce the required source evidence first.
