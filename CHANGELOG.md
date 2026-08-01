# Changelog

## [1.0.0] - 2026-08-01

### Features

- feat: establish Camellia Remote management production baseline (`dbb40bdb7fb4`)
- feat(security): harden management and release operations (#6) (`1d4e5dbdd09e`)
- feat(release): bind publication to client evidence (#8) (`478c378a6898`)

### Fixes

- fix(deps): preserve hosted uv updates (#7) (`87c38e168a46`)
- fix(release): resolve GitHub App bot identity (#9) (`272af116962b`)
- fix(release): preserve empty commit bodies (#10) (`aced3c550084`)
- fix(release): preserve porcelain status columns (#11) (`0b50f609dbfe`)
- fix(release): harden candidate recovery (#13) (`fe53fbe3580a`)
- fix(release): preserve read-only draft authorization (#14) (`809fa9a7e4b2`)
- fix(release): gate candidates on exact client release (#15) (`4513af1e0acf`)
- fix(release): preserve managed draft visibility (#17) (`b46eca577330`)
- fix(release): preserve completed recovery lifecycle (#18) (`5da827f0a539`)
- fix(release): scan extracted OCI layout (#19) (`50e1ae0aeb38`)
- fix(release): bind platform readback to manifests (#20) (`b455ca2f0ac8`)
- fix(release): reconcile incomplete registry aliases (#21) (`fd3d28d845d2`)
- fix(release): make completion cleanup reentrant (#22) (`7906697af117`)
- fix(release): authorize merged PR label cleanup (#23) (`4379072bb68d`)

### Other changes

- chore: finalize management production gates (`b583963e5d0f`)
- ci: document and scope the pinned Web build action (#4) (`c530a2fe8cec`)
- ci: make immutable release recovery idempotent (#5) (`08c699222576`)
- revert: withdraw stale management v1 candidate (#16) (`04e71291ee0c`)
- chore(deps): bundle Remote Client v1.0.0 (#24) (`fcabdb418c36`)
