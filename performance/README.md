# Management performance scenario

`contract.lock` pins the exact `remote-protocol` commit that supplies the shared, dependency-free evidence collector. CI checks out that immutable revision; Management does not add a Protocol runtime dependency or maintain a divergent schema implementation.

`management_http_observation.py` creates a fresh private SQLite database for each process, migrates and seeds synthetic devices outside the timed window, then measures the real authenticated `/api/devices` control-filter path. PR evidence covers application/query-shape regressions; scheduled and release evidence must run the same scenario against isolated PostgreSQL and record a distinct tier. It refuses every PostgreSQL environment variable so a local smoke cannot connect to an operator database by accident.
