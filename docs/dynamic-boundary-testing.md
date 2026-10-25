# Dynamic boundary testing

The normal Required pytest suite discovers
`api/test_dynamic_input_contract.py`. It combines fixed malformed JSON cases,
512 deterministic mutations, and 100 derandomized Hypothesis examples. Inputs,
nesting, numeric precision, and execution time are bounded.

The scheduled `Dynamic Boundaries` workflow repeats that contract on
Ubuntu 24.04 with Python 3.15.1, `uv 0.13.5`, and the committed dependency lock.
The ten-minute job budget covers environment setup; the mutation test has its
own 60-second limit and each Hypothesis example has a 500 ms deadline.

The test constructs synthetic values only. It reads no environment secrets,
credentials, database rows, raw logs, addresses, or user data. It uploads no
corpus. This layer tests JSON parsing, not PostgreSQL, Compose, browser, or
Win11 runtime behavior; those remain in their dedicated integration suites.
