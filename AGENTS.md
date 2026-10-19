# CI commands

- Run `make -j2 test` for the CI path. Keep `check` and `test-race` mandatory prerequisites of `test`, including formatting, module tidiness, both vet commands, and race tests with uncached shuffled execution.
- Add ordinary Go tests to the packages discovered by `./...`; keep tagged container scenarios in `make e2e-docker` and their vet check in `check`. Read package duration lines before sharding, accounting for the roughly 13s baseline startup and setup per added job.
- Preserve the `test` and `audit` check identities, PR-only cancellation, and serialized deployment with its CI dependency and smoke probes. Re-measure completed runs before increasing parallel jobs or runner spending.
