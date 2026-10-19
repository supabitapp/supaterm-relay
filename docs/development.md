# Development

Use Go 1.27.2 or later. The module selects Go 1.27.2 through its `toolchain` directive; older Go installations download it when automatic toolchain selection is enabled.

| Command | Purpose |
| --- | --- |
| `make build` | Build `bin/relay` |
| `make run` | Listen on `127.0.0.1:8080` |
| `make test` | Check formatting and `go.mod` tidiness, vet all packages and the container suite, and run all Go tests in shuffled order with the race detector |
| `make audit` | Report known vulnerabilities reachable from the relay binary with `govulncheck`. Standard library results depend on the local Go version |
| `make e2e-docker` | Verify one relay through the published port and a separate probe container |
| `make bench` | Measure standalone relay echo throughput and latency on loopback |
| `make bench-docker` | Measure the relay from another container and retain resource samples |

Pull requests run `make -j2 test` and `make audit` in [CI](../.github/workflows/ci.yml). Code changes pushed to `main` run `make -j2 test` before deploying.

The container suite checks the public surface, pairing and ordered streaming across 12 hosts, duplicate identity replacement, graceful restart and abrupt restart, per-client limits, and log privacy. It removes its containers and network on completion. Set `E2E_KEEP=1` to retain them, `E2E_SKIP_BUILD=1` to use existing images, or `E2E_RELAY_PORT` to change the published port.

The benchmark accepts `-url` for an existing relay or `-spawn` for a local process. Payload sizes, client counts, message window, and measurement duration are configurable. Spawned relays default the per-host client network quota to the host capacity and preserve an explicit `RELAY_MAX_CLIENTS_PER_HOST_PER_IP` value. Container benchmarks set that quota to the host capacity. Existing relays retain their [configured quotas](configuration.md). Verify payloads and stop on failed echoes when testing a live service.

The [performance tuning notes](performance.md) cover component benchmarks, profiling, measured allocation reductions, and the Go 1.27 JSON v2 decision. Run those benchmarks separately from tests and other load generators.

`make test` replays the fixed fuzz seeds. Run a campaign with `go test ./internal/relay -run '^$' -fuzz '^FuzzControlQueue$' -fuzztime=30s`, substituting the package and target. `FuzzPairLifecycle` opens real sockets and can exhaust local addresses, so bound it with `-fuzztime=1000x -parallel=1`.
