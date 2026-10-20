# Development

Use Go 1.27.2 or later. The module selects Go 1.27.2 through its `toolchain` directive; older Go installations download it when automatic toolchain selection is enabled.

| Command | Purpose |
| --- | --- |
| `make build` | Build `bin/relay` |
| `make run` | Listen on `127.0.0.1:8080` |
| `make test` | Check formatting and `go.mod` tidiness, vet all packages, the container suite and the Supaterm interop suite, and run all Go tests in shuffled order with the race detector |
| `make audit` | Report known vulnerabilities reachable from the relay binary with `govulncheck`. Standard library results depend on the local Go version |
| `make e2e-docker` | Verify one relay through the published port and a separate probe container |
| `make interop` | Run Supaterm's own relay host and client from `SUPATERM_DIR` against a race-enabled relay build |
| `make bench` | Measure standalone relay echo throughput and latency on loopback |
| `make bench-docker` | Measure the relay from another container and retain resource samples |

Pull requests run `make -j2 test`, `make audit`, and `make interop` against the latest Supaterm release and nightly in [CI](../.github/workflows/ci.yml). Code changes pushed to `main` run `make -j2 test` and both interop jobs before deploying. After deploying, the smoke probes pair plain sockets and then carry HTTP, an inner WebSocket and an encrypted ping through a Supaterm tunnel on the public endpoint.

`e2e/supaterm` reproduces Supaterm's relay host, client handshake and tunnel multiplexer in Go. `make test` runs it against the relay binary: fixture routes, bulk and full-duplex transfers, inner WebSockets, the 64-pair host cap, quotas, relay and host restarts, superseded hosts, drain, and the failure each relay answer produces in Supaterm's clients. Its `testdata/vectors.json` is copied from Supaterm's `apps/mobile/modules/supaterm-relay-tunnel/android/jvm/fixtures/vectors.json`; refresh both when Supaterm changes the tunnel protocol.

`make interop` needs a Supaterm checkout whose relay dependencies are installed with `pnpm install --frozen-lockfile --ignore-scripts --filter ./apps/server... --filter ./packages/shared...`. It drives Supaterm's `nativeFixture.ts` through the client's loopback origin, then restarts the relay and the host.

The container suite checks the public surface, pairing and ordered streaming across 12 hosts, duplicate identity replacement, graceful restart and abrupt restart, per-client limits, and log privacy. It removes its containers and network on completion. Set `E2E_KEEP=1` to retain them, `E2E_SKIP_BUILD=1` to use existing images, or `E2E_RELAY_PORT` to change the published port.

The benchmark accepts `-url` for an existing relay or `-spawn` for a local process. Payload sizes, client counts, message window, and measurement duration are configurable. Spawned relays default the per-host client network quota to the host capacity and preserve an explicit `RELAY_MAX_CLIENTS_PER_HOST_PER_IP` value. Container benchmarks set that quota to the host capacity. Existing relays retain their [configured quotas](configuration.md). Verify payloads and stop on failed echoes when testing a live service.

`make test` replays the fixed fuzz seeds. Run a campaign with `go test ./internal/relay -run '^$' -fuzz '^FuzzControlQueue$' -fuzztime=30s`, substituting the package and target. `FuzzPairLifecycle` opens real sockets and can exhaust local addresses, so bound it with `-fuzztime=1000x -parallel=1`.
