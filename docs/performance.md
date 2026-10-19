# Performance tuning

## Decision

Keep production imports on `encoding/json` for now. **Go 1.27.2 already runs that API on the v2 engine**, retaining v1 semantics. Direct `encoding/json/v2` adoption is supported in this toolchain, but is not an automatic speedup and does not accelerate ciphertext forwarding.

The measured wins here are bounded host ranking, typed control messages, allocation-free valid proxy-header parsing, reuse of empty control queues, and canonical Base64 validation without re-encoding. Forwarding buffers, deadlines, backpressure, admission limits, and CI/deployment gates are unchanged.

## Local measurements

Measured on 2026-10-19 against baseline `0145c4e`, using Go 1.27.2, darwin/arm64, Apple M2, default GOMAXPROCS 8, no race instrumentation or experiment override. These are local component measurements, **not production throughput estimates**. Times are medians of five 300 ms samples. IP parsing was remeasured in alternating baseline/current order. Control encoding compares the old map shape and the actual new five-field struct in the same run; setup and payload lengths match.

| Operation | Before | After | Bytes/op before → after | Allocs/op before → after |
| --- | ---: | ---: | ---: | ---: |
| Rank 20 hosts | 663 ns | 391 ns | 896 → 896 | 1 → 1 |
| Rank 1,000 hosts | 90.4 µs | 10.3 µs | 40,960 → 896 | 1 → 1 |
| Rank 50,000 hosts | 6.70 ms | 0.359 ms | 2,007,040 → 896 | 1 → 1 |
| Encode incoming control message | 569 ns | 338 ns | 552 → 288 | 9 → 3 |
| Push/pop/release one control message | 46.3 ns | 38.7 ns | 32 → 0 | 1 → 0 |
| Decode canonical 32-byte Base64 value | 76.2 ns | 37.9 ns | 128 → 32 | 3 → 1 |
| Decode canonical 64-byte Base64 value | 122 ns | 62.4 ns | 256 → 64 | 3 → 1 |
| Parse one forwarded address | 104 ns | 92.7 ns | 16 → 0 | 1 → 0 |
| Parse a forwarded chain | 153 ns | 125 ns | 48 → 0 | 1 → 0 |
| Parse repeated forwarding headers | 178 ns | 124 ns | 80 → 0 | 2 → 0 |
| Parse a direct, untrusted peer | 38.6 ns | 40.5 ns | 0 → 0 | 0 → 0 |

The direct-peer control has no allocation benefit and was slightly slower; this is not an across-the-board IP-parsing speedup. Valid proxy paths avoid temporary joins/splits, and can stop at the first untrusted hop without processing a spoofed prefix. Malformed-address errors can still allocate inside `netip.ParseAddr`.

Host ranking no longer allocates/sorts all hosts under the server mutex. It scans every host but retains only a descending top-20 list: O(N × K) worst-case work and O(K) result memory, with K fixed at 20. Most candidates are rejected in constant time once the list is full. Ranking ties remain unspecified, empty output remains `[]`, and endpoint prefixes remain private-only.

Control messages retain the previous exact JSON field order and omission behavior. Queue reuse is for the common drained queue, not a new payload queue or a promise of allocation-free arbitrary bursts. Base64 validation retains strict trailing-bit checks and rejects CR/LF, padding, and wrong lengths; no hand-written codec was introduced.

### Established-session control

The forwarding path already uses `NextReader → NextWriter → io.Copy`; Gorilla's `ReadFrom` reads directly into the pooled writer buffer. Adding another copy buffer, accumulating complete messages, or retaining permanent 16 KiB buffers on every idle socket would not be a free improvement.

A three-second, in-process 1 KiB forwarding CPU profile was dominated by socket syscalls and macOS event polling (about 71% and 26% of samples). Its allocation profile was dominated by Gorilla reader/writer objects. The ordinary forwarding benchmark includes both endpoints, not just relay costs, and measured five allocations per forwarded message across 64 B, 1 KiB, and 64 KiB payloads. This does not justify rewriting the WebSocket library or weakening deadlines.

The separate-process echo check used four hosts, four messages in flight per client, 500 ms warmup and two-second windows. Baseline/current order alternated across three repetitions. Values below are medians of run-level measurements; all **36 cases had zero failed or corrupt messages**.

| Payload | Clients | Before msg/s | After msg/s | Before p99 RTT | After p99 RTT |
| --- | ---: | ---: | ---: | ---: | ---: |
| 64 B | 1 | 41,610 | 45,280 | 233 µs | 207 µs |
| 64 B | 32 | 57,166 | 59,192 | 3.49 ms | 3.38 ms |
| 1 KiB | 1 | 43,550 | 43,124 | 204 µs | 199 µs |
| 1 KiB | 32 | 59,186 | 57,824 | 3.70 ms | 4.01 ms |
| 64 KiB | 1 | 5,762 | 5,324 | 1.25 ms | 1.44 ms |
| 64 KiB | 32 | 5,286 | 5,394 | 52.3 ms | 54.4 ms |

These mixed changes on a shared workstation do **not** establish a steady-state throughput or latency improvement. The optimized operations occur during connection churn and metrics collection, not each forwarded message. The echo check did not load those operations concurrently, and is not a capacity or long-duration test.

## Should we use encoding/json/v2?

Not as a blanket performance change for this relay:

- The [Go 1.27 release notes](https://go.dev/doc/go1.27#jsonv2) and [migration guide](https://go.dev/doc/jsonv2-migration) confirm that v2 is available by default and migration is optional. The Go 1.25 experimental announcement is not the current toolchain's status.
- On the installed toolchain, `go list -f '{{.GoFiles}}' encoding/json` selects the `v2_*.go` files. Its `Marshal`/`Unmarshal` wrappers call v2 with `DefaultOptionsV1()`. No `GOEXPERIMENT=jsonv2` setting is needed.
- Production JSON is control/authentication, HTTP status/metrics, and startup logs. Ciphertext is never JSON-decoded, including text frames that happen to contain JSON.
- Default v2 rejects duplicate names and invalid UTF-8 and matches struct fields case-sensitively. Authentication acceptance changes in both directions when differently cased aliases coexist. Unknown fields are still ignored by default. Treat changes to that policy as deliberate protocol hardening, not an incidental optimization.
- Map ordering, escaping, nil collections and streaming/newline APIs also differ. Existing untagged startup/metrics consumers rely on v1's case-insensitive matching; replacing imports alone can silently leave their fields empty. Gorilla's JSON helpers continue using the v1 API.
- Direct production imports require raising the module's `go 1.25.0` minimum or version-gated alternatives: the mandatory `go vet` stdversion check rejects unguarded Go 1.27 APIs even with `toolchain go1.27.2` selected. No minimum-version change was needed for the implemented optimizations.

Five 500 ms samples of the repository's version-gated API benchmarks:

| Codec-only operation | v1 API | v2 API | Allocation change |
| --- | ---: | ---: | --- |
| Encode typed incoming control | 304 ns | 321 ns | None: 288 B / 3 allocations |
| Decode canonical authentication object | 309 ns | 232 ns | None: 32 B / 1 allocation |

The auth saving is about **77 ns per registration**, before Base64 decoding, Ed25519 verification, HTTP/WebSocket setup, and network I/O. It is not a reason to change the accepted authentication language on its own.

An additional scratch comparison using the baseline's full metrics shape with 20 hosts, two-space indentation and a final newline measured 13.1 µs for v1, 10.6 µs for default v2, and 11.5 µs for deterministic v2. Default v2 omits map sorting. Streaming v2 reduced buffered-output allocations, but this experiment used `io.Discard` and excluded host ranking, `ReadMemStats`, locks and HTTP writes. It is not a measured handler improvement. If metrics serialization becomes a profile hotspot, evaluate a typed metrics snapshot and streaming together, preserving response framing/privacy and checking partial-write behavior.

## Reproduce and validate

Benchmarks live in the ordinary package test suites; they are not run by CI unless explicitly requested. The v2 comparison file requires `go1.27 && goexperiment.jsonv2`, so it does not raise the production module minimum or break the old-engine diagnostic build.

```sh
go test ./internal/relay ./internal/admission -run '^$' \
  -bench 'Benchmark(Forward|TopHosts|ControlFrame|ControlQueue|DecodeB64|ClientIP)$' \
  -benchmem -benchtime=300ms -count=5

go test ./internal/relay -run '^$' -bench 'BenchmarkJSON' \
  -benchmem -benchtime=500ms -count=5

go test ./internal/relay -run '^$' -bench '^BenchmarkForward/1024B$' \
  -benchtime=3s -cpuprofile=/tmp/relay.cpu -memprofile=/tmp/relay.mem \
  -o /tmp/relay.test
go tool pprof -top /tmp/relay.cpu

make build
go run ./e2e/bench -spawn -relay-bin bin/relay -warmup=500ms -duration=2s
make -j2 test
```

For a before/after comparison, use identical benchmark code and toolchains on separate baseline/current checkouts, preserve payload and endpoint settings, alternate execution order, and retain individual samples. Do not compare race-instrumented timings with release timings.

Validation passed: `make -j2 test` (formatting, module tidiness, both vet commands and uncached shuffled race tests), focused legacy-engine tests with `GOEXPERIMENT=nojsonv2`, short two-worker fuzz campaigns for proxy parsing, canonical Base64 and queue accounting, exact control-wire tests, exhaustive-reference host-ranking tests, and independent code review. Tagged Docker scenarios and production/TLS load tests were not run; Docker vet remains in the mandatory check target.

Further transport tuning needs measurements on the actual deployment. Earlier transport measurements found a shared outbound bandwidth ceiling and a latency/throughput tradeoff from endpoint pacing. Measure current network capacity and outstanding bytes before adding CPUs, backend hops, buffers or queues. Preserve interrupted-message failure, slow-reader isolation, bounded memory and exact timeout behavior in any subsequent experiment.
