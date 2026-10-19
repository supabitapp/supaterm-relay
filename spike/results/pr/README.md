# Idle-socket PR samples

`main` is commit `e652282`. `final` is commit `23d0db8` on `khoi/lean-idle-sockets`. Both relays were built with `-tags spike` (the pprof hook in `cmd/relay/spike_pprof.go`) and run by `spike/run-hold.sh` with `RELAY_ADMISSION_RATE=1000000`, `RELAY_MAX_CONNS_PER_IP=1000000` and `GOMEMLIMIT=2GiB` in an `alpine:3.22` container limited to 4 CPUs.

- `*-pairs.jsonl`: `-steps 0,15000`, one host control socket and two data sockets per user.
- `*-hosts.jsonl`: `-hosts-only -steps 0,15000`.
- `bench-<build>-<run>.jsonl`: `-mode bench`, defaults (64 B, 1 KiB and 64 KiB payloads; 1 and 32 clients; 4 in flight; 2 s warmup; 5 s window). Runs alternated `main`, `final` three times.

Per-socket values are (sample at 15,000 users minus sample at 0) divided by sockets.
