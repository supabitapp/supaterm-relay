# WebSocket footprint spike

Measures idle memory per socket and echo throughput for the relay and for two alternative socket models, on Linux in Docker (arm64, 4 CPUs, Go 1.27.2, `GOMEMLIMIT=2GiB`).

| Path | What it is |
| --- | --- |
| `lean.patch` | Relay changes behind `SPIKE_HANDOFF=1` (return from the HTTP handler after upgrade), `SPIKE_READBUF=<bytes>` (gorilla read buffer) and `SPIKE_PINGTIMER=1` (data-socket pings from a timer instead of a goroutine) |
| `hold/` | Relay load generator: holds paired users idle and samples memory, or runs the echo benchmark with `-mode bench` |
| `epoll/` | Standalone forwarder on gobwas/ws in `-mode goroutine` (one goroutine per socket, no idle buffers) or `-mode epoll` (no goroutine per idle socket), with its own load generator |
| `results/` | Raw samples; `python3 summarize.py` prints the tables |

```sh
spike/build-variants.sh
spike/run-hold.sh baseline -steps 0,1000,5000,15000
SPIKE_HANDOFF=1 SPIKE_READBUF=256 SPIKE_PINGTIMER=1 SPIKE_TAG=all spike/run-hold.sh lean -steps 0,1000,5000,15000
spike/run-hold.sh baseline -mode bench
spike/run-epoll.sh epoll -steps 0,1000,5000,15000
spike/run-epoll.sh epoll -mode bench
```

A paired user is one host control socket and two data sockets. Memory is sampled after two forced GCs, 20 seconds after each step.
