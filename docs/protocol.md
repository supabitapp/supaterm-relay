# Protocol

1. The host opens `/v1/control?publicKey=B64` and answers the relay's challenge.
2. A client opens `/v1/connect?endpointId=HEX`.
3. The relay sends the host `{"type":"incoming","connectionId":"ID","token":"TOKEN"}`.
4. The host opens `/v1/accept?endpointId=HEX&connectionId=ID&token=TOKEN`, and the two sockets are paired. A host may ignore `incoming`, for example when it is at capacity; the relay closes that client with 1013 after `RELAY_PAIR_TIMEOUT_MS`.
5. When either side closes, the relay sends the host `{"type":"closed","connectionId":"ID"}`.

The relay serves `/v1/control`, `/v1/connect` and `/v1/accept` at the root and under any path prefix, so a relay URL such as `wss://relay.example/tunnel` works behind a proxy that forwards the full path. Health, metrics and the dashboard stay at the root.

Messages keep their order, boundaries, and text or binary type. Before acceptance the relay pauses application reads; early bytes wait in the socket buffers and arrive once the pair is ready.

Each direction streams into a fixed WebSocket writer buffer. A pooled 4 KiB socket buffer combines already-available frames, flushing before reading more input and immediately for control frames. Reads take a second pooled 4 KiB buffer only when input is ready, so one read collects every frame that has arrived. A slow receiver stops its sender through TCP backpressure. The configured data-buffer capacity totals about 50 KiB per pair, plus framing, connection state, goroutine stacks and socket memory. Buffers do not grow with message size or elapsed traffic; idle sockets return their batch and read buffers to the pool. Pending, active and closing connections retain their admission slots until cleanup finishes.

A blocked receiver is closed with 1013 after `RELAY_DELIVERY_TIMEOUT_MS`. Oversized or interrupted messages may forward partial fragments, but those fragments are never finalized into a successful shorter message. Close frames are attempted within a bounded deadline; an aborted or stalled transport can prevent their delivery. Control notifications use a bounded queue.

`endpointId` is the lowercase hex SHA-256 of the host's 32-byte Ed25519 public key. Base64 values are unpadded Base64URL.

## Authentication

```text
relay → host  {"type":"challenge","nonce":"B64"}
host  → relay {"type":"authenticate","signature":"B64"}
relay → host  {"type":"registered","endpointId":"HEX"}
```

The host signs `"supaterm-relay-v1\n" + endpointId + "\n" + nonce`. The relay also accepts the `"supacode-relay-v1\n"` prefix that Supacode builds sign. A bad signature or a timeout closes the socket with 1008. If the same endpoint registers again and authenticates, the newer registration wins and the older control socket closes with 4001. A host that gets 4001 shouldn't reconnect automatically, because something else holding its key took over. After registering, the host must not send anything on the control socket, or the relay closes it.

Treat `connectionId` as opaque. The relay generates a random unpadded Base64URL value.

## Close codes

| Code | Reason |
| --- | --- |
| peer's code | Forwarded from the other side |
| 1001 | Peer disconnected or timed out, host went offline, relay is shutting down, or relay is draining |
| 1008 | Authentication failed or unexpected control message |
| 1009 | Message larger than `RELAY_MAX_MESSAGE_BYTES` |
| 1011 | Upgrade failed |
| 1013 | Pair timeout, delivery timeout, or control queue full |
| 4001 | Registration superseded by a newer one for the same endpoint |

## HTTP

A client connecting to an endpoint with no registered host receives HTTP 404, which Supaterm reports as the host being offline. Protocol requests receive HTTP 429 when a [client network quota](configuration.md) is reached, or HTTP 503 when the relay holds 50,000 protocol connections, the host already has `RELAY_MAX_CLIENTS_PER_HOST` pairs, or the relay is draining. These checks run before the WebSocket upgrade. The per-host client quota counts a pair until both sides finish cleanup.

`GET /healthz` returns 200, or 503 while shutting down. `GET /metrics` returns JSON counters, including active and closing admission slots, configured data-buffer capacity, Go heap and allocation counters, and `topHosts`. `topHosts` lists the 20 hosts on the relay that have relayed the most bytes since they registered, with the first 16 hex characters of each endpoint ID, bytes relayed to and from the host, and open pairs. When `RELAY_PRIVATE_ADDR` is set, health and detailed metrics use that listener. The public `/metrics` response retains aggregate counters and excludes `topHosts`. `relay healthcheck` and `relay metrics` query them locally.

The production service serves aggregate stats at [https://relay.supaterm.com/metrics](https://relay.supaterm.com/metrics). Public metrics use a separate per-client limiter at `RELAY_ADMISSION_RATE`, so polling consumes no WebSocket admission slots. `openConnectionIPs` counts client quota groups, using the same address grouping as admission. `rejectedConnectionsByReason` splits `rejectedConnections` by the reason returned to the caller. `endpoint not found` counts clients connecting to an endpoint that is not registered, usually because its host is offline, so a client that keeps retrying an offline host raises it without indicating relay pressure. Private metrics are not rate limited.
