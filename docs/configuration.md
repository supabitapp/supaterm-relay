# Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `RELAY_ADDR` | `127.0.0.1:8080` | Listen address |
| `RELAY_MAX_MESSAGE_BYTES` | `33554418` | Largest single message |
| `RELAY_MAX_CLIENTS_PER_HOST` | `64` | Pairs per host. Matches the Supaterm host's 64-pair cap; excess connections receive HTTP 503 |
| `RELAY_MAX_CLIENTS_PER_HOST_PER_IP` | `16` | Pairs per host from one client network, including pending, active and closing pairs. Excess connections receive HTTP 429 |
| `RELAY_MAX_CONNS_PER_IP` | `128` | Concurrent protocol connections per client network |
| `RELAY_AUTH_TIMEOUT_MS` | `5000` | Time to answer the challenge |
| `RELAY_PAIR_TIMEOUT_MS` | `5000` | Time for the host to complete accepting a client |
| `RELAY_DELIVERY_TIMEOUT_MS` | `30000` | How long a write to a pair's receiver may stay blocked before the receiver is closed |
| `RELAY_HEARTBEAT_MS` | `15000` | Ping interval |
| `RELAY_ADMISSION_RATE` | `100` | Connection attempts per second per client network |
| `RELAY_TRUSTED_PROXIES` | | CIDRs whose `X-Forwarded-For` is trusted |
| `RELAY_PRIVATE_ADDR` | | Separate listener for `/healthz` and `/metrics`. Bind it to a loopback or private address |

The relay refuses to start when `RELAY_ALLOWED_PEERS`, `RELAY_PRIVATE_ALLOWED_PEERS`, or `RELAY_CLIENT_IP_HEADER` is set. Restrict access by binding each listener to the addresses that may reach it; a trusted proxy supplies the client IP in `X-Forwarded-For`.

Client quotas use one IPv4 address or one IPv6 `/64` prefix. IPv4-mapped IPv6 addresses share the IPv4 quota. Devices behind the same IPv4 NAT or within the same IPv6 `/64` share these limits. Keep `RELAY_MAX_CLIENTS_PER_HOST_PER_IP` below `RELAY_MAX_CLIENTS_PER_HOST` to leave capacity for other networks. Hosts with many clients on one network may need a higher per-network limit. The relay cannot distinguish application-authenticated clients inside encrypted traffic. The admission rate limiter tracks at most 65,536 client networks; while it is full, new networks receive HTTP 429 until entries idle for a minute expire.

Each host's control queue holds at most 256 notifications or 64 KiB; a host that falls further behind is closed with 1013. Control and close writes time out after 5 seconds. These limits are fixed.

The relay accepts at most 50,000 protocol connections in total, including authentication and pairing; further connections receive HTTP 503 while existing sessions continue. This ceiling is fixed. It has no separate limit on hosts or pairs. The [service unit](../deploy/supaterm-relay.service) is sized for the 2 GiB production machine: it sets a 1 GiB soft Go memory target and caps the service at 1.5 GiB of memory and 131,072 open files.
