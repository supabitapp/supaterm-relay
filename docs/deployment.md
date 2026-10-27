# Deployment

The deployment workflow installs the relay on two independent machines. `supaterm-relay.exe.xyz` serves clients and hosts directly behind the exe.dev HTTPS proxy at `wss://relay.supaterm.com`. An AWS Lightsail instance in Stockholm (`eu-north-1`) serves `wss://relay2.supaterm.com` behind Cloudflare's proxy.

The exe.dev relay also serves `wss://relay.supacode.sh` for Supacode builds, so hosts and clients on either hostname share one set of registrations.

Both hostnames are DNS-only Cloudflare CNAMEs to `supaterm-relay.exe.xyz`, each registered with `ssh exe.dev domain add supaterm-relay <hostname>`; exe.dev manages their TLS certificates. Keep Cloudflare proxying off for these records, as required by [exe.dev's custom-domain setup](https://exe.dev/docs/cnames).

`relay2.supaterm.com` is a proxied Cloudflare A record for the Lightsail static IP `13.63.231.197`. Cloudflare terminates public TLS and connects to [Caddy](../deploy/relay2/Caddyfile) on port 443, which presents a Cloudflare Origin CA certificate; a configuration rule sets SSL to Full (strict) for this hostname only. Caddy accepts only connections that present the authenticated origin pull certificate uploaded for `relay2.supaterm.com`, so requests through other Cloudflare accounts cannot reach the relay. The [firewall](../deploy/relay2/nftables.conf) accepts port 443 only from Cloudflare's published IP ranges, and SSH from anywhere; update it when Cloudflare changes those ranges.

Caddy replaces `X-Forwarded-For` with `CF-Connecting-IP` before proxying to `127.0.0.1:8080`, so the relay's per-network quotas count the visitor's address. A [drop-in](../deploy/relay2/memory.conf) at `/etc/systemd/system/supaterm-relay.service.d/memory.conf` lowers the Go memory target to 1 GiB and the service cap to 1.5 GiB for the 2 GiB machine. Caddy's file lives at `/etc/caddy/Caddyfile` and the firewall's at `/etc/nftables.conf`. These files are installed by hand; the workflow installs only the binary and service unit, and fails relay2's deployment before installing when any live copy differs from the repository.

The [service unit](../deploy/supaterm-relay.service) binds protocol traffic to `127.0.0.1:8080` and private health and detailed metrics to `127.0.0.1:9090`. The exe.dev proxy forwards the public TLS endpoint to port 8080. Only the local proxy may supply the client IP, and the private listener accepts loopback peers only. Public `/metrics` contains aggregate counters. The public [`/dashboard/`](https://relay.supaterm.com/dashboard/) refreshes those counters every two seconds and adds throughput, process CPU, the machine's load average and memory, and the process start time. Host traffic details stay on the private listener.

Code changes pushed to `main` run [the deployment workflow](../.github/workflows/deploy.yml): the race test suite, then, on each machine in parallel, a Linux build, service installation, and verified smoke exchanges through its public hostname. The exe.dev machine is also smoke tested at its origin, `wss://supaterm-relay.exe.xyz`. Restarting the relay closes its sockets, so hosts and clients must reconnect. Each relay instance owns its authenticated registrations and pairs in memory; distributing an endpoint's sockets across independent instances is unsupported. The two machines share no registrations, so a client must connect through the relay its host registered with.

The [installer](../deploy/install-relay.sh) installs the binary and unit, restarts the service, and enables it once the private health check passes.

Each machine is its own failure domain; this deployment does not implement automatic failover between them.
