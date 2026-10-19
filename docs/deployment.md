# Deployment

The deployment workflow installs one standalone relay on `supaterm-relay.exe.xyz`. The relay serves clients and hosts directly behind the exe.dev HTTPS proxy at `wss://relay.supaterm.com`.

The same relay also serves `wss://relay.supacode.sh` for Supacode builds, so hosts and clients on either hostname share one set of registrations.

The [service unit](../deploy/supaterm-relay.service) binds protocol traffic to `127.0.0.1:8080` and private health and detailed metrics to `127.0.0.1:9090`. The exe.dev proxy forwards the public TLS endpoint to port 8080. Only the local proxy may supply the client IP, and the private listener accepts loopback peers only. Public `/metrics` contains aggregate counters. The public [`/dashboard/`](https://relay.supaterm.com/dashboard/) refreshes those counters every two seconds and adds throughput, process CPU, the machine's load average and memory, and the process start time. Host traffic details stay on the private listener.

Code changes pushed to `main` run [the deployment workflow](../.github/workflows/deploy.yml): the race test suite, a Linux build, service installation, and verified smoke exchanges through both public hostnames. Restarting the relay closes its sockets, so hosts and clients must reconnect. Each relay instance owns its authenticated registrations and pairs in memory; distributing an endpoint's sockets across independent instances is unsupported.

The [installer](../deploy/install-relay.sh) installs the binary and unit, restarts the service, and enables it once the private health check passes.

A single relay has one failure domain; this deployment does not implement automatic failover.
