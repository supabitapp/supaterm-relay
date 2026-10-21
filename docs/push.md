# Push gateway

`cmd/push` is the gateway that delivers Supaterm notifications to iPhones through APNs. It runs as its own binary and service; the relay never holds APNs keys. Phones enroll with it directly, and Supaterm hosts send it notifications that are already end-to-end encrypted to the phone. The gateway cannot read them.

## What it stores

The SQLite database at `PUSH_DATABASE` holds three tables:

| Table | Columns |
| --- | --- |
| `installations` | ID, SHA-256 of the owner token, APNs device token, topic, environment, created and updated times |
| `handles` | handle, installation ID, the host's Ed25519 public key, created time |
| `enrollments` | ID, device token, topic, environment, installation ID being rotated, SHA-256 of the challenge code, failed attempts, expiry |

Rate-limit buckets and the signature replay cache live in memory and reset on restart. The gateway never stores or logs notification payloads, and never logs device tokens, handles, or owner tokens. Its logs carry APNs status codes and reasons.

## Protocol

Bodies are JSON and at most 8 KiB. Binary values are unpadded base64url; device tokens are lowercase hex. Errors are `{"error": "<code>", "message": "<text>"}`, and 429 responses carry `Retry-After`.

**Owner auth** is `Authorization: Bearer <ownerToken>` for the installation in the path. An unknown installation answers 404, a wrong token 401.

**Host auth** is three headers: `supaterm-push-key` (the Ed25519 public key), `supaterm-push-timestamp` (unix milliseconds), and `supaterm-push-signature` over

```text
supaterm-push-request-v1\n<METHOD>\n<path>\n<timestamp>\n<lowercase hex SHA-256 of the body>
```

The timestamp must be within 300 seconds of the gateway's clock, and a signature is accepted once.

| Endpoint | Auth | Result |
| --- | --- | --- |
| `POST /v1/enrollments` `{token, topic, environment, installationId?}` | owner auth when `installationId` is set | Sends a challenge push and answers `201 {enrollmentId, expiresAt}` |
| `POST /v1/enrollments/{id}/confirm` `{code}` | none | `200 {installationId, ownerToken?}` |
| `GET /v1/installations/{id}` | owner | `200 {installationId, topic, environment, handles}` |
| `DELETE /v1/installations/{id}` | owner | 204; deletes its handles |
| `POST /v1/installations/{id}/handles` `{hostKey}` | owner | `201 {handle}`; at most 64 per installation |
| `DELETE /v1/installations/{id}/handles/{handle}` | owner | 204 or 404 |
| `POST /v1/send` `{handle, payload, expiration, priority, collapseId?}` | host | `200 {status: "accepted"}` |
| `DELETE /v1/handles/{handle}` | host | 204, or 404 unless the handle belongs to the signing key |
| `GET /healthz` | none | `ok`, or 503 when the database is unavailable |

### Enrollment

Enrolling proves the phone holds the device token. The gateway pushes `{"supatermChallenge": {"enrollmentId", "code"}}` to the token, and the app confirms with the code within 10 minutes. Five wrong codes delete the enrollment.

Confirming without an `installationId` creates an installation and returns its owner token, once. Confirming an enrollment that named an `installationId` moves that installation to the new token and keeps its handles. Either way, every other installation holding the same token is deleted with its handles, because it belongs to an earlier install of the app on that device.

The topic must be listed in `APNS_TOPICS` (403 `topic_not_allowed`) and the environment must have a configured key (400). APNs rejecting the token answers 410 `token_rejected`.

### Sending

A handle is bound to the host key the phone minted it for. `/v1/send` answers 410 `gone` for an unknown handle, a deleted installation, or a different signing key, without saying which. `payload` must be a JSON object; it is forwarded as the `supaterm` key of an alert with the generic text `Supaterm` / `New activity` and `mutable-content: 1`, and the whole APNs body must fit in 4096 bytes. `expiration` is unix seconds, at most 24 hours ahead; `priority` is 10 or 5.

| APNs answer | Gateway answer |
| --- | --- |
| 200 | 200 `accepted` |
| 410, or 400 `BadDeviceToken` / `DeviceTokenNotForTopic` | Deletes the installation, 410 `gone` |
| 403, or 400 `BadTopic` / `TopicDisallowed` / `MissingTopic` | 503 `gateway_unavailable`: the gateway's credentials or topics are wrong |
| 429, 5xx, other errors, or no answer | 502 `apns_unavailable` |

Hosts may retry 502 and 503.

### Limits

| Scope | Limit |
| --- | --- |
| Enrollments per client network | 20 per rolling hour |
| Challenges per device token | 5 per rolling hour |
| Handle mints and host deletions per installation | 30 per hour, burst 10 |
| Handle mints and host deletions per client network | 120 per hour, burst 30 |
| Sends per handle | 30 per minute, burst 10 |
| Sends per host key | 600 per minute, burst 60 |
| Sends per installation | 120 per minute, burst 20 |

The replay cache holds at most 262,144 live signatures. While it is full, new signed requests answer 429 `rate_limited` instead of evicting signatures that could still be replayed.

A client network is one IPv4 address or IPv6 `/64`. The gateway takes the client address from `X-Forwarded-For` only when the peer is loopback, which is the local HTTPS proxy in production.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PUSH_ADDR` | `127.0.0.1:8000` | Listen address |
| `PUSH_DATABASE` | | SQLite database path. Required |
| `APNS_TEAM_ID` | | Apple developer team ID. Required |
| `APNS_TOPICS` | | Comma-separated bundle IDs the gateway serves. Required |
| `APNS_SANDBOX_KEY_ID`, `APNS_SANDBOX_KEY_FILE` | | Key ID and `.p8` file for `api.sandbox.push.apple.com` |
| `APNS_PRODUCTION_KEY_ID`, `APNS_PRODUCTION_KEY_FILE` | | Key ID and `.p8` file for `api.push.apple.com` |

Set each environment's ID and file together; at least one environment is required. Enrollments for an environment without a key are refused. The provider JWT for each key is reused for 50 minutes.

A fork that ships its own app runs this gateway with its own team, keys, and bundle ID, and adds its origin to its hosts' allowed push gateways.

## Deployment

The official gateway runs on `supaterm-push.exe.xyz` behind the exe.dev HTTPS proxy, which serves it as `https://push.supaterm.com`. `push.supaterm.com` is a DNS-only Cloudflare CNAME to `supaterm-push.exe.xyz`, registered with `ssh exe.dev domain add supaterm-push push.supaterm.com`; keep Cloudflare proxying off, as [exe.dev's custom-domain setup](https://exe.dev/docs/cnames) requires.

The [service unit](../deploy/supaterm-push.service) listens on `127.0.0.1:8000`, keeps the database in its `StateDirectory`, and loads both `.p8` keys from `/etc/supaterm-push` as systemd credentials. `/etc/supaterm-push/push.env` sets `APNS_TEAM_ID`, `APNS_TOPICS`, `APNS_SANDBOX_KEY_ID`, and `APNS_PRODUCTION_KEY_ID`.

To deploy, build with `make build-push`, copy `bin/push` and the unit to `/tmp/push` and `/tmp/supaterm-push.service` on the machine, and run [`install-push.sh`](../deploy/install-push.sh). It installs both, restarts the service, and enables it once `/healthz` answers. Restarting clears the rate limits and the replay cache; the database survives.
