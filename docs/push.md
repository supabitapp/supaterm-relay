# Push gateway

`cmd/push` delivers Supaterm notifications to phones through APNs and FCM. Hosts send it ciphertext that only the phone can decrypt. The gateway, Apple and Google see when a phone is notified, how large and how urgent the push is, and one of four fixed alert texts the host picks. They never see thread titles, text or identifiers. The gateway is a separate binary and service, so the relay never holds Apple or Firebase credentials.

## What it stores

Nothing per phone or per host. Each subscription lives inside its endpoint URL, sealed with AES-256-GCM under the first key in `PUSH_SEAL_KEY_FILE`: a random grant ID, the platform, the device token, the APNs topic and environment, the host's and the phone's P-256 public keys, and the issue and expiry times. Phones, hosts, Apple and Google can neither read nor alter it. The gateway opens it on every request.

The only file it writes is `PUSH_REVOCATION_FILE`, one `<grant ID> <unix expiry>` line per revoked grant. A line is kept 30 days, the longest an endpoint lives, and expired lines are dropped on start. A second gateway pointed at the same file refuses to start while the first holds `<file>.lock`. Losing the file makes revoked endpoints usable again until they expire.

Rate-limit buckets live in memory. The gateway never stores or logs payloads, device tokens or endpoints; its logs carry APNs and FCM status codes and reasons.

## Protocol

| Request | Sent by | Success |
| --- | --- | --- |
| `POST /v1/subscriptions`, JSON | phone | 202; pushes a new endpoint to the device |
| `POST /v1/push/{sealed}`, `aes128gcm` body | host | 201 |
| `POST /v1/subscriptions/renew`, JWS | phone | 200 with a new endpoint, or 202 when moving to a new device token |
| `POST /v1/subscriptions/revoke`, JWS | phone | 204 |
| `GET /healthz` | | 200, or 503 while shutting down |
| `GET /dashboard/` | | [Status page](#status-page) |

Public keys are uncompressed P-256 points in unpadded base64url. Errors are `{"error": "<code>"}`; 429, 502 and 503 carry `Retry-After`.

### Subscribing

The phone subscribes once per host it pairs with:

| Field | Value |
| --- | --- |
| `platform` | `apns` or `fcm` |
| `token` | APNs device token in hex, or FCM registration token |
| `topic` | APNs only. A bundle ID listed in `APNS_TOPICS` |
| `environment` | APNs only. `sandbox` or `production`, with a configured key |
| `hostKey` | The host's VAPID public key |
| `managementKey` | A key the phone keeps for renewing and revoking this subscription |
| `request` | 1 to 64 characters from `A-Z a-z 0-9 - _`, echoed back with the endpoint |

A topic outside `APNS_TOPICS` answers 403 `topic_not_allowed`, a platform or APNs environment without credentials answers 400 `platform_not_configured`, and a token APNs or FCM rejects answers 410 `token_unregistered`.

The response never contains the endpoint. The gateway pushes it to the device token instead, so only the device holding the token can obtain it. The phone hands the endpoint to its host over their end-to-end encrypted connection.

### What the phone receives

Both platforms carry the same string fields. APNs puts them at the top level of the payload beside `aps`; FCM sends them as a data-only message, and the app posts the notification itself.

| Field | Endpoint push | Message |
| --- | --- | --- |
| `type` | `subscription` | `message` |
| `request` | The subscribe or renew request's value | |
| `endpoint` | The endpoint URL | |
| `expiresAt`, `renewAfter` | Unix seconds | |
| `alert` | | The host's `Supaterm-Alert` |
| `c` | | The host's request body in unpadded base64url |

APNs pushes are alerts with `mutable-content: 1`, so the notification service extension can decrypt `c` and replace the text. Without the extension the phone shows the fixed text: "Notifications are on" without sound for endpoint pushes, and the `Supaterm-Alert` text with the default sound for messages. The gateway never sets `thread-id` or `apns-collapse-id`.

### Sending

A host sends to the endpoint as an [RFC 8030](https://www.rfc-editor.org/rfc/rfc8030) push resource, with an [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291) body and [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292) authorization:

| Header | Value |
| --- | --- |
| `Authorization` | `vapid t=<JWT>, k=<key>`. `k` is the subscription's `hostKey`; the ES256 JWT has `aud` set to `PUSH_PUBLIC_URL` and `exp` within the next hour |
| `Content-Encoding` | `aes128gcm` |
| `TTL` | Seconds the platform may hold the push, 0 to 2419200. 0 delivers now or never |
| `Urgency` | `high` sends at APNs priority 10 and FCM `HIGH`. `very-low`, `low`, `normal` or no header send at 5 and `NORMAL` |
| `Supaterm-Alert` | `activity` (default): "New activity". `completed`: "An agent finished". `needs-input`: "An agent needs your input". `failed`: "An agent ran into a problem" |

Web Push libraries often sign 12 or 24 hour tokens by default, which answer 401 here; set `exp` explicitly.

The whole APNs payload, or the FCM data, must fit in 4096 bytes. Bodies up to 2,954 bytes always fit; larger ones may answer 413.

| Status | `error` | Host action |
| --- | --- | --- |
| 400 | `invalid_request`, `platform_not_configured` | Fix the request |
| 401 | `unauthorized` | Check the VAPID key and token |
| 403 | `endpoint_expired` | Keep the subscription and wait for the phone to renew it |
| 404 | `endpoint_invalid` | Keep the subscription; the gateway cannot open this endpoint |
| 410 | `endpoint_revoked` | Delete the subscription |
| 410 | `token_unregistered` | Delete the subscription; APNs or FCM says the app is gone |
| 413 | `payload_too_large` | Send less |
| 415 | `unsupported_encoding` | Encrypt with `aes128gcm` |
| 429 | `rate_limited` | Retry after `Retry-After` |
| 502 | `upstream_unavailable` | Retry later |
| 503 | `gateway_misconfigured` | Retry later; APNs or FCM refused the gateway's credentials or topic, or the gateway no longer serves the endpoint's platform, environment or topic |

Delete a subscription only for the two 410 codes, never on a status alone.

| APNs or FCM answer | Gateway answer |
| --- | --- |
| APNs 410, or 400 `BadDeviceToken` or `DeviceTokenNotForTopic` | 410 `token_unregistered` |
| FCM `UNREGISTERED` or `SENDER_ID_MISMATCH` | 410 `token_unregistered` |
| APNs 413 | 413 `payload_too_large` |
| APNs 403, or 400 `BadTopic`, `TopicDisallowed` or `MissingTopic`; FCM 401, 403, or 404 without those codes | 503 `gateway_misconfigured` |
| Anything else, or no answer | 502 `upstream_unavailable` |

### Renewing and revoking

Both bodies are a compact ES256 JWS signed by the subscription's `managementKey`:

| Claim | Value |
| --- | --- |
| `aud` | `PUSH_PUBLIC_URL` |
| `act` | `renew` or `revoke` |
| `iat`, `exp` | Unix seconds. `exp` is in the future and at most 5 minutes after `iat` |
| `endpoint` | The endpoint URL |
| `token` | Renew only. A new device token to move the subscription to |
| `request` | Renew only, required with `token` |

Renewing answers 410 `endpoint_revoked` for a revoked grant, 403 `endpoint_expired` for an expired endpoint, and 409 `renewal_too_early` before `renewAfter`. It checks the topic, environment and platform against the current configuration, as subscribing does. Otherwise it issues a new endpoint for the same grant, valid 30 more days, and answers `200 {endpoint, expiresAt, renewAfter}`. With a new `token`, which is allowed before `renewAfter`, it pushes the new endpoint to that token and answers 202, as subscribing does. Earlier endpoints keep working until they expire.

Revoking covers every endpoint of the grant, including renewed and expired ones, and answers 204 only after the revocation is on disk; 503 `revocation_unavailable` means it was not stored. Renewal and revocation run one at a time, so an endpoint renewed alongside a revocation is still covered by it.

## Limits

| Scope | Limit |
| --- | --- |
| Subscribe, renew and revoke per client network | 60 per hour, burst 20 |
| Endpoint pushes per device token | 20 per hour, burst 10 |
| Sends per client network | 20 per second, burst 200 |
| Sends per grant | 30 per minute, burst 10 |
| Status page per client network | 5 per second, burst 20 |

A client network is one IPv4 address or IPv6 `/64`, taken from `X-Forwarded-For` only when the peer is in `PUSH_TRUSTED_PROXIES`. Each limit tracks at most 65,536 keys and answers 429 to new keys while full.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PUSH_ADDR` | `127.0.0.1:8000` | Listen address |
| `PUSH_PUBLIC_URL` | | The origin hosts and phones reach, such as `https://push.supaterm.com`. Endpoints start with it and JWTs name it as `aud`. Must be `https` unless the host is loopback. Required |
| `PUSH_SEAL_KEY_FILE` | | One 32-byte key per line in standard base64. The first seals new endpoints; all of them open endpoints. Required |
| `PUSH_REVOCATION_FILE` | | Revocation log path. Required |
| `PUSH_TRUSTED_PROXIES` | | CIDRs whose `X-Forwarded-For` is trusted |
| `APNS_TEAM_ID` | | Apple developer team ID. Required with an APNs key |
| `APNS_TOPICS` | | Comma-separated bundle IDs. Required with an APNs key |
| `APNS_SANDBOX_KEY_ID`, `APNS_SANDBOX_KEY_FILE` | | Key ID and `.p8` file for `api.sandbox.push.apple.com` |
| `APNS_PRODUCTION_KEY_ID`, `APNS_PRODUCTION_KEY_FILE` | | Key ID and `.p8` file for `api.push.apple.com` |
| `FCM_CREDENTIALS_FILE` | | Firebase service account key JSON. Sends go to its project |

Set each APNs environment's ID and file together. At least one APNs key or the FCM credentials are required. The APNs provider JWT is reused for 50 minutes, and the FCM access token until 5 minutes before it expires.

Generate a seal key with `openssl rand -base64 32`. To rotate, put the new key on the first line and keep the old one below it for 30 days; endpoints sealed with a removed key answer `endpoint_invalid`.

A fork that ships its own app runs its own gateway with its own Apple team, keys, bundle IDs and Firebase project.

## Status page

`/dashboard/` is the relay's status page for the gateway: subscriptions issued and renewals since start, stored revocations, delivered pushes and bytes over the last minute, error answers by code, CPU and memory.

## Deployment

The [service unit](../deploy/supaterm-push.service) listens on `127.0.0.1:8000` behind a local HTTPS proxy, trusts that proxy's `X-Forwarded-For`, keeps the revocation file in its `StateDirectory`, and loads the seal keys and both `.p8` keys from `/etc/supaterm-push` as systemd credentials. `/etc/supaterm-push/push.env` sets `PUSH_PUBLIC_URL`, `APNS_TEAM_ID`, `APNS_TOPICS`, `APNS_SANDBOX_KEY_ID` and `APNS_PRODUCTION_KEY_ID`. The unit expects both APNs keys; for one environment, remove the other's `LoadCredential` and `APNS_*_KEY_FILE` lines. To enable FCM, add `LoadCredential=fcm.json:/etc/supaterm-push/fcm.json` and `Environment=FCM_CREDENTIALS_FILE=%d/fcm.json`.

To deploy, build with `make build-push`, stage the binary and unit in a private directory on the machine, and run [`install-push.sh`](../deploy/install-push.sh) with that directory:

```sh
dir=$(ssh "$HOST" mktemp -d)
scp bin/push deploy/supaterm-push.service "$HOST:$dir/"
ssh "$HOST" bash -s "$dir" < deploy/install-push.sh
```

It installs both, removes the directory, restarts the service, and enables it once `/healthz` answers. The deployment workflow does not deploy the gateway. Restarting clears the rate limits; endpoints and revocations survive.
