# Deployment

The deployment workflow installs one standalone relay on `supaterm-relay.exe.xyz` and another on [AWS Lightsail](#lightsail-relay). The exe.dev relay serves clients and hosts directly behind the exe.dev HTTPS proxy at `wss://relay.supaterm.com`.

The same relay also serves `wss://relay.supacode.sh` for Supacode builds, so hosts and clients on either hostname share one set of registrations.

Both hostnames are DNS-only Cloudflare CNAMEs to `supaterm-relay.exe.xyz`, each registered with `ssh exe.dev domain add supaterm-relay <hostname>`; exe.dev manages their TLS certificates. Keep Cloudflare proxying off for these records, as required by [exe.dev's custom-domain setup](https://exe.dev/docs/cnames).

The [service unit](../deploy/supaterm-relay.service) binds protocol traffic to `127.0.0.1:8080` and private health and detailed metrics to `127.0.0.1:9090`. The exe.dev proxy forwards the public TLS endpoint to port 8080. Only the local proxy may supply the client IP, and the private listener accepts loopback peers only. Public `/metrics` contains aggregate counters. The public [`/dashboard/`](https://relay.supaterm.com/dashboard/) refreshes those counters every two seconds and adds throughput, process CPU, the machine's load average and memory, and the process start time. Host traffic details stay on the private listener.

Code changes pushed to `main` run [the deployment workflow](../.github/workflows/deploy.yml): the race test suite, a Linux build, service installation, and verified smoke exchanges through both public hostnames. Restarting the relay closes its sockets, so hosts and clients must reconnect. Each relay instance owns its authenticated registrations and pairs in memory; distributing an endpoint's sockets across independent instances is unsupported.

The [installer](../deploy/install-relay.sh) installs the binary and unit, restarts the service, and enables it once the private health check passes.

A single relay has one failure domain; this deployment does not implement automatic failover.

## Lightsail relay

The same workflow also deploys an independent relay to `wss://relay2.supaterm.com` on an AWS Lightsail instance. It shares no registrations with `relay.supaterm.com`, so a host and its clients must use the same relay.

The [Pulumi stack](../deploy/lightsail/Pulumi.yaml) creates a 4 GiB Ubuntu 24.04 instance, attaches a static IP, opens ports 22, 80 and 443, and points DNS-only Cloudflare `A` and `AAAA` records at the instance. [`Pulumi.relay2.yaml`](../deploy/lightsail/Pulumi.relay2.yaml) sets the hostname, Cloudflare zone and AWS region.

On every deployment, the `relay2` job runs `pulumi up` and then connects over SSH with the short-lived certificate from Lightsail's `GetInstanceAccessDetails`. It checks the instance against the host keys Lightsail recorded. The [Caddy installer](../deploy/lightsail/install-caddy.sh) installs Ubuntu's Caddy package and points it at the relay. Caddy obtains the TLS certificate and supplies the client IP in `X-Forwarded-For`. The job then runs the same [installer](../deploy/install-relay.sh) and [service unit](../deploy/supaterm-relay.service) as `relay.supaterm.com`, waits for the certificate, and runs the smoke and tunnel probes against the public hostname.

### One-time setup

The job needs these settings in the `relay2` GitHub environment:

| Name | Kind | Value |
| --- | --- | --- |
| `AWS_ROLE_ARN` | Variable | IAM role that GitHub Actions assumes through OIDC, allowed `lightsail:*` |
| `PULUMI_ACCESS_TOKEN` | Secret | Pulumi Cloud token. The first deployment creates the `relay2` stack in the token's default organization |
| `CLOUDFLARE_API_TOKEN` | Secret | Cloudflare token with Zone Read and DNS Edit on `supaterm.com` |

Create them with administrator AWS credentials. Skip `create-open-id-connect-provider` if the account already trusts GitHub's OIDC provider.

```sh
account=$(aws sts get-caller-identity --query Account --output text)
aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com
aws iam create-role --role-name supaterm-relay-deploy --assume-role-policy-document "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::$account:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:supabitapp/supaterm-relay:environment:relay2"
    }}
  }]
}
EOF
)"
aws iam put-role-policy --role-name supaterm-relay-deploy --policy-name lightsail \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lightsail:*","Resource":"*"}]}'
gh api -X PUT repos/supabitapp/supaterm-relay/environments/relay2
gh variable set AWS_ROLE_ARN --env relay2 --body "arn:aws:iam::$account:role/supaterm-relay-deploy"
gh secret set PULUMI_ACCESS_TOKEN --env relay2
gh secret set CLOUDFLARE_API_TOKEN --env relay2
```

To preview infrastructure changes locally, run `pulumi preview --stack relay2` in `deploy/lightsail` with AWS credentials and `CLOUDFLARE_API_TOKEN` set.
