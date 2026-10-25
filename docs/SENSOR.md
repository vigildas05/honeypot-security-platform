# Sensor VM: hardening, deployment and rebuilds

The sensor is the only part of this platform that is meant to be attacked. It runs two fake
services and nothing else. This document covers how it is isolated and how to deploy it.
The broader deployment guide (backend, database, dashboard) comes in Phase 9:
`docs/DEPLOYMENT.md`.

> **Do not expose the sensor until the backend is deployed and the checklist at the end of
> this page passes.**

## What runs where

| Host | Runs | Holds |
| --- | --- | --- |
| Sensor VM (public) | `ssh-honeypot`, `http-honeypot` containers | Two sensor ingest tokens. Nothing else. |
| Backend (private) | API, worker, Postgres | DB credentials, JWT secret, LLM / threat-intel keys, EDL credentials |
| Enforcer VM (optional) | `enforcer/enforcer.sh` | EDL credentials. **Never the sensor.** |

## Isolation layers

**Application**

- The fake SSH shell never executes anything. It maps input strings to canned output, imports
  no `child_process` / `fs` / `vm`, and a unit test enforces that. Every login attempt and
  every command (interactive and `exec`) is logged.
- Port forwarding, SFTP, X11 and agent forwarding are refused, so the honeypot can't be used
  as a proxy. Per-IP and total connection caps apply, and sessions have idle and absolute
  timeouts.
- The HTTP sensor takes the source IP from the TCP socket only. Spoofed `X-Forwarded-For`
  headers are kept as evidence and never trusted.
- **Secret isolation is enforced in code.** A sensor refuses to start if any backend secret is
  in its environment (`DATABASE_URL`, `JWT_SECRET_KEY`, `LLM_API_KEY`, threat-intel keys,
  `EDL_TOKEN`, …). See `FORBIDDEN_SENSOR_ENV` in `honeypots/common/reporter.js`.
- In production, ingest must use `https://` and a token of at least 24 characters.

**Container** (`deploy/sensor/docker-compose.yml`)

| Control | Setting |
| --- | --- |
| Base image | `gcr.io/distroless/nodejs22-debian12:nonroot`: no shell, package manager, wget/curl/nc |
| User | uid 65532 (non-root) |
| Root filesystem | read-only. Only `/tmp` (16 MB tmpfs, noexec) and the SSH host-key volume are writable |
| Capabilities | all dropped (`cap_drop: [ALL]`), `no-new-privileges` |
| Limits | 256 MB / 192 MB memory, 0.5 CPU, 128 PIDs, 4096 open files |
| Logs | json-file, 10 MB × 3 per container |
| Network | dedicated bridge `172.30.53.0/24`, IPv4 only, inter-container traffic disabled |

**Host firewall** (`deploy/sensor/firewall.sh`)

- **Inbound:** 22 and 80 to the containers, plus your admin SSH port. Everything else is dropped.
- **Outbound, default-deny.** Allowed: the backend ingest host (resolved into an ipset and
  refreshed every 5 minutes), DNS, NTP, and the cloud metadata service for root on the host only.
- **Containers can reach only the ingest host and DNS.** In particular they can't reach the
  metadata service, which is a classic credential-theft path. The rules live in Docker's
  `DOCKER-USER` chain because published ports and container egress bypass `INPUT`/`OUTPUT`
  (and therefore ufw).
- `setup` mode additionally opens outbound 80/443 for package and image pulls. `update.sh`
  uses it for a short window, then locks down again.
- **Lock-out protection:** `setup`/`lockdown` restore the previous rules after 120 s unless you
  run `honeypot-firewall confirm` from a *new* admin SSH session.

## Deploy

1. **Create the VM** (Oracle Cloud Always Free, GCP e2-micro, or a Student Pack VPS), Ubuntu
   22.04/24.04, with `deploy/sensor/cloud-init.yaml` as user-data. First replace
   `ADMIN_SSH_KEY`, `REPO_REF` and, if you like, the admin port `49222`.
2. **Cloud network rules** (OCI security list / GCP firewall): allow TCP 22, 80 and your admin
   port from anywhere, or the admin port from your IP only. Oracle's Ubuntu images also ship
   restrictive iptables rules. `firewall.sh` inserts its chains in front of them, so you don't
   need to edit those.
3. **Log in on the admin port** (sshd was moved off 22 by cloud-init):
   `ssh -p 49222 adminuser@SENSOR_IP`
4. **Configure the firewall:** `sudoedit /etc/honeypot-sensor/firewall.conf` (set
   `INGEST_HOST`, `ADMIN_SSH_PORT`, optionally `ADMIN_SOURCE_CIDRS`).
5. **Copy the sensor env file** (tokens only) from your machine:
   `scp -P 49222 deploy/sensor/.env adminuser@SENSOR_IP:/opt/honeypot/deploy/sensor/.env`,
   then `chmod 600` it. Register the same tokens on the backend as
   `SENSOR_TOKENS=oci-ssh-1:<token>,oci-http-1:<token>`.
6. **Start the sensors:** `cd /opt/honeypot/deploy/sensor && docker compose up -d --no-build`
7. **Lock down, then confirm from a second session:**
   ```bash
   sudo honeypot-firewall lockdown
   # in a NEW terminal:
   ssh -p 49222 adminuser@SENSOR_IP sudo honeypot-firewall confirm
   sudo systemctl enable --now honeypot-firewall.service honeypot-firewall-refresh.timer
   ```

### AWS instead of Oracle

AWS India accepts debit cards (Visa, Mastercard, RuPay) and UPI, and the AWS Free plan's
credits cover a small sensor VM. Same files, different console:

- EC2 → Launch instance: Ubuntu 24.04 LTS, `t3.micro` (or `t4g.small` for arm64), region
  `ap-south-1` (Mumbai); key pair = your `.pub`; **Advanced details → User data** = your cloud-init.
- **Security group** inbound rules (instead of an OCI security list): TCP 22, 80 and your admin
  port from `0.0.0.0/0`.
- The firewall already allows Amazon Time Sync (`169.254.169.123`) and reads the VPC DNS
  resolver from the system. Public IPv4 addresses are billed hourly on AWS, against your credits.

### Tailscale instead of a public admin port

Install Tailscale, set `TAILSCALE=true` in `firewall.conf`, set `ListenAddress` in the sshd
drop-in to the Tailscale IP, and remove the admin port from the cloud firewall. Trade-off:
Tailscale needs outbound 443 to its control and DERP servers, whose IPs change, so the host
(not the containers) gets outbound 443 to any. Container egress stays restricted either way.

## Verify (checklist before going public)

Run these on the sensor after `lockdown` + `confirm`:

```bash
# Containers are hardened
docker inspect $(docker compose ps -q) --format '{{.Name}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}}'
# Only the ingest token reaches the sensors (prints names, not values)
docker compose exec http-honeypot /nodejs/bin/node -e 'console.log(Object.keys(process.env).filter(k=>/TOKEN|KEY|SECRET|PASS|DATABASE/.test(k)))'
# A container on the sensor network can reach the backend but nothing else
docker run --rm --network sensor_sensor curlimages/curl:8.10.1 -sS -m 5 -o /dev/null -w '%{http_code}\n' https://$INGEST_HOST/health   # expect 200
docker run --rm --network sensor_sensor curlimages/curl:8.10.1 -sS -m 5 https://example.com || echo "blocked (good)"
docker run --rm --network sensor_sensor curlimages/curl:8.10.1 -sS -m 3 http://169.254.169.254/ || echo "metadata blocked (good)"
# Firewall state
sudo honeypot-firewall status
```

(The `curlimages/curl` pulls need `setup` mode, or pull them beforehand.)

From your own machine:

```bash
nmap -Pn -p 1-65535 SENSOR_IP        # expect only 22, 80 and your admin port open
ssh -p 22 root@SENSOR_IP             # the fake shell; try "whoami" then check the dashboard
curl http://SENSOR_IP/.env            # should appear as an incident within a minute
```

`TODO: fill after deployment`: record the nmap result and the first-incident screenshot here.

## Rebuild and update cadence

The sensor is treated as disposable. Assume it can be compromised, and rebuild it often enough
that a compromise doesn't last.

| What | How | How often |
| --- | --- | --- |
| Sensor images | `sudo /opt/honeypot/deploy/sensor/update.sh` (opens egress briefly, pulls, recreates containers, locks down) | weekly, and after every release |
| OS packages | `unattended-upgrades` (installed by cloud-init) | daily, automatic |
| Whole VM | destroy and recreate from `cloud-init.yaml`, then steps 3–7 above (about 10 minutes) | monthly, or immediately if anything looks off |
| Ingest tokens | generate new tokens, update `.env` and the backend's `SENSOR_TOKENS` | on every VM rebuild |

Containers are read-only, so recreating them already discards anything written outside the
host-key volume. Rebuilding the VM also resets the host OS. Pin images by tag or digest in
`.env` so a rebuild runs exactly what CI tested.

## Things that are deliberately not on the sensor

- No database client, no backend code, no LLM or threat-intel keys, no EDL credentials.
- No blocklist enforcement: `enforcer/enforcer.sh` refuses to run where `/etc/honeypot-sensor`
  exists.
- No inbound management API. The sensor only pushes events out over HTTPS.
