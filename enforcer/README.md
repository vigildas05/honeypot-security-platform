# Blocklist enforcer (optional, demo VM only)

`enforcer.sh` pulls the backend's External Dynamic List (`/edl/blocklist.txt`)
and applies it on a Linux host with `ipset` + `iptables`/`ip6tables`. It is the
same list a real firewall (e.g. a PAN-OS External Dynamic List of type *IP List*)
would consume. It only ever contains blocks that a human admin approved.

> **Never run this on the sensor.** The sensor is the attacked host and must not
> hold EDL credentials or change its own firewall based on attacker-influenced
> decisions. The script refuses to start if `/etc/honeypot-sensor` exists or if
> honeypot containers are running. `deploy/sensor/` creates that marker file.

## Safety properties

- **Strict validation.** Every line must be an IPv4/IPv6 literal. One malformed
  line rejects the whole update.
- **Fail-safe.** Fetch errors (network, 401, 5xx) or oversized lists keep the
  currently applied blocks. Nothing is flushed.
- **Atomic.** The new list is built in a temporary set and `ipset swap`ped in.
- **Allowlist first.** Entries in `/etc/honeypot-enforcer.allow` (IPs or CIDRs,
  one per line, `#` comments) go into `honeypot_allow`, whose ACCEPT rule sits
  above the DROP rule. Put your own admin IPs there.
- **No secrets on the command line.** Credentials are passed to curl through a
  config on stdin, not argv. The config file must be `chmod 600`.
- **Defense in depth.** The backend also refuses to publish private, reserved or
  never-block addresses, even if one somehow got marked active.

## Install (Debian/Ubuntu)

```bash
sudo apt-get install -y ipset iptables curl
sudo install -m 0755 enforcer.sh /usr/local/sbin/honeypot-enforcer
sudo install -m 0600 honeypot-enforcer.conf.example /etc/honeypot-enforcer.conf
sudoedit /etc/honeypot-enforcer.conf          # set EDL_URL and EDL_TOKEN
echo "203.0.113.10   # my admin IP" | sudo tee /etc/honeypot-enforcer.allow
sudo honeypot-enforcer --dry-run              # shows what would be applied
sudo install -m 0644 honeypot-enforcer.service honeypot-enforcer.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now honeypot-enforcer.timer
```

Inspect:

```bash
sudo ipset list honeypot_block
sudo iptables -S INPUT | grep honeypot
journalctl -u honeypot-enforcer
```

Remove everything:

```bash
sudo systemctl disable --now honeypot-enforcer.timer
sudo iptables -D INPUT -m set --match-set honeypot_allow src -j ACCEPT
sudo iptables -D INPUT -m set --match-set honeypot_block src -j DROP
sudo ip6tables -D INPUT -m set --match-set honeypot_allow6 src -j ACCEPT
sudo ip6tables -D INPUT -m set --match-set honeypot_block6 src -j DROP
sudo ipset destroy honeypot_block; sudo ipset destroy honeypot_block6
sudo ipset destroy honeypot_allow; sudo ipset destroy honeypot_allow6
```

`ufw` users: ufw has no native ipset support, but these rules sit in `INPUT`
alongside ufw's chains and work with it. Persist ipsets across reboots with the
timer (it rebuilds on boot) rather than ufw config.

## Using a real firewall instead

Point the firewall's EDL at
`https://YOUR-BACKEND/edl/blocklist.txt?token=...`, or configure basic auth
(`EDL_AUTH_MODE=basic`). Use a refresh interval of 5 minutes or more, and use the
EDL in a deny rule.
