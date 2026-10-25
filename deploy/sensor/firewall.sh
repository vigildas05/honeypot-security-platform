#!/usr/bin/env bash
# Sensor VM firewall (iptables + ipset; works alongside Docker).
#
# Inbound : 22 (fake SSH) and 80 (fake HTTP) to the sensor containers,
#           ADMIN_SSH_PORT for real admin SSH (key-only, configured in sshd).
# Outbound: DENY by default. Allowed: the backend ingest host, DNS, NTP
#           (and the cloud metadata service for the host only). `setup` mode
#           additionally allows 80/443 so packages and images can be pulled.
#
# Why DOCKER-USER: Docker-published ports and container egress traverse the
# FORWARD chain, so ufw/INPUT/OUTPUT rules alone would NOT restrict the
# containers. Container egress is filtered in DOCKER-USER, which Docker
# evaluates before its own rules and never flushes.
#
# Changes are applied with an automatic rollback (default 120 s) unless you run
# `firewall.sh confirm` from a NEW admin SSH session, so a mistake can't lock
# you out of the VM.
#
# Usage: firewall.sh {setup|lockdown|refresh|confirm|rollback|status} [--no-rollback] [--rollback-seconds N]
set -euo pipefail

CONF="${HONEYPOT_FW_CONF:-/etc/honeypot-sensor/firewall.conf}"
STATE_DIR="${HONEYPOT_FW_STATE:-/var/lib/honeypot-firewall}"
# shellcheck source=/dev/null
[[ -r "$CONF" ]] && source "$CONF"

: "${ADMIN_SSH_PORT:?set ADMIN_SSH_PORT in $CONF (real sshd port, not 22)}"
: "${INGEST_HOST:?set INGEST_HOST in $CONF (backend hostname, e.g. api.example.com)}"
INGEST_PORT="${INGEST_PORT:-443}"
ADMIN_SOURCE_CIDRS="${ADMIN_SOURCE_CIDRS:-}"          # e.g. "203.0.113.10/32,198.51.100.0/24"; empty = any
SENSOR_SUBNET="${SENSOR_SUBNET:-172.30.53.0/24}"      # matches deploy/sensor/docker-compose.yml
SENSOR_PORTS="${SENSOR_PORTS:-2222,8080}"             # container-side ports after Docker's DNAT
NTP_SERVERS="${NTP_SERVERS:-169.254.169.254,169.254.169.123}"  # OCI/GCP metadata IP, AWS Time Sync
ALLOW_HOST_METADATA="${ALLOW_HOST_METADATA:-true}"    # cloud agents on the HOST need it; containers never get it
TAILSCALE="${TAILSCALE:-false}"
ROLLBACK_SECONDS=120
NO_ROLLBACK=0
INGEST_SET=hp_ingest

MODE="${1:-}"; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-rollback) NO_ROLLBACK=1 ;;
    --rollback-seconds) ROLLBACK_SECONDS="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

log() { echo "[firewall] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root"
for bin in iptables ip6tables ipset getent; do command -v "$bin" >/dev/null || die "$bin not installed"; done
[[ "$ADMIN_SSH_PORT" =~ ^[0-9]+$ && "$ADMIN_SSH_PORT" != 22 ]] || die "ADMIN_SSH_PORT must be a number other than 22"
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"

dns_servers() {
  if [[ -n "${DNS_SERVERS:-}" ]]; then tr ',' ' ' <<<"$DNS_SERVERS"; return; fi
  local f
  for f in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    [[ -r "$f" ]] || continue
    awk '/^nameserver/ && $2 !~ /^127\./ && $2 !~ /:/ {print $2}' "$f"
    return
  done
}

# Resolve INGEST_HOST into the ipset. Never empties the set on failure, so a
# DNS hiccup can't cut the sensor off from the backend.
refresh_ingest_set() {
  ipset create -exist "$INGEST_SET" hash:ip family inet
  local ips
  if [[ "$INGEST_HOST" =~ ^[0-9.]+$ ]]; then ips="$INGEST_HOST"
  else ips=$(getent ahostsv4 "$INGEST_HOST" | awk '{print $1}' | sort -u || true)
  fi
  if [[ -z "$ips" ]]; then
    log "WARNING: could not resolve $INGEST_HOST; keeping previous ingest IPs"
    return
  fi
  ipset create -exist "${INGEST_SET}_new" hash:ip family inet
  ipset flush "${INGEST_SET}_new"
  for ip in $ips; do ipset add -exist "${INGEST_SET}_new" "$ip"; done
  ipset swap "${INGEST_SET}_new" "$INGEST_SET"
  ipset destroy "${INGEST_SET}_new"
  log "ingest allowlist: $(tr '\n' ' ' <<<"$ips")"
}

# (Re)create one of our chains, empty, and make sure the parent jumps to it first.
own_chain() { # bin parent chain
  "$1" -N "$3" 2>/dev/null || "$1" -F "$3"
  "$1" -C "$2" -j "$3" 2>/dev/null || "$1" -I "$2" 1 -j "$3"
}

admin_rules() { # bin chain
  if [[ -n "$ADMIN_SOURCE_CIDRS" ]]; then
    local cidr
    for cidr in ${ADMIN_SOURCE_CIDRS//,/ }; do
      if [[ "$1" == ip6tables ]]; then [[ "$cidr" == *:* ]] || continue; else [[ "$cidr" == *:* ]] && continue; fi
      "$1" -A "$2" -p tcp -s "$cidr" --dport "$ADMIN_SSH_PORT" -m conntrack --ctstate NEW -j ACCEPT
    done
  else
    "$1" -A "$2" -p tcp --dport "$ADMIN_SSH_PORT" -m conntrack --ctstate NEW -j ACCEPT
  fi
}

apply_v4() { # mode
  local mode="$1" dns ntp
  own_chain iptables INPUT HP_INPUT
  own_chain iptables OUTPUT HP_OUTPUT
  iptables -N DOCKER-USER 2>/dev/null || true
  own_chain iptables DOCKER-USER HP_DOCKER

  # ---- host inbound
  iptables -A HP_INPUT -i lo -j ACCEPT
  iptables -A HP_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A HP_INPUT -m conntrack --ctstate INVALID -j DROP
  iptables -A HP_INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT
  admin_rules iptables HP_INPUT
  if [[ "$TAILSCALE" == true ]]; then
    iptables -A HP_INPUT -i tailscale0 -j ACCEPT
    iptables -A HP_INPUT -p udp --dport 41641 -j ACCEPT
  fi
  iptables -A HP_INPUT -m limit --limit 6/minute -j LOG --log-prefix "hp-in-drop: "
  iptables -A HP_INPUT -j DROP

  # ---- host outbound
  iptables -A HP_OUTPUT -o lo -j ACCEPT
  iptables -A HP_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for dns in $(dns_servers); do
    iptables -A HP_OUTPUT -d "$dns" -p udp --dport 53 -j ACCEPT
    iptables -A HP_OUTPUT -d "$dns" -p tcp --dport 53 -j ACCEPT
  done
  for ntp in ${NTP_SERVERS//,/ }; do iptables -A HP_OUTPUT -d "$ntp" -p udp --dport 123 -j ACCEPT; done
  if [[ "$ALLOW_HOST_METADATA" == true ]]; then
    iptables -A HP_OUTPUT -d 169.254.169.254 -m owner --uid-owner 0 -j ACCEPT
  fi
  iptables -A HP_OUTPUT -p tcp --dport "$INGEST_PORT" -m set --match-set "$INGEST_SET" dst -j ACCEPT
  if [[ "$mode" == setup ]]; then
    iptables -A HP_OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT   # apt mirrors, docker/ghcr pulls
  fi
  if [[ "$TAILSCALE" == true ]]; then
    iptables -A HP_OUTPUT -o tailscale0 -j ACCEPT
    iptables -A HP_OUTPUT -p udp --dport 41641 -j ACCEPT
    iptables -A HP_OUTPUT -p tcp --dport 443 -j ACCEPT   # Tailscale control/DERP (documented trade-off)
  fi
  iptables -A HP_OUTPUT -m limit --limit 6/minute -j LOG --log-prefix "hp-out-drop: "
  iptables -A HP_OUTPUT -j REJECT

  # ---- containers (FORWARD via DOCKER-USER). RETURN hands back to Docker's rules.
  iptables -A HP_DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A HP_DOCKER -d "$SENSOR_SUBNET" -p tcp -m multiport --dports "$SENSOR_PORTS" -m conntrack --ctstate NEW -j RETURN
  iptables -A HP_DOCKER -s "$SENSOR_SUBNET" -p tcp --dport "$INGEST_PORT" -m set --match-set "$INGEST_SET" dst -j RETURN
  for dns in $(dns_servers); do
    iptables -A HP_DOCKER -s "$SENSOR_SUBNET" -d "$dns" -p udp --dport 53 -j RETURN
    iptables -A HP_DOCKER -s "$SENSOR_SUBNET" -d "$dns" -p tcp --dport 53 -j RETURN
  done
  iptables -A HP_DOCKER -s "$SENSOR_SUBNET" -m limit --limit 6/minute -j LOG --log-prefix "hp-sensor-egress-drop: "
  iptables -A HP_DOCKER -s "$SENSOR_SUBNET" -j DROP     # incl. cloud metadata: sensors never reach it
  iptables -A HP_DOCKER -d "$SENSOR_SUBNET" -m conntrack --ctstate NEW -j DROP
  iptables -A HP_DOCKER -j RETURN

  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
}

apply_v6() {
  # The sensor network is IPv4-only (enable_ipv6: false). Keep IPv6 to the
  # bare minimum: neighbor discovery, admin SSH, established traffic.
  own_chain ip6tables INPUT HP_INPUT
  own_chain ip6tables OUTPUT HP_OUTPUT
  local t
  for c in HP_INPUT HP_OUTPUT; do
    local dir="-i"; [[ $c == HP_OUTPUT ]] && dir="-o"
    ip6tables -A "$c" "$dir" lo -j ACCEPT
    ip6tables -A "$c" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for t in 1 2 3 4 133 134 135 136 137; do ip6tables -A "$c" -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT; done
  done
  admin_rules ip6tables HP_INPUT
  ip6tables -A HP_INPUT -j DROP
  ip6tables -A HP_OUTPUT -j REJECT
  ip6tables -P INPUT DROP
  ip6tables -P OUTPUT DROP
  ip6tables -P FORWARD DROP
}

schedule_rollback() {
  [[ "$NO_ROLLBACK" -eq 1 ]] && return
  cancel_rollback quiet
  setsid nohup bash -c "sleep $ROLLBACK_SECONDS; iptables-restore < '$STATE_DIR/rollback.v4'; ip6tables-restore < '$STATE_DIR/rollback.v6'; echo rolled-back > '$STATE_DIR/last-rollback'" \
    >/dev/null 2>&1 &
  echo $! > "$STATE_DIR/rollback.pid"
  log "applied. Open a NEW admin SSH session to port $ADMIN_SSH_PORT and run: $0 confirm"
  log "otherwise the previous rules are restored in ${ROLLBACK_SECONDS}s"
}

cancel_rollback() {
  if [[ -s "$STATE_DIR/rollback.pid" ]]; then
    local pid; pid=$(cat "$STATE_DIR/rollback.pid")
    # Kill the whole session (bash + its sleep).
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    rm -f "$STATE_DIR/rollback.pid"
    [[ "${1:-}" == quiet ]] || log "rollback cancelled; rules kept"
  elif [[ "${1:-}" != quiet ]]; then
    log "no pending rollback"
  fi
}

case "$MODE" in
  setup|lockdown)
    iptables-save > "$STATE_DIR/rollback.v4"
    ip6tables-save > "$STATE_DIR/rollback.v6"
    refresh_ingest_set
    apply_v4 "$MODE"
    apply_v6
    echo "$MODE" > "$STATE_DIR/mode"
    log "mode: $MODE"
    schedule_rollback
    ;;
  refresh)
    refresh_ingest_set
    ;;
  confirm)
    cancel_rollback
    ;;
  rollback)
    [[ -r "$STATE_DIR/rollback.v4" ]] || die "no saved rules"
    cancel_rollback quiet
    iptables-restore < "$STATE_DIR/rollback.v4"
    ip6tables-restore < "$STATE_DIR/rollback.v6"
    log "restored rules saved before the last apply"
    ;;
  status)
    echo "mode: $(cat "$STATE_DIR/mode" 2>/dev/null || echo none)"
    [[ -s "$STATE_DIR/rollback.pid" ]] && echo "PENDING ROLLBACK (run: $0 confirm)"
    echo "ingest IPs: $(ipset list "$INGEST_SET" 2>/dev/null | sed -n '/Members/,$p' | tail -n +2 | tr '\n' ' ')"
    iptables -S HP_INPUT; iptables -S HP_OUTPUT; iptables -S HP_DOCKER
    ;;
  *)
    echo "usage: $0 {setup|lockdown|refresh|confirm|rollback|status} [--no-rollback] [--rollback-seconds N]" >&2
    exit 2
    ;;
esac
