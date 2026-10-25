#!/usr/bin/env bash
# Honeypot blocklist enforcer for a SEPARATE demo VM (never the sensor).
#
# Pulls the approved, active blocklist from the backend's EDL endpoint and
# applies it with ipset + iptables/ip6tables:
#   - every line is strictly validated; one bad line rejects the whole update
#   - the new list is swapped in atomically (ipset swap)
#   - a failed or suspicious fetch never flushes the existing blocks
#   - a local allowlist (honeypot_allow) is matched BEFORE the block set
#
# Usage: enforcer.sh [--dry-run] [--config /etc/honeypot-enforcer.conf]
set -euo pipefail

CONFIG=/etc/honeypot-enforcer.conf
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --config) CONFIG="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { echo "[enforcer] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------- safety ---
# The sensor must never enforce: it would let attacker-influenced decisions
# touch the honeypot host, and the sensor holds no credentials for the EDL.
if [[ -e /etc/honeypot-sensor ]]; then
  die "this host is marked as a sensor (/etc/honeypot-sensor); refusing to run"
fi
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -Eq 'ssh-honeypot|http-honeypot'; then
  die "honeypot sensor containers are running on this host; refusing to run"
fi

[[ -r "$CONFIG" ]] || die "config $CONFIG not readable"
# shellcheck source=/dev/null
source "$CONFIG"

: "${EDL_URL:?EDL_URL must be set in $CONFIG}"
MAX_ENTRIES="${MAX_ENTRIES:-50000}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-/etc/honeypot-enforcer.allow}"
SET4=honeypot_block
SET6=honeypot_block6
ALLOW4=honeypot_allow
ALLOW6=honeypot_allow6

if [[ "$EDL_URL" != https://* && "${ALLOW_HTTP:-0}" != "1" ]]; then
  die "EDL_URL must be https:// (set ALLOW_HTTP=1 only for local testing)"
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  perms=$(stat -c '%a' "$CONFIG")
  [[ "$perms" =~ ^[46]00$ ]] || die "$CONFIG holds credentials; chmod 600 it (is $perms)"
fi

# ----------------------------------------------------------------- fetch ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Credentials go through a curl config on stdin, never on the command line
# (which would expose them in `ps`).
{
  echo "silent"
  echo "show-error"
  echo "fail"
  echo "max-time = 20"
  echo "max-filesize = 5000000"
  echo "proto = =https,http"
  if [[ -n "${EDL_TOKEN:-}" ]]; then
    sep='?'; [[ "$EDL_URL" == *\?* ]] && sep='&'
    echo "url = \"${EDL_URL}${sep}token=${EDL_TOKEN}\""
  else
    echo "url = \"${EDL_URL}\""
    [[ -n "${EDL_USER:-}" ]] && echo "user = \"${EDL_USER}:${EDL_PASSWORD:-}\""
  fi
  echo "output = \"$TMP/list.txt\""
} | curl -K - || die "fetch failed; keeping existing blocks"

# -------------------------------------------------------------- validate ---
IPV4='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
IPV6='^[0-9a-fA-F:]{2,39}$'
: > "$TMP/v4"; : > "$TMP/v6"
count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  if [[ "$line" =~ $IPV4 ]]; then
    echo "$line" >> "$TMP/v4"
  elif [[ "$line" =~ $IPV6 && "$line" == *:* ]]; then
    echo "$line" >> "$TMP/v6"
  else
    die "invalid line in blocklist (${#line} chars); rejecting whole update, keeping existing blocks"
  fi
  count=$((count + 1))
  (( count <= MAX_ENTRIES )) || die "blocklist exceeds MAX_ENTRIES=$MAX_ENTRIES; rejecting update"
done < "$TMP/list.txt"

log "fetched $count entries ($(wc -l < "$TMP/v4") IPv4, $(wc -l < "$TMP/v6") IPv6)"

if [[ "$DRY_RUN" -eq 1 ]]; then
  log "dry run: would apply:"
  cat "$TMP/v4" "$TMP/v6"
  exit 0
fi

[[ $EUID -eq 0 ]] || die "must run as root (or use --dry-run)"
command -v ipset >/dev/null || die "ipset not installed"

# ----------------------------------------------------------------- apply ---
# All sets (and their *_new swap partners) use identical parameters; ipset
# refuses `create -exist` and `swap` when they differ.
MAXELEM=$((MAX_ENTRIES + 1024))
ensure_set() { ipset create -exist "$1" "$2" family "$3" maxelem "$MAXELEM"; }
ensure_set "$SET4" hash:ip inet
ensure_set "$SET6" hash:ip inet6
ensure_set "$ALLOW4" hash:net inet
ensure_set "$ALLOW6" hash:net inet6

swap_in() { # set type family file
  local tmpset="${1}_new"
  ipset create -exist "$tmpset" "$2" family "$3" maxelem "$MAXELEM"
  ipset flush "$tmpset"
  while IFS= read -r ip; do ipset add -exist "$tmpset" "$ip"; done < "$4"
  ipset swap "$tmpset" "$1"
  ipset destroy "$tmpset"
}

# Allowlist (your own IPs / ranges, CIDR allowed). Rebuilt and swapped each run.
: > "$TMP/allow4"; : > "$TMP/allow6"
if [[ -r "$ALLOWLIST_FILE" ]]; then
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    entry="${entry%%#*}"; entry="${entry// /}"
    [[ -z "$entry" ]] && continue
    if [[ "$entry" == *:* ]]; then echo "$entry" >> "$TMP/allow6"; else echo "$entry" >> "$TMP/allow4"; fi
  done < "$ALLOWLIST_FILE"
fi
swap_in "$ALLOW4" hash:net inet "$TMP/allow4"
swap_in "$ALLOW6" hash:net inet6 "$TMP/allow6"

swap_in "$SET4" hash:ip inet "$TMP/v4"
swap_in "$SET6" hash:ip inet6 "$TMP/v6"

ensure_rule() { # binary set target
  "$1" -C INPUT -m set --match-set "$2" src -j "$3" 2>/dev/null || "$1" -I INPUT 1 -m set --match-set "$2" src -j "$3"
}
# Insert DROP first, then ACCEPT at position 1, so the allowlist always wins.
ensure_rule iptables "$SET4" DROP
ensure_rule iptables "$ALLOW4" ACCEPT
if command -v ip6tables >/dev/null; then
  ensure_rule ip6tables "$SET6" DROP
  ensure_rule ip6tables "$ALLOW6" ACCEPT
fi

log "applied $count blocks"
