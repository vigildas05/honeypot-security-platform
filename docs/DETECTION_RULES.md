# Detection rules and severity

Incident correlation, ATT&CK mapping and severity are **deterministic**: plain code in
[`backend/src/correlation/`](../backend/src/correlation/), no LLM involved. The LLM agent
(Phase 4) only adds a written report on top of these results and can never change them.

## Correlation

- Events are grouped into incidents by `src_ip`.
- An incident stays open while the gap between consecutive events is at most
  `INCIDENT_WINDOW_MINUTES` (default **30**). A longer gap starts a new incident.
- Incidents with no events inside the window are closed.
- Correlation is idempotent: each event belongs to exactly one incident
  (`incident_events.event_id` is unique), and per-IP advisory locks make concurrent runs safe.

## Technique mapping

Source of truth: the `RULES` table in [`rules.js`](../backend/src/correlation/rules.js).
Tests: [`rules.test.js`](../backend/test/unit/rules.test.js).

| ATT&CK | Name | Fires when | Weight |
| --- | --- | --- | --- |
| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | ≥ 5 distinct HTTP paths | 5 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | request to a known exploit / sensitive path (`/cgi-bin/`, `/.env`, `/wp-login.php`, `/.git/`, phpunit, ThinkPHP, path traversal, Log4Shell `${jndi:`, GlobalProtect / Fortinet / Cisco VPN paths, …) | 20 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | ≥ 5 failed logins (SSH + HTTP login posts) | 15 |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | ≥ 5 distinct passwords against ≤ 2 usernames | 5 |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | ≥ 5 usernames with ≤ max(2, usernames/5) passwords | 5 |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | any successful login to the fake shell | 25 |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | any shell command | 15 |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | `uname`, `lscpu`, `nproc`, `free`, `/proc/cpuinfo`, … | 5 |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | `whoami`, `id`, `w`, `who`, `last` | 3 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `wget`, `curl`, `tftp`, `ftpget`, `scp`, `/dev/tcp/` | 25 |
| [T1222.002](https://attack.mitre.org/techniques/T1222/002/) | Linux File Permissions Modification | `chmod +x` / `chmod 777` | 5 |
| [T1070.003](https://attack.mitre.org/techniques/T1070/003/) | Clear Command History | `history -c`, `unset HISTFILE`, … | 10 |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | `crontab`, `/etc/cron*`, `/var/spool/cron` | 25 |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | any command touching `authorized_keys` | 30 |
| [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | miner binaries/pools (`xmrig`, `kinsing`, `stratum+tcp://`, …) | 30 |

## Severity score

```
score = sum(weights of matched techniques)
      + 5   if failed logins >= 100
      + 10  if AbuseIPDB confidence >= 75
      + 10  if >= 3 VirusTotal engines flag the IP
      + 5   if GreyNoise classifies it as malicious
      - 10  if GreyNoise says benign / RIOT (known business service or research scanner)
score = max(score, 0)
```

| Score | Level |
| --- | --- |
| < 20 | low |
| 20 – 44 | medium |
| 45 – 69 | high |
| ≥ 70 | critical |

**Floors**, applied after scoring:

- A successful login (T1078) followed by payload or persistence (T1105, T1053.003, T1098.004
  or T1496) is always **critical**.
- Any successful login (T1078) is at least **high**.

Every matched rule and modifier is stored in `incidents.stats.severity_reasons`, so the
dashboard can show exactly why an incident got its level.

## Tuning

Thresholds are in `DEFAULT_THRESHOLDS` in `rules.js`. Change them there and update the tests.
