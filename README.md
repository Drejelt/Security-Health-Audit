# Security-Health-Audit

> A **read-only** audit for Debian/Ubuntu servers: 21 security and health checks, colour-coded `pass / warn / fail` verdicts, a summary tally, and a monitoring-friendly exit code. It changes nothing on the system — it only reports.

![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-blue)
![Shell](https://img.shields.io/badge/shell-bash-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Safe to run repeatedly, including from cron. Output is mirrored to a log file with ANSI colours stripped, so logs and pipes stay clean.

---

## Contents

- [How it works](#how-it-works)
- [Checks performed](#checks-performed)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Logging](#logging)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## How it works

```
   run ──► 21 read-only checks ──► verdicts ──► summary ──► exit code
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
            [✓] pass               [!] warn              [✗] fail
                │                     │                     │
                └──────── exit 0 ─────┘            exit 1 (problem found)

            exit 2 = the script itself couldn't run a step
```

Each check is self-contained and prints its own verdict; a stray non-zero from one `grep`/`stat`/`awk` never aborts the report. Counters are tallied at the end and mapped to a single, meaningful exit code.

---

## Checks performed

| # | Area | Highlights |
|---|------|-----------|
| 1 | Open ports | Lists listening sockets; flags SSH bound to a wildcard address |
| 2 | Firewall | `ufw` / `nftables` / `iptables` active and populated |
| 3 | SSH config | `PermitRootLogin`, `PasswordAuthentication`, empty passwords, port |
| 4 | Failed SSH logins (24h) | From the journal or `btmp`; warns on possible brute force |
| 5 | Available updates | Cache-only (no network); flags security updates |
| 6 | Package metadata age | Warns when the package cache is stale |
| 7 | File permissions | `passwd`, `shadow`, `gshadow`, `sudoers`, `sshd_config` |
| 8 | Sudo users | Group members, direct grants, stray `UID=0` accounts |
| 9 | fail2ban | Running state and active jails |
| 10 | WireGuard | Active interfaces and peer counts |
| 11 | Failed systemd units | Lists any units in a failed state |
| 12 | OOM / kernel errors | OOM-killer events and error-level kernel messages |
| 13 | Memory | RAM and swap usage against thresholds |
| 14 | Load average | 5-minute load per core |
| 15 | Temperatures | `hwmon` / thermal-zone sensors with warn/crit thresholds |
| 16 | Uptime | Warns on very long uptime (pending kernel updates) |
| 17 | Time sync | `timedatectl` / `chrony` synchronization state |
| 18 | Docker | Service state and unhealthy containers |
| 19 | Disk space | Per-partition usage |
| 20 | Journal size | Warns when the systemd journal grows large |
| 21 | Disk SMART | Overall SMART health per physical disk |

---

## Requirements

| Component | Minimum |
|-----------|---------|
| OS | Debian / Ubuntu (graceful fallback for other distros) |
| Privileges | runs as any user; **root recommended** for full coverage |
| Core tools | `awk`, `grep`, `sed`, `date`, `stat` (the only hard requirement) |

> ⚠️ **Run with `sudo` for complete results.** Without root, `sshd -T`, `smartctl`, `lastb`, `fail2ban`, `wg`, and Docker checks run partially and say so — the audit still completes.

Optional tooling is detected at runtime and used only when present: `ss`, `ufw`/`nft`/`iptables`, `journalctl`, `fail2ban-client`, `wg`, `docker`, `smartctl`, `free`, `nproc`, `lm-sensors`. Anything missing is reported and skipped, not treated as an error.

---

## Installation

```bash
git clone https://github.com/Drejelt/Security-Health-Audit.git
cd system-audit
chmod +x system-audit.sh
sudo ./system-audit.sh
```

---

## Usage

```bash
# Full audit (root = complete coverage)
sudo ./system-audit.sh

# Non-root: still useful, some checks partial
./system-audit.sh

# In cron / monitoring — act on the exit code
sudo ./system-audit.sh || echo "Audit found a problem"
```

---

## Configuration

Thresholds live at the top of the script and can be edited to taste:

| Variable | Meaning | Default |
|----------|---------|---------|
| `UPTIME_WARN_DAYS` | Warn if uptime exceeds this | `180` |
| `APT_STALE_DAYS` | Warn if package metadata is older | `7` |
| `MEM_WARN_PCT` | Warn at this memory usage | `90` |
| `LOGIN_WARN_COUNT` | Warn at this many failed logins (24h) | `100` |
| `TEMP_WARN_C` / `TEMP_CRIT_C` | Temperature warn / fail (°C) | `80` / `90` |
| `LOAD_WARN_RATIO` / `LOAD_FAIL_RATIO` | Per-core 5-min load warn / fail | `1.0` / `2.0` |
| `JOURNAL_WARN_MB` | Warn if the journal exceeds this (MB) | `5120` |
| `LOG_FILE` | Where to mirror output | `/var/log/system-audit.log` |

---

## Logging

Every run is mirrored to `LOG_FILE` (default `/var/log/system-audit.log`) with ANSI colour codes stripped. If that path isn't writable, logging disables itself automatically and the run continues — terminal output is never lost.

```bash
tail -f /var/log/system-audit.log
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No `FAIL` verdicts (clean, or warnings only) |
| `1` | At least one `FAIL` verdict (a problem was found) |
| `2` | The script itself could not run a step (distinct from a finding) |

---

## Troubleshooting

**Lots of checks say "needs root".**
Run with `sudo`. Root unlocks `sshd -T`, `smartctl`, `lastb`, `fail2ban`, `wg`, and Docker queries.

**"No temperature sensors."**
Sensors need bare metal; VMs expose none. Install `lm-sensors` and run `sensors-detect` for richer readings.

**Cron reports a non-zero exit.**
Exit `1` is a *finding* (a `FAIL` verdict), not a script error — that's the intended signal. Only exit `2` means the script itself couldn't run a step.

**Log file shows "(disabled — no write access)".**
`/var/log` isn't writable for the current user. Run as root, or point `LOG_FILE` at a writable path.

**Update check shows nothing useful.**
It's cache-only by design (never hits the network). Refresh the cache yourself first: `sudo apt-get update` (or `dnf check-update`).

---

## License

MIT — see the [LICENSE](LICENSE) file.

> ⚠️ Read-only and safe to run repeatedly. Provided "as is", without warranty.
