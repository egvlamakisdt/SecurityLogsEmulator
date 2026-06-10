# Security Logs Emulator

[![CI](https://github.com/egvlamakisdt/SecurityLogsEmulator/actions/workflows/ci.yml/badge.svg)](https://github.com/egvlamakisdt/SecurityLogsEmulator/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A zero-dependency Python tool that generates realistic Linux / EC2 security logs
for SIEM testing, detection-rule development, and demos.

It produces log lines in three classic formats:

| Format        | Style of                       | Example events                                    |
| ------------- | ------------------------------ | ------------------------------------------------- |
| `auth.log`    | `/var/log/auth.log`            | SSH login attempts, sudo, PAM session, useradd    |
| `syslog`      | `/var/log/syslog`              | cron jobs, UFW/iptables firewall, kernel events   |
| `audit.log`   | `auditd` (`/var/log/audit/`)   | `EXECVE`, sensitive file open, network `connect`  |

It can write to local files, stdout, JSONL, and/or push directly to a
**Splunk HTTP Event Collector (HEC)** — multiple sinks at once are supported.

> Built for ops/security engineers who need a reproducible stream of believable
> events to validate Splunk parsing, build detections (e.g. SSH brute-force,
> sudo misuse, sensitive-file access), or seed dashboards for demos.

---

## Features

- **Realistic content** — RFC1918 + known Tor/scanner-style IPs, common attack
  usernames, real command paths, kernel messages, auditd records.
- **Two modes**
  - `stream` — real-time, configurable events/sec (good for live dashboards).
  - `bulk` — historical batch spread across an arbitrary time window
    (good for backfilling indices).
- **Brute-force bursts** — randomly injects short SSH brute-force bursts from a
  single source IP so detections actually have something to fire on.
- **Multiple output sinks** that can be combined:
  - file sink (`auth.log` / `syslog` / `audit.log`)
  - structured JSONL
  - stdout
  - Splunk HEC (batched, with sourcetype mapping)
- **Pure stdlib** — no `pip install` required. Runs on any Python 3.10+.

---

## Requirements

- **Python 3.10 or newer** (uses PEP 604 union types like `datetime | None`).
- No third-party packages.

To run on Windows, macOS, or Linux:

```powershell
python --version   # should be 3.10+
```

---

## Installation

Clone the repo and you're done — there's nothing to install:

```bash
git clone https://github.com/egvlamakisdt/SecurityLogsEmulator.git
cd SecurityLogsEmulator
python security_log_emulator.py --help
```

---

## Usage

### Stream events to stdout (quick sanity check)

```bash
python security_log_emulator.py --mode stream --rate 5 --stdout
```

### Stream to local files (Splunk Universal Forwarder picks them up)

```bash
python security_log_emulator.py \
  --mode stream --rate 5 \
  --output ./logs
```

This creates / appends to:

- `./logs/auth.log`
- `./logs/syslog`
- `./logs/audit.log`

### Bulk-generate 5,000 events across the last 24h

```bash
python security_log_emulator.py \
  --mode bulk --count 5000 --span-hours 24 \
  --output ./logs --jsonl ./logs
```

Produces standard log files **and** an `events.jsonl` with structured fields
suitable for ingestion as JSON.

### Push directly to Splunk HEC

```bash
python security_log_emulator.py \
  --mode stream --rate 10 \
  --splunk-hec-url https://splunk.example.com:8088 \
  --splunk-hec-token <YOUR_HEC_TOKEN> \
  --splunk-index main
```

Sourcetypes default to:

| Log type | Sourcetype     |
| -------- | -------------- |
| `auth`   | `linux_secure` |
| `syslog` | `syslog`       |
| `audit`  | `linux_audit`  |

---

## Command-line reference

```text
--mode {stream,bulk}      stream: real-time; bulk: historical batch
--rate FLOAT              [stream] events per second (default: 2)
--count INT               [bulk]   number of events to generate (default: 1000)
--span-hours FLOAT        [bulk]   time window in hours (default: 24)
--host HOSTNAME           hostname to embed in log lines

Outputs (one or more may be combined):
  --output DIR            write auth.log / syslog / audit.log into DIR
  --jsonl DIR             write structured events to DIR/events.jsonl
  --stdout                print raw log lines to stdout
  --splunk-hec-url URL    Splunk HEC endpoint, e.g. https://splunk:8088
  --splunk-hec-token TOK  Splunk HEC token (required with --splunk-hec-url)
  --splunk-index NAME     Splunk index (default: main)
```

---

## Event catalogue

Weights below are relative; tune them in `EVENT_CATALOGUE` inside
[security_log_emulator.py](security_log_emulator.py).

| Generator                    | Weight | Log     | What it simulates                              |
| ---------------------------- | -----: | ------- | ---------------------------------------------- |
| `gen_ssh_failed_password`    |     30 | auth    | Failed SSH password (often external IP)        |
| `gen_ssh_invalid_user`       |     15 | auth    | SSH attempt with non-existent user             |
| `gen_ssh_accepted`           |     12 | auth    | Successful publickey login                     |
| `gen_kernel_firewall`        |     12 | syslog  | UFW ACCEPT/DROP/REJECT                         |
| `gen_ssh_connection_closed`  |     10 | auth    | SSH preauth disconnect                         |
| `gen_pam_unix_session`       |     10 | auth    | PAM session opened/closed                      |
| `gen_sudo_success`           |      8 | auth    | sudo command executed                          |
| `gen_cron_job`               |      8 | syslog  | cron job execution                             |
| `gen_auditd_execve`          |      6 | audit   | `auditd` EXECVE record                         |
| `gen_kernel_event`           |      5 | syslog  | promiscuous mode, SYN flood, conntrack full…   |
| `gen_sudo_failed`            |      4 | auth    | sudo with wrong password                       |
| `gen_auditd_open_sensitive`  |      4 | audit   | open of `/etc/shadow`, authorized_keys, …      |
| `gen_auditd_network`         |      4 | audit   | outbound `connect()` syscall                   |
| `gen_useradd`                |      2 | auth    | new user account                               |
| `gen_passwd_change`          |      2 | auth    | password change                                |

In addition, every event has a ~4% chance of triggering a **brute-force burst**
(8–25 failed SSH logins from a single external IP within a few seconds).

---

## Detection ideas to test

Once events are flowing into Splunk (or any SIEM), these are easy detections to
stand up against the data this tool produces:

- `>= 10` `Failed password` events from one `src_ip` in 5 minutes (brute force).
- `Invalid user` events for usernames not in your asset directory.
- `sudo: ... 3 incorrect password attempts`.
- `auditd` `open` of `/etc/shadow` or `authorized_keys` by non-root.
- New user creation outside change windows (`useradd`).
- UFW `DROP` traffic to non-public ports from external sources.

---

## Disclaimer

This tool generates **synthetic** log data only. It does not perform any network
activity besides optionally POSTing to a Splunk HEC URL you configure. The
"attacker" IP addresses are static strings used purely to add visual realism;
treat any matches against real-world IOC feeds as coincidence, not attribution.

Use only against systems you own or have explicit permission to test.

---

## Contributing

Pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
