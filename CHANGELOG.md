# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-12

### Added
- **`web_ui.py`** — browser-based control panel for the emulator (zero new
  dependencies; uses Python's built-in `http.server`).
  - Start / Stop the emulator from the UI with live status badge, event counter,
    and uptime timer.
  - Mode selector (Stream / Bulk) with rate, event count, and span controls.
  - Event Catalogue panel — enable or disable individual event generators via
    checkboxes, with log-type badges and relative weights shown.
  - Output Sinks panel — toggle file logs, JSONL, and stdout independently, each
    with a configurable output path.
  - Log Cleanup panel — preset interval buttons (1 h / 6 h / 12 h / 24 h),
    configurable keep-tail size (MB), and an immediate cleanup trigger.
  - **Bindplane Demo — Noise Injection** section with three independently toggled
    and frequency-tunable noise types:
    - *Duplicate logs* — re-emits the same line to demonstrate Bindplane
      deduplication pipelines.
    - *Empty-value logs* — logs with blank key fields (SRC, USER, COMMAND) to
      demonstrate drop-if-empty transforms.
    - *Sensitive data (PII)* — synthetic SSN, date-of-birth, and credit-card
      numbers to demonstrate Bindplane masking / redaction before Dynatrace
      ingest.
  - Color-coded live log tail (SSH=red, sudo=yellow, kernel/UFW=blue,
    audit=purple, PII=amber) with auto-scroll.
- Remote-access guidance: SSH port-forward (`ssh -L`) and `--bind 0.0.0.0`
  options for headless Linux / EC2 deployments.

## [0.1.0] - 2026-06-10

### Added
- Initial release of the Linux / EC2 security log emulator.
- Three log formats: `auth.log`, `syslog`, `auditd`.
- Event generators: SSH (failed/accepted/invalid/disconnect), sudo
  (success/failed), PAM session, useradd, passwd change, cron, kernel
  firewall (UFW), kernel events, auditd EXECVE, auditd sensitive-file open,
  auditd network connect.
- Random SSH brute-force burst injection (~4% probability per event).
- Two run modes: `stream` (real-time) and `bulk` (historical batch over
  a configurable time window).
- Output sinks: file (`auth.log`/`syslog`/`audit.log`), JSONL, stdout, and
  Splunk HTTP Event Collector — combinable.
- README, LICENSE (MIT), CONTRIBUTING, and `.gitignore`.
- GitHub Actions workflow for lint + smoke test.

[Unreleased]: https://github.com/egvlamakisdt/SecurityLogsEmulator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/egvlamakisdt/SecurityLogsEmulator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/egvlamakisdt/SecurityLogsEmulator/releases/tag/v0.1.0
