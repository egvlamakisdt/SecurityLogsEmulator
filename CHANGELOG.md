# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/egvlamakisdt/SecurityLogsEmulator/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/egvlamakisdt/SecurityLogsEmulator/releases/tag/v0.1.0
