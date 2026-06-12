# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Light / dark theme toggle** in the web UI. The button is now a
  high-contrast, labeled pill (sun + "Light Mode" / moon + "Dark Mode")
  in the top-right of the header so it's easy to spot in either palette.
  Choice is persisted across reloads via `localStorage`. CSS was
  refactored to use theme-scoped custom properties so all colors (cards,
  inputs, buttons, badges, log tail, scrollbars) adapt cleanly.
- **Trigger Cleanup feedback.** The button now disables while the request
  is in-flight, and shows a transient inline status message (green = ok,
  amber = nothing to clean, red = failed). The `/api/cleanup` endpoint
  returns a structured `{result, cleaned, mode}` payload.
- **In-page error banner** for backend failures. The web UI now surfaces
  emulator startup errors (e.g. `PermissionError` when the configured
  output directory is not writable) at the top of the page instead of
  silently leaving the status badge on `STOPPED`. The banner is
  dismissible per-message and is fed by a new `last_error` field on
  `/api/status`.
- **`POST /api/logs/clear`** endpoint to drain the in-memory log ring
  buffer used by the live tail.

### Changed
- **Auto-cleanup interval presets** changed from `1h / 6h / 12h / 24h`
  to `15m / 30m / 45m / 60m` to better match short demo cycles. Default
  selection is now 30 minutes. The button selection logic uses
  `parseFloat` so fractional-hour values match correctly.
- **Hostname and Output Sink controls are now locked while the emulator
  is running.** These values are only read once at start, so editing
  them mid-run had no effect; they are now visually disabled until Stop
  is clicked. Affects: Hostname dropdown, Log Files / JSONL / Stdout
  checkboxes, and the file/JSONL path inputs.
- **Default log output directory is now self-contained inside the repo.**
  The web UI's *Log Files* and *JSONL* fields, and their JS fallbacks,
  default to an absolute path computed from the script's own location
  (`<repo>/logs/`) rather than the CWD-relative `./logs`. Logs now land
  in the same place regardless of where `python web_ui.py` is launched
  from. (`logs/` is already gitignored.)
- **Live log tail** is taller (was `h-52` / 208 px, now `h-96` / 384 px
  with `min-height:14rem`) and user-resizable via the standard CSS
  `resize: vertical` grip.

### Fixed
- **Live log tail Clear button now actually clears.** Previously the
  Clear link only emptied the DOM; the next 1-second poll re-rendered
  the same buffer. The Clear handler now also drains the server-side
  ring buffer via `POST /api/logs/clear`.
- **Uptime counter no longer keeps running after Stop.** A new
  `stopped_at` timestamp is captured when the emulator stops (via the
  Stop button, when bulk mode finishes, on sink-init failure, or on
  runtime error) and `status()` freezes uptime at `stopped_at -
  started_at` once the emulator is no longer running.
- **Trigger Cleanup now actually truncates files when the emulator is
  stopped.** Previously the handler short-circuited because
  `EmulatorState._sink` is `None` after the worker thread exits, so the
  click was a silent no-op. The cleanup path now falls back to
  truncating the files referenced by the last-used config directly
  (honoring the configured *Keep tail (MB)* value) and reports per-path
  permission/IO errors via `last_error`.
- **Live log tail no longer stops refreshing once the in-memory buffer
  is full.** The "have logs changed?" check used buffer length, which is
  pinned at `maxlen=300`, so re-renders were skipped after the deque
  filled. The check is now a fingerprint of `length + first + last`
  line, so rolling content is detected and redrawn.
- **`generate_event` crash** — `random.choices(*zip(*[(w, f) for w, f in
  EVENT_CATALOGUE]))` was passing arguments in the wrong order, causing
  `TypeError: unsupported operand type(s) for +: 'function' and 'function'`
  on Python 3.12+/3.14. Replaced with the explicit
  `random.choices(fns, weights=weights, k=1)` form already used by
  `_weighted_choices`.
- **Silent emulator thread crash on output-dir permission errors.**
  `FileSink` / `JsonlSink` construction is now wrapped so a
  `PermissionError` or `OSError` records a friendly message in
  `last_error` and stops cleanly instead of killing the worker thread
  with no UI feedback. Runtime errors inside the stream/bulk loops are
  also captured the same way.

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
