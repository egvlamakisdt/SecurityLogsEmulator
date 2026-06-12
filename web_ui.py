#!/usr/bin/env python3
"""
Web UI for the Security Log Emulator.

Usage:
    python web_ui.py [--port 8080] [--bind 127.0.0.1]

Then open http://localhost:8080 in your browser.
"""

import argparse
import json
import os
import random
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from security_log_emulator import (
    EVENT_CATALOGUE,
    HOSTNAMES,
    FileSink,
    JsonlSink,
    StdoutSink,
    MultiSink,
    generate_event,
    start_cleanup_thread,
    _ts,
    _pid,
)

# Default log output directory — anchored to this script's location so logs
# always land in <repo>/logs/, regardless of the process's working directory.
DEFAULT_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


# ---------------------------------------------------------------------------
# Bindplane demo — noise generators
# ---------------------------------------------------------------------------

def _fake_ssn() -> str:
    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"


def _fake_dob() -> str:
    return (f"{random.randint(1960, 2002)}-"
            f"{random.randint(1, 12):02d}-"
            f"{random.randint(1, 28):02d}")


def _fake_cc() -> str:
    return (f"{random.randint(4000, 4999)}-{random.randint(1000, 9999)}"
            f"-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}")


def gen_sensitive_data(dt: datetime, host: str):
    """Synthetic log line containing PII — SSN, DOB, or credit card number."""
    pid = _pid()
    variant = random.randint(0, 2)
    if variant == 0:
        line = (f"{_ts(dt)} {host} app[{pid}]: user_registration "
                f"ssn={_fake_ssn()} date_of_birth={_fake_dob()}")
    elif variant == 1:
        line = (f"{_ts(dt)} {host} payment[{pid}]: transaction_complete "
                f"card_number={_fake_cc()} "
                f"amount={random.randint(5, 999)}.{random.randint(0, 99):02d}")
    else:
        line = (f"{_ts(dt)} {host} audit[{pid}]: patient_record_accessed "
                f"patient_ssn={_fake_ssn()} dob={_fake_dob()} "
                f"record_id={random.randint(10000, 99999)}")
    return ("auth", line, {"event_type": "sensitive_pii", "contains_pii": True})


def gen_empty_fields(dt: datetime, host: str):
    """Log line with blank/null field values — no actionable data."""
    pid = _pid()
    variant = random.randint(0, 2)
    if variant == 0:
        line = f"{_ts(dt)} {host} sshd[{pid}]: Failed password for  from  port  ssh2"
    elif variant == 1:
        line = (f"{_ts(dt)} {host} sudo[{pid}]: "
                "unknown : TTY= ; PWD= ; USER=root ; COMMAND=")
    else:
        line = (f"{_ts(dt)} {host} kernel: [UFW DROP] "
                "IN= OUT= MAC= SRC= DST= PROTO= SPT= DPT= LEN=")
    return ("syslog", line, {"event_type": "empty_fields", "has_empty_fields": True})


# ---------------------------------------------------------------------------
# Event catalogue metadata (resolved once at import time)
# ---------------------------------------------------------------------------

_SAMPLE_DT = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

CATALOGUE_META: list[dict] = []
for _w, _fn in EVENT_CATALOGUE:
    try:
        _log_type, _, _ = _fn(_SAMPLE_DT, "sample-host")
    except Exception:
        _log_type = "unknown"
    CATALOGUE_META.append({
        "name": _fn.__name__,
        "label": _fn.__name__.replace("gen_", "").replace("_", " "),
        "weight": _w,
        "log_type": _log_type,
    })

# Default enabled set — all event fn names
_ALL_EVENT_NAMES: set[str] = {m["name"] for m in CATALOGUE_META}


# ---------------------------------------------------------------------------
# Emulator state
# ---------------------------------------------------------------------------

class EmulatorState:
    def __init__(self):
        self._lock = threading.Lock()
        self.running: bool = False
        self.config: dict = {}
        self.events_total: int = 0
        self.events_noise: int = 0
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._log_buf: deque[str] = deque(maxlen=300)
        self._sink = None
        self._cleanup_stop: threading.Event | None = None
        self.last_error: str | None = None

    def status(self) -> dict:
        with self._lock:
            if self.started_at is None:
                uptime = 0.0
            else:
                end = self.stopped_at if (not self.running and self.stopped_at) else time.time()
                uptime = max(0.0, end - self.started_at)
            return {
                "running": self.running,
                "events_total": self.events_total,
                "events_noise": self.events_noise,
                "uptime_secs": round(uptime, 1),
                "config": self.config,
                "last_error": self.last_error,
            }

    def get_logs(self, n: int = 100) -> list[str]:
        with self._lock:
            return list(self._log_buf)[-n:]

    def clear_logs(self):
        with self._lock:
            self._log_buf.clear()

    def start(self, config: dict) -> str:
        with self._lock:
            if self.running:
                return "already_running"
            self.config = config
            self.events_total = 0
            self.events_noise = 0
            self.started_at = time.time()
            self.stopped_at = None
            self.running = True
            self.last_error = None
            self._stop_event.clear()
            self._log_buf.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="emulator")
        self._thread.start()
        return "started"

    def stop(self) -> str:
        with self._lock:
            if not self.running:
                return "not_running"
        self._stop_event.set()
        if self._cleanup_stop:
            self._cleanup_stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        with self._lock:
            self.running = False
            if self.stopped_at is None:
                self.stopped_at = time.time()
        return "stopped"

    def trigger_cleanup(self) -> dict:
        """Truncate the configured log files. Works whether or not the
        emulator is currently running. Returns a dict with `result` and
        `cleaned` (count) so the UI can give feedback.
        """
        with self._lock:
            sink = self._sink
            cfg  = dict(self.config)
        keep_mb    = float(cfg.get("cleanup_keep_mb", 0.0))
        keep_bytes = int(keep_mb * 1024 * 1024)

        # Path A — emulator is running: defer to the live MultiSink which
        # holds the open file handles and will reopen them after truncation.
        if sink is not None:
            try:
                sink.cleanup(keep_bytes)
                return {"result": "ok", "cleaned": -1, "mode": "live"}
            except Exception as e:
                with self._lock:
                    self.last_error = f"Cleanup failed: {e}"
                return {"result": "error", "error": str(e)}

        # Path B — emulator is stopped: truncate the files referenced by the
        # last-used config directly. (Without this, clicking "Trigger Cleanup"
        # after Stop was a silent no-op.)
        targets: list[str] = []
        if cfg.get("output_dir"):
            for name in ("auth.log", "syslog", "audit.log"):
                targets.append(os.path.join(cfg["output_dir"], name))
        if cfg.get("jsonl_dir"):
            targets.append(os.path.join(cfg["jsonl_dir"], "events.jsonl"))
        if not targets:
            return {"result": "no_files", "cleaned": 0,
                    "message": "No file/JSONL sink configured — nothing to clean."}

        cleaned = 0
        errors: list[str] = []
        for path in targets:
            if not os.path.exists(path):
                continue
            try:
                if keep_bytes > 0 and os.path.getsize(path) > keep_bytes:
                    with open(path, "rb") as src:
                        src.seek(-keep_bytes, os.SEEK_END)
                        tail = src.read()
                    nl = tail.find(b"\n")
                    if nl != -1:
                        tail = tail[nl + 1:]
                    with open(path, "wb") as dst:
                        dst.write(tail)
                else:
                    open(path, "wb").close()  # full truncate
                cleaned += 1
            except OSError as e:
                errors.append(f"{path}: {e}")

        if errors:
            msg = "Cleanup failed for: " + "; ".join(errors)
            with self._lock:
                self.last_error = msg
            return {"result": "error", "cleaned": cleaned, "error": msg}
        return {"result": "ok", "cleaned": cleaned, "mode": "offline"}

    # ── internal ──────────────────────────────────────────────────────────

    def _run(self):
        cfg = self.config
        sinks = []
        try:
            if cfg.get("output_dir"):
                sinks.append(FileSink(cfg["output_dir"]))
            if cfg.get("jsonl_dir"):
                sinks.append(JsonlSink(cfg["jsonl_dir"]))
            if cfg.get("stdout"):
                sinks.append(StdoutSink())
        except PermissionError as e:
            with self._lock:
                self.last_error = (
                    f"Permission denied creating output directory "
                    f"'{e.filename or cfg.get('output_dir') or cfg.get('jsonl_dir')}'. "
                    "Choose a writable path or disable file/JSONL sinks."
                )
                self.running = False
                if self.stopped_at is None:
                    self.stopped_at = time.time()
            for s in sinks:
                try: s.close()
                except Exception: pass
            return
        except OSError as e:
            with self._lock:
                self.last_error = f"Failed to initialize output sink: {e}"
                self.running = False
                if self.stopped_at is None:
                    self.stopped_at = time.time()
            for s in sinks:
                try: s.close()
                except Exception: pass
            return

        state_ref = self

        class _BufSink:
            def write(self, _lt, line, _s):
                with state_ref._lock:
                    state_ref._log_buf.append(line)
            def cleanup(self, keep_bytes=0): pass
            def close(self): pass

        sinks.append(_BufSink())
        sink = MultiSink(sinks) if len(sinks) > 1 else sinks[0]

        with self._lock:
            self._sink = sink

        interval = cfg.get("cleanup_interval_hours", 8.0)
        keep_mb  = cfg.get("cleanup_keep_mb", 0.0)
        if interval > 0 and cfg.get("output_dir"):
            self._cleanup_stop = start_cleanup_thread(sink, interval, keep_mb)

        dup_prob   = cfg.get("noise_duplicate_pct", 0) / 100.0
        empty_prob = cfg.get("noise_empty_pct", 0)    / 100.0
        pii_prob   = cfg.get("noise_pii_pct", 0)      / 100.0

        raw_enabled = cfg.get("enabled_events") or list(_ALL_EVENT_NAMES)
        enabled = set(raw_enabled)
        host = cfg.get("host", random.choice(HOSTNAMES))

        try:
            if cfg.get("mode", "stream") == "stream":
                self._stream_loop(sink, cfg, host, enabled, dup_prob, empty_prob, pii_prob)
            else:
                self._bulk_loop(sink, cfg, host, enabled, dup_prob, empty_prob, pii_prob)
        except Exception as e:
            with self._lock:
                self.last_error = f"Emulator error: {e}"
        finally:
            sink.close()
            with self._lock:
                self._sink = None
                self.running = False
                if self.stopped_at is None:
                    self.stopped_at = time.time()

    def _filter(self, entries, enabled):
        filtered = [e for e in entries
                    if f"gen_{e[2].get('event_type', '')}" in enabled]
        return filtered if filtered else entries  # don't drop burst entries entirely

    def _inject_noise(self, dt, host, base, dup_prob, empty_prob, pii_prob):
        noise, count = [], 0
        if dup_prob > 0 and base and random.random() < dup_prob:
            noise.append(random.choice(base))
            count += 1
        if empty_prob > 0 and random.random() < empty_prob:
            noise.append(gen_empty_fields(dt, host))
            count += 1
        if pii_prob > 0 and random.random() < pii_prob:
            noise.append(gen_sensitive_data(dt, host))
            count += 1
        return noise, count

    def _emit(self, sink, entries, noise_count=0):
        for log_type, line, struct in entries:
            sink.write(log_type, line, struct)
        with self._lock:
            self.events_total += len(entries)
            self.events_noise += noise_count

    def _stream_loop(self, sink, cfg, host, enabled, dup_prob, empty_prob, pii_prob):
        rate  = max(cfg.get("rate", 2.0), 0.01)
        delay = 1.0 / rate
        while not self._stop_event.is_set():
            dt      = datetime.now(timezone.utc)
            base    = self._filter(generate_event(dt, host), enabled)
            noise, n = self._inject_noise(dt, host, base, dup_prob, empty_prob, pii_prob)
            self._emit(sink, base + noise, n)
            self._stop_event.wait(delay)

    def _bulk_loop(self, sink, cfg, host, enabled, dup_prob, empty_prob, pii_prob):
        count      = cfg.get("count", 1000)
        span_hours = cfg.get("span_hours", 24.0)
        start_dt   = datetime.now(timezone.utc) - timedelta(hours=span_hours)
        offsets    = sorted(random.uniform(0, span_hours * 3600) for _ in range(count))
        for offset in offsets:
            if self._stop_event.is_set():
                break
            dt      = start_dt + timedelta(seconds=offset)
            base    = self._filter(generate_event(dt, host), enabled)
            noise, n = self._inject_noise(dt, host, base, dup_prob, empty_prob, pii_prob)
            self._emit(sink, base + noise, n)
        with self._lock:
            self.running = False


STATE = EmulatorState()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # suppress access log noise
        pass

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        if p == "/":
            self._html(HTML)
        elif p == "/api/status":
            self._json(STATE.status())
        elif p == "/api/logs":
            qs = parse_qs(parsed.query)
            n  = int(qs.get("n", ["100"])[0])
            self._json({"logs": STATE.get_logs(n)})
        elif p == "/api/catalogue":
            self._json({"catalogue": CATALOGUE_META})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/start":
            cfg    = self._read_json()
            result = STATE.start(cfg)
            self._json({"result": result})
        elif p == "/api/stop":
            self._json({"result": STATE.stop()})
        elif p == "/api/cleanup":
            self._json(STATE.trigger_cleanup())
        elif p == "/api/logs/clear":
            STATE.clear_logs()
            self._json({"result": "ok"})
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ---------------------------------------------------------------------------
# Embedded HTML/JS/CSS front-end
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Log Emulator</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* ---- Theme tokens (dark = default) ---- */
  :root {
    --bg-body:        #0d1117;
    --bg-card:        #161b22;
    --bg-input:       #0d1117;
    --bg-stats:       #0f172a;
    --bg-log:         #000000;
    --bg-ghost:       #1f2937;
    --bg-ghost-hover: #374151;
    --bg-toggle-off:  #374151;
    --thumb-off:      #9ca3af;
    --border-default: #30363d;
    --border-accent:  #4f46e5;
    --text-primary:   #e2e8f0;
    --text-heading:   #ffffff;
    --text-muted:     #94a3b8;
    --text-subtle:    #64748b;
    --text-ghost:     #d1d5db;
    --scroll-thumb:   #374151;
    --badge-run-bg:    #064e3b; --badge-run-fg:  #6ee7b7; --badge-run-bd:  #065f46;
    --badge-stop-bg:   #1c1917; --badge-stop-fg: #f87171; --badge-stop-bd: #7f1d1d;
  }

  [data-theme="light"] {
    --bg-body:        #f9fafb;
    --bg-card:        #ffffff;
    --bg-input:       #ffffff;
    --bg-stats:       #f3f4f6;
    --bg-log:         #1e293b;     /* keep terminal feel for log readability */
    --bg-ghost:       #f3f4f6;
    --bg-ghost-hover: #e5e7eb;
    --bg-toggle-off:  #d1d5db;
    --thumb-off:      #ffffff;
    --border-default: #e5e7eb;
    --border-accent:  #6366f1;
    --text-primary:   #1f2937;
    --text-heading:   #0f172a;
    --text-muted:     #4b5563;
    --text-subtle:    #6b7280;
    --text-ghost:     #374151;
    --scroll-thumb:   #cbd5e1;
    --badge-run-bg:    #d1fae5; --badge-run-fg:  #065f46; --badge-run-bd:  #a7f3d0;
    --badge-stop-bg:   #fee2e2; --badge-stop-fg: #991b1b; --badge-stop-bd: #fecaca;
  }

  body { background:var(--bg-body); color:var(--text-primary); font-family:system-ui,sans-serif; }
  .card { background:var(--bg-card); border:1px solid var(--border-default); border-radius:.75rem; }
  .card-accent { background:var(--bg-card); border:1px solid var(--border-accent); border-radius:.75rem; }
  input[type=range] { accent-color:#6366f1; width:100%; }
  input[type=number],input[type=text],select {
    background:var(--bg-input); color:var(--text-primary); border:1px solid var(--border-default);
    border-radius:.375rem; padding:.25rem .5rem; width:100%; font-size:.875rem;
  }
  input[type=number]:focus,input[type=text]:focus,select:focus {
    outline:none; border-color:#6366f1;
  }
  .log-tail { font-family:'Courier New',monospace; font-size:.72rem; line-height:1.4; }
  .log-tail::-webkit-scrollbar { width:4px; }
  .log-tail::-webkit-scrollbar-thumb { background:var(--scroll-thumb); border-radius:2px; }

  /* toggle switch (used for noise toggles AND theme toggle) */
  .tog-wrap { position:relative; display:inline-block; width:2.25rem; height:1.25rem; }
  .tog-inp  { opacity:0; width:0; height:0; position:absolute; }
  .tog-sl   { position:absolute; inset:0; background:var(--bg-toggle-off); border-radius:9999px;
              cursor:pointer; transition:.2s; }
  .tog-sl::before { content:""; position:absolute; width:.875rem; height:.875rem;
                    left:.1875rem; top:.1875rem; background:var(--thumb-off); border-radius:50%;
                    transition:.2s; }
  .tog-inp:checked + .tog-sl { background:#6366f1; }
  .tog-inp:checked + .tog-sl::before { transform:translateX(1rem); background:#fff; }

  .btn-primary   { background:#6366f1; color:#fff; }
  .btn-primary:hover   { background:#4f46e5; }
  .btn-primary:disabled { background:var(--bg-ghost-hover); color:var(--text-subtle); cursor:not-allowed; }
  .btn-danger    { background:#b91c1c; color:#fff; }
  .btn-danger:hover    { background:#dc2626; }
  .btn-danger:disabled { background:var(--bg-ghost-hover); color:var(--text-subtle); cursor:not-allowed; }
  .btn-ghost     { background:var(--bg-ghost); color:var(--text-ghost); }
  .btn-ghost:hover     { background:var(--bg-ghost-hover); }
  .btn-active    { background:#4f46e5; color:#fff; }
  .badge-run  { background:var(--badge-run-bg);  color:var(--badge-run-fg);  border:1px solid var(--badge-run-bd); }
  .badge-stop { background:var(--badge-stop-bg); color:var(--badge-stop-fg); border:1px solid var(--badge-stop-bd); }

  .cleanup-btn        { background:var(--bg-ghost); color:var(--text-subtle); }
  .cleanup-btn.sel    { background:#4f46e5; color:#fff; }
  .cleanup-btn:hover  { background:var(--bg-ghost-hover); }

  /* ---- Tailwind utility overrides for light theme ---- */
  [data-theme="light"] .text-white     { color: var(--text-heading) !important; }
  [data-theme="light"] .text-slate-300 { color: #1f2937 !important; }
  [data-theme="light"] .text-slate-400 { color: #4b5563 !important; }
  [data-theme="light"] .text-slate-500 { color: #6b7280 !important; }
  [data-theme="light"] .text-slate-600 { color: #9ca3af !important; }
  [data-theme="light"] .bg-slate-900   { background-color: var(--bg-stats) !important; }
  [data-theme="light"] #log-tail.bg-black { background-color: var(--bg-log) !important; }

  /* theme-toggle button — deliberately high contrast and labeled so it's
     easy to find in either mode. Renders as a pill with icon + word. */
  .theme-btn {
    display:inline-flex; align-items:center; gap:.4rem;
    padding:.4rem .85rem; border-radius:9999px;
    font-size:.8rem; font-weight:600; line-height:1;
    cursor:pointer; transition:transform .1s, background-color .2s, color .2s, box-shadow .2s;
    border:2px solid transparent;
  }
  .theme-btn .theme-icon { font-size:1rem; line-height:1; }
  .theme-btn:hover  { transform: translateY(-1px); }
  .theme-btn:active { transform: translateY(0); }
  /* When in DARK mode the button advertises switching TO light: bright/yellow */
  :root .theme-btn,
  [data-theme="dark"] .theme-btn {
    background:#facc15; color:#1f2937; border-color:#eab308;
    box-shadow:0 0 0 1px rgba(0,0,0,.2), 0 4px 14px rgba(250,204,21,.25);
  }
  :root .theme-btn:hover,
  [data-theme="dark"] .theme-btn:hover { background:#fde047; }
  /* When in LIGHT mode the button advertises switching TO dark: deep slate */
  [data-theme="light"] .theme-btn {
    background:#0f172a; color:#fde68a; border-color:#0f172a;
    box-shadow:0 0 0 1px rgba(255,255,255,.6), 0 4px 14px rgba(15,23,42,.25);
  }
  [data-theme="light"] .theme-btn:hover { background:#1e293b; }
</style>
</head>
<body class="min-h-screen p-4 md:p-6">

<!-- ── Header ── -->
<div class="flex flex-wrap items-center justify-between gap-3 mb-6">
  <div class="flex items-center gap-3">
    <span class="text-2xl">🔐</span>
    <div>
      <h1 class="text-lg font-bold text-white leading-tight">Security Log Emulator</h1>
      <p class="text-xs text-slate-500">Bindplane Demo Edition</p>
    </div>
  </div>
  <div class="flex items-center gap-3 flex-wrap">
    <span id="status-badge" class="badge-stop px-3 py-1 rounded-full text-xs font-semibold">● STOPPED</span>
    <span id="hdr-events" class="text-slate-400 text-sm tabular-nums">0 events</span>
    <span id="hdr-noise"  class="text-amber-500 text-sm tabular-nums hidden"></span>
    <span id="hdr-uptime" class="text-slate-600 text-xs hidden"></span>
    <button id="theme-toggle" type="button" class="theme-btn"
            onclick="toggleTheme()"
            aria-label="Toggle light/dark theme"
            title="Toggle light/dark theme">
      <span id="theme-icon" class="theme-icon">🌙</span>
      <span id="theme-label">Dark Mode</span>
    </button>
  </div>
</div>

<!-- ── Error banner ── -->
<div id="err-banner"
     class="hidden mb-4 p-3 rounded border text-sm"
     style="background:#7f1d1d20; border-color:#b91c1c; color:#fecaca;">
  <div class="flex items-start justify-between gap-3">
    <div><strong class="text-red-400">⚠ Error: </strong><span id="err-msg"></span></div>
    <button onclick="dismissError()" class="text-xs text-slate-400 hover:text-white">dismiss</button>
  </div>
</div>

<!-- ── Main grid ── -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-4">

  <!-- ── Col 1: Config + Sinks + Cleanup ── -->
  <div class="lg:col-span-3 flex flex-col gap-4">

    <!-- Configuration -->
    <div class="card p-4">
      <h2 class="section-title text-xs font-semibold text-slate-400 uppercase tracking-widest mb-3">Configuration</h2>

      <p class="text-xs text-slate-500 mb-1">Mode</p>
      <div class="flex gap-1 mb-3">
        <button id="btn-stream" onclick="setMode('stream')"
          class="flex-1 py-1.5 rounded text-sm font-medium btn-active transition-colors">Stream</button>
        <button id="btn-bulk"   onclick="setMode('bulk')"
          class="flex-1 py--1.5 rounded text-sm font-medium btn-ghost transition-colors">Bulk</button>
      </div>

      <div id="cfg-stream">
        <p class="text-xs text-slate-500 mb-1">Rate (events / sec)</p>
        <input type="number" id="rate" value="2" min="0.1" max="200" step="0.5" class="mb-3">
      </div>
      <div id="cfg-bulk" class="hidden">
        <p class="text-xs text-slate-500 mb-1">Event count</p>
        <input type="number" id="count" value="1000" min="1" max="500000" class="mb-2">
        <p class="text-xs text-slate-500 mb-1">Span (hours)</p>
        <input type="number" id="span-hours" value="24" min="1" max="720" class="mb-3">
      </div>

      <p class="text-xs text-slate-500 mb-1">Hostname</p>
      <select id="host" class="mb-0">
        <option>ip-172-31-12-45</option>
        <option>ip-172-31-8-201</option>
        <option>ip-172-31-22-99</option>
        <option>ip-10-0-1-15</option>
        <option>ip-10-0-3-88</option>
        <option>ip-10-0-5-212</option>
      </select>
    </div>

    <!-- Output Sinks -->
    <div class="card p-4">
      <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-3">Output Sinks</h2>

      <label class="flex items-center gap-2 mb-1 cursor-pointer">
        <input type="checkbox" id="sink-file" checked class="rounded accent-indigo-500">
        <span class="text-sm text-slate-300">Log Files</span>
      </label>
      <input type="text" id="output-dir" value="__DEFAULT_LOG_DIR__" class="mb-3 text-xs" placeholder="__DEFAULT_LOG_DIR__">

      <label class="flex items-center gap-2 mb-1 cursor-pointer">
        <input type="checkbox" id="sink-jsonl" class="rounded accent-indigo-500">
        <span class="text-sm text-slate-300">JSONL (structured)</span>
      </label>
      <input type="text" id="jsonl-dir" value="__DEFAULT_LOG_DIR__" class="mb-3 text-xs" placeholder="__DEFAULT_LOG_DIR__">

      <label class="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" id="sink-stdout" class="rounded accent-indigo-500">
        <span class="text-sm text-slate-300">Stdout</span>
      </label>
    </div>

    <!-- Cleanup -->
    <div class="card p-4">
      <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-3">Log Cleanup</h2>

      <p class="text-xs text-slate-500 mb-2">Auto-cleanup interval</p>
      <div class="grid grid-cols-4 gap-1 mb-3">
        <button onclick="setCleanup(0.25)" class="cleanup-btn py-1 rounded text-xs"     data-h="0.25">15m</button>
        <button onclick="setCleanup(0.5)"  class="cleanup-btn py-1 rounded text-xs sel" data-h="0.5">30m</button>
        <button onclick="setCleanup(0.75)" class="cleanup-btn py-1 rounded text-xs"     data-h="0.75">45m</button>
        <button onclick="setCleanup(1)"    class="cleanup-btn py-1 rounded text-xs"     data-h="1">60m</button>
      </div>

      <p class="text-xs text-slate-500 mb-1">Keep tail (MB, 0 = full truncate)</p>
      <input type="number" id="cleanup-mb" value="0" min="0" max="500" step="0.5" class="mb-3">

      <button id="btn-cleanup" onclick="triggerCleanup()"
        class="w-full py-1.5 rounded text-xs font-medium btn-ghost transition-colors">
        ⟳ Trigger Cleanup Now
      </button>
      <p id="cleanup-status" class="text-xs text-slate-500 mt-2 hidden"></p>
    </div>

  </div>

  <!-- ── Col 2: Event Catalogue ── -->
  <div class="lg:col-span-4">
    <div class="card p-4 h-full">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-widest">Event Catalogue</h2>
        <div class="flex gap-3 text-xs">
          <button onclick="selectAll(true)"  class="text-indigo-400 hover:text-indigo-300">All</button>
          <button onclick="selectAll(false)" class="text-slate-500 hover:text-slate-400">None</button>
        </div>
      </div>
      <div id="catalogue-list" class="space-y-1.5">
        <p class="text-xs text-slate-600">Loading...</p>
      </div>
    </div>
  </div>

  <!-- ── Col 3: Bindplane + Controls ── -->
  <div class="lg:col-span-5 flex flex-col gap-4">

    <!-- Bindplane Demo -->
    <div class="card-accent p-4">
      <div class="flex items-center gap-2 mb-1">
        <span class="text-base">⚡</span>
        <h2 class="text-xs font-semibold text-indigo-400 uppercase tracking-widest">Bindplane Demo — Noise Injection</h2>
      </div>
      <p class="text-xs text-slate-500 mb-4">
        Inject noisy events to demonstrate how Bindplane pipelines can filter low-value data
        before it reaches Dynatrace, reducing ingest volume and cost.
      </p>

      <!-- Duplicate logs -->
      <div class="mb-4">
        <div class="flex items-center justify-between mb-1.5">
          <div class="flex items-center gap-2">
            <label class="tog-wrap">
              <input type="checkbox" id="tog-dup" class="tog-inp">
              <span class="tog-sl"></span>
            </label>
            <span class="text-sm text-slate-300">Duplicate logs</span>
          </div>
          <span id="val-dup" class="text-xs text-slate-400 tabular-nums">25%</span>
        </div>
        <input type="range" id="rng-dup" min="1" max="50" value="25"
          oninput="document.getElementById('val-dup').textContent=this.value+'%'">
        <p class="text-xs text-slate-600 mt-1">
          Randomly re-emits the same log line. Bindplane can deduplicate to cut volume.
        </p>
      </div>

      <!-- Empty-field logs -->
      <div class="mb-4">
        <div class="flex items-center justify-between mb-1.5">
          <div class="flex items-center gap-2">
            <label class="tog-wrap">
              <input type="checkbox" id="tog-empty" class="tog-inp">
              <span class="tog-sl"></span>
            </label>
            <span class="text-sm text-slate-300">Empty-value logs</span>
          </div>
          <span id="val-empty" class="text-xs text-slate-400 tabular-nums">20%</span>
        </div>
        <input type="range" id="rng-empty" min="1" max="50" value="20"
          oninput="document.getElementById('val-empty').textContent=this.value+'%'">
        <p class="text-xs text-slate-600 mt-1">
          Logs where key fields (SRC, USER, COMMAND) are blank — no actionable data.
        </p>
      </div>

      <!-- PII logs -->
      <div class="mb-2">
        <div class="flex items-center justify-between mb-1.5">
          <div class="flex items-center gap-2">
            <label class="tog-wrap">
              <input type="checkbox" id="tog-pii" class="tog-inp">
              <span class="tog-sl"></span>
            </label>
            <span class="text-sm text-slate-300">Sensitive data (PII)</span>
          </div>
          <span id="val-pii" class="text-xs text-slate-400 tabular-nums">15%</span>
        </div>
        <input type="range" id="rng-pii" min="1" max="50" value="15"
          oninput="document.getElementById('val-pii').textContent=this.value+'%'">
        <p class="text-xs text-slate-600 mt-1">
          Synthetic SSN, date-of-birth, and credit card numbers. Bindplane can mask/redact.
        </p>
      </div>

      <div class="mt-3 p-3 rounded bg-slate-900 text-xs text-slate-500 leading-relaxed">
        💡 <strong class="text-slate-400">Demo script:</strong> Start the emulator with all
        three noise types enabled, then open Bindplane and show how a transform pipeline
        (dedup → drop-if-empty → PII-mask) removes the noise before forwarding to Dynatrace.
        Toggle noise on/off live to show the before/after event rate.
      </div>
    </div>

    <!-- Controls -->
    <div class="card p-4">
      <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-3">Controls</h2>
      <div class="flex gap-2">
        <button id="btn-start" onclick="startEmulator()"
          class="flex-1 py-2 rounded font-semibold text-sm btn-primary transition-colors">
          ▶ Start Emulator
        </button>
        <button id="btn-stop" onclick="stopEmulator()" disabled
          class="flex-1 py-2 rounded font-semibold text-sm btn-danger transition-colors">
          ■ Stop
        </button>
      </div>

      <div id="run-stats" class="hidden mt-3 grid grid-cols-3 gap-2 text-center">
        <div class="bg-slate-900 rounded p-2">
          <div id="stat-uptime" class="text-sm font-mono font-bold text-white">0s</div>
          <div class="text-xs text-slate-500">uptime</div>
        </div>
        <div class="bg-slate-900 rounded p-2">
          <div id="stat-events" class="text-sm font-mono font-bold text-emerald-400">0</div>
          <div class="text-xs text-slate-500">events</div>
        </div>
        <div class="bg-slate-900 rounded p-2">
          <div id="stat-noise"  class="text-sm font-mono font-bold text-amber-400">0</div>
          <div class="text-xs text-slate-500">noise</div>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- ── Log Tail ── -->
<div class="card mt-4 p-4">
  <div class="flex items-center justify-between mb-2">
    <h2 class="text-xs font-semibold text-slate-400 uppercase tracking-widest">Live Log Tail</h2>
    <div class="flex items-center gap-4">
      <label class="flex items-center gap-1.5 cursor-pointer text-xs text-slate-500">
        <input type="checkbox" id="autoscroll" checked class="rounded accent-indigo-500">
        Auto-scroll
      </label>
      <button onclick="clearLogs()" class="text-xs text-slate-600 hover:text-slate-400">Clear</button>
    </div>
  </div>
  <div id="log-tail"
       class="log-tail h-96 overflow-y-auto bg-black rounded p-2"
       style="min-height:14rem; resize:vertical;">
    <span class="text-slate-600">Waiting for emulator to start…</span>
  </div>
</div>

<script>
// ── state ────────────────────────────────────────────────────────────────
let mode = 'stream';
let cleanupHours = 0.5;          // default = 30 minutes
let lastLogKey = '';   // fingerprint of currently-rendered log buffer
let lastRunning = null;          // tracks running-state transitions for field locking

// ── theme (light / dark) ─────────────────────────────────────────────────
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  const icon  = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (icon)  icon.textContent  = (t === 'light') ? '☀️' : '🌙';
  if (label) label.textContent = (t === 'light') ? 'Light Mode' : 'Dark Mode';
}
function toggleTheme() {
  const cur  = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = (cur === 'light') ? 'dark' : 'light';
  try { localStorage.setItem('sle-theme', next); } catch (e) {}
  applyTheme(next);
}
(function initTheme() {
  let saved = 'dark';
  try { saved = localStorage.getItem('sle-theme') || 'dark'; } catch (e) {}
  applyTheme(saved);
})();

// ── mode ─────────────────────────────────────────────────────────────────
function setMode(m) {
  mode = m;
  document.getElementById('cfg-stream').classList.toggle('hidden', m !== 'stream');
  document.getElementById('cfg-bulk').classList.toggle('hidden', m !== 'bulk');
  document.getElementById('btn-stream').className =
    'flex-1 py-1.5 rounded text-sm font-medium transition-colors ' + (m==='stream' ? 'btn-active' : 'btn-ghost');
  document.getElementById('btn-bulk').className =
    'flex-1 py-1.5 rounded text-sm font-medium transition-colors ' + (m==='bulk' ? 'btn-active' : 'btn-ghost');
}

// ── cleanup interval ──────────────────────────────────────────────────────
function setCleanup(h) {
  cleanupHours = h;
  document.querySelectorAll('.cleanup-btn').forEach(b => {
    const active = parseInt(b.dataset.h) === h;
    b.classList.toggle('sel', active);
  });
}

// ── event catalogue ───────────────────────────────────────────────────────
const TYPE_COLOR = { auth:'text-red-400', syslog:'text-blue-400', audit:'text-purple-400' };

async function loadCatalogue() {
  const r = await fetch('/api/catalogue');
  const { catalogue } = await r.json();
  const el = document.getElementById('catalogue-list');
  el.innerHTML = catalogue.map(e => `
    <label class="flex items-center gap-2 cursor-pointer group">
      <input type="checkbox" class="evt-cb rounded accent-indigo-500" data-name="${e.name}" checked>
      <span class="flex-1 text-xs text-slate-300 group-hover:text-white">${e.label}</span>
      <span class="text-xs ${TYPE_COLOR[e.log_type]||'text-slate-500'} w-12 text-right">${e.log_type}</span>
      <span class="text-xs text-slate-600 w-5 text-right">${e.weight}</span>
    </label>`).join('');
}

function selectAll(v) {
  document.querySelectorAll('.evt-cb').forEach(cb => cb.checked = v);
}

function enabledEvents() {
  return [...document.querySelectorAll('.evt-cb:checked')].map(cb => cb.dataset.name);
}

// ── lock/unlock config controls when emulator is running ────────────────
// Hostname + Output Sinks are only read once at start, so changing them
// mid-run has no effect — disable them while running to make that obvious.
const LOCKED_IDS = ['host', 'sink-file', 'output-dir',
                    'sink-jsonl', 'jsonl-dir', 'sink-stdout'];
function setConfigLocked(locked) {
  LOCKED_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = locked;
      el.classList.toggle('opacity-50', locked);
      el.classList.toggle('cursor-not-allowed', locked);
    }
  });
}

// ── start / stop ──────────────────────────────────────────────────────────
async function startEmulator() {
  const cfg = {
    mode,
    rate:       parseFloat(document.getElementById('rate').value) || 2,
    count:      parseInt(document.getElementById('count').value)  || 1000,
    span_hours: parseFloat(document.getElementById('span-hours').value) || 24,
    host:       document.getElementById('host').value,
    output_dir: document.getElementById('sink-file').checked
                  ? (document.getElementById('output-dir').value || '__DEFAULT_LOG_DIR__') : null,
    jsonl_dir:  document.getElementById('sink-jsonl').checked
                  ? (document.getElementById('jsonl-dir').value || '__DEFAULT_LOG_DIR__') : null,
    stdout:     document.getElementById('sink-stdout').checked,
    cleanup_interval_hours: cleanupHours,
    cleanup_keep_mb:        parseFloat(document.getElementById('cleanup-mb').value) || 0,
    enabled_events:         enabledEvents(),
    noise_duplicate_pct:    document.getElementById('tog-dup').checked
                              ? parseInt(document.getElementById('rng-dup').value)   : 0,
    noise_empty_pct:        document.getElementById('tog-empty').checked
                              ? parseInt(document.getElementById('rng-empty').value) : 0,
    noise_pii_pct:          document.getElementById('tog-pii').checked
                              ? parseInt(document.getElementById('rng-pii').value)   : 0,
  };
  await fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(cfg),
  });
}

async function stopEmulator() {
  await fetch('/api/stop', { method: 'POST' });
}

async function triggerCleanup() {
  const btn  = document.getElementById('btn-cleanup');
  const stat = document.getElementById('cleanup-status');
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = '… cleaning';
  try {
    const r    = await fetch('/api/cleanup', { method: 'POST' });
    const data = await r.json();
    let msg, color;
    if (data.result === 'ok') {
      msg   = (data.mode === 'live')
              ? 'Cleanup sent to live emulator sinks.'
              : `Truncated ${data.cleaned} file(s).`;
      color = 'text-emerald-400';
    } else if (data.result === 'no_files') {
      msg   = data.message || 'Nothing to clean.';
      color = 'text-slate-400';
    } else {
      msg   = 'Cleanup failed — see error banner.';
      color = 'text-red-400';
    }
    stat.className = 'text-xs mt-2 ' + color;
    stat.textContent = msg;
    stat.classList.remove('hidden');
    setTimeout(() => stat.classList.add('hidden'), 6000);
  } catch (e) {
    stat.className = 'text-xs mt-2 text-red-400';
    stat.textContent = 'Request failed: ' + e;
    stat.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

async function clearLogs() {
  // Clear the server-side ring buffer first — otherwise the next poll
  // will re-paint the same lines. Also clears the DOM optimistically.
  try { await fetch('/api/logs/clear', { method: 'POST' }); } catch (e) {}
  document.getElementById('log-tail').innerHTML =
    '<span class="text-slate-600">Log cleared.</span>';
  lastLogKey = '';
}

function dismissError() {
  const b = document.getElementById('err-banner');
  b.classList.add('hidden');
  b._dismissedFor = document.getElementById('err-msg').textContent;
}

function showError(msg) {
  const b = document.getElementById('err-banner');
  if (!msg) { b.classList.add('hidden'); b._dismissedFor = null; return; }
  if (b._dismissedFor === msg) return;   // user dismissed this exact error
  document.getElementById('err-msg').textContent = msg;
  b.classList.remove('hidden');
}

// ── log coloring ──────────────────────────────────────────────────────────
function logClass(line) {
  if (/Failed password|Invalid user|Disconnected|brute/i.test(line)) return 'text-red-400';
  if (/sudo/i.test(line))                                              return 'text-yellow-400';
  if (/UFW|firewall|kernel/i.test(line))                               return 'text-blue-300';
  if (/type=SYSCALL|type=EXECVE|type=PATH/i.test(line))                return 'text-purple-400';
  if (/pam_unix/i.test(line))                                          return 'text-emerald-400';
  if (/ssn=|card_number=|date_of_birth=|dob=/i.test(line))            return 'text-amber-400';
  if (/\s{2,}|SRC= |DST= |COMMAND=$/.test(line))                      return 'text-slate-500';
  return 'text-slate-300';
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── poll loop ─────────────────────────────────────────────────────────────
function fmtUptime(s) {
  if (s < 60)   return Math.round(s) + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + Math.round(s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

async function poll() {
  try {
    const [sr, lr] = await Promise.all([
      fetch('/api/status'),
      fetch('/api/logs?n=150'),
    ]);
    const status = await sr.json();
    const {logs} = await lr.json();

    // surface backend error (e.g. permission denied on output dir)
    showError(status.last_error);

    // badge
    const badge = document.getElementById('status-badge');
    badge.textContent = status.running ? '● RUNNING' : '● STOPPED';
    badge.className   = status.running ? 'badge-run px-3 py-1 rounded-full text-xs font-semibold'
                                       : 'badge-stop px-3 py-1 rounded-full text-xs font-semibold';

    // header counters
    document.getElementById('hdr-events').textContent = status.events_total.toLocaleString() + ' events';
    const nh = document.getElementById('hdr-noise');
    if (status.events_noise > 0) {
      nh.textContent = '+' + status.events_noise.toLocaleString() + ' noise';
      nh.classList.remove('hidden');
    } else {
      nh.classList.add('hidden');
    }
    const uh = document.getElementById('hdr-uptime');
    if (status.running) {
      uh.textContent = fmtUptime(status.uptime_secs);
      uh.classList.remove('hidden');
    } else {
      uh.classList.add('hidden');
    }

    // stats panel
    const stats = document.getElementById('run-stats');
    if (status.running || status.events_total > 0) {
      stats.classList.remove('hidden');
      document.getElementById('stat-uptime').textContent = fmtUptime(status.uptime_secs);
      document.getElementById('stat-events').textContent = status.events_total.toLocaleString();
      document.getElementById('stat-noise').textContent  = status.events_noise.toLocaleString();
    }

    // control buttons
    document.getElementById('btn-start').disabled = status.running;
    document.getElementById('btn-stop').disabled  = !status.running;

    // lock Hostname + Output Sink fields while running (only re-apply on
    // transitions, so the user can keep typing in inputs when stopped)
    if (status.running !== lastRunning) {
      lastRunning = status.running;
      setConfigLocked(status.running);
    }

    // log tail — fingerprint includes count + first + last line so we still
    // re-render once the deque is full and lines roll off the front.
    const key = logs.length + '|' + (logs[0] || '') + '|' + (logs[logs.length - 1] || '');
    if (key !== lastLogKey) {
      lastLogKey = key;
      const tail = document.getElementById('log-tail');
      if (logs.length === 0) {
        tail.innerHTML = '<span class="text-slate-600">No logs yet.</span>';
      } else {
        tail.innerHTML = logs.map(l =>
          `<div class="${logClass(l)}">${esc(l)}</div>`
        ).join('');
        if (document.getElementById('autoscroll').checked) {
          tail.scrollTop = tail.scrollHeight;
        }
      }
    }
  } catch (e) { /* server not ready yet */ }
}

// ── init ─────────────────────────────────────────────────────────────────
loadCatalogue();
poll();
setInterval(poll, 1000);
</script>
</body>
</html>"""

# Substitute the placeholder once at import time so the served page always
# reflects the absolute path to <repo>/logs/.
HTML = HTML.replace("__DEFAULT_LOG_DIR__", DEFAULT_LOG_DIR)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Web UI for the Security Log Emulator")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Bind address. Use 0.0.0.0 to expose on LAN.")
    args = parser.parse_args()

    server = HTTPServer((args.bind, args.port), Handler)
    url = f"http://localhost:{args.port}"
    print(f"[web-ui] Listening on http://{args.bind}:{args.port}", file=sys.stderr)
    print(f"[web-ui] Open {url}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web-ui] Shutting down…", file=sys.stderr)
        STATE.stop()
        server.server_close()


if __name__ == "__main__":
    main()
