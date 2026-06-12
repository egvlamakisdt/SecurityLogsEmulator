#!/usr/bin/env python3
"""
Linux EC2 Security Log Emulator
Generates realistic security logs for SIEM testing (e.g., Splunk).

Outputs:
  - /var/log/auth.log  style: SSH, sudo, PAM events
  - /var/log/syslog    style: system and firewall events
  - /var/log/audit     style: auditd records
  - Splunk HEC         (optional, via --splunk-hec-url / --splunk-hec-token)

Usage:
  python3 security_log_emulator.py --mode stream --rate 5
  python3 security_log_emulator.py --mode bulk --count 5000 --output ./logs
  python3 security_log_emulator.py --mode stream --splunk-hec-url https://splunk:8088 --splunk-hec-token TOKEN
"""

import argparse
import json
import os
import random
import socket
import string
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Callable


# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

HOSTNAMES = [
    "ip-172-31-12-45", "ip-172-31-8-201", "ip-172-31-22-99",
    "ip-10-0-1-15",    "ip-10-0-3-88",    "ip-10-0-5-212",
]

SYSTEM_USERS = ["root", "ubuntu", "ec2-user", "admin", "deploy", "jenkins", "ansible"]
ATTACK_USERS = [
    "admin", "root", "test", "guest", "oracle", "postgres", "pi", "user",
    "support", "ftp", "mail", "www-data", "operator", "nagios", "zabbix",
    "hadoop", "git", "svn", "backup", "mysql", "redis", "mongodb",
]

# Mix of internal RFC-1918 and external "attacker" IPs
INTERNAL_IPS = [f"10.0.{r}.{h}" for r in range(1, 6) for h in range(2, 10)]
EXTERNAL_IPS = [
    "185.220.101.47", "192.42.116.16", "198.98.54.220", "45.142.212.100",
    "89.248.167.131",  "80.82.77.33",   "141.98.10.29",  "94.102.61.7",
    "185.156.73.54",   "162.247.72.199","193.32.162.157", "176.10.99.200",
    "37.9.62.20",      "107.189.10.143","171.25.193.25",  "23.129.64.131",
]

SERVICES = ["sshd", "sudo", "cron", "systemd", "kernel", "useradd", "usermod", "passwd"]
COMMANDS  = [
    "/usr/bin/id", "/usr/bin/whoami", "/bin/bash", "/bin/sh",
    "/usr/bin/python3", "/usr/bin/curl", "/usr/bin/wget",
    "/usr/sbin/useradd", "/usr/bin/passwd", "/usr/bin/crontab",
    "/sbin/iptables",    "/usr/bin/nc",     "/usr/bin/nmap",
]

CRON_JOBS = [
    "/usr/sbin/logrotate /etc/logrotate.conf",
    "/usr/lib/update-notifier/apt-check",
    "/usr/bin/certbot renew",
    "/opt/app/bin/healthcheck.sh",
    "/home/ubuntu/scripts/backup.sh",
]

KERNEL_EVENTS = [
    "device veth{} entered promiscuous mode",
    "possible SYN flooding on port {}. Sending cookies.",
    "nf_conntrack: table full, dropping packet",
    "audit: type=1400 audit({}): apparmor=\"ALLOWED\" operation=\"open\"",
    "EXT4-fs error (device xvda1): ext4_find_entry:1455",
]

AUDITD_SYSCALLS = {
    "open":    "2",
    "read":    "0",
    "write":   "1",
    "execve":  "59",
    "connect": "42",
    "bind":    "49",
    "chmod":   "90",
    "chown":   "92",
    "unlink":  "87",
    "rename":  "82",
}

SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh/authorized_keys",
    "/home/ubuntu/.ssh/authorized_keys", "/etc/crontab", "/etc/hosts",
    "/var/log/auth.log", "/proc/net/tcp",
]

SSH_KEY_TYPES = ["RSA", "ECDSA", "ED25519"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rnd_ip(external_bias: float = 0.6) -> str:
    pool = EXTERNAL_IPS if random.random() < external_bias else INTERNAL_IPS
    return random.choice(pool)

def _rnd_port() -> int:
    return random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017,
                          random.randint(1024, 65535)])

def _pid() -> int:
    return random.randint(1000, 65535)

def _ts(dt: datetime) -> str:
    """syslog-style timestamp: Jun 10 14:03:22"""
    return dt.strftime("%b %d %H:%M:%S")

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _audit_ts(dt: datetime) -> str:
    return f"{dt.timestamp():.3f}"


# ---------------------------------------------------------------------------
# Log generators — each returns (log_type, raw_line, structured_dict)
# ---------------------------------------------------------------------------

LogEntry = tuple[str, str, dict]


def gen_ssh_failed_password(dt: datetime, host: str) -> LogEntry:
    user = random.choice(ATTACK_USERS)
    ip   = _rnd_ip(0.85)
    port = random.randint(40000, 65535)
    pid  = _pid()
    line = (f"{_ts(dt)} {host} sshd[{pid}]: Failed password for "
            f"{'invalid user ' if user not in SYSTEM_USERS else ''}"
            f"{user} from {ip} port {port} ssh2")
    return ("auth", line, {
        "event_type": "ssh_failed_password", "user": user,
        "src_ip": ip, "src_port": port, "pid": pid,
    })


def gen_ssh_accepted(dt: datetime, host: str) -> LogEntry:
    user    = random.choice(SYSTEM_USERS)
    ip      = _rnd_ip(0.3)
    port    = random.randint(40000, 65535)
    pid     = _pid()
    key_t   = random.choice(SSH_KEY_TYPES)
    line = (f"{_ts(dt)} {host} sshd[{pid}]: Accepted publickey for "
            f"{user} from {ip} port {port} ssh2: {key_t} "
            f"SHA256:{''.join(random.choices(string.ascii_letters+string.digits+'/', k=43))}")
    return ("auth", line, {
        "event_type": "ssh_accepted", "user": user,
        "src_ip": ip, "src_port": port, "pid": pid, "key_type": key_t,
    })


def gen_ssh_connection_closed(dt: datetime, host: str) -> LogEntry:
    user = random.choice(SYSTEM_USERS)
    ip   = _rnd_ip(0.3)
    port = random.randint(40000, 65535)
    pid  = _pid()
    line = (f"{_ts(dt)} {host} sshd[{pid}]: Disconnected from "
            f"authenticating user {user} {ip} port {port} [preauth]")
    return ("auth", line, {
        "event_type": "ssh_disconnected", "user": user,
        "src_ip": ip, "src_port": port, "pid": pid,
    })


def gen_ssh_invalid_user(dt: datetime, host: str) -> LogEntry:
    user = random.choice(ATTACK_USERS + ["" + "".join(random.choices(string.ascii_lowercase, k=5))])
    ip   = _rnd_ip(0.9)
    port = random.randint(40000, 65535)
    pid  = _pid()
    line = (f"{_ts(dt)} {host} sshd[{pid}]: "
            f"Invalid user {user} from {ip} port {port}")
    return ("auth", line, {
        "event_type": "ssh_invalid_user", "user": user,
        "src_ip": ip, "src_port": port, "pid": pid,
    })


def gen_sudo_success(dt: datetime, host: str) -> LogEntry:
    user  = random.choice(SYSTEM_USERS[1:])
    cmd   = random.choice(COMMANDS)
    pid   = _pid()
    line  = (f"{_ts(dt)} {host} sudo: {user} : TTY=pts/0 ; "
             f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
    return ("auth", line, {
        "event_type": "sudo_success", "user": user, "command": cmd, "pid": pid,
    })


def gen_sudo_failed(dt: datetime, host: str) -> LogEntry:
    user = random.choice(SYSTEM_USERS[1:] + ATTACK_USERS[:5])
    pid  = _pid()
    line = (f"{_ts(dt)} {host} sudo: {user} : 3 incorrect password attempts ; "
            f"TTY=pts/1 ; PWD=/home/{user} ; USER=root ; "
            f"COMMAND={random.choice(COMMANDS)}")
    return ("auth", line, {
        "event_type": "sudo_failed", "user": user, "pid": pid,
    })


def gen_pam_unix_session(dt: datetime, host: str) -> LogEntry:
    action = random.choice(["opened", "closed"])
    user   = random.choice(SYSTEM_USERS)
    pid    = _pid()
    by     = "root" if action == "opened" else random.choice(SYSTEM_USERS)
    line   = (f"{_ts(dt)} {host} sshd[{pid}]: pam_unix(sshd:session): "
              f"session {action} for user {user} by {by}(uid=0)")
    return ("auth", line, {
        "event_type": f"pam_session_{action}", "user": user, "by": by, "pid": pid,
    })


def gen_useradd(dt: datetime, host: str) -> LogEntry:
    new_user = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
    pid      = _pid()
    line     = (f"{_ts(dt)} {host} useradd[{pid}]: new user: "
                f"name={new_user}, UID={random.randint(1000, 9999)}, "
                f"GID={random.randint(1000, 9999)}, home=/home/{new_user}, shell=/bin/bash")
    return ("auth", line, {
        "event_type": "useradd", "new_user": new_user, "pid": pid,
    })


def gen_passwd_change(dt: datetime, host: str) -> LogEntry:
    user = random.choice(SYSTEM_USERS)
    pid  = _pid()
    line = (f"{_ts(dt)} {host} passwd[{pid}]: pam_unix(passwd:chauthtok): "
            f"password changed for {user}")
    return ("auth", line, {
        "event_type": "passwd_change", "user": user, "pid": pid,
    })


def gen_cron_job(dt: datetime, host: str) -> LogEntry:
    user = random.choice(SYSTEM_USERS)
    cmd  = random.choice(CRON_JOBS)
    pid  = _pid()
    line = f"{_ts(dt)} {host} CRON[{pid}]: ({user}) CMD ({cmd})"
    return ("syslog", line, {
        "event_type": "cron_execution", "user": user, "command": cmd, "pid": pid,
    })


def gen_kernel_firewall(dt: datetime, host: str) -> LogEntry:
    action  = random.choice(["ACCEPT", "DROP", "REJECT"])
    proto   = random.choice(["TCP", "UDP", "ICMP"])
    src_ip  = _rnd_ip(0.7)
    dst_ip  = random.choice(INTERNAL_IPS)
    src_p   = random.randint(1024, 65535)
    dst_p   = _rnd_port()
    pid     = _pid()
    line    = (f"{_ts(dt)} {host} kernel: [UFW {action}] "
               f"IN=eth0 OUT= MAC=... SRC={src_ip} DST={dst_ip} "
               f"PROTO={proto} SPT={src_p} DPT={dst_p} LEN=60")
    return ("syslog", line, {
        "event_type": "firewall", "action": action, "proto": proto,
        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_p, "dst_port": dst_p,
    })


def gen_kernel_event(dt: datetime, host: str) -> LogEntry:
    tmpl = random.choice(KERNEL_EVENTS)
    filler = random.choice([
        f"{''.join(random.choices(string.ascii_lowercase, k=6))}",
        str(random.randint(1024, 65535)),
        _audit_ts(dt),
    ])
    try:
        msg = tmpl.format(filler)
    except Exception:
        msg = tmpl
    pid  = _pid()
    line = f"{_ts(dt)} {host} kernel[{pid}]: {msg}"
    return ("syslog", line, {
        "event_type": "kernel", "message": msg,
    })


def gen_auditd_execve(dt: datetime, host: str) -> LogEntry:
    user   = random.choice(SYSTEM_USERS)
    cmd    = random.choice(COMMANDS)
    uid    = random.randint(0, 2000)
    pid    = _pid()
    serial = random.randint(100000, 999999)
    ts     = _audit_ts(dt)
    line   = (f"type=EXECVE msg=audit({ts}:{serial}): argc=2 "
              f"a0=\"{cmd.split('/')[-1]}\" a1=\"--help\" "
              f"uid={uid} auid={uid} pid={pid} comm=\"{cmd.split('/')[-1]}\"")
    return ("audit", line, {
        "event_type": "auditd_execve", "user": user, "command": cmd,
        "uid": uid, "pid": pid, "serial": serial,
    })


def gen_auditd_open_sensitive(dt: datetime, host: str) -> LogEntry:
    user   = random.choice(SYSTEM_USERS + ATTACK_USERS[:3])
    fpath  = random.choice(SENSITIVE_FILES)
    uid    = 0 if user == "root" else random.randint(1000, 9999)
    pid    = _pid()
    serial = random.randint(100000, 999999)
    ts     = _audit_ts(dt)
    line   = (f"type=SYSCALL msg=audit({ts}:{serial}): arch=x86_64 "
              f"syscall=open success=yes exit=3 "
              f"uid={uid} gid={uid} pid={pid} comm=\"cat\" "
              f"exe=\"/bin/cat\" key=\"sensitive_file\"")
    line2  = (f"type=PATH msg=audit({ts}:{serial}): item=0 "
              f"name=\"{fpath}\" inode=1234 dev=08:01 mode=0100640")
    return ("audit", line + "\n" + line2, {
        "event_type": "auditd_sensitive_file", "user": user,
        "file": fpath, "uid": uid, "pid": pid,
    })


def gen_auditd_network(dt: datetime, host: str) -> LogEntry:
    src_ip  = random.choice(INTERNAL_IPS)
    dst_ip  = _rnd_ip(0.5)
    dst_p   = _rnd_port()
    pid     = _pid()
    uid     = random.randint(0, 2000)
    serial  = random.randint(100000, 999999)
    ts      = _audit_ts(dt)
    line    = (f"type=SYSCALL msg=audit({ts}:{serial}): arch=x86_64 "
               f"syscall=connect success=yes exit=0 "
               f"uid={uid} pid={pid} comm=\"curl\" exe=\"/usr/bin/curl\"")
    return ("audit", line, {
        "event_type": "auditd_network_connect", "dst_ip": dst_ip,
        "dst_port": dst_p, "uid": uid, "pid": pid,
    })


def gen_brute_force_burst(dt: datetime, host: str) -> list[LogEntry]:
    """Simulate a short SSH brute-force burst from a single IP."""
    ip    = random.choice(EXTERNAL_IPS)
    count = random.randint(8, 25)
    entries = []
    for i in range(count):
        user = random.choice(ATTACK_USERS)
        port = random.randint(40000, 65535)
        pid  = _pid()
        t    = dt + timedelta(seconds=i * random.uniform(0.1, 0.8))
        line = (f"{_ts(t)} {host} sshd[{pid}]: Failed password for "
                f"invalid user {user} from {ip} port {port} ssh2")
        entries.append(("auth", line, {
            "event_type": "ssh_failed_password", "user": user,
            "src_ip": ip, "src_port": port, "pid": pid, "burst": True,
        }))
    return entries


# ---------------------------------------------------------------------------
# Weighted event catalogue
# ---------------------------------------------------------------------------

# (weight, generator_fn)
EVENT_CATALOGUE: list[tuple[int, Callable]] = [
    (30, gen_ssh_failed_password),
    (12, gen_ssh_accepted),
    (10, gen_ssh_connection_closed),
    (15, gen_ssh_invalid_user),
    (8,  gen_sudo_success),
    (4,  gen_sudo_failed),
    (10, gen_pam_unix_session),
    (2,  gen_useradd),
    (2,  gen_passwd_change),
    (8,  gen_cron_job),
    (12, gen_kernel_firewall),
    (5,  gen_kernel_event),
    (6,  gen_auditd_execve),
    (4,  gen_auditd_open_sensitive),
    (4,  gen_auditd_network),
]

BURST_PROBABILITY = 0.04   # ~4% chance of triggering a brute-force burst


def _weighted_choices(n: int) -> list[Callable]:
    weights, fns = zip(*EVENT_CATALOGUE)
    return random.choices(fns, weights=weights, k=n)


def generate_event(dt: datetime, host: str) -> list[LogEntry]:
    if random.random() < BURST_PROBABILITY:
        return gen_brute_force_burst(dt, host)
    weights, fns = zip(*EVENT_CATALOGUE)
    fn = random.choices(fns, weights=weights, k=1)[0]
    result = fn(dt, host)
    return [result]


# ---------------------------------------------------------------------------
# Output sinks
# ---------------------------------------------------------------------------

class FileSink:
    def __init__(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        self._dir = output_dir
        self._paths = {
            "auth":   os.path.join(output_dir, "auth.log"),
            "syslog": os.path.join(output_dir, "syslog"),
            "audit":  os.path.join(output_dir, "audit.log"),
        }
        self._files = {k: open(p, "a", buffering=1) for k, p in self._paths.items()}
        self._lock = threading.Lock()

    def write(self, log_type: str, line: str, _struct: dict):
        with self._lock:
            fh = self._files.get(log_type, self._files["syslog"])
            fh.write(line + "\n")

    def cleanup(self, keep_bytes: int = 0):
        """Truncate managed log files to free disk space.

        If keep_bytes > 0, retain the trailing keep_bytes of each file
        (tail buffer) so very recent context survives the rotation.
        """
        with self._lock:
            for key, fh in list(self._files.items()):
                path = self._paths[key]
                try:
                    fh.flush()
                    fh.close()
                    if keep_bytes > 0 and os.path.getsize(path) > keep_bytes:
                        with open(path, "rb") as src:
                            src.seek(-keep_bytes, os.SEEK_END)
                            tail = src.read()
                        # align tail to next newline to avoid splitting a record
                        nl = tail.find(b"\n")
                        if nl != -1:
                            tail = tail[nl + 1:]
                        with open(path, "wb") as dst:
                            dst.write(tail)
                    else:
                        # full truncate
                        open(path, "wb").close()
                except OSError as exc:
                    print(f"[cleanup warn] {path}: {exc}", file=sys.stderr)
                finally:
                    self._files[key] = open(path, "a", buffering=1)

    def close(self):
        with self._lock:
            for fh in self._files.values():
                fh.close()


class StdoutSink:
    def write(self, log_type: str, line: str, _struct: dict):
        print(line)

    def cleanup(self, keep_bytes: int = 0):
        # nothing to clean — output is not persisted by this sink
        pass

    def close(self): pass


class JsonlSink:
    def __init__(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        self._path = os.path.join(output_dir, "events.jsonl")
        self._fh = open(self._path, "a", buffering=1)
        self._lock = threading.Lock()

    def write(self, log_type: str, line: str, struct: dict):
        record = {"log_type": log_type, "raw": line, **struct}
        with self._lock:
            self._fh.write(json.dumps(record) + "\n")

    def cleanup(self, keep_bytes: int = 0):
        with self._lock:
            try:
                self._fh.flush()
                self._fh.close()
                if keep_bytes > 0 and os.path.getsize(self._path) > keep_bytes:
                    with open(self._path, "rb") as src:
                        src.seek(-keep_bytes, os.SEEK_END)
                        tail = src.read()
                    nl = tail.find(b"\n")
                    if nl != -1:
                        tail = tail[nl + 1:]
                    with open(self._path, "wb") as dst:
                        dst.write(tail)
                else:
                    open(self._path, "wb").close()
            except OSError as exc:
                print(f"[cleanup warn] {self._path}: {exc}", file=sys.stderr)
            finally:
                self._fh = open(self._path, "a", buffering=1)

    def close(self):
        with self._lock:
            self._fh.close()


class SplunkHECSink:
    """Sends events to Splunk HTTP Event Collector."""
    def __init__(self, url: str, token: str, index: str = "main",
                 sourcetype_map: dict | None = None):
        self._url   = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._index = index
        self._sourcetype_map = sourcetype_map or {
            "auth":   "linux_secure",
            "syslog": "syslog",
            "audit":  "linux_audit",
        }
        self._batch:  list[dict] = []
        self._batch_size = 50
        self._lock = threading.Lock()

    def write(self, log_type: str, line: str, struct: dict):
        event = {
            "time":       time.time(),
            "host":       struct.get("host", socket.gethostname()),
            "source":     f"/var/log/{log_type}",
            "sourcetype": self._sourcetype_map.get(log_type, "syslog"),
            "index":      self._index,
            "event":      line,
            "fields":     {k: v for k, v in struct.items() if k != "host"},
        }
        with self._lock:
            self._batch.append(event)
            should_flush = len(self._batch) >= self._batch_size
        if should_flush:
            self._flush()

    def _flush(self):
        with self._lock:
            if not self._batch:
                return
            batch = self._batch
            self._batch = []
        payload = "\n".join(json.dumps(e) for e in batch).encode()
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 201):
                    print(f"[HEC warn] HTTP {resp.status}", file=sys.stderr)
        except urllib.error.URLError as exc:
            print(f"[HEC error] {exc}", file=sys.stderr)

    def cleanup(self, keep_bytes: int = 0):
        # remote sink — no local disk to clean. Flush any pending batch
        # so we don't accumulate memory indefinitely.
        self._flush()

    def close(self):
        self._flush()


class MultiSink:
    def __init__(self, sinks: list):
        self._sinks = sinks

    def write(self, log_type: str, line: str, struct: dict):
        for s in self._sinks:
            s.write(log_type, line, struct)

    def cleanup(self, keep_bytes: int = 0):
        for s in self._sinks:
            cleanup_fn = getattr(s, "cleanup", None)
            if callable(cleanup_fn):
                cleanup_fn(keep_bytes)

    def close(self):
        for s in self._sinks:
            s.close()


# ---------------------------------------------------------------------------
# Periodic cleanup
# ---------------------------------------------------------------------------

def start_cleanup_thread(sink, interval_hours: float, keep_mb: float) -> threading.Event:
    """Spawn a daemon thread that calls sink.cleanup() every interval_hours.

    Returns a stop Event the caller can set during shutdown to stop the loop.
    """
    interval_secs = max(interval_hours * 3600.0, 60.0)
    keep_bytes = int(max(keep_mb, 0.0) * 1024 * 1024)
    stop_evt = threading.Event()

    def _loop():
        print(f"[cleanup] every {interval_hours}h, "
              f"keep_tail={keep_mb} MB", file=sys.stderr)
        while not stop_evt.wait(interval_secs):
            try:
                sink.cleanup(keep_bytes)
                print(f"[cleanup] {datetime.now(timezone.utc).isoformat()} "
                      f"truncated logs (kept last {keep_mb} MB)", file=sys.stderr)
            except Exception as exc:  # pragma: no cover — defensive
                print(f"[cleanup error] {exc}", file=sys.stderr)

    t = threading.Thread(target=_loop, name="log-cleanup", daemon=True)
    t.start()
    return stop_evt


# ---------------------------------------------------------------------------
# Emulator modes
# ---------------------------------------------------------------------------

def run_stream(sink, rate: float, host: str,
               cleanup_interval_hours: float = 8.0,
               cleanup_keep_mb: float = 0.0):
    """Real-time streaming — emit ~rate events/sec.

    A background daemon thread truncates persistent log sinks every
    `cleanup_interval_hours` to keep the EC2 volume from filling up.
    Set cleanup_interval_hours <= 0 to disable.
    """
    delay = 1.0 / max(rate, 0.01)
    print(f"[emulator] streaming at ~{rate} events/sec, host={host}  (Ctrl-C to stop)",
          file=sys.stderr)
    stop_cleanup = None
    if cleanup_interval_hours > 0:
        stop_cleanup = start_cleanup_thread(sink, cleanup_interval_hours, cleanup_keep_mb)
    total = 0
    try:
        while True:
            entries = generate_event(datetime.now(timezone.utc), host)
            for log_type, line, struct in entries:
                sink.write(log_type, line, struct)
                total += 1
            time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n[emulator] stopped after {total} events.", file=sys.stderr)
    finally:
        if stop_cleanup is not None:
            stop_cleanup.set()
        sink.close()


def run_bulk(sink, count: int, host: str, start: datetime | None = None,
             span_hours: float = 24.0):
    """Generate `count` events spread across span_hours in the past."""
    if start is None:
        start = datetime.now(timezone.utc) - timedelta(hours=span_hours)
    span_secs = span_hours * 3600
    print(f"[emulator] generating {count} bulk events over {span_hours}h, host={host}",
          file=sys.stderr)
    # Pre-generate timestamps, sort ascending
    offsets = sorted(random.uniform(0, span_secs) for _ in range(count))
    generated = 0
    for offset in offsets:
        dt = start + timedelta(seconds=offset)
        entries = generate_event(dt, host)
        for log_type, line, struct in entries:
            sink.write(log_type, line, struct)
            generated += 1
    print(f"[emulator] wrote {generated} events.", file=sys.stderr)
    sink.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Linux EC2 security log emulator for SIEM testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=["stream", "bulk"], default="stream",
                   help="stream: real-time; bulk: historical batch")
    p.add_argument("--rate", type=float, default=2.0,
                   help="[stream] events per second (default: 2)")
    p.add_argument("--count", type=int, default=1000,
                   help="[bulk] number of events to generate (default: 1000)")
    p.add_argument("--span-hours", type=float, default=24.0,
                   help="[bulk] time window in hours to spread events across (default: 24)")
    p.add_argument("--host", default=random.choice(HOSTNAMES),
                   help="hostname to embed in logs")

    out = p.add_argument_group("output (one or more may be combined)")
    out.add_argument("--output", metavar="DIR",
                     help="write auth.log / syslog / audit.log to this directory")
    out.add_argument("--jsonl", metavar="DIR",
                     help="write all events as JSONL to DIR/events.jsonl")
    out.add_argument("--stdout", action="store_true",
                     help="print raw log lines to stdout")
    out.add_argument("--splunk-hec-url", metavar="URL",
                     help="Splunk HEC endpoint  e.g. https://splunk:8088")
    out.add_argument("--splunk-hec-token", metavar="TOKEN",
                     help="Splunk HEC token")
    out.add_argument("--splunk-index", default="main",
                     help="Splunk index (default: main)")

    cleanup = p.add_argument_group("disk cleanup (stream mode only)")
    cleanup.add_argument("--cleanup-interval-hours", type=float, default=8.0,
                         help="how often to truncate local log files "
                              "(default: 8; set <=0 to disable)")
    cleanup.add_argument("--cleanup-keep-mb", type=float, default=0.0,
                         help="bytes (in MB) of trailing log content to retain "
                              "across each cleanup (default: 0 = full truncate)")
    return p


def main():
    args = build_parser().parse_args()

    sinks = []

    if args.output:
        sinks.append(FileSink(args.output))
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    if args.stdout:
        sinks.append(StdoutSink())
    if args.splunk_hec_url:
        if not args.splunk_hec_token:
            print("[error] --splunk-hec-token required when --splunk-hec-url is set",
                  file=sys.stderr)
            sys.exit(1)
        sinks.append(SplunkHECSink(
            args.splunk_hec_url, args.splunk_hec_token, args.splunk_index
        ))

    if not sinks:
        print("[info] no output specified — defaulting to stdout", file=sys.stderr)
        sinks.append(StdoutSink())

    sink = MultiSink(sinks) if len(sinks) > 1 else sinks[0]

    if args.mode == "stream":
        run_stream(sink, args.rate, args.host,
                   cleanup_interval_hours=args.cleanup_interval_hours,
                   cleanup_keep_mb=args.cleanup_keep_mb)
    else:
        run_bulk(sink, args.count, args.host, span_hours=args.span_hours)


if __name__ == "__main__":
    main()
