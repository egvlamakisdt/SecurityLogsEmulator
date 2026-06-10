# Contributing

Thanks for taking an interest in improving the Security Logs Emulator!

## Ground rules

- Keep the project **dependency-free**. Everything must run with a stock
  Python 3.10+ install — no `pip install` step.
- Generated content should be **plausible Linux/EC2 log output**. If you can't
  point to a real-world example of the format you're adding, it probably
  doesn't belong.
- Never include real credentials, real customer hostnames, or real IOC data.

## Development setup

```bash
git clone https://github.com/egvlamakisdt/SecurityLogsEmulator.git
cd SecurityLogsEmulator
python security_log_emulator.py --mode stream --rate 5 --stdout
```

That's the whole loop. There is no build step.

## Adding a new event type

1. Write a `gen_*` function in `security_log_emulator.py` that returns a
   `LogEntry` tuple `(log_type, raw_line, structured_dict)`.
   - `log_type` must be one of `"auth"`, `"syslog"`, or `"audit"`.
   - `raw_line` should match the format real Linux logs use (compare against
     `/var/log/auth.log` or `ausearch` output on a real box).
   - `structured_dict` should expose useful fields (`event_type`, `user`,
     `src_ip`, `command`, …) so the JSONL and Splunk HEC sinks stay rich.
2. Register it in `EVENT_CATALOGUE` with a sensible weight.
3. Try a stream and confirm the line looks right:

   ```bash
   python security_log_emulator.py --mode stream --rate 20 --stdout | head
   ```

## Pull requests

- One logical change per PR.
- Update `README.md` (event catalogue table) when adding/removing generators.
- Bump entries in `CHANGELOG.md` if you create one.
- Keep the diff focused — please don't reformat unrelated code.

## Reporting issues

When filing a bug, include:

- Python version (`python --version`).
- The exact command you ran.
- The unexpected output (or a snippet of the offending log line).
