"""Where an alert goes once it fires: the terminal, a JSON-lines file, a webhook,
or a command of your own.

The webhook and command sinks reach outside the process, so both fail soft: a
dead endpoint or a broken command must never stop the watch from reporting the
next event.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .watch import Alert


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_record(alert: Alert, directory: str) -> dict:
    return {
        "time": _now(),
        "event": alert.event,
        "severity": alert.severity,
        "path": alert.path,
        "directory": directory,
        "detail": alert.detail,
    }


_COLORS = {True: {90: "1;31", 95: "1;31", 50: "33", 40: "2"}, False: {}}


def _use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def format_terminal(alert: Alert, color: bool) -> str:
    tag = f"[{alert.event}]"
    line = f"{_now()}  {tag:<16} {alert.path}  —  {alert.detail}"
    code = _COLORS[color].get(alert.severity) if color else None
    return f"\033[{code}m{line}\033[0m" if code else line


@dataclass
class Sinks:
    """Fan one alert out to every configured destination."""

    directory: str
    json_path: str | None = None
    webhook: str | None = None
    exec_cmd: list[str] | None = None
    color: bool = False

    def emit(self, alert: Alert) -> None:
        print(format_terminal(alert, self.color), file=sys.stderr, flush=True)
        record = to_record(alert, self.directory)
        if self.json_path:
            self._write_json(record)
        if self.webhook:
            self._post(record)
        if self.exec_cmd:
            self._run(record)

    def _write_json(self, record: dict) -> None:
        try:
            with open(self.json_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except OSError as error:
            print(f"honeyfile: cannot write {self.json_path}: {error}", file=sys.stderr)

    def _post(self, record: dict) -> None:
        body = json.dumps(record).encode()
        request = urllib.request.Request(
            self.webhook, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except (urllib.error.URLError, OSError) as error:
            print(f"honeyfile: webhook failed: {error}", file=sys.stderr)

    def _run(self, record: dict) -> None:
        # The command gets the event as HONEYFILE_* env vars; no shell, so a path
        # from the filesystem is never interpreted.
        env = {**os.environ, **{f"HONEYFILE_{k.upper()}": str(v) for k, v in record.items()}}
        try:
            subprocess.run(self.exec_cmd, env=env, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            print(f"honeyfile: --exec failed: {error}", file=sys.stderr)
