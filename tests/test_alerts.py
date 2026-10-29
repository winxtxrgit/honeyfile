from __future__ import annotations

import json
import sys

from honeyfile.alerts import Sinks, format_terminal, to_record
from honeyfile.watch import Alert


def _alert(event="modified", path="passwords.txt", detail="contents changed"):
    return Alert(event, path, detail)


def test_to_record_has_expected_fields():
    rec = to_record(_alert(), "/srv/share")
    assert rec["event"] == "modified"
    assert rec["path"] == "passwords.txt"
    assert rec["directory"] == "/srv/share"
    assert rec["severity"] == 90
    assert {"time", "event", "severity", "path", "directory", "detail"} <= rec.keys()


def test_format_terminal_plain_has_no_ansi():
    line = format_terminal(_alert(), color=False)
    assert "\033[" not in line
    assert "passwords.txt" in line and "[modified]" in line


def test_format_terminal_color_wraps_in_ansi():
    line = format_terminal(_alert(), color=True)
    assert line.startswith("\033[") and line.endswith("\033[0m")


def test_json_sink_appends_one_object_per_line(tmp_path):
    out = tmp_path / "alerts.jsonl"
    sinks = Sinks(directory=str(tmp_path), json_path=str(out))
    sinks.emit(_alert(event="deleted"))
    sinks.emit(_alert(event="new-file", path="ransom.txt"))
    lines = out.read_text().splitlines()
    assert len(lines) == 2
    recs = [json.loads(line) for line in lines]
    assert recs[0]["event"] == "deleted"
    assert recs[1]["path"] == "ransom.txt"


def test_webhook_posts_json(monkeypatch):
    import honeyfile.alerts as alerts

    captured = {}

    class _Resp:
        def close(self):
            pass

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode())
        captured["ctype"] = request.headers.get("Content-type")
        return _Resp()

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    Sinks(directory="/d", webhook="https://example.invalid/hook").emit(_alert())
    assert captured["url"] == "https://example.invalid/hook"
    assert captured["body"]["event"] == "modified"
    assert captured["ctype"] == "application/json"


def test_webhook_failure_is_soft(monkeypatch, capsys):
    import honeyfile.alerts as alerts

    def boom(request, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(alerts.urllib.request, "urlopen", boom)
    Sinks(directory="/d", webhook="https://example.invalid/hook").emit(_alert())  # must not raise
    assert "webhook failed" in capsys.readouterr().err


def test_exec_runs_command_with_env(tmp_path):
    marker = tmp_path / "fired.txt"
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import os, pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text("
        "os.environ['HONEYFILE_EVENT'] + ':' + os.environ['HONEYFILE_PATH'])\n"
    )
    Sinks(directory="/d", exec_cmd=[sys.executable, str(hook)]).emit(
        _alert(event="deleted", path="passwords.txt")
    )
    assert marker.read_text() == "deleted:passwords.txt"


def test_exec_failure_is_soft(capsys):
    Sinks(directory="/d", exec_cmd=["definitely-not-a-real-command-xyz"]).emit(_alert())
    assert "--exec failed" in capsys.readouterr().err
