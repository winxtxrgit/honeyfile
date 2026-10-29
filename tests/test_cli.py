from __future__ import annotations

import json
import os
import shlex
import sys

import pytest

from honeyfile.cli import main


def test_plant_then_status_clean(tmp_path, capsys):
    assert main(["plant", str(tmp_path), "--profile", "dev"]) == 0
    assert "Planted 3 dev decoys" in capsys.readouterr().out
    assert main(["status", str(tmp_path)]) == 0
    assert "intact" in capsys.readouterr().out


def test_status_detects_tampering(tmp_path, capsys):
    main(["plant", str(tmp_path)])
    capsys.readouterr()
    (tmp_path / "passwords.txt").write_text("encrypted")
    assert main(["status", str(tmp_path)]) == 1
    assert "modified" in capsys.readouterr().out


def test_watch_once_exit_codes(tmp_path):
    main(["plant", str(tmp_path)])
    assert main(["watch", str(tmp_path), "--once"]) == 0
    (tmp_path / "passwords.txt").unlink()
    assert main(["watch", str(tmp_path), "--once"]) == 1


def test_watch_once_writes_json(tmp_path):
    main(["plant", str(tmp_path)])
    (tmp_path / "passwords.txt").write_text("x")
    out = tmp_path / "alerts.jsonl"
    main(["watch", str(tmp_path), "--once", "--json", str(out)])
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert any(r["event"] == "modified" and r["path"] == "passwords.txt" for r in records)
    assert all({"time", "event", "severity", "detail"} <= r.keys() for r in records)


@pytest.mark.skipif(os.name == "nt", reason="shell-style path quoting differs on Windows")
def test_watch_exec_runs_command_with_env(tmp_path):
    main(["plant", str(tmp_path)])
    (tmp_path / "passwords.txt").unlink()
    # Keep the hook and its output outside the watched dir, or they become new-file alerts.
    outside = tmp_path.parent / "exec_out"
    outside.mkdir(exist_ok=True)
    hook, marker = outside / "hook.py", outside / "fired.txt"
    hook.write_text(
        f'import os, pathlib\npathlib.Path(r"{marker}").write_text(os.environ["HONEYFILE_EVENT"])\n'
    )
    main(["watch", str(tmp_path), "--once", "--exec", f"{sys.executable} {shlex.quote(str(hook))}"])
    # Exec runs per alert, worst first, so "deleted" (90) fires before any "new-file" (50).
    assert marker.read_text() == "deleted"


def test_status_without_manifest_errors(tmp_path, capsys):
    assert main(["status", str(tmp_path)]) == 2
    assert "honeyfile:" in capsys.readouterr().err


def test_external_manifest_round_trips(tmp_path, capsys):
    share = tmp_path / "share"
    ext = tmp_path / "base.json"
    assert main(["plant", str(share), "--manifest", str(ext)]) == 0
    capsys.readouterr()
    assert ext.exists()
    assert not (share / ".honeyfile.json").exists()
    # Without --manifest the baseline can't be found...
    assert main(["status", str(share)]) == 2
    capsys.readouterr()
    # ...but with it, the decoys read clean.
    assert main(["status", str(share), "--manifest", str(ext)]) == 0
    assert "intact" in capsys.readouterr().out


def test_bad_interval_rejected(tmp_path, capsys):
    main(["plant", str(tmp_path)])
    try:
        main(["watch", str(tmp_path), "--interval", "0"])
    except SystemExit as exit:
        assert exit.code == 2
    assert "greater than 0" in capsys.readouterr().err
