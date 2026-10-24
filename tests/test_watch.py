from __future__ import annotations

import os

from honeyfile.manifest import read
from honeyfile.plant import plant
from honeyfile.watch import scan


def events(tmp_path, **kwargs):
    manifest = read(tmp_path)
    return {(a.event, a.path) for a in scan(tmp_path, manifest, **kwargs)}


def test_clean_directory_has_no_alerts(tmp_path):
    plant(tmp_path, "office")
    assert events(tmp_path) == set()


def test_modified_decoy_is_caught(tmp_path):
    plant(tmp_path, "dev")
    (tmp_path / ".env").write_text("encrypted")
    assert ("modified", ".env") in events(tmp_path)


def test_same_size_different_content_is_caught(tmp_path):
    # A byte-for-byte size collision must still be detected via the hash.
    plant(tmp_path, "db")
    target = tmp_path / "backup.sql"
    original = target.read_text()
    target.write_text("X" * len(original))
    assert ("modified", "backup.sql") in events(tmp_path)


def test_deleted_decoy_is_caught(tmp_path):
    plant(tmp_path, "office")
    (tmp_path / "passwords.txt").unlink()
    assert ("deleted", "passwords.txt") in events(tmp_path)


def test_touch_without_content_change_is_lower_severity(tmp_path):
    plant(tmp_path, "db")
    path = tmp_path / "backup.sql"
    future = path.stat().st_mtime + 120
    os.utime(path, (future, future))
    alerts = scan(tmp_path, read(tmp_path))
    touched = [a for a in alerts if a.path == "backup.sql"]
    assert touched and touched[0].event == "touched"
    assert touched[0].severity < 90


def test_new_file_is_flagged_and_can_be_disabled(tmp_path):
    plant(tmp_path, "office")
    (tmp_path / "READ_ME_RANSOM.txt").write_text("pay up")
    assert ("new-file", "READ_ME_RANSOM.txt") in events(tmp_path)
    assert ("new-file", "READ_ME_RANSOM.txt") not in events(tmp_path, detect_new=False)


def test_manifest_itself_is_not_flagged_as_a_new_file(tmp_path):
    plant(tmp_path, "office")
    assert not any(path == ".honeyfile.json" for _, path in events(tmp_path))


def test_alerts_are_sorted_worst_first(tmp_path):
    plant(tmp_path, "office")
    (tmp_path / "passwords.txt").unlink()  # severity 90
    (tmp_path / "note.txt").write_text("hi")  # severity 50
    severities = [a.severity for a in scan(tmp_path, read(tmp_path))]
    assert severities == sorted(severities, reverse=True)
