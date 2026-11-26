"""Functional tests for the kqueue backend (macOS and the BSDs), skipped elsewhere.

Like the inotify tests, each one drains ``kqueue.monitor`` on a background thread,
waits for the watches to be set up, then performs the file action.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable

import pytest

from honeyfile import kqueue
from honeyfile.manifest import ManifestError
from honeyfile.plant import plant

pytestmark = pytest.mark.skipif(not kqueue.available(), reason="kqueue is macOS/BSD-only")


def observe(
    directory,
    action: Callable[[], None],
    *,
    detect_new: bool = True,
    manifest_path=None,
    settle: float = 0.3,
    quiet: float = 0.8,
) -> list[tuple[str, str]]:
    """Run *action* under an active watch and return the alerts it produced, in order."""
    alerts: list[tuple[str, str]] = []

    def consume() -> None:
        for event in kqueue.monitor(
            directory, detect_new=detect_new, manifest_path=manifest_path, _timeout=quiet
        ):
            if isinstance(event, ManifestError):
                alerts.append(("manifest-error", str(event)))
            else:
                alerts.append((event.event, event.path))

    thread = threading.Thread(target=consume)
    thread.start()
    time.sleep(settle)  # let the watches get established before we act
    action()
    thread.join(timeout=quiet + 3.0)
    assert not thread.is_alive(), "monitor did not go quiet"
    return alerts


def test_modifying_a_decoy_is_caught(tmp_path):
    plant(tmp_path, "dev")
    alerts = observe(tmp_path, lambda: (tmp_path / ".env").write_text("encrypted"))
    assert ("modified", ".env") in alerts


def test_deleting_a_decoy_is_reported_once(tmp_path):
    plant(tmp_path, "office")

    def act():
        (tmp_path / "passwords.txt").unlink()
        time.sleep(0.2)
        (tmp_path / "unrelated.txt").write_text("x")  # another directory event afterwards

    alerts = observe(tmp_path, act)
    assert alerts.count(("deleted", "passwords.txt")) == 1


def test_encrypt_and_replace_is_modified_and_followed(tmp_path):
    # Ransomware often writes the encrypted copy next to the original, then renames it over.
    plant(tmp_path, "office")
    target = tmp_path / "passwords.txt"

    def act():
        staged = tmp_path / ".passwords.tmp"
        staged.write_bytes(os.urandom(64))
        os.replace(staged, target)
        time.sleep(0.3)
        target.write_text("second change")  # the watch must now be on the new file

    alerts = observe(tmp_path, act, detect_new=False)
    assert ("modified", "passwords.txt") in alerts
    assert alerts.count(("modified", "passwords.txt")) >= 2
    assert ("deleted", "passwords.txt") not in alerts


def test_rename_away_is_deleted_plus_a_new_file(tmp_path):
    plant(tmp_path, "office")
    act = lambda: (tmp_path / "passwords.txt").rename(tmp_path / "passwords.txt.locked")  # noqa: E731
    alerts = observe(tmp_path, act)
    assert ("deleted", "passwords.txt") in alerts
    assert ("new-file", "passwords.txt.locked") in alerts


def test_new_file_is_flagged_and_can_be_disabled(tmp_path):
    plant(tmp_path, "office")
    drop = lambda: (tmp_path / "READ_ME_RANSOM.txt").write_text("pay up")  # noqa: E731
    assert ("new-file", "READ_ME_RANSOM.txt") in observe(tmp_path, drop)

    drop2 = lambda: (tmp_path / "another.txt").write_text("hi")  # noqa: E731
    assert ("new-file", "another.txt") not in observe(tmp_path, drop2, detect_new=False)


def test_a_changed_timestamp_is_touched(tmp_path):
    plant(tmp_path, "office")
    act = lambda: os.utime(tmp_path / "passwords.txt", (1, 1))  # noqa: E731
    assert ("touched", "passwords.txt") in observe(tmp_path, act)


def test_a_plain_read_is_not_visible_to_kqueue(tmp_path):
    # Documented limit: macOS kqueue has no open event.
    plant(tmp_path, "office")
    act = lambda: (tmp_path / "passwords.txt").read_bytes()  # noqa: E731
    assert observe(tmp_path, act) == []


def test_tampering_with_the_baseline_is_reported(tmp_path):
    plant(tmp_path, "office")
    baseline = tmp_path / ".honeyfile.json"
    act = lambda: baseline.write_text(baseline.read_text().replace("office", "nothing"))  # noqa: E731
    alerts = observe(tmp_path, act)
    assert any(event == "manifest-error" and "checksum" in detail for event, detail in alerts)
    assert not any(path == ".honeyfile.json" for _, path in alerts)


def test_deleting_the_baseline_is_reported(tmp_path):
    plant(tmp_path, "office")
    alerts = observe(tmp_path, lambda: (tmp_path / ".honeyfile.json").unlink())
    assert any(event == "manifest-error" for event, _ in alerts)


def test_external_baseline(tmp_path):
    share, store = tmp_path / "share", tmp_path / "store" / "share.json"
    share.mkdir()
    plant(share, "office", manifest_path=store)
    act = lambda: (share / "passwords.txt").write_text("encrypted")  # noqa: E731
    assert ("modified", "passwords.txt") in observe(share, act, manifest_path=store)


def test_a_shell_redirect_is_reported_once(tmp_path):
    # `printf x > file` truncates and then writes: two kqueue events, one change.
    plant(tmp_path, "office")

    def act():
        with open(tmp_path / "passwords.txt", "w") as handle:  # truncate
            handle.flush()
            time.sleep(0.01)
            handle.write("ENCRYPTED")

    assert observe(tmp_path, act).count(("modified", "passwords.txt")) == 1
