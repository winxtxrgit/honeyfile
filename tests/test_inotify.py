"""Functional tests for the Linux inotify backend, skipped where unavailable.

``inotify.monitor`` is a generator, so its watch is only established on the first
iteration. Each test therefore drains it on a background thread, waits for the
watch to settle, then performs the file action — otherwise the event would fire
before anything is listening.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pytest

from honeyfile import inotify
from honeyfile.plant import plant

pytestmark = pytest.mark.skipif(not inotify.available(), reason="inotify is Linux-only")


def observe(
    directory,
    action: Callable[[], None],
    *,
    detect_new: bool = True,
    manifest_path=None,
    settle: float = 0.5,
    quiet: float = 1.0,
) -> set[tuple[str, str]]:
    """Run *action* under an active watch and return the alerts it produced."""
    alerts: list[tuple[str, str]] = []

    def consume() -> None:
        for event in inotify.monitor(
            directory, detect_new=detect_new, manifest_path=manifest_path, _timeout=quiet
        ):
            alerts.append((event.event, event.path))

    thread = threading.Thread(target=consume)
    thread.start()
    time.sleep(settle)  # let the inotify watch get established before we act
    action()
    thread.join(timeout=quiet + 2.0)
    return set(alerts)


def test_reading_a_decoy_is_caught_as_opened(tmp_path):
    # The whole point of inotify: a read changes nothing a snapshot could see.
    plant(tmp_path, "office")
    alerts = observe(tmp_path, lambda: (tmp_path / "passwords.txt").read_text())
    assert ("opened", "passwords.txt") in alerts


def test_modifying_a_decoy_is_caught(tmp_path):
    plant(tmp_path, "dev")
    alerts = observe(tmp_path, lambda: (tmp_path / ".env").write_text("encrypted"))
    assert ("modified", ".env") in alerts


def test_deleting_a_decoy_is_caught(tmp_path):
    plant(tmp_path, "office")
    alerts = observe(tmp_path, lambda: (tmp_path / "passwords.txt").unlink())
    assert ("deleted", "passwords.txt") in alerts


def test_new_file_is_flagged_and_can_be_disabled(tmp_path):
    plant(tmp_path, "office")
    drop = lambda: (tmp_path / "READ_ME_RANSOM.txt").write_text("pay up")  # noqa: E731
    assert ("new-file", "READ_ME_RANSOM.txt") in observe(tmp_path, drop)

    drop2 = lambda: (tmp_path / "another.txt").write_text("hi")  # noqa: E731
    assert ("new-file", "another.txt") not in observe(tmp_path, drop2, detect_new=False)


def test_manifest_is_not_reported_as_a_new_file(tmp_path):
    plant(tmp_path, "office")
    alerts = observe(tmp_path, lambda: (tmp_path / "passwords.txt").read_text())
    assert not any(path == ".honeyfile.json" for _, path in alerts)
