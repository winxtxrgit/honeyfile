"""macOS and BSD kqueue backend: react the instant a decoy is changed, deleted or replaced.

kqueue watches open file descriptors rather than paths. honeyfile keeps one on the
directory, which reports that its entries changed (a file created, deleted or renamed),
one on each decoy, which reports writes, attribute changes, deletion and renaming, and
one on the baseline. Everything comes from :mod:`select` in the standard library.

Unlike inotify, kqueue on macOS has no "opened" event, so a read that changes nothing is
not reported here; that needs Endpoint Security, which requires an Apple entitlement.

On a platform without kqueue :func:`available` returns ``False`` and the CLI falls back
to polling.
"""

from __future__ import annotations

import os
import select
from collections.abc import Iterator
from pathlib import Path

from .manifest import MANIFEST_NAME, Manifest, ManifestError, read
from .manifest import manifest_path as locate
from .watch import Alert, _check_decoy

# A descriptor opened only to receive events, so a watched decoy never keeps a volume busy
# (macOS). Elsewhere a plain read-only open, which reads nothing.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_EVTONLY", 0) | getattr(os, "O_CLOEXEC", 0)

# Gather events that follow each other this closely into one batch, for at most this
# many rounds, so a constant stream of writes still gets reported.
_SETTLE = 0.05
_SETTLE_ROUNDS = 20

_DIRECTORY = "\0directory"  # roles that can never be a file name
_MANIFEST = "\0manifest"


def available() -> bool:
    """True when this Python has kqueue (macOS and the BSDs)."""
    return hasattr(select, "kqueue")


def _gone_flags() -> int:
    return select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME | select.KQ_NOTE_REVOKE


def _all_flags() -> int:
    return (
        _gone_flags()
        | select.KQ_NOTE_WRITE
        | select.KQ_NOTE_EXTEND
        | select.KQ_NOTE_ATTRIB
        | select.KQ_NOTE_LINK
    )


class _Kqueue:
    """A kqueue plus the descriptors it watches, each tagged with a role."""

    def __init__(self) -> None:
        self._kq = select.kqueue()
        self._roles: dict[int, str] = {}
        self._fds: dict[str, tuple[int, int]] = {}  # role -> (fd, inode)

    def watch(self, path: Path, role: str) -> bool:
        """Watch *path* as *role*, replacing any earlier watch. False if it does not exist."""
        self.unwatch(role)
        try:
            fd = os.open(path, _OPEN_FLAGS)
        except OSError:
            return False
        event = select.kevent(
            fd,
            filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
            fflags=_all_flags(),
        )
        try:
            self._kq.control([event], 0, 0)
        except OSError:
            os.close(fd)
            return False
        self._roles[fd] = role
        self._fds[role] = (fd, os.fstat(fd).st_ino)
        return True

    def unwatch(self, role: str) -> None:
        held = self._fds.pop(role, None)
        if held is not None:
            self._roles.pop(held[0], None)
            os.close(held[0])  # closing the descriptor also removes its kevent

    def inode(self, role: str) -> int | None:
        """The inode *role* is watching, or ``None`` when it watches nothing."""
        held = self._fds.get(role)
        return held[1] if held else None

    def read(self, timeout: float | None) -> list[tuple[str, int]]:
        """Block up to *timeout* seconds, then return ``(role, fflags)`` pairs.

        One shell redirect is a truncate and then a write, which kqueue reports
        microseconds apart. Events that keep arriving within :data:`_SETTLE` of each
        other are returned as one batch, so that change is reported once.
        """
        events = self._kq.control(None, 64, timeout)
        for _ in range(_SETTLE_ROUNDS):
            if not events:
                break
            more = self._kq.control(None, 64, _SETTLE)
            if not more:
                break
            events += more
        return [(self._roles[e.ident], e.fflags) for e in events if e.ident in self._roles]

    def close(self) -> None:
        for role in list(self._fds):
            self.unwatch(role)
        self._kq.close()

    def __enter__(self) -> _Kqueue:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _files(directory: Path) -> set[str]:
    try:
        return {entry.name for entry in os.scandir(directory) if entry.is_file()}
    except OSError:
        return set()


def _inode(path: Path) -> int | None:
    try:
        return path.stat().st_ino
    except OSError:
        return None


def monitor(
    directory: Path,
    *,
    detect_new: bool = True,
    manifest_path: Path | None = None,
    _timeout: float | None = None,
) -> Iterator[Alert | ManifestError]:
    """Watch *directory* with kqueue, yielding each alert the instant it happens.

    Mirrors :func:`honeyfile.inotify.monitor`: a :class:`ManifestError` is yielded (not
    raised) if the baseline becomes unreadable, and iteration ends only when the caller
    stops consuming. *_timeout* bounds each wait and exists for the tests.
    """
    baseline = locate(directory, manifest_path)
    try:
        manifest: Manifest | None = read(directory, manifest_path)
    except ManifestError as error:
        yield error
        manifest = None

    with _Kqueue() as kq:
        missing: set[str] = set()  # decoys already reported gone, not to be reported again

        def watch_decoys() -> None:
            for entry in manifest.entries if manifest else ():
                if kq.inode(entry.name) is None and not kq.watch(
                    directory / entry.name, entry.name
                ):
                    missing.add(entry.name)

        def check(name: str) -> Alert | None:
            """Re-examine one decoy: changed in place, replaced, deleted or back again."""
            entry = manifest.by_name().get(name) if manifest else None
            if entry is None:
                return None
            path = directory / name
            now = _inode(path)
            if now is None:
                kq.unwatch(name)
                if name in missing:
                    return None
                missing.add(name)
                return _check_decoy(entry, path)  # "deleted"
            if now != kq.inode(name):
                # Written elsewhere and renamed over the decoy: watch the file now there.
                kq.watch(path, name)
            missing.discard(name)
            return _check_decoy(entry, path)

        kq.watch(directory, _DIRECTORY)
        kq.watch(baseline, _MANIFEST)
        watch_decoys()
        present = _files(directory)

        while True:
            events = kq.read(_timeout)
            if not events and _timeout is not None:
                return

            # The baseline changed, vanished, or reappeared after vanishing: re-read it.
            baseline_events = [flags for role, flags in events if role == _MANIFEST]
            if any(flags & _gone_flags() for flags in baseline_events):
                kq.unwatch(_MANIFEST)
            reappeared = kq.inode(_MANIFEST) is None and kq.watch(baseline, _MANIFEST)
            if baseline_events or reappeared:
                try:
                    manifest = read(directory, manifest_path)
                    watch_decoys()
                except ManifestError as error:
                    yield error
                    manifest = None
            if manifest is None:
                continue

            alerts: list[Alert] = []
            for role, _flags in events:
                if role == _MANIFEST:
                    continue
                if role != _DIRECTORY:
                    if (alert := check(role)) is not None:
                        alerts.append(alert)
                    continue
                # Entries changed: find decoys deleted or replaced, and files dropped in.
                planted = manifest.by_name()
                for name in planted:
                    now = _inode(directory / name)
                    changed = now != kq.inode(name) and not (now is None and name in missing)
                    if changed and (alert := check(name)) is not None:
                        alerts.append(alert)
                now_present = _files(directory)
                if detect_new:
                    for name in sorted(now_present - present - set(planted) - {MANIFEST_NAME}):
                        if directory / name != baseline:
                            alerts.append(
                                Alert("new-file", name, "a file that was not planted appeared")
                            )
                present = now_present

            # One encryption arrives as several events; report each change once per batch.
            fired: set[tuple[str, str]] = set()
            for alert in alerts:
                if (alert.event, alert.path) not in fired:
                    fired.add((alert.event, alert.path))
                    yield alert
