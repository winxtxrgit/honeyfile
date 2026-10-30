"""Linux inotify backend: react the instant a decoy is touched — including read.

The polling backend (:mod:`honeyfile.watch`) can only compare snapshots, so it
can never see a read: opening a file to copy or inspect it changes neither its
size, hash nor (on a ``noatime`` mount) its mtime. inotify can. A single watch
on the planted directory reports ``IN_OPEN`` for every file opened inside it, so
honeyfile fires an ``opened`` alert the moment an intruder so much as looks at a
decoy — earlier than any content change.

This module is Linux-only and uses :mod:`ctypes` against libc, so it adds no
dependency. On any other platform :func:`available` returns ``False`` and the
CLI falls back to polling.
"""

from __future__ import annotations

import ctypes
import errno
import os
import select
import struct
import sys
from collections.abc import Iterator
from pathlib import Path

from .manifest import MANIFEST_NAME, Manifest, ManifestError, read
from .watch import Alert, _check_decoy

# inotify event-mask bits we care about (from <sys/inotify.h>).
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_ISDIR = 0x40000000

IN_NONBLOCK = 0x00000800
IN_CLOEXEC = 0x00080000

# One watch on the directory sees all of these for the files inside it.
_WATCH_MASK = (
    IN_OPEN
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CREATE
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
)

_EVENT_HEADER = struct.Struct("iIII")  # wd, mask, cookie, name-length


def available() -> bool:
    """True when this process can use inotify (a Linux build with the syscalls)."""
    return sys.platform.startswith("linux") and hasattr(_libc(), "inotify_init1")


_LIBC: ctypes.CDLL | None = None


def _libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
        # Declare signatures explicitly: the path is a pointer, and leaving ctypes
        # to guess would truncate it to an int on 64-bit systems.
        lib.inotify_init1.argtypes = [ctypes.c_int]
        lib.inotify_init1.restype = ctypes.c_int
        lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        lib.inotify_add_watch.restype = ctypes.c_int
        _LIBC = lib
    return _LIBC


def _raise_errno(what: str) -> None:
    err = ctypes.get_errno()
    raise OSError(err, f"{what}: {os.strerror(err)}")


class _Inotify:
    """A thin, closeable wrapper over an inotify file descriptor."""

    def __init__(self) -> None:
        libc = _libc()
        fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            _raise_errno("inotify_init1")
        self._fd = fd

    def add(self, path: Path, mask: int) -> int:
        wd = _libc().inotify_add_watch(self._fd, os.fsencode(str(path)), mask)
        if wd < 0:
            _raise_errno(f"inotify_add_watch {path}")
        return wd

    def read(self, timeout: float | None) -> list[tuple[int, int, str]]:
        """Block up to *timeout* seconds, then return ``(wd, mask, name)`` tuples.

        An empty list means the timeout elapsed with nothing to report.
        """
        ready, _, _ = select.select([self._fd], [], [], timeout)
        if not ready:
            return []
        try:
            buf = os.read(self._fd, 65536)
        except BlockingIOError:
            return []
        except OSError as error:
            if error.errno == errno.EINTR:
                return []
            raise

        events: list[tuple[int, int, str]] = []
        offset = 0
        while offset < len(buf):
            wd, mask, _cookie, length = _EVENT_HEADER.unpack_from(buf, offset)
            offset += _EVENT_HEADER.size
            raw = buf[offset : offset + length]
            offset += length
            name = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
            events.append((wd, mask, name))
        return events

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> _Inotify:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _alert_for(mask: int, name: str, directory: Path, manifest: Manifest) -> Alert | None:
    """Translate one directory event on *name* into an alert, or ``None`` to ignore."""
    entry = manifest.by_name().get(name)
    if entry is not None:
        if mask & IN_OPEN:
            return Alert("opened", name, "decoy was opened — nothing should ever read it")
        if mask & (IN_DELETE | IN_MOVED_FROM):
            return Alert("deleted", name, "decoy file is gone")
        if mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB):
            # Re-use the polling check so "modified" vs "touched" and the detail
            # text stay identical across both backends.
            return _check_decoy(entry, directory / name)
        return None

    if mask & (IN_CREATE | IN_MOVED_TO) and not mask & IN_ISDIR:
        return Alert("new-file", name, "a file that was not planted appeared")
    return None


def monitor(
    directory: Path,
    *,
    detect_new: bool = True,
    manifest_path: Path | None = None,
    _timeout: float | None = None,
) -> Iterator[Alert | ManifestError]:
    """Watch *directory* with inotify, yielding each alert the instant it happens.

    Mirrors :func:`honeyfile.watch.monitor`: a :class:`ManifestError` is yielded
    (not raised) if the baseline becomes unreadable, since destroying it is itself
    an attack. Iteration ends only when the caller stops consuming. *_timeout*
    bounds each blocking read and exists for the tests; leave it ``None`` in use.

    Unlike the polling backend this also emits ``opened`` alerts: a read of a
    decoy, which a snapshot comparison can never see.
    """
    try:
        manifest: Manifest | None = read(directory, manifest_path)
    except ManifestError as error:
        yield error
        manifest = None

    mpath = (manifest_path or directory / MANIFEST_NAME).resolve()
    watch_manifest_here = mpath.parent == directory.resolve()

    with _Inotify() as ino:
        ino.add(directory, _WATCH_MASK)
        while True:
            events = ino.read(_timeout)
            if not events and _timeout is not None:
                return
            # One write arrives as IN_OPEN + IN_MODIFY + IN_CLOSE_WRITE in a single
            # batch; collapse the identical alerts so a tamper is reported once.
            fired: set[tuple[str, str]] = set()
            for _wd, mask, name in events:
                # The baseline changed or vanished: re-read it and report any break.
                if watch_manifest_here and name == mpath.name:
                    try:
                        manifest = read(directory, manifest_path)
                    except ManifestError as error:
                        yield error
                        manifest = None
                    continue
                if name == MANIFEST_NAME or manifest is None:
                    continue
                alert = _alert_for(mask, name, directory, manifest)
                if alert is None or (alert.event == "new-file" and not detect_new):
                    continue
                if (alert.event, alert.path) in fired:
                    continue
                fired.add((alert.event, alert.path))
                yield alert
