"""Compare a directory against its baseline and report what changed.

One :func:`scan` is a point-in-time check: it returns an alert for every decoy
that was modified, deleted or merely touched, and for every unexpected new file
that appeared next to the decoys (a ransom note, a dropped tool). :func:`monitor`
runs :func:`scan` on a loop and yields each alert once.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .manifest import MANIFEST_NAME, Entry, Manifest, ManifestError, digest, read

# Higher is worse. Encryption and deletion are the ransomware signal; a changed
# timestamp or a new sibling file is weaker on its own.
SEVERITY = {
    "modified": 90,
    "deleted": 90,
    "manifest-error": 95,
    "new-file": 50,
    "touched": 40,
}


@dataclass(frozen=True)
class Alert:
    event: str
    path: str
    detail: str

    @property
    def severity(self) -> int:
        return SEVERITY.get(self.event, 50)


def _check_decoy(entry: Entry, path: Path) -> Alert | None:
    try:
        stat = path.stat()
        changed = stat.st_size != entry.size or digest(path) != entry.sha256
    except FileNotFoundError:
        return Alert("deleted", entry.name, "decoy file is gone")
    except OSError as error:
        # Replaced by a directory, or read permission pulled — a change worth flagging.
        return Alert("modified", entry.name, f"cannot read decoy: {error}")

    if changed:
        if stat.st_size != entry.size:
            detail = f"contents changed ({entry.size} → {stat.st_size} bytes)"
        else:
            detail = f"contents changed (same {entry.size} bytes, hash differs)"
        return Alert("modified", entry.name, detail)
    if stat.st_mtime != entry.mtime:
        return Alert("touched", entry.name, "timestamp changed but contents are intact")
    return None


def scan(directory: Path, manifest: Manifest, *, detect_new: bool = True) -> list[Alert]:
    """Every way *directory* now differs from *manifest*, worst first."""
    alerts = [
        alert
        for entry in manifest.entries
        if (alert := _check_decoy(entry, directory / entry.name)) is not None
    ]

    if detect_new:
        known = set(manifest.by_name()) | {MANIFEST_NAME}
        try:
            present = [p for p in directory.iterdir() if p.is_file()]
        except OSError:
            present = []
        for path in present:
            if path.name not in known:
                alerts.append(Alert("new-file", path.name, "a file that was not planted appeared"))

    alerts.sort(key=lambda a: (-a.severity, a.path))
    return alerts


def monitor(
    directory: Path,
    interval: float,
    *,
    detect_new: bool = True,
    manifest_path: Path | None = None,
) -> Iterator[Alert | ManifestError]:
    """Scan *directory* every *interval* seconds, yielding each alert once.

    A :class:`ManifestError` is yielded (not raised) the first time the manifest
    becomes unreadable or fails its checksum, since destroying the baseline is
    itself an attack worth reporting. Iteration ends only when interrupted.
    """
    seen: set[tuple[str, str]] = set()
    manifest_broken = False
    while True:
        try:
            manifest = read(directory, manifest_path)
            manifest_broken = False
        except ManifestError as error:
            if not manifest_broken:
                manifest_broken = True
                yield error
            time.sleep(interval)
            continue

        current = scan(directory, manifest, detect_new=detect_new)
        keys = {(a.event, a.path) for a in current}
        for alert in current:
            if (alert.event, alert.path) not in seen:
                yield alert
        # Let a cleared alert fire again if it recurs, but keep active ones quiet.
        seen = keys
        time.sleep(interval)
