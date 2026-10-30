"""Plant decoy files in a directory and record their baseline manifest."""

from __future__ import annotations

import contextlib
import os
import random
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .decoys import decoys_for
from .manifest import Entry, Manifest, digest, read, write
from .manifest import manifest_path as manifest_path_of


class PlantError(Exception):
    """Planting could not proceed, e.g. a decoy already exists."""


def _token() -> str:
    # A unique marker per decoy. Watch for it in logs, email or egress traffic.
    return f"HONEYFILE-CANARY-{secrets.token_hex(8)}"


def _backdate(path: Path) -> None:
    """Give a decoy a varied, plausibly-old timestamp.

    Freshly planted decoys would otherwise all share one creation time — a tell
    that the directory is a honeypot. A random age (roughly 1–13 months) makes
    them blend in with real files. The baseline records whatever timestamp ends
    up on disk, so tamper detection is unaffected.
    """
    age = random.uniform(30, 400) * 86400  # seconds
    when = time.time() - age
    # If the filesystem refuses the change, keep the real mtime; detection still works.
    with contextlib.suppress(OSError):
        os.utime(path, (when, when))


def plant(
    directory: Path,
    profile: str = "office",
    force: bool = False,
    manifest_path: Path | None = None,
) -> Manifest:
    """Write the *profile* decoys into *directory* and return the recorded baseline.

    Refuses to overwrite an existing file unless *force* is set, so a real file
    that happens to share a decoy's name is never clobbered. Pass *manifest_path*
    to store the baseline outside *directory* (out of an intruder's reach).
    """
    decoys = decoys_for(profile)
    directory.mkdir(parents=True, exist_ok=True)

    targets = [(decoy, directory / decoy.name) for decoy in decoys]
    clashes = [path.name for _, path in targets if path.exists()]
    if clashes and not force:
        raise PlantError(
            "these names already exist in the directory: "
            + ", ".join(sorted(clashes))
            + " (use --force to overwrite, but check they are not real files first)"
        )

    entries = []
    for decoy, path in targets:
        token = _token()
        path.write_text(decoy.body.format(token=token), encoding="utf-8")
        _backdate(path)
        stat = path.stat()
        entries.append(Entry(decoy.name, digest(path), stat.st_size, stat.st_mtime, token))

    manifest = Manifest(datetime.now(timezone.utc).isoformat(timespec="seconds"), profile, entries)
    write(directory, manifest, manifest_path)
    return manifest


@dataclass(frozen=True)
class Removed:
    """What an ``unplant`` took away, so the caller can report it honestly."""

    deleted: list[str]  # decoy names removed from disk
    missing: list[str]  # decoys the baseline listed but were already gone
    manifest: Path  # the baseline file that was removed


def unplant(directory: Path, manifest_path: Path | None = None) -> Removed:
    """Remove the decoys recorded in the baseline, then the baseline itself.

    Only files named in the manifest are deleted, so anything you created in the
    directory yourself is left alone. A decoy already gone is reported, not an
    error. Raises :class:`~honeyfile.manifest.ManifestError` if no baseline is
    found — there is then nothing to safely remove.
    """
    manifest = read(directory, manifest_path)
    deleted: list[str] = []
    missing: list[str] = []
    for entry in manifest.entries:
        path = directory / entry.name
        try:
            path.unlink()
            deleted.append(entry.name)
        except FileNotFoundError:
            missing.append(entry.name)
    mpath = manifest_path_of(directory, manifest_path)
    mpath.unlink()
    return Removed(deleted, missing, mpath)
