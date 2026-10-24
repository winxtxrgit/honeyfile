"""Plant decoy files in a directory and record their baseline manifest."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path

from .decoys import decoys_for
from .manifest import Entry, Manifest, digest, write


class PlantError(Exception):
    """Planting could not proceed, e.g. a decoy already exists."""


def _token() -> str:
    # A unique marker per decoy. Watch for it in logs, email or egress traffic.
    return f"HONEYFILE-CANARY-{secrets.token_hex(8)}"


def plant(directory: Path, profile: str = "office", force: bool = False) -> Manifest:
    """Write the *profile* decoys into *directory* and return the recorded baseline.

    Refuses to overwrite an existing file unless *force* is set, so a real file
    that happens to share a decoy's name is never clobbered.
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
        stat = path.stat()
        entries.append(Entry(decoy.name, digest(path), stat.st_size, stat.st_mtime, token))

    manifest = Manifest(datetime.now(timezone.utc).isoformat(timespec="seconds"), profile, entries)
    write(directory, manifest)
    return manifest
