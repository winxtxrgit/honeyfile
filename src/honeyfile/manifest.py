"""The baseline manifest: what each decoy looked like when it was planted.

Stored as ``.honeyfile.json`` in the watched directory. The manifest records a
sha256, size and mtime per decoy so :mod:`honeyfile.watch` can tell a tampered
decoy from an untouched one. The manifest carries a checksum of its own entries,
so editing or truncating it is itself detectable; deleting it is reported as a
missing baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

MANIFEST_NAME = ".honeyfile.json"
_FORMAT = 1


@dataclass(frozen=True)
class Entry:
    name: str  # relative to the watched directory
    sha256: str
    size: int
    mtime: float
    token: str


@dataclass(frozen=True)
class Manifest:
    created: str  # ISO 8601 UTC
    profile: str
    entries: list[Entry]

    def by_name(self) -> dict[str, Entry]:
        return {entry.name: entry for entry in self.entries}


def digest(path: Path) -> str:
    """sha256 of a file, read in chunks so a large decoy does not load into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _checksum(created: str, profile: str, entries: list[Entry]) -> str:
    # Over a canonical form of the data, so reordering or editing any field shows up.
    payload = json.dumps(
        {"created": created, "profile": profile, "entries": [asdict(e) for e in entries]},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def manifest_path(directory: Path, path: Path | None = None) -> Path:
    """Where the baseline lives: *path* if given, else ``.honeyfile.json`` in *directory*.

    Passing *path* keeps the baseline out of the watched directory, so an intruder
    who lands among the decoys cannot read it to learn which files are bait.
    """
    return path if path is not None else directory / MANIFEST_NAME


def write(directory: Path, manifest: Manifest, path: Path | None = None) -> Path:
    mpath = manifest_path(directory, path)
    data = {
        "format": _FORMAT,
        "created": manifest.created,
        "profile": manifest.profile,
        "entries": [asdict(e) for e in manifest.entries],
        "checksum": _checksum(manifest.created, manifest.profile, manifest.entries),
    }
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return mpath


class ManifestError(Exception):
    """The manifest is missing, unreadable, or fails its own integrity check."""


def read(directory: Path, path: Path | None = None) -> Manifest:
    mpath = manifest_path(directory, path)
    try:
        raw = json.loads(mpath.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ManifestError(
            f"no {mpath.name} in {mpath.parent}; run 'honeyfile plant' first"
        ) from None
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"{mpath} is unreadable: {error}") from None

    try:
        entries = [
            Entry(e["name"], e["sha256"], int(e["size"]), float(e["mtime"]), e["token"])
            for e in raw["entries"]
        ]
        created, profile, stored = raw["created"], raw["profile"], raw["checksum"]
    except (KeyError, TypeError, ValueError) as error:
        raise ManifestError(f"{mpath} is not a valid manifest: {error}") from None

    if _checksum(created, profile, entries) != stored:
        raise ManifestError(f"{mpath} has been modified since it was written (checksum mismatch)")
    return Manifest(created, profile, entries)
