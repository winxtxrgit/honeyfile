from __future__ import annotations

import json

import pytest

from honeyfile.manifest import MANIFEST_NAME, ManifestError, read
from honeyfile.plant import plant


def test_missing_manifest(tmp_path):
    with pytest.raises(ManifestError, match="no .honeyfile.json"):
        read(tmp_path)


def test_corrupt_json(tmp_path):
    plant(tmp_path, "office")
    (tmp_path / MANIFEST_NAME).write_text("{not json")
    with pytest.raises(ManifestError, match="unreadable"):
        read(tmp_path)


def test_edited_manifest_fails_its_checksum(tmp_path):
    plant(tmp_path, "office")
    path = tmp_path / MANIFEST_NAME
    data = json.loads(path.read_text())
    data["entries"][0]["sha256"] = "0" * 64  # attacker rewrites the baseline hash
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError, match="checksum|modified"):
        read(tmp_path)


def test_missing_field(tmp_path):
    plant(tmp_path, "office")
    path = tmp_path / MANIFEST_NAME
    data = json.loads(path.read_text())
    del data["checksum"]
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError, match="not a valid manifest"):
        read(tmp_path)
