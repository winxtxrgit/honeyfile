from __future__ import annotations

import pytest

from honeyfile.cli import main
from honeyfile.manifest import MANIFEST_NAME, ManifestError
from honeyfile.plant import plant, unplant


def test_unplant_removes_decoys_and_baseline(tmp_path):
    manifest = plant(tmp_path, "office")
    removed = unplant(tmp_path)
    assert set(removed.deleted) == {e.name for e in manifest.entries}
    for entry in manifest.entries:
        assert not (tmp_path / entry.name).exists()
    assert not (tmp_path / MANIFEST_NAME).exists()


def test_unplant_leaves_your_own_files_alone(tmp_path):
    plant(tmp_path, "office")
    mine = tmp_path / "my_real_notes.txt"
    mine.write_text("keep me")
    unplant(tmp_path)
    assert mine.read_text() == "keep me"


def test_unplant_reports_an_already_deleted_decoy(tmp_path):
    plant(tmp_path, "db")
    (tmp_path / "backup.sql").unlink()
    removed = unplant(tmp_path)
    assert "backup.sql" in removed.missing
    assert "backup.sql" not in removed.deleted


def test_unplant_without_baseline_errors(tmp_path):
    with pytest.raises(ManifestError):
        unplant(tmp_path)


def test_unplant_external_manifest(tmp_path):
    share, ext = tmp_path / "share", tmp_path / "base.json"
    plant(share, "office", manifest_path=ext)
    removed = unplant(share, ext)
    assert not ext.exists()
    assert removed.manifest == ext
    assert list(share.iterdir()) == []  # every planted file gone, nothing left behind


def test_unplant_cli(tmp_path, capsys):
    main(["plant", str(tmp_path), "--profile", "dev"])
    capsys.readouterr()
    assert main(["unplant", str(tmp_path)]) == 0
    assert "Removed 3 decoy(s)" in capsys.readouterr().out
    assert main(["unplant", str(tmp_path)]) == 2  # nothing left to unplant
