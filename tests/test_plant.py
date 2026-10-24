from __future__ import annotations

import pytest

from honeyfile.decoys import PROFILES, decoys_for
from honeyfile.manifest import MANIFEST_NAME, read
from honeyfile.plant import PlantError, plant


def test_plant_writes_decoys_and_manifest(tmp_path):
    manifest = plant(tmp_path, "office")
    assert {e.name for e in manifest.entries} == {d.name for d in decoys_for("office")}
    for entry in manifest.entries:
        assert (tmp_path / entry.name).exists()
    assert (tmp_path / MANIFEST_NAME).exists()
    assert read(tmp_path).entries == manifest.entries


def test_decoys_contain_no_real_secrets_only_tokens(tmp_path):
    plant(tmp_path, "dev")
    for file in tmp_path.iterdir():
        if file.name == MANIFEST_NAME:
            continue
        body = file.read_text()
        assert "HONEYFILE-CANARY-" in body
        # The only AWS-shaped key present is AWS's own documented example.
        if "AKIA" in body:
            assert "AKIAIOSFODNN7EXAMPLE" in body


def test_tokens_are_unique_per_file(tmp_path):
    manifest = plant(tmp_path, "db")
    tokens = [e.token for e in manifest.entries]
    assert len(set(tokens)) == len(tokens)


def test_plant_refuses_to_overwrite_without_force(tmp_path):
    real = tmp_path / "passwords.txt"
    real.write_text("my actual notes")
    with pytest.raises(PlantError, match="already exist"):
        plant(tmp_path, "office")
    assert real.read_text() == "my actual notes"  # untouched


def test_force_overwrites(tmp_path):
    (tmp_path / "passwords.txt").write_text("x")
    plant(tmp_path, "office", force=True)
    assert "HONEYFILE-CANARY-" in (tmp_path / "passwords.txt").read_text()


def test_unknown_profile():
    with pytest.raises(ValueError, match="unknown profile"):
        decoys_for("nope")


def test_every_profile_template_formats():
    # A stray "{" in a decoy body would raise when .format() runs during planting.
    for profile in PROFILES:
        for decoy in decoys_for(profile):
            decoy.body.format(token="X")
