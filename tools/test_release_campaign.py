import pytest

import release_campaign as campaign
from lmyzmail_blackbox.errors import GoldenMismatch
from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore


def test_campaign_preserves_old_bytes_and_requires_exact_new_replay(tmp_path, monkeypatch):
    original = tmp_path / "original"
    destination = tmp_path / "campaign"
    monkeypatch.setattr(campaign, "ORIGINAL", original)
    monkeypatch.setattr(campaign, "_campaign", destination)
    monkeypatch.setattr(GoldenStore, "_resolve", campaign.resolve)
    old = original / "profile/observation.json"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"immutable historical observation\n")
    attestation = GoldenAttestation("commit", "jar", (), "definition", "profile", ())
    record = GoldenStore(original / "profile", attestation, record=True)
    record.assert_observation("observation.json", {"status": 250, "bytes": "exact"})
    assert old.read_bytes() == b"immutable historical observation\n"
    replay = GoldenStore(original / "profile", attestation)
    replay.assert_observation("observation.json", {"status": 250, "bytes": "exact"})
    with pytest.raises(GoldenMismatch):
        replay.assert_observation("observation.json", {"status": 251, "bytes": "exact"})
    with pytest.raises(GoldenMismatch):
        record.assert_observation("observation.json", {"status": 251, "bytes": "exact"})
    with pytest.raises(GoldenMismatch):
        replay.assert_observation("not-recorded.json", {})


def test_campaign_does_not_redirect_unrelated_test_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(campaign, "ORIGINAL", tmp_path / "original")
    monkeypatch.setattr(campaign, "_campaign", tmp_path / "campaign")
    store = GoldenStore(tmp_path / "unrelated", None)
    assert campaign.resolve(store, "observation.json") == tmp_path / "unrelated/observation.json"
    with pytest.raises(ValueError):
        campaign.resolve(store, "../escape.json")


def test_campaign_rejects_destination_symlink_escape(tmp_path, monkeypatch):
    original = tmp_path / "original"
    destination = tmp_path / "campaign"
    destination.mkdir()
    (destination / "profile").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(campaign, "ORIGINAL", original)
    monkeypatch.setattr(campaign, "_campaign", destination)
    store = GoldenStore(original / "profile", None)
    with pytest.raises(ValueError):
        campaign.resolve(store, "observation.json")
