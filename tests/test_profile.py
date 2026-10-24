from logtui.models import Profile, load_profile, save_profile


def test_profile_roundtrip(tmp_path):
    p = tmp_path / "profile.json"
    prof = Profile(
        os="linux",
        os_version="1.0",
        init="systemd",
        sources={"journal": True},
        hardware={"wifi": "iwlwifi"},
    )
    save_profile(prof, p)
    loaded = load_profile(p)
    assert loaded is not None
    assert loaded.os == "linux"
    assert loaded.sources == {"journal": True}
    assert loaded.hardware == {"wifi": "iwlwifi"}


def test_profile_preserves_overrides(tmp_path):
    p = tmp_path / "profile.json"
    prof = Profile(os="linux", overrides={"sources": {"journal": False}})
    save_profile(prof, p)
    # rescan-like: new profile without overrides, save merges
    prof2 = Profile(os="linux", sources={"journal": True})
    save_profile(prof2, p)
    loaded = load_profile(p)
    assert loaded.overrides == {"sources": {"journal": False}}


def test_effective_sources(tmp_path):
    prof = Profile(
        sources={"journal": True, "coredump": False}, overrides={"sources": {"coredump": True}}
    )
    assert prof.effective_sources() == {"journal": True, "coredump": True}


def test_load_missing(tmp_path):
    assert load_profile(tmp_path / "nope.json") is None
