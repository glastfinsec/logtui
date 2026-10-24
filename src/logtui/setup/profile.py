"""Profile read/write orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..models import Profile, load_profile, save_profile
from .detect import detect_all
from .hardware import detect_hardware


def build_profile(existing: Profile | None = None, rescan: bool = False) -> Profile:
    detected = detect_all()
    hw = detect_hardware()
    # start from existing to preserve overrides on rescan
    if existing is not None and not rescan:
        prof = existing
    elif existing is not None and rescan:
        prof = Profile()
        prof.overrides = dict(existing.overrides)
    else:
        prof = Profile()

    prof.schema_version = 1
    prof.detected_at = datetime.now(UTC).isoformat()
    prof.os = detected["os"]
    prof.os_version = detected["os_version"]
    prof.init = detected["init"]
    prof.sources = detected["sources"]
    prof.elevation = detected["elevation"]
    prof.hardware = hw
    return prof


def run_setup(rescan: bool = False, path: Path | None = None) -> Profile:
    existing = load_profile(path)
    prof = build_profile(existing, rescan=rescan)
    save_profile(prof, path)
    return prof
