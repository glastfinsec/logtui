"""Core data model for logtui."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Level(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_str(cls, value: str | None) -> Level:
        if not value:
            return Level.INFO
        v = value.strip().upper()
        # common aliases
        aliases = {
            "WARNING": "WARN",
            "ERR": "ERROR",
            "CRIT": "CRITICAL",
            "FATAL": "CRITICAL",
            "TRACE": "DEBUG",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            # numeric syslog priorities
            mapping = {
                "0": cls.CRITICAL,
                "1": cls.CRITICAL,
                "2": cls.CRITICAL,
                "3": cls.ERROR,
                "4": cls.WARN,
                "5": cls.INFO,
                "6": cls.INFO,
                "7": cls.DEBUG,
            }
            return mapping.get(str(value).strip(), Level.INFO)


@dataclass(frozen=True)
class Event:
    time: datetime
    source: str
    level: Level
    message: str
    os: str
    raw_id: str | None = None
    categories: frozenset[str] = field(default_factory=frozenset)
    raw: dict[str, Any] | None = None

    def with_categories(self, categories: frozenset[str]) -> Event:
        return Event(
            time=self.time,
            source=self.source,
            level=self.level,
            message=self.message,
            os=self.os,
            raw_id=self.raw_id,
            categories=categories,
            raw=self.raw,
        )


@dataclass
class Profile:
    schema_version: int = 1
    detected_at: str = ""
    os: str = ""
    os_version: str = ""
    init: str = "other"
    sources: dict[str, bool] = field(default_factory=dict)
    elevation: dict[str, bool] = field(default_factory=dict)
    hardware: dict[str, Any] = field(default_factory=dict)
    overrides: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "detected_at": self.detected_at,
            "os": self.os,
            "os_version": self.os_version,
            "init": self.init,
            "sources": dict(self.sources),
            "elevation": dict(self.elevation),
            "hardware": dict(self.hardware),
            "overrides": dict(self.overrides),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        return cls(
            schema_version=int(data.get("schema_version", 1)),
            detected_at=str(data.get("detected_at", "")),
            os=str(data.get("os", "")),
            os_version=str(data.get("os_version", "")),
            init=str(data.get("init", "other")),
            sources=dict(data.get("sources", {})),
            elevation=dict(data.get("elevation", {})),
            hardware=dict(data.get("hardware", {})),
            overrides=dict(data.get("overrides", {})),
        )

    def effective_sources(self) -> dict[str, bool]:
        """Sources with overrides applied (overrides win)."""
        out = dict(self.sources)
        ov = self.overrides.get("sources", {})
        if isinstance(ov, dict):
            out.update(ov)
        return out

    def effective_hardware(self) -> dict[str, Any]:
        out = dict(self.hardware)
        ov = self.overrides.get("hardware", {})
        if isinstance(ov, dict):
            out.update(ov)
        return out


def profile_path() -> Path:
    """Return the platform-appropriate profile.json path."""
    import os
    import platform

    system = platform.system().lower()
    if system == "windows":
        base = os.environ.get("APPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "logtui" / "profile.json"
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / "logtui" / "profile.json"
    # linux / other
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "logtui" / "profile.json"


def load_profile(path: Path | None = None) -> Profile | None:
    p = path or profile_path()
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            return Profile.from_dict(json.load(f))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def save_profile(profile: Profile, path: Path | None = None) -> Path:
    p = path or profile_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # merge with existing to preserve user overrides not in memory
    existing = load_profile(p)
    if existing is not None:
        merged_overrides = dict(existing.overrides)
        merged_overrides.update(profile.overrides)
        profile.overrides = merged_overrides
    with p.open("w", encoding="utf-8") as f:
        json.dump(profile.to_dict(), f, indent=2, default=str)
        f.write("\n")
    return p
