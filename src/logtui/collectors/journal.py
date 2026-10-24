"""Linux journalctl collector."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime

from ..models import Event, Level

PRIORITY_MAP = {
    "0": Level.CRITICAL,
    "1": Level.CRITICAL,
    "2": Level.CRITICAL,
    "3": Level.ERROR,
    "4": Level.WARN,
    "5": Level.INFO,
    "6": Level.INFO,
    "7": Level.DEBUG,
}


def _parse_ts(obj: dict) -> datetime | None:
    # journalctl __REALTIME_TIMESTAMP is microseconds since epoch (string)
    for key in ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"):
        v = obj.get(key)
        if v is not None:
            try:
                us = int(v)
                return datetime.fromtimestamp(us / 1_000_000, tz=UTC)
            except (ValueError, TypeError, OSError):
                pass
    # fallback ISO-ish
    for key in ("_SOURCE_REALTIME_TIMESTAMP", "timestamp"):
        v = obj.get(key)
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except ValueError:
                pass
    return None


def _message(obj: dict) -> str:
    m = obj.get("MESSAGE")
    if isinstance(m, list):
        # journalctl may encode bytes as arrays
        try:
            return bytes(m).decode("utf-8", errors="replace")
        except Exception:
            return str(m)
    if m is None:
        return ""
    return str(m)


def parse_journal_jsonl(text: str, os_name: str = "linux") -> list[Event]:
    events: list[Event] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        ts = _parse_ts(obj)
        if ts is None:
            continue
        source = (
            obj.get("SYSLOG_IDENTIFIER")
            or obj.get("_SYSTEMD_UNIT")
            or obj.get("_COMM")
            or obj.get("UNIT")
            or "journal"
        )
        if isinstance(source, list):
            source = bytes(source).decode("utf-8", errors="replace")
        source = str(source)
        prio = obj.get("PRIORITY")
        level = PRIORITY_MAP.get(str(prio).strip(), Level.INFO) if prio is not None else Level.INFO
        raw_id = obj.get("_SYSTEMD_UNIT") or obj.get("UNIT")
        if isinstance(raw_id, list):
            raw_id = bytes(raw_id).decode("utf-8", errors="replace")
        raw_id = str(raw_id) if raw_id is not None else None
        events.append(
            Event(
                time=ts,
                source=source,
                level=level,
                message=_message(obj),
                os=os_name,
                raw_id=raw_id,
                raw=obj,
            )
        )
    return events


def _build_cmd(since: datetime, until: datetime | None) -> list[str]:
    cmd = ["journalctl", "--since", since.astimezone().strftime("%Y-%m-%d %H:%M:%S")]
    if until is not None:
        cmd += ["--until", until.astimezone().strftime("%Y-%m-%d %H:%M:%S")]
    cmd += ["-o", "json", "--no-pager", "-p", "warning"]
    return cmd


class JournalCollector:
    name = "journal"

    def available(self) -> bool:
        import shutil

        return shutil.which("journalctl") is not None

    def needs_elevation(self) -> bool:
        return False

    def fetch(self, since: datetime, until: datetime | None = None) -> Iterable[Event]:
        if not self.available():
            return []
        cmd = _build_cmd(since, until)
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []
        text = r.stdout or ""
        if r.returncode != 0 and not text.strip():
            return []
        return parse_journal_jsonl(text)
