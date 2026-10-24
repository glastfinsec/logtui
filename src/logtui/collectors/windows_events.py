"""Windows Event Log collector."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from ..models import Event, Level

ID_CATEGORIES = {
    41: frozenset({"reboot"}),
    6008: frozenset({"reboot"}),
    1000: frozenset({"crash"}),
    1001: frozenset({"crash"}),
    1002: frozenset({"hang"}),
}


def _level_from_name(name: str | None) -> Level:
    if not name:
        return Level.INFO
    n = name.strip().lower()
    if "critical" in n:
        return Level.CRITICAL
    if "error" in n:
        return Level.ERROR
    if "warning" in n:
        return Level.WARN
    if "verbose" in n or "debug" in n:
        return Level.DEBUG
    return Level.INFO


def parse_windows_events_json(text: str, os_name: str = "windows") -> list[Event]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    events: list[Event] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            t = datetime.fromisoformat(str(item.get("TimeCreated")))
        except (ValueError, TypeError):
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=UTC)
        eid = item.get("Id")
        try:
            eid_int = int(eid)
        except (TypeError, ValueError):
            eid_int = None
        cats = ID_CATEGORIES.get(eid_int, frozenset()) if eid_int is not None else frozenset()
        events.append(
            Event(
                time=t,
                source=str(item.get("ProviderName") or item.get("Source") or "WindowsEvent"),
                level=_level_from_name(item.get("LevelDisplayName") or item.get("Level")),
                message=str(item.get("Message") or ""),
                os=os_name,
                raw_id=str(eid) if eid is not None else None,
                categories=cats,
                raw=item,
            )
        )
    return events


def _build_ps(since: datetime, until: datetime | None, channels: list[str]) -> str:
    since_s = since.astimezone().strftime("%Y-%m-%dT%H:%M:%S")
    until_clause = ""
    if until is not None:
        until_s = until.astimezone().strftime("%Y-%m-%dT%H:%M:%S")
        until_clause = f" -and $_.TimeCreated -le [datetime]'{until_s}'"
    chans = ",".join("'" + c.replace("'", "''") + "'" for c in channels)
    return f"""
$since = [datetime]'{since_s}'
$events = Get-WinEvent -FilterHashtable @{{LogName=@({chans}); StartTime=$since}} -ErrorAction SilentlyContinue |
  Where-Object {{ $_.TimeCreated -ge $since{until_clause} }} |
  Select-Object @{{N='TimeCreated';E={{$_.TimeCreated.ToString('o')}}}}, Id, LevelDisplayName, ProviderName, Message, LogName
@($events) | ConvertTo-Json -Depth 3
"""


class WindowsEventCollector:
    name = "windows_events"

    def __init__(self, channels: list[str] | None = None):
        self.channels = channels or [
            "System",
            "Application",
            "Microsoft-Windows-WLAN-AutoConfig/Operational",
        ]

    def available(self) -> bool:
        import platform

        return platform.system().lower() == "windows"

    def needs_elevation(self) -> bool:
        return False

    def fetch(self, since: datetime, until: datetime | None = None) -> Iterable[Event]:
        if not self.available():
            return []
        ps = _build_ps(since, until, self.channels)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=60,
                errors="replace",
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []
        if r.returncode != 0:
            return []
        return parse_windows_events_json(r.stdout)


def parse_wer_reports(root: Path | None = None) -> list[Event]:
    """Best-effort parse of WER ReportQueue/ReportArchive folders."""
    if root is None:
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        root = Path(base) / "Microsoft" / "Windows" / "WER"
    events: list[Event] = []
    for sub in ("ReportQueue", "ReportArchive"):
        d = root / sub
        if not d.exists():
            continue
        for report_dir in d.iterdir():
            if not report_dir.is_dir():
                continue
            wer = report_dir / "Report.wer"
            if not wer.exists():
                continue
            try:
                text = wer.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fields: dict[str, str] = {}
            for line in text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    fields[k.strip()] = v.strip()
            app = fields.get("AppName") or fields.get("App") or "unknown"
            event_name = fields.get("EventName") or "WER"
            # timestamp from file mtime
            try:
                mtime = datetime.fromtimestamp(wer.stat().st_mtime, tz=UTC)
            except OSError:
                mtime = datetime.now(UTC)
            events.append(
                Event(
                    time=mtime,
                    source="Windows Error Reporting",
                    level=Level.ERROR,
                    message=f"{event_name}: {app} {fields.get('FaultingModule', '')}".strip(),
                    os="windows",
                    raw_id=report_dir.name,
                    categories=frozenset({"crash"}),
                    raw=fields,
                )
            )
    return events


class WerCollector:
    name = "wer"

    def available(self) -> bool:
        import platform

        return platform.system().lower() == "windows"

    def needs_elevation(self) -> bool:
        return False

    def fetch(self, since: datetime, until: datetime | None = None) -> Iterable[Event]:
        out = []
        for e in parse_wer_reports():
            if e.time < since:
                continue
            if until is not None and e.time > until:
                continue
            out.append(e)
        return out
