"""Linux coredumpctl collector."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime

from ..models import Event, Level


def parse_coredump_json(text: str, os_name: str = "linux") -> list[Event]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # maybe JSONL
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    events: list[Event] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # timestamp fields vary
        ts = None
        for key in ("time", "timestamp", "realtime", "__REALTIME_TIMESTAMP"):
            v = item.get(key)
            if v is None:
                continue
            if isinstance(v, (int, float)):
                try:
                    ts = datetime.fromtimestamp(v if v < 1e12 else v / 1e6, tz=UTC)
                    break
                except (ValueError, OSError):
                    pass
            if isinstance(v, str):
                try:
                    if v.isdigit():
                        iv = int(v)
                        ts = datetime.fromtimestamp(iv if iv < 1e12 else iv / 1e6, tz=UTC)
                    else:
                        ts = datetime.fromisoformat(v)
                    break
                except (ValueError, OSError):
                    pass
        if ts is None:
            continue
        comm = item.get("comm") or item.get("executable") or item.get("exe") or "coredump"
        pid = item.get("pid") or item.get("PID")
        signal = item.get("signal") or item.get("sig")
        msg = f"{comm} crashed"
        if pid is not None:
            msg += f" (pid {pid})"
        if signal is not None:
            msg += f" signal {signal}"
        events.append(
            Event(
                time=ts,
                source="coredumpctl",
                level=Level.CRITICAL,
                message=msg,
                os=os_name,
                raw_id=str(pid) if pid is not None else None,
                categories=frozenset({"crash"}),
                raw=item,
            )
        )
    return events


class CoredumpCollector:
    name = "coredump"

    def available(self) -> bool:
        import shutil

        return shutil.which("coredumpctl") is not None

    def needs_elevation(self) -> bool:
        return False

    def fetch(self, since: datetime, until: datetime | None = None) -> Iterable[Event]:
        if not self.available():
            return []
        cmd = ["coredumpctl", "list", "--json=short"]
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
        if r.returncode != 0 and not (r.stdout or "").strip():
            return []
        events = parse_coredump_json(r.stdout or "")
        out = []
        for e in events:
            if e.time < since:
                continue
            if until is not None and e.time > until:
                continue
            out.append(e)
        return out
