import json
from pathlib import Path

from logtui.collectors.windows_events import parse_windows_events_json
from logtui.models import Level

FIX = Path(__file__).parent / "fixtures" / "windows" / "sample.json"


def test_parse_fixture():
    text = FIX.read_text(encoding="utf-8")
    events = parse_windows_events_json(text)
    assert len(events) > 0
    e = events[0]
    assert e.os == "windows"
    assert e.source
    assert e.level in (Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR, Level.CRITICAL)


def test_parse_empty():
    assert parse_windows_events_json("") == []
    assert parse_windows_events_json("null") == [] or parse_windows_events_json("null") == []


def test_parse_single_object():
    obj = {
        "TimeCreated": "2026-10-23T21:27:30.1063598+05:30",
        "Id": 41,
        "LevelDisplayName": "Critical",
        "ProviderName": "Kernel-Power",
        "Message": "unexpected shutdown",
        "LogName": "System",
    }
    events = parse_windows_events_json(json.dumps(obj))
    assert len(events) == 1
    assert events[0].categories == frozenset({"reboot"})
    assert events[0].level == Level.CRITICAL


def test_event_id_mapping():
    text = FIX.read_text(encoding="utf-8")
    # inject an event with id 1002
    data = json.loads(text)
    data.append(
        {
            "TimeCreated": "2026-10-23T21:27:30.1063598+05:30",
            "Id": 1002,
            "LevelDisplayName": "Error",
            "ProviderName": "Application Error",
            "Message": "app hang",
            "LogName": "Application",
        }
    )
    events = parse_windows_events_json(json.dumps(data))
    hang_events = [e for e in events if e.raw_id == "1002"]
    assert hang_events and "hang" in hang_events[0].categories
