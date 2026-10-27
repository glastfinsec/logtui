from datetime import datetime

from logtui.models import Event, Level
from logtui.tui.widgets import event_to_mapping, format_assessment


def test_event_mapping_preserves_raw_and_fills_fields():
    event = Event(
        time=datetime(2026, 10, 27, 17, 59),
        source="Microsoft-Windows-Kernel-General",
        level=Level.INFO,
        message="access history cleared",
        os="windows",
        raw_id="16",
        raw={"Id": 16, "ProviderName": "Microsoft-Windows-Kernel-General"},
    )
    mapping = event_to_mapping(event)
    assert mapping["Id"] == 16
    assert mapping["ProviderName"] == "Microsoft-Windows-Kernel-General"
    assert mapping["Message"] == "access history cleared"


def test_assessment_format_contains_interpretation():
    from logtui.event_intelligence import classify_event

    assessment = classify_event(
        {
            "Id": 16,
            "ProviderName": "Microsoft-Windows-Kernel-General",
            "Message": "The access history in hive X was cleared updating keys and creating modified pages.",
        }
    )
    lines = format_assessment(assessment)
    text = "\n".join(lines)
    assert "Interpretation:" in text
    assert "Suggested category: registry" in text
    assert "does not show" in text
