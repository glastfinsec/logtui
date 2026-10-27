from datetime import datetime, timedelta

from logtui.event_intelligence import classify_event, correlate_events


def test_kernel_general_registry_hive_event_is_not_misclassified_as_reboot():
    event = {
        "TimeCreated": datetime(2026, 10, 27, 17, 59, 0),
        "Id": 16,
        "ProviderName": "Microsoft-Windows-Kernel-General",
        "Message": (
            r"The access history in hive \SystemRoot\System32\config\DRIVERS "
            "was cleared updating 53805 keys and creating 2789 modified pages."
        ),
        "Categories": "reboot",
        "Raw ID": 16,
    }
    result = classify_event(event)
    assert result.category == "registry"
    assert "does not show" in result.interpretation
    # Classifier must not mutate the source object or overwrite its raw category.
    assert event["Categories"] == "reboot"
    assert event["Raw ID"] == 16


def test_user32_1074_is_a_restart_request_not_root_cause():
    event = {
        "Id": 1074,
        "ProviderName": "User32",
        "Message": "The process Explorer.EXE has initiated the restart of computer TEST.",
    }
    result = classify_event(event)
    assert result.category == "reboot"
    assert result.title == "Restart or shutdown requested"
    assert "not necessarily the underlying reason" in result.interpretation


def test_eventlog_6006_is_not_assumed_to_prove_clean_shutdown():
    result = classify_event(
        {"Id": 6006, "ProviderName": "EventLog", "Message": "The Event log service was stopped."}
    )
    assert result.category == "reboot"
    assert "does not prove" in result.interpretation


def test_correlates_events_in_time_window_without_claiming_causation():
    anchor_time = datetime(2026, 10, 25, 23, 37, 47)
    anchor = {
        "TimeCreated": anchor_time,
        "Id": 1074,
        "ProviderName": "User32",
        "Message": "restart",
    }
    nearby = {
        "TimeCreated": anchor_time + timedelta(seconds=4),
        "Id": 6006,
        "ProviderName": "EventLog",
    }
    distant = {
        "TimeCreated": anchor_time + timedelta(hours=2),
        "Id": 6005,
        "ProviderName": "EventLog",
    }
    result = correlate_events([anchor, nearby, distant], anchor, window_minutes=1)
    assert result.related == (nearby,)
    assert "does not prove causation" in result.explanation
