"""Conservative event interpretation and timeline correlation for logtui.

This module intentionally separates:
  * raw source data (never rewritten),
  * event classification (what the event is about),
  * interpretation (what it can reasonably mean),
  * correlation (nearby events that may help explain a symptom).

It is backend/UI-framework agnostic and can be called from a Textual TUI.
Python 3.11+.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


@dataclass(frozen=True, slots=True)
class EventAssessment:
    category: str
    severity: str
    title: str
    interpretation: str
    confidence: str = "low"
    evidence: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventCorrelation:
    anchor: Mapping[str, Any]
    related: tuple[Mapping[str, Any], ...]
    explanation: str


# Event IDs are provider-specific. Never classify by ID alone when a provider
# is available, and never treat a missing provider as proof of a specific event.
_PROVIDER_ALIASES = {
    "microsoft-windows-kernel-general": "kernel-general",
    "microsoft-windows-kernel-power": "kernel-power",
    "microsoft-windows-windowsupdateclient": "windows-update",
    "microsoft-windows-winsock-name-resolution": "dns",
    "microsoft-windows-wlan-autoconfig": "wlan",
    "microsoft-windows-bluetooth-bthusb": "bluetooth",
    "microsoft-windows-bluetooth-bthport": "bluetooth",
    "eventlog": "eventlog",
    "user32": "user32",
    "microsoft-windows-kernel-boot": "kernel-boot",
    "microsoft-windows-werm": "wer",
    "windows error reporting": "wer",
    "bugcheck": "bugcheck",
}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _provider(event: Mapping[str, Any]) -> str:
    raw = _text(event.get("ProviderName") or event.get("provider") or event.get("provider_name"))
    lowered = raw.casefold()
    return _PROVIDER_ALIASES.get(lowered, lowered)


def _event_id(event: Mapping[str, Any]) -> int | None:
    raw = event.get("Id", event.get("id", event.get("event_id", event.get("Raw ID"))))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _message(event: Mapping[str, Any]) -> str:
    return _text(event.get("Message") or event.get("message") or event.get("description"))


def _timestamp(event: Mapping[str, Any]) -> datetime | None:
    raw = event.get("TimeCreated", event.get("timestamp", event.get("time_created")))
    if isinstance(raw, datetime):
        return raw
    if raw is None:
        return None
    value = str(raw).strip()
    for fmt in ("%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def classify_event(event: Mapping[str, Any]) -> EventAssessment:
    """Return a cautious, human-readable interpretation without mutating event."""
    eid = _event_id(event)
    provider = _provider(event)
    message = _message(event)
    lowered = message.casefold()

    # Kernel-General 16 is registry access-history housekeeping, not a reboot.
    if (
        eid == 16
        and provider in ("kernel-general", "")
        and ("access history" in lowered or "hive" in lowered or "modified pages" in lowered)
    ):
        return EventAssessment(
            category="registry",
            severity="info",
            title="Registry access-history maintenance",
            interpretation=(
                "Windows reports that access-history information for a registry hive "
                "was cleared and registry pages were updated. This event alone does not "
                "show registry corruption, malware, or that this activity caused a reboot."
            ),
            confidence="high",
            evidence=("Source message describes registry-hive access history and modified pages.",),
            next_steps=(
                "Keep the original event fields available for inspection.",
                "If investigating a reboot, correlate by timestamp with shutdown, boot, power, and bug-check events.",
            ),
        )

    if eid == 1074 and provider in ("user32", ""):
        return EventAssessment(
            category="reboot",
            severity="notice",
            title="Restart or shutdown requested",
            interpretation=(
                "Windows recorded a process or user initiating a shutdown/restart request. "
                "The initiating process is evidence about the request, not necessarily the "
                "underlying reason the restart happened."
            ),
            confidence="high",
            evidence=("Event ID 1074 records a shutdown/restart request.",),
            next_steps=(
                "Inspect the full event message for process, user, reason code, and shutdown type.",
                "Check nearby update, service, crash, and power events to identify context.",
            ),
        )

    if eid == 41 and provider in ("kernel-power", ""):
        return EventAssessment(
            category="reboot",
            severity="warning",
            title="Unexpected shutdown detected",
            interpretation=(
                "Windows detected that the previous shutdown was not completed cleanly. "
                "This event usually records the symptom; it does not by itself identify "
                "whether power loss, a hang, a crash, or another issue caused it."
            ),
            confidence="high",
            evidence=("Kernel-Power Event ID 41 indicates an unclean previous shutdown.",),
            next_steps=(
                "Check BugCheck/Event ID 1001, WHEA events, minidumps, and power/thermal evidence.",
                "Compare the event timestamp with the next boot and any user-reported symptom.",
            ),
        )

    if eid == 6008 and provider in ("eventlog", ""):
        return EventAssessment(
            category="reboot",
            severity="warning",
            title="Previous shutdown was unexpected",
            interpretation=(
                "Windows reports that the previous shutdown was unexpected. This is a "
                "retrospective symptom and usually needs correlation with events before the shutdown."
            ),
            confidence="high",
            evidence=("EventLog Event ID 6008 reports an unexpected previous shutdown.",),
            next_steps=(
                "Check Kernel-Power 41, BugCheck 1001, and events immediately before the outage.",
            ),
        )

    if eid == 6006 and provider in ("eventlog", ""):
        return EventAssessment(
            category="reboot",
            severity="info",
            title="Event Log service stopped",
            interpretation=(
                "The Event Log service stopped. During a normal shutdown this is expected; "
                "this event alone does not prove the shutdown was clean or user-initiated."
            ),
            confidence="medium",
            evidence=("EventLog Event ID 6006 says the Event Log service stopped.",),
            next_steps=("Use adjacent shutdown and startup events to establish the sequence.",),
        )

    if eid == 6005 and provider in ("eventlog", ""):
        return EventAssessment(
            category="reboot",
            severity="info",
            title="Event Log service started",
            interpretation="The Event Log service started, commonly during Windows startup.",
            confidence="medium",
            evidence=("EventLog Event ID 6005 says the Event Log service started.",),
            next_steps=(
                "Compare with Kernel-General/Kernel-Boot startup events and the preceding shutdown.",
            ),
        )

    if eid == 1001 and (
        "bugcheck" in provider or "bugcheck" in lowered or "blue screen" in lowered
    ):
        return EventAssessment(
            category="crash",
            severity="error",
            title="Windows bug-check report",
            interpretation=(
                "A Windows bug-check/crash report may be present. Read the full message for "
                "the stop code and dump path; do not infer a specific faulty driver from the ID alone."
            ),
            confidence="medium",
            evidence=("Event content/provider identifies a bug-check or blue-screen report.",),
            next_steps=(
                "Inspect the stop code and dump file, then correlate with driver, WHEA, and update events.",
            ),
        )

    if "wlan" in provider or "wireless" in lowered or "wi-fi" in lowered:
        return EventAssessment(
            category="network",
            severity="info",
            title="Wireless/network event",
            interpretation="This event is related to wireless or network activity; inspect its message and nearby connection events.",
            confidence="medium",
            evidence=("Provider or message references wireless/network activity.",),
            next_steps=(
                "Correlate disconnect/reconnect events and adapter/driver events around the reported slowdown.",
            ),
        )

    if "bluetooth" in provider or "bluetooth" in lowered:
        return EventAssessment(
            category="bluetooth",
            severity="info",
            title="Bluetooth event",
            interpretation="This event references Bluetooth activity; it is not enough by itself to establish why a device disconnected.",
            confidence="medium",
            evidence=("Provider or message references Bluetooth.",),
            next_steps=(
                "Correlate device, adapter, service, and power-management events around the disconnection.",
            ),
        )

    return EventAssessment(
        category="other",
        severity="info",
        title="System event",
        interpretation=(
            "No specific root-cause interpretation is available for this event. "
            "The original event remains authoritative; use nearby events and the reported symptom for context."
        ),
        confidence="low",
        evidence=("No conservative rule matched this event.",),
        next_steps=(
            "Inspect the provider, event ID, full message, and events near the same timestamp.",
        ),
    )


def correlate_events(
    events: Sequence[Mapping[str, Any]],
    anchor: Mapping[str, Any],
    *,
    window_minutes: int = 10,
    limit: int = 12,
) -> EventCorrelation:
    """Find nearby events; this is temporal correlation, not proof of causation."""
    anchor_time = _timestamp(anchor)
    if anchor_time is None:
        return EventCorrelation(anchor, (), "No usable timestamp; events could not be correlated.")

    window = timedelta(minutes=max(0, window_minutes))
    candidates: list[tuple[float, Mapping[str, Any]]] = []
    for event in events:
        if event is anchor:
            continue
        timestamp = _timestamp(event)
        if timestamp is None:
            continue
        # Normalize naive/aware datetimes by dropping timezone only for comparison
        # when the source data mixes timestamp formats. Keep raw values untouched.
        a, b = anchor_time, timestamp
        if (a.tzinfo is None) != (b.tzinfo is None):
            a, b = a.replace(tzinfo=None), b.replace(tzinfo=None)
        delta = abs((b - a).total_seconds())
        if delta <= window.total_seconds():
            candidates.append((delta, event))

    candidates.sort(key=lambda item: item[0])
    related = tuple(event for _, event in candidates[: max(0, limit)])
    explanation = (
        f"Showing {len(related)} event(s) within ±{window_minutes} minutes. "
        "Temporal proximity can help investigation but does not prove causation."
    )
    return EventCorrelation(anchor, related, explanation)


def event_display_fields(event: Mapping[str, Any]) -> dict[str, str]:
    """Safe compact fields for a TUI detail pane; raw values are preserved as strings."""
    return {
        "time": _text(
            event.get("TimeCreated") or event.get("timestamp") or event.get("time_created")
        )
        or "Unknown",
        "provider": _text(
            event.get("ProviderName") or event.get("provider") or event.get("provider_name")
        )
        or "Unknown",
        "event_id": _text(
            event.get("Id", event.get("id", event.get("event_id", event.get("Raw ID"))))
        )
        or "Unknown",
        "category": classify_event(event).category,
        "title": classify_event(event).title,
        "severity": classify_event(event).severity,
        "message": _message(event) or "(No message supplied)",
    }
