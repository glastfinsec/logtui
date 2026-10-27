"""Reusable TUI widgets/helpers."""

from __future__ import annotations

from textual.widgets import Static

from ..event_intelligence import classify_event, correlate_events


def event_to_mapping(event) -> dict:
    """Build a mapping for the intelligence module without mutating the Event."""
    raw = event.raw if isinstance(event.raw, dict) else {}
    mapping = dict(raw)
    mapping.setdefault("TimeCreated", event.time)
    mapping.setdefault("Id", event.raw_id)
    mapping.setdefault("ProviderName", event.source)
    mapping.setdefault("Message", event.message)
    return mapping


def format_assessment(assessment) -> list[str]:
    lines = [
        "Interpretation:",
        f"  Title: {assessment.title}",
        f"  Suggested category: {assessment.category}",
        f"  Severity: {assessment.severity}",
        f"  Confidence: {assessment.confidence}",
        f"  Meaning: {assessment.interpretation}",
    ]
    if assessment.evidence:
        lines.append("  Evidence:")
        lines.extend(f"    - {item}" for item in assessment.evidence)
    if assessment.next_steps:
        lines.append("  Next steps:")
        lines.extend(f"    - {item}" for item in assessment.next_steps)
    return lines


class DetailPane(Static):
    """Shows full message, interpretation, and raw fields for selected event."""

    def show_event(self, event, all_events=None) -> None:
        if event is None:
            self.update("Select an event to see details.")
            return

        mapping = event_to_mapping(event)
        assessment = classify_event(mapping)

        lines = [
            f"Time: {event.time.isoformat()}",
            f"Source: {event.source}",
            f"Level: {event.level.value}",
            f"Categories: {', '.join(sorted(event.categories)) or '-'}",
            f"Raw ID: {event.raw_id}",
            "",
            "Raw event:",
            event.message,
            "",
        ]
        lines.extend(format_assessment(assessment))

        if all_events:
            mappings = [event_to_mapping(e) for e in all_events]
            correlation = correlate_events(mappings, mapping, window_minutes=10, limit=5)
            lines.append("")
            lines.append("Nearby events:")
            lines.append(f"  {correlation.explanation}")
            for related in correlation.related:
                ts = related.get("TimeCreated", "?")
                provider = related.get("ProviderName", "?")
                msg = str(related.get("Message", ""))[:70].replace("\n", " ")
                lines.append(f"  - {ts} {provider}: {msg}")

        lines.append("")
        lines.append("Raw fields:")
        if event.raw:
            for k, v in event.raw.items():
                lines.append(f"  {k}: {v}")
        self.update("\n".join(lines))
