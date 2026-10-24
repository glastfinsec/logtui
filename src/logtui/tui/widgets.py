"""Reusable TUI widgets/helpers."""

from __future__ import annotations

from textual.widgets import Static


class DetailPane(Static):
    """Shows full message and raw fields for selected event."""

    def show_event(self, event) -> None:
        if event is None:
            self.update("Select an event to see details.")
            return
        lines = [
            f"Time: {event.time.isoformat()}",
            f"Source: {event.source}",
            f"Level: {event.level.value}",
            f"Categories: {', '.join(sorted(event.categories)) or '-'}",
            f"Raw ID: {event.raw_id}",
            "",
            event.message,
            "",
            "Raw fields:",
        ]
        if event.raw:
            for k, v in event.raw.items():
                lines.append(f"  {k}: {v}")
        self.update("\n".join(lines))
