"""Textual application for logtui."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    Static,
)

from ..categorize import categorize_events, load_rules
from ..collectors.base import Collector
from ..models import Event, load_profile
from .widgets import DetailPane

TIME_WINDOWS = [
    ("10 min", "10m"),
    ("1 hr", "1h"),
    ("24 hr", "24h"),
    ("previous boot", "boot"),
]


def window_delta(key: str) -> timedelta | None:
    if key == "10m":
        return timedelta(minutes=10)
    if key == "1h":
        return timedelta(hours=1)
    if key == "24h":
        return timedelta(hours=24)
    return None  # boot handled separately


class LogTUI(App):
    CSS = """
    #filter { height: 3; }
    #window { width: 24; }
    #events { height: 1fr; }
    #detail { height: 12; border: solid gray; }
    #status { height: 1; background: $panel; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh", priority=True),
        Binding("s", "save", "Save", priority=True),
        Binding("/", "focus_filter", "Filter"),
        Binding("escape", "blur_filter", "Back", priority=True),
    ]

    def __init__(self, profile=None, collectors=None):
        super().__init__()
        self.profile = profile if profile is not None else load_profile()
        self.rules = load_rules()
        self.events: list[Event] = []
        self.filtered: list[Event] = []
        if collectors is None:
            self.collectors: list[Collector] = self._build_collectors()
        else:
            self.collectors = list(collectors)
        self.time_window = "1h"
        self.filter_text = ""
        self.refresh_count = 0

    def _build_collectors(self) -> list[Collector]:
        colls: list[Collector] = []
        # Windows
        try:
            from ..collectors.windows_events import WerCollector, WindowsEventCollector

            we = WindowsEventCollector()
            if we.available():
                colls.append(we)
            wc = WerCollector()
            if wc.available():
                colls.append(wc)
        except Exception:
            pass
        # Linux
        try:
            from ..collectors.coredump import CoredumpCollector
            from ..collectors.journal import JournalCollector

            jc = JournalCollector()
            if jc.available():
                colls.append(jc)
            cc = CoredumpCollector()
            if cc.available():
                colls.append(cc)
        except Exception:
            pass
        # macOS: (to be implemented)
        return colls

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            yield Input(placeholder="Filter (category or text)", id="filter")
            yield Select([(label, key) for label, key in TIME_WINDOWS], value="1h", id="window")
        yield DataTable(id="events")
        yield DetailPane("Select an event to see details.", id="detail")
        yield Static("Ready", id="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#events", DataTable)
        table.add_columns("Time", "Level", "Source", "Categories", "Message")
        table.cursor_type = "row"
        self.refresh_events()
        self.set_focus(table)
        self.set_interval(30.0, self.action_refresh)

    def _since_until(self):
        now = datetime.now(UTC)
        if self.time_window == "boot":
            try:
                boot = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
            except Exception:
                boot = now - timedelta(hours=24)
            return boot, None
        delta = window_delta(self.time_window) or timedelta(hours=1)
        return now - delta, None

    def refresh_events(self) -> None:
        since, until = self._since_until()
        all_events: list[Event] = []
        for c in self.collectors:
            try:
                if not c.available():
                    continue
                all_events.extend(c.fetch(since, until))
            except Exception:
                pass
        # categorize (union)
        all_events = categorize_events(all_events, self.rules)
        self.events = sorted(all_events, key=lambda e: e.time, reverse=True)
        self.refresh_count += 1
        self._apply_filter()
        self._update_status()

    def _apply_filter(self) -> None:
        ft = self.filter_text.strip().lower()
        if not ft:
            self.filtered = list(self.events)
        else:
            self.filtered = [
                e
                for e in self.events
                if ft in e.message.lower()
                or ft in e.source.lower()
                or ft in {c.lower() for c in e.categories}
            ]
        table = self.query_one("#events", DataTable)
        table.clear()
        for e in self.filtered:
            table.add_row(
                e.time.strftime("%Y-%m-%d %H:%M:%S"),
                e.level.value,
                e.source,
                ",".join(sorted(e.categories)) or "-",
                (e.message[:80].replace("\n", " ")),
                key=str(id(e)),
            )
        # store mapping row->event
        self._row_events = {str(id(e)): e for e in self.filtered}

    def on_data_table_row_selected(self, event) -> None:
        row_key = event.row_key
        key = row_key.value if hasattr(row_key, "value") else str(row_key)
        e = getattr(self, "_row_events", {}).get(key)
        self.query_one("#detail", DetailPane).show_event(e)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.filter_text = event.value
            self._apply_filter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "window":
            self.time_window = str(event.value)
            self.refresh_events()

    def action_refresh(self) -> None:
        self.refresh_events()

    def action_focus_filter(self) -> None:
        self.set_focus(self.query_one("#filter", Input))

    def action_blur_filter(self) -> None:
        self.set_focus(self.query_one("#events", DataTable))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            self.set_focus(self.query_one("#events", DataTable))

    def action_save(self) -> None:
        out = Path("logtui_export.json")
        data = [
            {
                "time": e.time.isoformat(),
                "source": e.source,
                "level": e.level.value,
                "message": e.message,
                "categories": sorted(e.categories),
                "raw_id": e.raw_id,
            }
            for e in self.filtered
        ]
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.query_one("#status", Static).update(f"Saved {len(data)} events to {out}")

    def _update_status(self) -> None:
        sources = []
        for c in self.collectors:
            sources.append(c.name)
        active = ", ".join(sources) if sources else "none"
        self.query_one("#status", Static).update(
            f"Sources: {active} | Events: {len(self.filtered)}/{len(self.events)} | Refreshes: {self.refresh_count}"
        )


def main() -> None:
    app = LogTUI()
    app.run()


if __name__ == "__main__":
    main()
