"""Common collector interface."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..models import Event


@runtime_checkable
class Collector(Protocol):
    name: str

    def available(self) -> bool: ...

    def needs_elevation(self) -> bool: ...

    def fetch(self, since: datetime, until: datetime | None = None) -> Iterable[Event]: ...
