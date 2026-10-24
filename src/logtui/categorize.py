"""Categorization of events based on rules/default.toml."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

from .models import Event


def _default_rules_path() -> Path:
    return Path(__file__).parent / "rules" / "default.toml"


def load_rules(path: Path | None = None) -> dict[str, dict]:
    """Load category rules. Returns mapping category -> {sources, keywords}."""
    p = path or _default_rules_path()
    with p.open("rb") as f:
        data = tomllib.load(f)
    cats = data.get("category", {})
    out: dict[str, dict] = {}
    for name, spec in cats.items():
        out[name] = {
            "sources": [str(s) for s in spec.get("sources", [])],
            "keywords": [str(k) for k in spec.get("keywords", [])],
        }
    return out


def _match(rule: dict, event: Event) -> bool:
    sources = [s.lower() for s in rule.get("sources", [])]
    keywords = [k.lower() for k in rule.get("keywords", [])]
    src = (event.source or "").lower()
    msg = (event.message or "").lower()
    if sources and src in sources:
        return True
    # source substring match? Plan says source matches; keep exact-ish but also contains
    for s in sources:
        if s and s in src:
            return True
    for k in keywords:
        if not k:
            continue
        try:
            pat = re.compile(r"(?<!\w)" + re.escape(k), re.IGNORECASE)
        except re.error:
            pat = None
        if pat is not None and (pat.search(msg) or pat.search(src)):
            return True
    return False


def categorize_event(event: Event, rules: dict[str, dict] | None = None) -> frozenset[str]:
    if rules is None:
        rules = load_rules()
    cats = set(event.categories)
    cats |= {name for name, rule in rules.items() if _match(rule, event)}
    return frozenset(cats)


def categorize_events(events: Iterable[Event], rules: dict[str, dict] | None = None) -> list[Event]:
    if rules is None:
        rules = load_rules()
    out = []
    for e in events:
        cats = categorize_event(e, rules)
        if cats != e.categories:
            e = e.with_categories(cats)
        out.append(e)
    return out


def merge_rules(*rule_sets: dict[str, dict]) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    for rs in rule_sets:
        for name, spec in rs.items():
            if name in merged:
                merged[name]["sources"] = list(
                    dict.fromkeys(merged[name]["sources"] + spec.get("sources", []))
                )
                merged[name]["keywords"] = list(
                    dict.fromkeys(merged[name]["keywords"] + spec.get("keywords", []))
                )
            else:
                merged[name] = {
                    "sources": list(spec.get("sources", [])),
                    "keywords": list(spec.get("keywords", [])),
                }
    return merged
