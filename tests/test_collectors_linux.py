from pathlib import Path

from logtui.collectors.coredump import parse_coredump_json
from logtui.collectors.journal import parse_journal_jsonl
from logtui.models import Level

FIX = Path(__file__).parent / "fixtures" / "linux"


def test_journal_parse():
    text = (FIX / "journal.jsonl").read_text(encoding="utf-8")
    events = parse_journal_jsonl(text)
    assert len(events) == 4
    srcs = {e.source for e in events}
    assert "NetworkManager" in srcs or "kernel" in srcs
    # segfault line -> crash category? categorizer separate; level mapping
    crit = [e for e in events if e.level == Level.CRITICAL]
    assert len(crit) >= 1


def test_journal_empty():
    assert parse_journal_jsonl("") == []
    assert parse_journal_jsonl("not json") == []


def test_coredump_parse():
    text = (FIX / "coredump.json").read_text(encoding="utf-8")
    events = parse_coredump_json(text)
    assert len(events) == 2
    assert all(e.categories == frozenset({"crash"}) for e in events)
    assert events[0].level == Level.CRITICAL


def test_coredump_empty():
    assert parse_coredump_json("") == []
