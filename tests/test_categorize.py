from datetime import datetime

from logtui.categorize import categorize_event, categorize_events, load_rules, merge_rules
from logtui.models import Event, Level


def make_event(source, message, os="linux"):
    return Event(time=datetime.now(), source=source, level=Level.INFO, message=message, os=os)


def test_keyword_match():
    rules = load_rules()
    e = make_event("foo", "wifi deauth detected")
    cats = categorize_event(e, rules)
    assert "wifi" in cats


def test_source_match():
    rules = load_rules()
    e = make_event("NetworkManager", "something happened")
    cats = categorize_event(e, rules)
    assert "wifi" in cats


def test_multi_category():
    rules = load_rules()
    e = make_event("Kernel-Power", "unexpected shutdown after crash")
    cats = categorize_event(e, rules)
    assert "reboot" in cats
    assert "crash" in cats


def test_no_match():
    rules = load_rules()
    e = make_event("foo", "hello world")
    cats = categorize_event(e, rules)
    assert cats == frozenset()


def test_categorize_events_updates():
    rules = load_rules()
    events = [make_event("NetworkManager", "x"), make_event("foo", "y")]
    out = categorize_events(events, rules)
    assert out[0].categories == frozenset({"wifi"})
    assert out[1].categories == frozenset()


def test_merge_rules():
    a = {"wifi": {"sources": ["a"], "keywords": ["k1"]}}
    b = {"wifi": {"sources": ["b"], "keywords": ["k2"]}, "new": {"sources": [], "keywords": ["x"]}}
    m = merge_rules(a, b)
    assert set(m["wifi"]["sources"]) == {"a", "b"}
    assert "k1" in m["wifi"]["keywords"] and "k2" in m["wifi"]["keywords"]
    assert "new" in m
