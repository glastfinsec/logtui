import sys

sys.path.insert(0, "src")

from logtui.tui.app import LogTUI


def test_main_screen_snapshot(snap_compare):
    app = LogTUI(collectors=[])
    assert snap_compare(app)
