import pytest

pytest.importorskip("textual")


@pytest.mark.asyncio
async def test_tui_launches_and_quits():
    import sys

    sys.path.insert(0, "src")
    from logtui.tui.app import LogTUI

    app = LogTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#events") is not None
        assert app.query_one("#filter") is not None
        assert app.query_one("#detail") is not None
        # filter input works
        await pilot.press("tab")
        await pilot.pause()
        # quit
        await pilot.press("q")
        await pilot.pause()
    # if we get here, quit cleanly


@pytest.mark.asyncio
async def test_tui_refresh_binding():
    import sys

    sys.path.insert(0, "src")
    from logtui.tui.app import LogTUI

    app = LogTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        status = app.query_one("#status").content
        assert "Sources:" in str(status) or "Events:" in str(status)
