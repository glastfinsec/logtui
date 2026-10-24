"""CLI entry point for logtui."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="logtui", description="Cross-platform system log viewer")
    sub = parser.add_subparsers(dest="command")

    setup_p = sub.add_parser("setup", help="Detect machine capabilities and write profile.json")
    setup_p.add_argument("--rescan", action="store_true", help="Re-detect and update profile")
    setup_p.add_argument("--path", help="Override profile path")

    args = parser.parse_args(argv)

    if args.command == "setup":
        from pathlib import Path

        from .setup.profile import run_setup

        p = Path(args.path) if args.path else None
        prof = run_setup(rescan=args.rescan, path=p)
        print(f"Profile written: {p or 'default'}")
        print(f"OS: {prof.os} {prof.os_version}")
        print(f"Sources: {prof.sources}")
        return 0

    # default: launch TUI
    try:
        from .tui.app import LogTUI

        app = LogTUI()
        app.run()
        return 0
    except Exception as e:
        print(f"Failed to launch TUI: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
