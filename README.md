> [!WARNING]
> 🚧 **TRAILER / UNDER ACTIVE DEVELOPMENT** 🚧
> *logtui is currently a work-in-progress project by **glastfin**. Features, syntax, and behaviors are subject to change as development evolves.*

# logtui

Cross-platform terminal system log viewer.

Shows the relevant system logs for a problem you're investigating — Wi-Fi slowness, game crashes, unexpected reboots, app hangs, Bluetooth dropping. Runs on Linux, Windows, and macOS. On first install it detects the machine's capabilities and writes a profile that controls which log sources are enabled.

## Install

One-shot (PowerShell 7):

```
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Install-logtui.ps1 -Auto
```

Or double-click `Install logtui.cmd`.

Manual:

```
pip install -e .
python -m logtui setup
python -m logtui
```

## Usage

- `logtui setup` — detect capabilities and write profile.json (idempotent; `--rescan` to update).
- `logtui` — launch the TUI.
- In the TUI: `r` refresh, `q` quit, `s` save filtered events, `/` filter, `Esc` back.

## Stack

Python 3.11+, Textual, pytest, ruff.

## License

MIT (see LICENSE).