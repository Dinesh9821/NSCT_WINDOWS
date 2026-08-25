# Network AI Enterprise — macOS (Nord Edition)

A native-feeling macOS desktop **Enterprise Network AI Dashboard** for network
diagnostics and AI-assisted troubleshooting. Nord theme with a working Dark/Light
toggle. This build is fully ported to macOS — all diagnostics use macOS-native
commands, and the Live Topology is rendered with **pyvis** (vis.js) inside
QtWebEngine.

## Highlights
- Nord palette (Polar Night / Snow Storm / Frost / Aurora) with Dark/Light toggle
  (bottom-left of the sidebar, above the user chip).
- Landing dashboard: live status cards (Internet Health, Network Score, Latency,
  Packet Loss, Jitter, CPU, Memory, Public IP) with status colors, trend/progress
  indicators, and timestamps. Refreshes on background threads (no UI freeze).
- Network Tools: ping / traceroute / custom command + AI analysis, plus the full
  Diagnostics suite and a Results console.
- Live Topology: traceroute rendered as an interactive, icon-based graph (routers,
  switches, ISP, cloud, destination) via pyvis; zoom / pan / hover.
- AI Assistant: scrollable chat, rounded input, Send, Load PDF.
- Reports: full macOS diagnostic sweep (ifconfig, netstat -rn, scutil --dns,
  system_profiler, etc.), exportable to a text file.
- Responsive from 1280x800 (13" MacBook) through 4K/Retina; no overlapping widgets.

## macOS command mapping (vs the Windows build)
    ping -n            -> ping -c
    tracert            -> traceroute -n -w 1 -q 1 -m 20
    ipconfig /all      -> ifconfig / route -n get default / scutil --dns
    route print        -> netstat -rn
    netsh wlan ...      -> system_profiler SPAirPortDataType
    getmac             -> ifconfig (ether lines)
    %USERNAME%         -> getpass.getuser()
    (hidden console)   -> not needed on macOS

## Run
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python main.py

## Package a macOS .app (build ON macOS)
PyInstaller cannot cross-compile; build on the Mac you target:

    pip install pyinstaller
    pyinstaller --noconfirm --windowed --name "Network AI Enterprise" \
      --collect-all qtawesome \
      --collect-all pyvis \
      --collect-all psutil \
      main.py

Notes for the .app bundle:
- QtWebEngine adds size and needs its helper process bundled; `--windowed` +
  `--collect-all PySide6` (heavier) is the most reliable if the topology view is
  blank in the packaged app.
- To sign/notarize for distribution, run `codesign`/`notarytool` on the built
  `.app` per Apple's guidance.
- Some commands (ping, traceroute) may prompt for network permission the first
  time; `system_profiler SPAirPortDataType` (in Reports) can take a few seconds.

## Project layout
    core/      constants, signals, workers, theme (Nord + toggle), colors, iconkit
    backend/   diagnostics (macOS) + chatbot
    widgets/   flow_layout, card, avatar, sparkline, stat_card, console, header,
               footer, sidebar
    pages/     dashboard, tools, topology (pyvis), assistant, reports, settings
    app.py     window shell (sidebar + header + stack + footer)
    main.py    bootstrap (WebEngine attr, theme.qss(), centering)

## Notes
- API credentials live in core/constants.py as plaintext — move them server-side
  before distribution.


## Custom icons
The sidebar/dashboard/tools icons load from `assets/icons/*.png`. Keep that folder
next to the code. When packaging with PyInstaller, bundle it:

    pyinstaller --noconfirm --windowed --name "Network AI Enterprise" ^
      --collect-all qtawesome --collect-all pyvis --collect-all psutil ^
      --add-data "assets;assets" ^
      main.py

(On macOS/Linux use "assets:assets" with a colon.)
