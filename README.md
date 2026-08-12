# signalk-ewelink

eWeLink/Sonoff devices as **native Signal K** — no MQTT broker, no external
control plugin, no `.env`. One self-contained plugin that is the bridge to the
hardware, configured in the Signal K admin UI.

## What it does

- **LAN-first, cloud-fallback, by discovery.** If mDNS finds a device on the
  server's network, its state and control go direct over the encrypted eWeLink
  LAN protocol — fully offline. A device it has not discovered routes to the
  eWeLink cloud. Discovery can *undiscover* (mDNS goodbye or repeated poll
  misses) and the cloud resumes seamlessly.
- **Push, not poll.** State arrives the moment it changes — mDNS updates on LAN,
  the eWeLink WebSocket on cloud (including changes from the eWeLink app or a
  device's physical buttons). A slow reconcile poll only backstops missed
  pushes.
- **Live power.** For energy-metering plugs (POWR3) the plugin sends the
  device's `uiActive` streaming nudge, so power/voltage/current update every few
  seconds instead of freezing between the device's own lazy reports.
- **Native PUT control.** Registers a Signal K PUT handler per switch path, so a
  client or dashboard sets `…​.state` and the plugin drives the relay. No
  separate control plugin.

## Architecture

A thin `index.js` (the official [sk-plugin-python-demo] pattern) spawns
`plugin.py`, pipes its stdout — one Signal K delta per line — into
`app.handleMessage`, feeds config on stdin, and forwards PUTs to the child. All
eWeLink logic (LAN AES + mDNS, OAuth, WebSocket push, streaming, discovery
routing) lives in `plugin.py`. Language-agnostic by design; the proven Python
runs unchanged behind the Node contract.

[sk-plugin-python-demo]: https://github.com/SignalK/sk-plugin-python-demo

## Requirements

`python3` on the server host with `pip install -r requirements.txt`
(pycryptodome, zeroconf, websocket-client). mDNS needs the Signal K host to
share the device's LAN (host networking if containerised).

## Config (Signal K admin UI)

Enable the plugin, enter your **eWeLink OAuth** app id/secret and region, save.
Reopen the config page and pick devices from the **Device** dropdown (populated
by discovery — cloud device list + mDNS). For each, set its `kind`
(`single`/`multi`), channel count, and a Signal K `basePath`
(e.g. `electrical.ac.shore` or `electrical.switches.ewe4`).

Devicekeys are fetched from the cloud and cached automatically — there is no keys
file. OAuth tokens are obtained once (see the standalone
[ewelink-mqtt-bridge](https://github.com/dennismilton/ewelink-mqtt-bridge) `auth`
flow) and stored beside the plugin.

## Python

The worker is Python. Install its deps against the python3 the Signal K server
runs (on modern Debian/Raspberry Pi OS that means a venv or
`pip install --break-system-packages`, or `pip install --target vendor/` inside
the plugin dir). The official Signal K docker image ships without python3.

## License

MIT.
