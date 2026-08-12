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

- **Device keys file** — path to a JSON `{ deviceId: devicekey }`. Secrets live
  here, not in the plugin config, which Signal K stores in plaintext. Fetch a
  devicekey once from the cloud device list (`/v2/device/thing`).
- **eWeLink cloud (OAuth2.0)** — app id/secret from
  [dev.ewelink.cc](https://dev.ewelink.cc), region, token store path. Needed for
  cloud fallback and for POWR3 power readings. Run the one-time login (see
  `auth` in the standalone bridge, or paste a token file). Omit to run
  LAN-discovered devices only.
- **Devices** — for each: `id`, `kind` (`single` | `multi`), `channels`, and a
  Signal K `basePath`:
  - `single` → `basePath.state` `.power` `.voltage` `.current`
  - `multi`  → `basePath.chN.state` and `basePath.online`

Example: a POWR3 as `electrical.ac.shore`, a 4-channel switch as
`electrical.switches.ewe4`.

## License

MIT.
