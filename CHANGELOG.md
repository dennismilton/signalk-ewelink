# Changelog

## 1.0.0 — 2026-08-12

First release. eWeLink/Sonoff devices as a native, self-contained Signal K
plugin — no MQTT broker, no external control plugin, no `.env`.

- **LAN-first, cloud-fallback, by discovery.** mDNS-discovered devices are
  driven directly over the encrypted eWeLink LAN protocol (offline); undiscovered
  devices route to the cloud. Discovery can *undiscover* (mDNS goodbye or
  repeated poll misses) and the cloud resumes.
- **Push, not poll.** State arrives the moment it changes — mDNS updates on LAN,
  the eWeLink WebSocket on cloud (including eWeLink-app taps and physical
  buttons). A slow reconcile poll only backstops missed pushes.
- **Live power.** For energy-metering plugs (POWR3) the plugin sends the
  `uiActive` streaming nudge, so power/voltage/current update every few seconds
  instead of freezing between the device's own lazy reports.
- **Native PUT control** via `registerPutHandler` per switch path.
- **Secrets in a file**, not in the (plaintext) Signal K plugin config.

The bridge logic was proven on the vessel *Maracaibo* as a standalone
container (`ewelink-mqtt-bridge`) before being wrapped as this plugin; the LAN
AES + mDNS, OAuth, WebSocket push, uiActive streaming and discovery-routing are
carried over intact, with the MQTT tail replaced by the Signal K plugin
contract (stdout deltas, stdin config + control).
