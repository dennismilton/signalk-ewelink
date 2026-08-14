# Changelog

## 1.0.5 — 2026-08-14

- Docs corrected + trimmed: the official Signal K Docker image already ships
  `python3` and `pip3` (Ubuntu-based), so you only install the Python deps — no
  custom image; a free eWeLink developer account (dev.ewelink.cc) is required.
- Internal cleanup + hardening, behaviour unchanged: cut the narration, closed
  leaked sockets (context managers), narrowed broad `except`s, reset the cloud
  reconnect backoff only after a stable connection, made a read-only data dir no
  longer able to crash a token refresh, and a lost stdout now exits cleanly like
  a lost stdin. Verified live on the boat — data flows, survives a restart.

## 1.0.4 — 2026-08-13

- **Tokens and caches now survive a reinstall.** OAuth tokens, the device key
  cache and the discovery list were written beside `plugin.py`, inside the plugin
  install — so every npm/appstore update wiped them and you had to authorise
  again. They now live in the Signal K plugin data directory, which is outside
  the install. Existing files are migrated across automatically on first run, and
  the old location is still used as a fallback on servers that do not expose a
  data directory.
- **OAuth authorisation is now done in the plugin.** Previously tokens had to be
  produced by a separate tool and dropped in by hand. The config page takes a
  Redirect URL and a one-time Authorisation code, the plugin prints the eWeLink
  login URL to the server log, exchanges the code for tokens itself and refreshes
  them from then on.
- **Degrades gracefully instead of failing quietly.** A fresh install with no
  credentials, no authorisation or no devices now starts cleanly and reports what
  is missing in the admin UI status line and the log. A missing or corrupt device
  key cache or token file is tolerated and refetched rather than thrown; a
  half-filled device row is skipped instead of registering an `undefined.state`
  PUT handler; no config field is mandatory, so credentials can be saved before
  any device exists.
- Restored this changelog, which was emptied by accident in 1.0.2.

## 1.0.3 — 2026-08-12

- Fixed a duplicate worker and a false "exited" error when saving the config: a
  generation guard means the replaced child's exit is no longer reported as a
  crash and no longer triggers a second respawn.

## 1.0.2 — 2026-08-12

- The App secret field is masked in the config UI.

## 1.0.1 — 2026-08-12

- **Autodiscovery in the config page.** The Device field is now a dropdown of
  devices found on the account/network (cloud device list + mDNS); no typing IDs.
- **No keys file.** Devicekeys are fetched from the eWeLink cloud automatically
  and cached locally, so LAN control works with nothing to enter by hand.
- Review hardening: LAN control failure falls through to cloud (no lost command);
  stdout framed across chunk boundaries; child stdin errors handled; worker
  respawns on exit and exits when Signal K closes stdin (no orphan); token
  refresh is locked and the token file is chmod 0600; PUT returns FAILURE when
  the worker is down; a single going offline nulls its paths.

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
