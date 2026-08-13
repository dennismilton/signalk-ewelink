# signalk-ewelink

eWeLink/Sonoff devices as **native Signal K** — no MQTT broker, no external
control plugin, no `.env`. One self-contained plugin that is the bridge to the
hardware, configured entirely in the Signal K admin UI.

## What it does

- **LAN-first, cloud-fallback, by discovery.** If mDNS finds a device on the
  server's network, its state and control go direct over the encrypted eWeLink
  LAN protocol — no internet involved. A device it has *not* discovered routes
  to the eWeLink cloud instead. Discovery can also *undiscover* (an mDNS goodbye
  or repeated poll misses) and the cloud takes over seamlessly. In practice that
  means switches keep working when the boat is offline, and still work when
  you are away from it.
- **Push, not poll.** State arrives the moment it changes — mDNS updates on LAN,
  the eWeLink WebSocket on cloud (including changes made from the eWeLink app or
  a device's physical button). A slow reconcile poll only backstops missed
  pushes.
- **Live power.** For energy-metering plugs (POWR3 and friends) the plugin sends
  the device's `uiActive` streaming nudge, so power/voltage/current update every
  few seconds instead of freezing between the device's own lazy reports.
- **Native PUT control.** Registers a Signal K PUT handler per switch path, so
  any client or dashboard sets `….state` and the plugin drives the relay. No
  separate control plugin.

## Requirements

- A Signal K node server.
- **`python3` on the server host**, with the packages in `requirements.txt`
  (`pycryptodome`, `zeroconf`, `websocket-client`). See [Python deps](#python-deps).
- For LAN control, the Signal K host must share a network with the devices —
  mDNS does not cross subnets, so a container needs **host networking**.
- An eWeLink account, and an OAuth app from [dev.ewelink.cc](https://dev.ewelink.cc)
  (free). Cloud access is what supplies the device list and the per-device LAN
  keys, so it is needed at least once even for a LAN-only setup.

## Install

From the Signal K **Appstore** (search for `signalk-ewelink`), or by hand:

```sh
cd ~/.signalk/node_modules
npm install signalk-ewelink
```

Then restart the server and enable the plugin in **Server → Plugin Config**.

### Python deps

The worker is Python, so install its dependencies against the same `python3`
the Signal K server runs:

```sh
python3 -m pip install -r requirements.txt
```

On modern Debian/Raspberry Pi OS that needs a venv or
`pip install --break-system-packages`. Alternatively, vendor them inside the
plugin directory, which keeps the plugin self-contained:

```sh
cd ~/.signalk/node_modules/signalk-ewelink
python3 -m pip install --target vendor/ -r requirements.txt
```

Note that the official Signal K docker image ships **without** python3.

## Configure (Signal K admin UI)

### 1. Create an eWeLink OAuth app

At [dev.ewelink.cc](https://dev.ewelink.cc), create an app and note its **App ID**
and **App secret**. Register a **Redirect URL** for it — your Signal K server's
address (e.g. `http://localhost:3000/`) works fine; nothing has to be listening
there, it is only where the browser lands.

### 2. Enter credentials and authorise

In the plugin config, fill in **App ID**, **App secret**, **Region** (`eu`, `us`,
`as`, `cn` — the region your eWeLink account was created in) and the **Redirect
URL** you registered. Save.

eWeLink's OAuth is a browser login, so it needs one manual step. Check the Signal
K server log: the plugin prints a login URL. Open it, sign in to eWeLink and
approve. Your browser is redirected to your Redirect URL with `?code=…` on the
end. Copy that code out of the address bar, paste it into the plugin's
**Authorisation code** field and save again.

That is a one-time step. The plugin exchanges the code for tokens, stores them,
and refreshes them by itself from then on. You can clear the code field
afterwards. Authorisation codes are single-use and expire within minutes — if it
fails, reload the login URL and get a fresh one.

### 3. Pick your devices

Reopen the config page. The **Device** dropdown is now populated by discovery
(your cloud device list plus anything mDNS sees). For each device you want in
Signal K, add an entry and set:

- **Device** — pick from the dropdown.
- **Kind** — `single` for a one-relay device, `multi` for a multi-gang switch.
- **Channels** — for `multi`, how many relays.
- **Signal K path** — the base path to publish under, e.g.
  `electrical.switches.shorepower`.

A `single` device publishes `<path>.state` (and `.power`, `.voltage`, `.current`
if it meters). A `multi` publishes `<path>.chN.state` per channel plus
`<path>.online`. All switch paths accept PUT.

Device LAN keys are fetched from the cloud and cached automatically — there is
no keys file to manage, and LAN control keeps working offline afterwards.

## Where state is stored

Tokens (`_tokens.json`), the device key cache (`_keycache.json`) and the
discovery list (`discovered.json`) are written to the **Signal K plugin data
directory**, not into the plugin install. That means upgrading or reinstalling
the plugin does not lose your authorisation. A `Token file` config option can
override the token location if you need it elsewhere.

## Troubleshooting

The plugin's status line in the admin UI says what is missing, and the server log
carries the detail.

| Symptom | Cause |
| --- | --- |
| "No eWeLink credentials" | App ID/App secret not set yet. |
| "Not authorised" | Credentials set, but the code step is not done — see the login URL in the log. |
| Code exchange refused | The code was reused or expired, or the Redirect URL does not match the one registered at dev.ewelink.cc. |
| Devices work from cloud but never LAN | mDNS is not reaching the server — check host networking, and that server and devices share a subnet. |
| `plugin.py exited` in the log | Python dependencies missing; see [Python deps](#python-deps). |

With no credentials at all, the plugin still starts and simply does nothing but
listen — it does not crash the server.

## Architecture

A thin `index.js` (the official [sk-plugin-python-demo] pattern) spawns
`plugin.py`, pipes its stdout — one Signal K delta per line — into
`app.handleMessage`, feeds config on stdin, and forwards PUTs to the child. All
eWeLink logic (LAN AES + mDNS, OAuth, WebSocket push, `uiActive` streaming,
discovery routing) lives in `plugin.py`.

[sk-plugin-python-demo]: https://github.com/SignalK/sk-plugin-python-demo

## License

MIT — see [LICENSE](LICENSE).
