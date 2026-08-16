# signalk-ewelink

Control and monitor eWeLink / Sonoff switches and plugs from Signal K — direct
over the LAN when the device is local, via the eWeLink cloud when it isn't.

## What it does

- **LAN-first, cloud fallback.** A device seen on the LAN is driven direct and
  offline; one that isn't goes via the cloud. It re-routes on its own as devices
  come and go.
- **Push, not poll.** State changes arrive instantly — LAN mDNS and the eWeLink
  WebSocket, including changes made from the app or a physical button.
- **Live power.** POWR3 and other metering plugs stream power / voltage / current.
- **PUT control.** A Signal K PUT to `….state` throws the relay.

## Requirements

- A Signal K server.
- **The Python deps** — `pycryptodome`, `zeroconf`, `websocket-client`. `python3`
  and `pip3` are already in the official Docker image; you only install these.
- **A free eWeLink developer account** at [dev.ewelink.cc](https://dev.ewelink.cc)
  — not your phone-app login. It supplies the device list and the LAN keys, so it
  is needed even for LAN-only use.
- For LAN, the server must share the devices' network — host networking in a
  container, since mDNS does not cross subnets.

## Install

Signal K **Appstore** (search `signalk-ewelink`), or by hand:

```sh
cd ~/.signalk/node_modules && npm install signalk-ewelink
```

Then the Python deps:

```sh
cd ~/.signalk/node_modules/signalk-ewelink
python3 -m pip install --target vendor/ -r requirements.txt
```

Restart the server and enable the plugin.

> **`vendor/` does not survive a plugin upgrade.** It lives inside the package
> directory, which npm replaces wholesale when you update the plugin — and if
> SignalK runs from a stock Docker image, installing deps *into the container*
> is worse still, since any recreate wipes them. Either way the plugin degrades
> the way it is designed to, quietly: no error, no log line, the
> `electrical.*` paths just stop appearing and whatever reads them goes dead.
>
> For a long-lived install, put the deps somewhere neither npm nor Docker
> touches — the mounted config dir — and point Python at it:
>
> ```sh
> python3 -m pip install --target ~/.signalk/pylibs -r requirements.txt
> # Docker: add PYTHONPATH=/home/node/.signalk/pylibs to the service environment
> ```
>
> Verify after any upgrade by checking the paths are still on the bus, not by
> checking that the plugin is enabled.

## Configure (admin UI)

1. **Create an app** at [dev.ewelink.cc](https://dev.ewelink.cc): note the **App
   ID** and **App secret**, and register a **Redirect URL** — your server's
   address, e.g. `http://localhost:3000/` (nothing needs to listen there).
2. **Enter and authorise.** Put the App ID, App secret, Region and Redirect URL
   in the config and save. The server log prints a login URL — open it, sign in,
   and paste the `?code=…` from the redirect into **Authorisation code**, save
   again. One-time; tokens are kept and refreshed automatically. Codes are
   single-use and expire in minutes — reload the URL if it fails.
3. **Pick devices.** Reopen the config; the **Device** dropdown is filled by
   discovery. Per device set its **kind** (`single`/`multi`), channels, and a
   **Signal K path** (e.g. `electrical.switches.shorepower`).

`single` → `<path>.state` (+ `.power`, `.voltage`, `.current` if it meters).
`multi` → `<path>.chN.state` + `<path>.online`. All accept PUT. LAN keys are
fetched and cached automatically. Tokens and caches live in the Signal K plugin
data directory, so an upgrade does not lose your authorisation.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| "No eWeLink credentials" | App ID/App secret not set yet. |
| "Not authorised" | Credentials set, but the code step is not done — see the login URL in the log. |
| Code exchange refused | The code was reused or expired, or the Redirect URL does not match the one registered at dev.ewelink.cc. |
| Devices work from cloud but never LAN | mDNS is not reaching the server — check host networking and that server and devices share a subnet. |
| `plugin.py exited` in the log | Python deps missing — see [Install](#install). |

## Architecture

`index.js` spawns `plugin.py` and pipes its deltas into Signal K; all eWeLink
logic — LAN AES + mDNS, OAuth, WebSocket push, discovery routing — lives in
`plugin.py`. The [sk-plugin-python-demo] pattern.

[sk-plugin-python-demo]: https://github.com/SignalK/sk-plugin-python-demo

## License

MIT.
