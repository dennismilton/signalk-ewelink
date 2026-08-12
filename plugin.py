#!/usr/bin/env python3
"""signalk-ewelink plugin worker. Same bridge that ran on the boat as
maracaibo-sonoff, with the MQTT tail replaced by the Signal K plugin contract:

  • config arrives as ONE json line on stdin: {"type":"config","options":{...}}
  • control arrives as further stdin lines:   {"type":"cmd","deviceid","outlet","on"}
  • device state leaves as Signal K DELTAS on stdout, one json object per line —
    index.js pipes each straight into app.handleMessage. No MQTT, no broker.

THE CONTRACT is unchanged from the standalone bridge: if mDNS has discovered a
device on this network, LAN owns its state and control; otherwise the cloud
does. Discovery can UNDISCOVER. State is pushed (mDNS + eWeLink WebSocket); a
slow poll reconciles and fetches power/V/A; a uiActive nudge streams live power.
"""
import sys, os, json, time, hashlib, hmac, base64, secrets, threading
import urllib.request, urllib.parse
# vendored deps live beside this file (pip install --target vendor/), so the
# plugin carries pycryptodome/zeroconf/websocket-client and survives a Signal K
# container recreation without touching the image.
_vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
if os.path.isdir(_vendor):
    sys.path.insert(0, _vendor)
from Crypto.Cipher import AES
from zeroconf import Zeroconf, ServiceBrowser
try:
    import websocket
except ImportError:
    websocket = None

log = lambda *a: print(*a, file=sys.stderr, flush=True)

_out = threading.Lock()   # emit() runs from LAN, poll, push and confirm threads
def emit(delta):
    line = json.dumps(delta)
    with _out:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

def sk(values):
    """values: [(path, value), ...] -> a Signal K delta on stdout."""
    emit({"updates": [{"values": [{"path": p, "value": v} for p, v in values]}]})

# ── config (filled from the stdin config line) ───────────────────────────────
CFG = {}
DEVICES = {}          # deviceid -> {id,key,kind,base,channels,name}
KEYS = {}             # deviceid -> devicekey (from keysFile)
DISCOVERED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "discovered.json")
KEYCACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_keycache.json")
KEYS = {}             # deviceid -> devicekey, AUTO-fetched from the cloud + cached
_disc = {}            # everything the account/network shows, for the config page
MULTI_UIIDS = {2, 3, 4, 7, 8, 9, 29, 30, 31, 41, 77, 78, 112, 126, 140}  # multi-relay

def write_discovered():
    try:
        tmp = DISCOVERED + ".tmp"
        json.dump(_disc, open(tmp, "w")); os.replace(tmp, DISCOVERED)
    except Exception as e:
        log(f"discovered.json write failed: {e}")

def _api_base(region):
    return f"https://{region}-apia.coolkit.{'cn' if region == 'cn' else 'cc'}"

def _cloud_req(url, body=None, bearer=None, appid=None):
    data = json.dumps(body).encode() if body is not None else None
    secret = CFG.get("oauth", {}).get("appSecret", "")
    auth = (f"Bearer {bearer}" if bearer else "Sign " + base64.b64encode(
        hmac.new(secret.encode(), data or b"", hashlib.sha256).digest()).decode())
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "X-CK-Appid": appid or CFG.get("oauth", {}).get("appId", ""),
        "X-CK-Nonce": secrets.token_hex(4), "Authorization": auth})
    return json.load(urllib.request.urlopen(req, timeout=10))

class CloudAuth:
    REFRESH_MARGIN_MS = 24 * 3600 * 1000

    def __init__(self):
        self.tok = None
        self._lock = threading.Lock()   # refresh runs from main + WS + stdin threads
        self.file = CFG.get("oauth", {}).get("tokenFile") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tokens.json")
        try:
            with open(self.file) as f:
                self.tok = json.load(f)
            log(f"loaded OAuth tokens from {self.file}")
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"token file {self.file} unreadable: {e}")

    def save(self):
        tmp = self.file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.tok, f)
        try: os.chmod(tmp, 0o600)          # tokens are secrets — not world-readable
        except OSError: pass
        os.replace(tmp, self.file)

    @property
    def region(self):
        return (self.tok or {}).get("region") or CFG.get("oauth", {}).get("region", "eu")

    @property
    def appid(self):
        return CFG.get("oauth", {}).get("appId", "")

    def refresh(self):
        o = CFG.get("oauth", {})
        if not (self.tok and self.tok.get("rt") and o.get("appId") and o.get("appSecret")):
            return False
        with self._lock:
            # a second thread may have refreshed while we waited — eWeLink ROTATES
            # the refresh token, so re-checking here avoids persisting a stale rt
            now = int(time.time() * 1000)
            if now < self.tok.get("atExpiredTime", 0) - self.REFRESH_MARGIN_MS:
                return True
            try:
                d = _cloud_req(f"{_api_base(self.region)}/v2/user/refresh", body={"rt": self.tok["rt"]})
                if d.get("error"):
                    log(f"token refresh error {d.get('error')} {d.get('msg', '')}"); return False
                self.tok.update({"at": d["data"]["at"], "rt": d["data"]["rt"],
                                 "atExpiredTime": now + 30 * 86400 * 1000,
                                 "rtExpiredTime": now + 60 * 86400 * 1000})
            except Exception as e:
                log(f"token refresh failed: {e}"); return False
            self.save(); log("OAuth tokens refreshed"); return True

    def credentials(self):
        if self.tok and self.tok.get("at"):
            now = int(time.time() * 1000)
            if now >= self.tok.get("atExpiredTime", 0) - self.REFRESH_MARGIN_MS:
                if not self.refresh() and now >= self.tok.get("atExpiredTime", 0):
                    log("OAuth access token expired and refresh failed"); return None
            return (self.tok["at"], self.appid, self.region)
        return None

    def invalidate(self):
        if self.tok:
            self.tok["atExpiredTime"] = 0
            return self.refresh()
        return False

# ── LAN crypto ───────────────────────────────────────────────────────────────

def _aes(key_str):
    return hashlib.md5(key_str.encode()).digest()

def decrypt(props, devkey):
    iv = base64.b64decode(props["iv"])
    ct = base64.b64decode("".join(props.get(f"data{i}") or "" for i in (1, 2, 3, 4)))
    pt = AES.new(_aes(devkey), AES.MODE_CBC, iv).decrypt(ct)
    return json.loads(pt[: -pt[-1]])

def encrypt(params, devkey):
    iv = os.urandom(16)
    data = json.dumps(params).encode()
    data += bytes([16 - len(data) % 16]) * (16 - len(data) % 16)
    ct = AES.new(_aes(devkey), AES.MODE_CBC, iv).encrypt(data)
    return base64.b64encode(iv).decode(), base64.b64encode(ct).decode()

def _props(info):
    out = {}
    for k, v in (info.properties or {}).items():
        try:
            out[k.decode()] = v.decode() if isinstance(v, bytes) else v
        except Exception:
            pass
    return out

LAN_POLL_S = 15
LAN_MISS_LIMIT = 4

# ── the bridge ───────────────────────────────────────────────────────────────

class Bridge:
    def __init__(self, zc, auth):
        self.zc = zc
        self.auth = auth
        self.cloud_fails = 0
        self.apikey = None
        self.lan = {d: {"name": None, "addr": None, "port": None, "miss": 0} for d in DEVICES}
        self.last = {}

    def lan_active(self, did):
        return bool(self.lan[did]["addr"]) if did in self.lan else False

    def _undiscover(self, did, why):
        st = self.lan[did]
        if st["addr"]:
            log(f"LAN lost {DEVICES[did]['base']} ({why}) — cloud resumes")
        st.update(addr=None, port=None, miss=0)

    def _match(self, info):
        if not info:
            return None
        did = _props(info).get("id")
        # record ANY eWeLink device seen on the LAN for the config page, even one
        # not yet configured — id + ip is enough to offer it
        if did:
            try:
                addrs = info.parsed_addresses()
                ip = addrs[0] if addrs else None
            except Exception:
                ip = None
            if ip and _disc.get(did, {}).get("ip") != ip:
                _disc.setdefault(did, {"name": did}).update(ip=ip, source="lan")
                write_discovered()
        cfg = DEVICES.get(did)
        if cfg:
            try:
                addrs = info.parsed_addresses()
                if addrs:
                    self.lan[cfg["id"]].update(addr=addrs[0], port=info.port, miss=0)
            except Exception:
                pass
        return cfg

    def add_service(self, zc, type_, name):    self._seen(name)
    def update_service(self, zc, type_, name): self._seen(name)

    def remove_service(self, zc, type_, name):
        for did, st in self.lan.items():
            if st["name"] == name:
                self._undiscover(did, "mDNS goodbye")

    def _seen(self, name):
        info = self.zc.get_service_info("_ewelink._tcp.local.", name, timeout=2000)
        cfg = self._match(info)
        if cfg:
            if not self.lan[cfg["id"]]["name"]:
                log(f"LAN discovered {cfg['base']} at {self.lan[cfg['id']]['addr']}")
            self.lan[cfg["id"]]["name"] = name
            self._lan_state(info, cfg)

    def lan_poll(self):
        for did, st in self.lan.items():
            if not st["name"]:
                continue
            info = self.zc.get_service_info("_ewelink._tcp.local.", st["name"], timeout=2000)
            cfg = self._match(info)
            if cfg:
                self._lan_state(info, cfg)
            elif st["addr"]:
                st["miss"] += 1
                if st["miss"] >= LAN_MISS_LIMIT:
                    self._undiscover(did, f"{LAN_MISS_LIMIT} poll misses")

    def _lan_state(self, info, cfg):
        if not cfg.get("key"):
            if not cfg.get("_warned_nokey"):
                log(f"{cfg['base']}: no devicekey — LAN disabled for it (cloud only)")
                cfg["_warned_nokey"] = True
            return
        props = _props(info)
        try:
            p = decrypt(props, cfg["key"]) if props.get("encrypt") in ("true", True) else {}
        except Exception as e:
            log(f"decrypt failed: {e}"); return
        self.publish_state(cfg, p, online=True, source="LAN")

    # -- the one publisher: device params -> Signal K deltas ----------------
    def publish_state(self, cfg, p, online, source):
        base = cfg["base"]
        if cfg["kind"] == "multi":
            sws = p.get("switches")
            if sws is None:
                if online is False and cfg["id"] in self.last:
                    vals = [(f"{base}.ch{ch}.state", v) for ch, v in self.last[cfg["id"]].items()]
                    sk(vals + [(f"{base}.online", 0)])
                return
            vals = [(f"{base}.online", 1 if online else 0)]
            chans = {}
            for sw in sws:
                if sw.get("outlet") is not None:
                    ch = sw["outlet"] + 1
                    v = 1 if sw.get("switch") == "on" else 0
                    vals.append((f"{base}.ch{ch}.state", v))
                    chans[ch] = v
            self.last[cfg["id"]] = chans
            sk(vals)
            log(f"{source} {base}: {chans}")
            return
        if online is False:
            # a single going offline: null its paths so .state does not read stale
            emit_paths = [(f"{base}.state", None)]
            if cfg.get("_meter"):
                emit_paths += [(f"{base}.power", None), (f"{base}.voltage", None),
                               (f"{base}.current", None)]
            sk(emit_paths)
            return
        vals = []
        if source != "LAN":              # power/V/A: cloud only (LAN freezes them)
            if "power" in p:
                try: vals.append((f"{base}.power", float(p["power"])));
                except Exception: pass
            if "voltage" in p:
                try: vals.append((f"{base}.voltage", float(p["voltage"])))
                except Exception: pass
            if "current" in p:
                try: vals.append((f"{base}.current", float(p["current"])))
                except Exception: pass
        if "switch" in p and (source == "LAN" or not self.lan_active(cfg["id"])):
            vals.append((f"{base}.state", 1 if p["switch"] == "on" else 0))
        if any(k in (f"{base}.power", f"{base}.voltage", f"{base}.current") for k, _ in vals):
            cfg["_meter"] = True
        if vals:
            sk(vals)
            log(f"{source} {base}: {dict(vals)}")

    # -- control: discovery decides -----------------------------------------
    def control(self, cfg, params):
        # try LAN when discovered; a LAN FAILURE now FALLS THROUGH to the cloud
        # rather than silently losing the command (the discovery race:
        # lan_active() true, then undiscovered before the request). Reachability
        # is still preferred, but a dropped switch is never acceptable.
        st = self.lan.get(cfg["id"]) or {}
        if st.get("addr"):
            endpoint = "switches" if cfg["kind"] == "multi" else "switch"
            iv_b64, data_b64 = encrypt(params, cfg["key"])
            body = json.dumps({
                "sequence": str(int(time.time() * 1000)), "deviceid": cfg["id"],
                "selfApikey": "123", "iv": iv_b64, "encrypt": True, "data": data_b64,
            }).encode()
            try:
                req = urllib.request.Request(
                    f"http://{st['addr']}:{st['port']}/zeroconf/{endpoint}",
                    data=body, headers={"Content-Type": "application/json"})
                resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
                if resp.get("error") == 0:
                    log(f"LAN control {cfg['base']} {params} -> ok")
                    self.lan_poll()
                    return
                log(f"LAN control {cfg['base']} -> {resp}; trying cloud")
            except Exception as e:
                log(f"LAN control {cfg['base']} failed ({e}); trying cloud")
        creds = self.auth.credentials()
        if not creds:
            log("cloud control impossible — no credentials"); return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing/status",
                           body={"type": 1, "id": cfg["id"], "params": params},
                           bearer=at, appid=appid)
            ok = not d.get("error")
            log(f"cloud control {cfg['base']} {params} -> {'ok' if ok else (d.get('error'), d.get('msg', ''))}")
            if ok:
                self.cloud_poll()
        except Exception as e:
            log(f"cloud control {cfg['base']} FAILED: {e}")

    # -- cloud reconcile poll -----------------------------------------------
    def cloud_poll(self, _retry=True):
        creds = self.auth.credentials()
        if not creds:
            return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing", bearer=at, appid=appid)
        except Exception as e:
            log(f"cloud poll failed: {e}"); self._cloud_fail(); return
        if d.get("error"):
            if d["error"] in (401, 402) and _retry and self.auth.invalidate():
                return self.cloud_poll(_retry=False)
            log(f"cloud error {d.get('error')} {d.get('msg', '')}"); self._cloud_fail(); return
        seen = False
        changed = False
        for t in (d.get("data") or {}).get("thingList") or []:
            it = t.get("itemData", {})
            did = it.get("deviceid")
            if did:
                uiid = ((it.get("extra") or {}).get("uiid")
                        or (it.get("itemType") if isinstance(it.get("itemType"), int) else None))
                kind = "multi" if uiid in MULTI_UIIDS else "single"
                pr = it.get("params") or {}
                chans = len(pr.get("switches") or []) or (4 if kind == "multi" else 1)
                rec = {"name": it.get("name") or did, "model": it.get("productModel") or "",
                       "kind": kind, "channels": chans, "online": bool(it.get("online")),
                       "source": "cloud"}
                if _disc.get(did) != {**_disc.get(did, {}), **rec}:
                    _disc[did] = {**_disc.get(did, {}), **rec}; changed = True
            cfg = DEVICES.get(it.get("deviceid"))
            if not cfg:
                continue
            seen = True
            if it.get("apikey"):
                self.apikey = it["apikey"]
            # AUTO-KEY: the cloud hands us every devicekey — fill it in and cache
            # it (0600) so there is no keys file and LAN works offline thereafter
            dk = it.get("devicekey")
            if dk and cfg.get("key") != dk:
                cfg["key"] = dk
                KEYS[it["deviceid"]] = dk
                try:
                    tmp = KEYCACHE + ".tmp"; json.dump(KEYS, open(tmp, "w"))
                    os.chmod(tmp, 0o600); os.replace(tmp, KEYCACHE)
                    log(f"cached devicekey for {cfg['base']}")
                except Exception as e:
                    log(f"keycache write failed: {e}")
            if cfg["kind"] == "multi" and self.lan_active(cfg["id"]):
                continue
            self.publish_state(cfg, it.get("params") or {},
                               online=bool(it.get("online")), source="poll")
        if changed:
            write_discovered()
        if seen:
            self.cloud_fails = 0
        # a successful poll that simply contained none of OUR devices is NOT a
        # transport failure — do not count it toward clearing retained readings

    def _cloud_fail(self):
        self.cloud_fails += 1
        if self.cloud_fails == int(CFG.get("cloudMaxFails", 10)):
            log("cloud stale — clearing power/V/A")
            for cfg in DEVICES.values():
                if cfg["kind"] == "single":
                    sk([(f"{cfg['base']}.power", None), (f"{cfg['base']}.voltage", None),
                        (f"{cfg['base']}.current", None)])

# ── cloud push (WebSocket) + uiActive live power ─────────────────────────────

class CloudWS:
    def __init__(self, auth, bridge):
        self.auth = auth
        self.bridge = bridge

    def start(self):
        if websocket is None:
            log("cloud push disabled (websocket-client not installed)"); return
        threading.Thread(target=self._run, daemon=True).start()

    def _connect(self):
        creds = self.auth.credentials()
        if not creds:
            return None
        at, appid, region = creds
        d = _cloud_req(f"https://{region}-dispa.coolkit.{'cn' if region == 'cn' else 'cc'}/dispatch/app",
                       body={"appid": appid, "nonce": secrets.token_hex(4),
                             "ts": int(time.time()), "version": 8}, bearer=at, appid=appid)
        if not d.get("domain"):
            return None
        ws = websocket.create_connection(f"wss://{d['domain']}:{d['port']}/api/ws", timeout=15)
        ws.send(json.dumps({
            "action": "userOnline", "at": at, "apikey": self.bridge.apikey or "",
            "appid": appid, "nonce": secrets.token_hex(4), "ts": int(time.time()),
            "userAgent": "app", "sequence": str(int(time.time() * 1000)), "version": 8}))
        hello = json.loads(ws.recv())
        if hello.get("error") not in (0, None):
            ws.close(); raise OSError(f"handshake refused: {hello.get('error')}")
        hb = int((hello.get("config") or {}).get("hbInterval", 90))
        log(f"cloud push connected (hb {hb}s)")
        return ws, hb

    def _nudge(self, ws):
        for cfg in DEVICES.values():
            if cfg["kind"] != "single":
                continue
            ws.send(json.dumps({
                "action": "update", "deviceid": cfg["id"],
                "apikey": self.bridge.apikey or "", "userAgent": "app",
                "sequence": str(int(time.time() * 1000)), "params": {"uiActive": 120}}))

    def _run(self):
        backoff = 5
        ui = int(CFG.get("uiActiveS", 110))
        while True:
            ws = None
            try:
                got = self._connect()
                if not got:
                    time.sleep(60); continue
                ws, hb = got
                backoff = 5
                ws.settimeout(20)
                last_ping = last_nudge = 0.0
                while True:
                    now = time.time()
                    if now - last_ping >= hb:
                        ws.send("ping"); last_ping = now
                    if now - last_nudge >= ui:
                        self._nudge(ws); last_nudge = now
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    if not raw or raw == "pong":
                        continue
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    self._handle(msg)
            except Exception as e:
                log(f"cloud push dropped: {e}")
                try:
                    if ws: ws.close()
                except Exception:
                    pass
                time.sleep(backoff); backoff = min(backoff * 2, 300)

    def _handle(self, msg):
        cfg = DEVICES.get(msg.get("deviceid"))
        if not cfg:
            return
        if cfg["kind"] == "multi" and self.bridge.lan_active(cfg["id"]):
            return
        if msg.get("action") == "update":
            self.bridge.publish_state(cfg, msg.get("params") or {}, online=True, source="push")
        elif msg.get("action") == "sysmsg":
            online = (msg.get("params") or {}).get("online")
            if online is not None:
                self.bridge.publish_state(cfg, {}, online=bool(online), source="push")

# ── main ─────────────────────────────────────────────────────────────────────

def load_config(options):
    global CFG, DEVICES, KEYS
    CFG = options or {}
    # devicekeys are AUTO-fetched from the eWeLink cloud (they are in the device
    # list we already poll) and cached here, so there is no keys file to manage
    # and LAN keeps working offline after the first cloud sync.
    try:
        KEYS = json.load(open(KEYCACHE))
    except Exception:
        KEYS = {}
    DEVICES = {}
    for d in CFG.get("devices", []):
        did = (d.get("id") or "").strip()
        if not did:
            continue
        DEVICES[did] = {
            "id": did, "key": KEYS.get(did, ""),
            "kind": d.get("kind", "single"), "base": d.get("basePath", ""),
            "channels": int(d.get("channels", 4)), "name": d.get("name", did)}

def stdin_loop(bridge):
    """Every stdin line after config is a control command from index.js."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if msg.get("type") != "cmd":
                continue
            cfg = DEVICES.get(msg.get("deviceid"))
            if not cfg:
                continue
            on = bool(msg.get("on"))
            if cfg["kind"] == "multi":
                ch = int(msg.get("outlet") or 1)
                bridge.control(cfg, {"switches": [{"switch": "on" if on else "off", "outlet": ch - 1}]})
            else:
                bridge.control(cfg, {"switch": "on" if on else "off"})
        except Exception as e:          # a bad control line must not kill the thread
            log(f"control line error: {e}")
    # stdin closed = Signal K is gone → do not orphan a polling worker
    os._exit(0)

def main():
    # the first stdin line is the config; block for it
    first = sys.stdin.readline()
    try:
        msg = json.loads(first)
        load_config(msg.get("options", {}))
    except Exception as e:
        log(f"bad config line: {e}"); return
    auth = CloudAuth()
    zc = Zeroconf()
    bridge = Bridge(zc, auth)
    ServiceBrowser(zc, "_ewelink._tcp.local.", bridge)   # mDNS discovery always on

    if auth.credentials():
        log(f"cloud: reconcile every {CFG.get('cloudIntervalS', 60)}s + push")
        bridge.cloud_poll()
        CloudWS(auth, bridge).start()
    else:
        log("no cloud credentials — LAN-discovered devices only")

    threading.Thread(target=stdin_loop, args=(bridge,), daemon=True).start()

    interval = int(CFG.get("cloudIntervalS", 60))
    n = 0
    try:
        while True:
            time.sleep(LAN_POLL_S)
            bridge.lan_poll()
            n += 1
            if (n * LAN_POLL_S) % interval < LAN_POLL_S:
                bridge.cloud_poll()
    finally:
        zc.close()

if __name__ == "__main__":
    main()
