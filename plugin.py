#!/usr/bin/env python3
"""signalk-ewelink plugin worker — the eWeLink bridge behind the Signal K
plugin contract:

  • config in:  one json line on stdin, {"type":"config","options":{...}}
  • control in: further stdin lines,    {"type":"cmd","deviceid","outlet","on"}
  • state out:  Signal K deltas on stdout, one json object per line, which
    index.js pipes straight into app.handleMessage. No MQTT, no broker.
  • status out: {"type":"status","message":"..."} on the same stdout, which
    index.js routes to setPluginStatus instead of handleMessage.

If mDNS has discovered a device on this network, LAN owns its state and
control; otherwise the cloud does. Discovery can UNDISCOVER. State is pushed
(mDNS + eWeLink WebSocket); a slow poll reconciles and fetches power/V/A; a
uiActive nudge streams live power.
"""
import sys, os, json, time, hashlib, hmac, base64, secrets, shutil, threading
import urllib.request, urllib.parse
# vendored deps beside this file (pip install --target vendor/) so the plugin
# survives a Signal K container recreation without touching the image
_vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
if os.path.isdir(_vendor):
    sys.path.insert(0, _vendor)

log = lambda *a: print(*a, file=sys.stderr, flush=True)

# Hard third-party deps are GUARDED: a missing one must not raise at import,
# because index.js would then respawn this worker every 5 s forever. Collect
# what is missing, degrade, and say so in the admin UI status line instead.
MISSING_DEPS = []          # [(pip name, error)]
try:
    from Crypto.Cipher import AES
except Exception as e:                      # ImportError, or a broken install
    AES = None
    MISSING_DEPS.append(("pycryptodome", str(e)))
try:
    from zeroconf import Zeroconf, ServiceBrowser
except Exception as e:
    Zeroconf = ServiceBrowser = None
    MISSING_DEPS.append(("zeroconf", str(e)))
try:                                        # optional: no push, poll still works
    import websocket
except Exception:
    websocket = None

_HERE = os.path.dirname(os.path.abspath(__file__))

def _data_dir():
    # index.js passes the Signal K plugin data dir in the environment, and it is
    # OUTSIDE the plugin install — writing tokens beside plugin.py meant
    # re-authorising after every upgrade. Fall back to the old location only if
    # that dir is unusable.
    d = os.environ.get("SIGNALK_EWELINK_DATA")
    if d:
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".writetest")
            with open(probe, "w") as f:
                f.write("")
            os.remove(probe)
            return d
        except OSError as e:
            log(f"data dir {d} not usable ({e}) — falling back beside the plugin")
    return _HERE

DATA_DIR = _data_dir()

def _migrate(name):
    """Carry a pre-1.0.4 file from beside the plugin into the data dir once."""
    new = os.path.join(DATA_DIR, name)
    old = os.path.join(_HERE, name)
    if DATA_DIR != _HERE and os.path.exists(old) and not os.path.exists(new):
        try:
            shutil.copyfile(old, new)
            os.chmod(new, 0o600)
            log(f"migrated {name} into {DATA_DIR}")
        except OSError as e:
            log(f"could not migrate {name}: {e}")
    return new

def _write_json(path, obj, mode=None):
    """Atomic json write. Returns False (and logs) instead of raising. `mode` is
    applied at CREATE time, so a secrets file is never briefly world-readable."""
    tmp = path + ".tmp"
    try:
        if mode:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f)
            os.chmod(tmp, mode)     # a stale tmp may predate the mode
        else:
            with open(tmp, "w") as f:
                json.dump(obj, f)
        os.replace(tmp, path)
        return True
    except (OSError, ValueError, TypeError) as e:
        log(f"{os.path.basename(path)} write failed: {e}")
        try:
            os.remove(tmp)          # never leave a half-written tmp behind
        except OSError:
            pass
        return False

def _read_json(path, default=None):
    """Load json, degrading to `default` on missing/unreadable/corrupt rather
    than raising — a fresh install simply has no state files yet."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default              # first run; not an error
    except (OSError, ValueError, UnicodeDecodeError) as e:
        log(f"{os.path.basename(path)} unreadable ({e}) — ignoring it")
        return default

_out = threading.Lock()   # emit() runs from LAN, poll, push and stdin threads
def emit(obj):
    line = json.dumps(obj)
    with _out:
        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            os._exit(0)   # Signal K is gone — same contract as stdin EOF

def sk(values):
    """[(path, value), ...] -> one Signal K delta on stdout."""
    emit({"updates": [{"values": [{"path": p, "value": v} for p, v in values]}]})

_last_status = [None]
def status(message):
    if message != _last_status[0]:          # may run every cycle; emit on change
        _last_status[0] = message
        emit({"type": "status", "message": message})

def _missing_deps_status():
    names = [n for n, _ in MISSING_DEPS]
    mods = (f"module '{names[0]}'" if len(names) == 1
            else "modules " + ", ".join(f"'{n}'" for n in names))
    verb = "is" if len(names) == 1 else "are"
    return (f"Python {mods} {verb} not installed for this python3 — "
            f"run: python3 -m pip install {' '.join(names)}  "
            "(see the plugin README)")

# ── module state + config ────────────────────────────────────────────────────

CFG = {}
DEVICES = {}          # deviceid -> {id,key,kind,base,channels,name}
KEYS = {}             # deviceid -> devicekey, AUTO-fetched from the cloud + cached
BRIDGE = None         # the device object, once main() has built it
DISCOVERED = _migrate("discovered.json")   # device list for the config dropdown
KEYCACHE = _migrate("_keycache.json")      # devicekeys, so LAN works offline
TOKENS = _migrate("_tokens.json")          # OAuth access/refresh tokens
_disc = {}            # everything the account/network shows, for the config page
MULTI_UIIDS = {2, 3, 4, 7, 8, 9, 29, 30, 31, 41, 77, 78, 112, 126, 140}  # multi-relay

def write_discovered():
    _write_json(DISCOVERED, _disc)

def load_config(options):
    global CFG, DEVICES, KEYS
    CFG = options or {}
    # devicekeys are AUTO-fetched from the cloud thinglist and cached here, so
    # there is no keys file and LAN keeps working offline. A missing cache on a
    # fresh install is normal — the next cloud poll refills it.
    KEYS = _read_json(KEYCACHE, {})
    if not isinstance(KEYS, dict):
        log("devicekey cache malformed — refetching from the cloud")
        KEYS = {}
    DEVICES = {}
    for d in CFG.get("devices", []) or []:
        did = (d.get("id") or "").strip()
        base = (d.get("basePath") or "").strip()
        if not did or not base:
            log("ignoring a device entry with no device or no Signal K path")
            continue
        DEVICES[did] = {
            "id": did, "key": KEYS.get(did, ""),
            "kind": d.get("kind", "single"), "base": base,
            "channels": int(d.get("channels") or 4), "name": d.get("name", did)}

# ── cloud auth (OAuth2.0) ────────────────────────────────────────────────────

# eWeLink demands the redirect target match the one registered against the app
# at dev.ewelink.cc; the Signal K server's own address is the useful default.
DEFAULT_REDIRECT = "http://localhost:3000/"

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
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

class CloudAuth:
    REFRESH_MARGIN_MS = 24 * 3600 * 1000

    def __init__(self):
        self.tok = None
        self._lock = threading.Lock()   # refresh runs from main + WS + stdin threads
        self.file = CFG.get("oauth", {}).get("tokenFile") or TOKENS
        self.tok = _read_json(self.file)   # absent on a first run; authorise() creates it
        if self.tok:
            log(f"loaded OAuth tokens from {self.file}")

    def save(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.file)), exist_ok=True)
        except OSError:
            pass
        return _write_json(self.file, self.tok, 0o600)   # tokens are secrets

    # eWeLink OAuth2.0 is a browser redirect flow, so it cannot run headless:
    # the user visits login_url() once and pastes the ?code=… back into the
    # config. We trade it for tokens ONCE; refresh() keeps them alive after that.

    def login_url(self):
        o = CFG.get("oauth", {})
        appid, secret = o.get("appId", ""), o.get("appSecret", "")
        if not (appid and secret):
            return None
        seq = str(int(time.time() * 1000))
        sign = base64.b64encode(hmac.new(secret.encode(), f"{appid}_{seq}".encode(),
                                         hashlib.sha256).digest()).decode()
        return "https://c2ccdn.coolkit.cc/oauth/index.html?" + urllib.parse.urlencode({
            "clientId": appid, "seq": seq, "authorization": sign,
            "redirectUrl": o.get("redirectUrl") or DEFAULT_REDIRECT,
            "nonce": secrets.token_hex(4), "grantType": "authorization_code",
            "state": "signalk"})

    def exchange(self, code):
        o = CFG.get("oauth", {})
        region = o.get("region", "eu")
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/user/oauth/token", body={
                "clientId": o.get("appId", ""), "clientSecret": o.get("appSecret", ""),
                "grantType": "authorization_code", "code": code,
                "redirectUrl": o.get("redirectUrl") or DEFAULT_REDIRECT})
        except (OSError, ValueError) as e:
            log(f"OAuth code exchange failed: {e}")
            return False
        if d.get("error"):
            log(f"OAuth code exchange refused ({d.get('error')} {d.get('msg', '')}) — "
                "an authorisation code is single-use and expires within minutes, "
                "and the Redirect URL must match the one registered at dev.ewelink.cc")
            return False
        data = d.get("data") or {}
        if not data.get("accessToken"):
            log("OAuth code exchange returned no access token")
            return False
        now = int(time.time() * 1000)
        self.tok = {"at": data["accessToken"], "rt": data.get("refreshToken"),
                    "atExpiredTime": data.get("atExpiredTime") or now + 30 * 86400 * 1000,
                    "rtExpiredTime": data.get("rtExpiredTime") or now + 60 * 86400 * 1000,
                    "region": region}
        self.save()
        log(f"OAuth authorised — tokens saved to {self.file}")
        return True

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
            # eWeLink ROTATES the refresh token, so re-check under the lock: a
            # second thread may already have refreshed and ours would be stale
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
            except (OSError, ValueError, KeyError, TypeError) as e:
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
        except (UnicodeDecodeError, AttributeError):
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
        # self.lan, self.last and the per-device cfg dicts are touched by FOUR
        # threads: the mDNS callbacks, the main poll loop, the WebSocket reader
        # and stdin control. Reentrant because the publishers nest.
        self.lock = threading.RLock()

    def lan_active(self, did):
        with self.lock:
            return bool(self.lan.get(did, {}).get("addr"))

    def _undiscover(self, did, why):
        with self.lock:
            st = self.lan[did]
            if st["addr"]:
                log(f"LAN lost {DEVICES[did]['base']} ({why}) — cloud resumes")
            st.update(addr=None, port=None, miss=0)

    def _match(self, info):
        if not info:
            return None
        did = _props(info).get("id")
        try:
            addrs = info.parsed_addresses()
        except Exception:
            addrs = []
        cfg = DEVICES.get(did)
        with self.lock:
            # record ANY eWeLink device seen on the LAN for the config page, even
            # one not yet configured — id + ip is enough to offer it
            if did and addrs and _disc.get(did, {}).get("ip") != addrs[0]:
                _disc.setdefault(did, {"name": did}).update(ip=addrs[0], source="lan")
                write_discovered()
            if cfg and addrs:
                self.lan[cfg["id"]].update(addr=addrs[0], port=info.port, miss=0)
        return cfg

    def add_service(self, zc, type_, name):    self._seen(name)
    def update_service(self, zc, type_, name): self._seen(name)

    def remove_service(self, zc, type_, name):
        with self.lock:
            gone = [did for did, st in self.lan.items() if st["name"] == name]
        for did in gone:
            self._undiscover(did, "mDNS goodbye")

    def _seen(self, name):
        info = self.zc.get_service_info("_ewelink._tcp.local.", name, timeout=2000)
        cfg = self._match(info)
        if cfg:
            with self.lock:
                st = self.lan[cfg["id"]]
                if not st["name"]:
                    log(f"LAN discovered {cfg['base']} at {st['addr']}")
                st["name"] = name
            self._lan_state(info, cfg)

    def lan_poll(self):
        # snapshot the work list: get_service_info blocks on the network for up to
        # two seconds per device and must never hold the state lock while it does
        with self.lock:
            targets = [(did, st["name"]) for did, st in self.lan.items() if st["name"]]
        for did, name in targets:
            info = self.zc.get_service_info("_ewelink._tcp.local.", name, timeout=2000)
            cfg = self._match(info)
            if cfg:
                self._lan_state(info, cfg)
                continue
            with self.lock:
                st = self.lan.get(did) or {}
                if st.get("addr"):
                    st["miss"] += 1
                    miss = st["miss"]
                else:
                    miss = 0
            if miss >= LAN_MISS_LIMIT:
                self._undiscover(did, f"{LAN_MISS_LIMIT} poll misses")

    def _lan_state(self, info, cfg):
        props = _props(info)
        with self.lock:
            if not cfg.get("key"):
                if not cfg.get("_warned_nokey"):
                    log(f"{cfg['base']}: no devicekey — LAN disabled for it (cloud only)")
                    cfg["_warned_nokey"] = True
                return
            try:
                p = decrypt(props, cfg["key"]) if props.get("encrypt") in ("true", True) else {}
            except Exception as e:      # any malformed packet is skipped, never fatal
                log(f"decrypt failed: {e}"); return
            self.publish_state(cfg, p, online=True, source="LAN")

    # -- the one publisher: device params -> Signal K deltas ----------------
    def publish_state(self, cfg, p, online, source):
        # under the lock: self.last and the cfg meter flag are read-then-written,
        # and the delta must not interleave with a newer one from another thread
        with self.lock:
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
                # null the paths so .state does not read stale after a device drops
                vals = [(f"{base}.state", None)]
                if cfg.get("_meter"):
                    vals += [(f"{base}.power", None), (f"{base}.voltage", None),
                             (f"{base}.current", None)]
                sk(vals)
                return
            vals = []
            if source != "LAN":              # power/V/A freeze on LAN, so cloud only
                for k in ("power", "voltage", "current"):
                    if k in p:
                        try:
                            vals.append((f"{base}.{k}", float(p[k])))
                        except (TypeError, ValueError):
                            pass
                if vals:
                    cfg["_meter"] = True
            if "switch" in p and (source == "LAN" or not self.lan.get(cfg["id"], {}).get("addr")):
                vals.append((f"{base}.state", 1 if p["switch"] == "on" else 0))
            if vals:
                sk(vals)
                log(f"{source} {base}: {dict(vals)}")

    # -- control: discovery decides -----------------------------------------
    def control(self, cfg, params):
        # LAN when discovered, but a LAN FAILURE FALLS THROUGH to the cloud
        # rather than losing the command (the discovery race: lan_active() true,
        # then undiscovered before the request). A dropped switch is never ok.
        # The routing decision is a SNAPSHOT taken under the lock, so mDNS
        # cannot undiscover the device between the test and the request.
        with self.lock:
            st = dict(self.lan.get(cfg["id"]) or {})
            key = cfg.get("key")
        if st.get("addr"):
            endpoint = "switches" if cfg["kind"] == "multi" else "switch"
            iv_b64, data_b64 = encrypt(params, key)
            body = json.dumps({
                "sequence": str(int(time.time() * 1000)), "deviceid": cfg["id"],
                "selfApikey": "123", "iv": iv_b64, "encrypt": True, "data": data_b64,
            }).encode()
            try:
                req = urllib.request.Request(
                    f"http://{st['addr']}:{st['port']}/zeroconf/{endpoint}",
                    data=body, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    resp = json.loads(r.read())
                if resp.get("error") == 0:
                    log(f"LAN control {cfg['base']} {params} -> ok")
                    self.lan_poll()
                    return
                log(f"LAN control {cfg['base']} -> {resp}; trying cloud")
            except (OSError, ValueError) as e:
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
        except (OSError, ValueError) as e:
            log(f"cloud control {cfg['base']} FAILED: {e}")

    # -- cloud reconcile poll -----------------------------------------------
    def cloud_poll(self, _retry=True):
        creds = self.auth.credentials()
        if not creds:
            return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing", bearer=at, appid=appid)
        except (OSError, ValueError) as e:
            log(f"cloud poll failed: {e}"); self._cloud_fail(); return
        if d.get("error"):
            if d["error"] in (401, 402) and _retry and self.auth.invalidate():
                return self.cloud_poll(_retry=False)
            log(f"cloud error {d.get('error')} {d.get('msg', '')}"); self._cloud_fail(); return
        seen = changed = False
        for t in (d.get("data") or {}).get("thingList") or []:
            it = t.get("itemData", {})
            did = it.get("deviceid")
            cfg = DEVICES.get(did)
            with self.lock:
                if did:
                    uiid = ((it.get("extra") or {}).get("uiid")
                            or (it.get("itemType") if isinstance(it.get("itemType"), int) else None))
                    kind = "multi" if uiid in MULTI_UIIDS else "single"
                    pr = it.get("params") or {}
                    chans = len(pr.get("switches") or []) or (4 if kind == "multi" else 1)
                    rec = {**_disc.get(did, {}),
                           "name": it.get("name") or did, "model": it.get("productModel") or "",
                           "kind": kind, "channels": chans, "online": bool(it.get("online")),
                           "source": "cloud"}
                    if _disc.get(did) != rec:
                        _disc[did] = rec; changed = True
                if not cfg:
                    continue
                seen = True
                if it.get("apikey"):
                    self.apikey = it["apikey"]
                # AUTO-KEY: the cloud hands us every devicekey — fill it in and
                # cache it (0600) so there is no keys file and LAN works offline
                dk = it.get("devicekey")
                if dk and cfg.get("key") != dk:
                    cfg["key"] = dk
                    KEYS[did] = dk
                    if _write_json(KEYCACHE, KEYS, 0o600):
                        log(f"cached devicekey for {cfg['base']}")
                lan_owns = cfg["kind"] == "multi" and bool(self.lan.get(cfg["id"], {}).get("addr"))
            if lan_owns:
                continue
            self.publish_state(cfg, it.get("params") or {},
                               online=bool(it.get("online")), source="poll")
        if changed:
            with self.lock:
                write_discovered()
        # a successful poll that simply contained none of OUR devices is NOT a
        # transport failure — do not count it toward clearing retained readings
        if seen:
            with self.lock:
                self.cloud_fails = 0

    def _cloud_fail(self):
        with self.lock:
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
        try:
            ws.send(json.dumps({
                "action": "userOnline", "at": at, "apikey": self.bridge.apikey or "",
                "appid": appid, "nonce": secrets.token_hex(4), "ts": int(time.time()),
                "userAgent": "app", "sequence": str(int(time.time() * 1000)), "version": 8}))
            hello = json.loads(ws.recv())
            if hello.get("error") not in (0, None):
                raise OSError(f"handshake refused: {hello.get('error')}")
        except Exception:
            ws.close()      # never leak the socket on a half-open handshake
            raise
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
            up = 0.0
            try:
                got = self._connect()
                if not got:
                    time.sleep(60); continue
                ws, hb = got
                up = time.time()
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
                if ws:
                    try: ws.close()
                    except Exception: pass
                # only a connection that actually HELD resets the backoff — a
                # flapping link keeps escalating instead of retrying every 5s
                if up and time.time() - up >= 60:
                    backoff = 5
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

def stdin_loop():
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") != "cmd":
                    continue
                cfg = DEVICES.get(msg.get("deviceid"))
                if not (cfg and BRIDGE):
                    continue
                on = bool(msg.get("on"))
                if cfg["kind"] == "multi":
                    ch = int(msg.get("outlet") or 1)
                    BRIDGE.control(cfg, {"switches": [{"switch": "on" if on else "off", "outlet": ch - 1}]})
                else:
                    BRIDGE.control(cfg, {"switch": "on" if on else "off"})
            except Exception as e:      # a bad control line must not kill the reader
                log(f"control line error: {e}")
    except Exception as e:
        log(f"stdin read failed: {e}")
    os._exit(0)     # stdin closed = Signal K is gone; do not orphan the worker

def main():
    global BRIDGE
    first = sys.stdin.readline()        # the first line is the config; block for it
    if not first:                       # Signal K closed stdin before sending config
        return
    try:
        msg = json.loads(first)
        load_config(msg.get("options") or {})
    except Exception as e:
        log(f"bad config line: {e}")
        status("Could not read the plugin configuration — see the server log")
        return
    log(f"state directory: {DATA_DIR}")

    if MISSING_DEPS:
        # exiting here would just make index.js respawn us every 5 s forever
        for name, err in MISSING_DEPS:
            log(f"{name} is not importable: {err}")
        status(_missing_deps_status())
        threading.Thread(target=stdin_loop, daemon=True).start()
        while True:
            time.sleep(3600)

    auth = CloudAuth()
    o = CFG.get("oauth", {})

    # a fresh install has nothing — say exactly what is missing; the plugin
    # stays up either way, it just has less to do
    code = (o.get("code") or "").strip()
    if code and not auth.credentials():
        auth.exchange(code)
    if not (o.get("appId") and o.get("appSecret")):
        status("No eWeLink credentials — enter App ID and App secret (dev.ewelink.cc) in the plugin config")
        log("no appId/appSecret configured — cloud disabled. Create an app at "
            "dev.ewelink.cc and enter its App ID and App secret in the plugin config.")
    elif not auth.credentials():
        url = auth.login_url()
        status("Not authorised — open the eWeLink login URL from the server log, then paste the code into the config")
        log("appId/appSecret set but NOT AUTHORISED YET. Open this URL in a browser, "
            "log in to eWeLink, then copy the ?code=… value off the address bar you "
            "land on and paste it into the plugin config's 'Authorisation code' field:")
        log(url or "(cannot build the login URL without appId and appSecret)")

    zc = Zeroconf()
    try:
        bridge = BRIDGE = Bridge(zc, auth)
        ServiceBrowser(zc, "_ewelink._tcp.local.", bridge)   # mDNS discovery always on

        if auth.credentials():
            log(f"cloud: reconcile every {CFG.get('cloudIntervalS', 60)}s + push")
            bridge.cloud_poll()
            CloudWS(auth, bridge).start()
            status(f"{len(DEVICES)} device(s), LAN-first" if DEVICES
                   else "Connected — now pick your devices in the plugin config")
        else:
            log("no cloud credentials — LAN-discovered devices only")

        threading.Thread(target=stdin_loop, daemon=True).start()

        interval = int(CFG.get("cloudIntervalS", 60))
        n = 0
        while True:
            time.sleep(LAN_POLL_S)
            # a transient zeroconf/network fault must cost one poll, not the
            # worker: index.js would respawn us and we would lose all LAN state
            try:
                bridge.lan_poll()
            except Exception as e:
                log(f"LAN poll failed: {type(e).__name__}: {e}")
            n += 1
            if (n * LAN_POLL_S) % interval < LAN_POLL_S:
                try:
                    bridge.cloud_poll()
                except Exception as e:
                    log(f"cloud poll failed: {type(e).__name__}: {e}")
    finally:
        zc.close()

if __name__ == "__main__":
    main()
