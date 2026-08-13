// signalk-ewelink — the Node scaffolding around a Python bridge.
//
// This file is deliberately thin (the "index.js + plugin.py" pattern from the
// official sk-plugin-python-demo). It does three things and nothing else:
//   1. spawn plugin.py and hand it the saved config on stdin;
//   2. pipe the child's stdout — one Signal K delta JSON per line — straight
//      into app.handleMessage, so device state becomes Signal K paths with no
//      MQTT, no broker, no mapping plugin;
//   3. register a PUT handler per controllable path and forward each command
//      down the child's stdin — which is the entire job the old external
//      `signalk-powr3-control` plugin did, now folded into the one plugin that
//      owns the device.
//
// All eWeLink logic — LAN AES + mDNS discovery, OAuth, the cloud WebSocket push,
// uiActive power streaming, discovery-decides routing — lives in plugin.py,
// proven on the water before this wrapper existed.
const { spawn } = require('child_process')
const path = require('path')
const fs = require('fs')

module.exports = function (app) {
  const plugin = {}
  let child = null
  let devices = []

  // Tokens, the devicekey cache and the discovery list belong OUTSIDE the plugin
  // install directory — anything written beside plugin.py is destroyed by the
  // next npm/appstore update, which used to mean re-authorising after every
  // upgrade. Signal K hands each plugin a durable data dir; older servers that
  // lack the call fall back to the install dir, which is the old behaviour.
  const dataDir = (() => {
    try {
      if (typeof app.getDataDirPath === 'function') {
        const d = app.getDataDirPath()
        if (d) { fs.mkdirSync(d, { recursive: true }); return d }
      }
    } catch (e) {
      app.error('plugin data dir unavailable (' + e.message + '); using the install dir')
    }
    return __dirname
  })()

  plugin.id = 'signalk-ewelink'
  plugin.name = 'eWeLink / Sonoff'
  plugin.description =
    'eWeLink/Sonoff devices as native Signal K — LAN-first with cloud fallback, ' +
    'push (WebSocket) not poll, live power streaming. No MQTT.'

  // schema is a function so the Device dropdown lists what discovery found.
  plugin.schema = function () {
    let disc = {}
    // data dir first; the install dir is only the pre-1.0.4 fallback
    for (const dir of [dataDir, __dirname]) {
      try {
        disc = JSON.parse(fs.readFileSync(path.join(dir, 'discovered.json')))
        break
      } catch (e) {}
    }
    const ids = Object.keys(disc)
    const idField = { type: 'string', title: 'Device' }
    if (ids.length) {
      idField.enum = ids
      idField.enumNames = ids.map((id) => {
        const d = disc[id]
        return `${d.name || id}${d.model ? ' · ' + d.model : ''}${d.kind === 'multi' ? ' (' + (d.channels || 4) + 'ch)' : ''}`
      })
    }
    return {
      type: 'object',
      // deliberately nothing required: a new user must be able to save their
      // credentials and authorise BEFORE any device exists to choose
      properties: {
        oauth: {
          type: 'object',
          title: 'eWeLink cloud (OAuth2.0)',
          description:
            'Create an app at dev.ewelink.cc to get an App ID and App secret. ' +
            'Save them here, then check the Signal K server log: it prints a ' +
            'login URL. Open it, sign in to eWeLink, and paste the code=… value ' +
            'from the address bar you land on into "Authorisation code" below. ' +
            'That is a one-time step — the tokens are then kept and refreshed ' +
            'automatically, and survive plugin upgrades.',
          properties: {
            appId: { type: 'string', title: 'App ID' },
            appSecret: { type: 'string', title: 'App secret', format: 'password' },
            region: { type: 'string', title: 'Region', default: 'eu',
              enum: ['eu', 'us', 'as', 'cn'] },
            redirectUrl: { type: 'string', title: 'Redirect URL',
              default: 'http://localhost:3000/',
              description: 'Must match the redirect URL registered for your app at dev.ewelink.cc.' },
            code: { type: 'string', title: 'Authorisation code',
              description: 'One-time code from the login redirect. Used once, then it can be cleared.' },
            tokenFile: { type: 'string', title: 'Token file (optional)',
              description: 'Leave empty to store tokens in the Signal K plugin data directory (recommended).' }
          }
        },
        devices: {
          type: 'array',
          title: 'Devices',
          items: {
            type: 'object',
            required: ['id', 'kind', 'basePath'],
            properties: {
              id: idField,
              kind: { type: 'string', title: 'Kind', default: 'single',
                enum: ['single', 'multi'] },
              channels: { type: 'number', title: 'Channels', default: 4 },
              basePath: { type: 'string', title: 'Signal K path' }
            }
          }
        }
      }
    }
  }

  // paths this device exposes for control, so start() can registerPutHandler
  const putPaths = (d) => {
    if (d.kind === 'multi') {
      const n = d.channels || 4
      return Array.from({ length: n }, (_, i) => ({
        path: `${d.basePath}.ch${i + 1}.state`, deviceid: d.id, outlet: i + 1
      }))
    }
    return [{ path: `${d.basePath}.state`, deviceid: d.id, outlet: null }]
  }

  // a command reaches the child only if the child is alive; the boolean says so,
  // so the PUT handler can report FAILURE instead of a false COMPLETED.
  const send = (obj) => {
    if (!child || !child.stdin || !child.stdin.writable) return false
    try { child.stdin.write(JSON.stringify(obj) + '\n'); return true } catch (e) {
      app.error('write to plugin.py failed: ' + e.message); return false
    }
  }

  let stopping = false
  let gen = 0
  const lastErr = []                     // ring buffer of recent stderr, for exit reporting

  const spawnChild = (options) => {
    const pyBin = (options && options.pythonPath) || 'python3'
    if (child) { try { child.kill() } catch (e) {} }     // never leak a prior worker
    const myGen = ++gen
    child = spawn(pyBin, ['-u', path.join(__dirname, 'plugin.py')], {
      cwd: __dirname,
      env: Object.assign({}, process.env, { SIGNALK_EWELINK_DATA: dataDir })
    })
    child.stdin.on('error', (e) => app.error('plugin.py stdin: ' + e.message))

    // FRAME BY NEWLINE ACROSS CHUNKS. A delta split over two 'data' events must
    // not parse as two broken fragments — keep the partial tail as a remainder.
    let buf = ''
    child.stdout.on('data', (chunk) => {
      buf += chunk.toString()
      let nl
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1)
        if (!line) continue
        let msg
        try { msg = JSON.parse(line) } catch (e) {
          app.error('bad delta from plugin.py: ' + e.message); continue
        }
        // the worker knows what is actually missing (credentials, authorisation,
        // devices) — let it own the admin UI status line rather than guessing here
        if (msg && msg.type === 'status') {
          app.setPluginStatus && app.setPluginStatus(msg.message)
          continue
        }
        try { app.handleMessage(plugin.id, msg) } catch (e) {
          app.error('bad delta from plugin.py: ' + e.message)
        }
      }
    })
    child.stderr.on('data', (chunk) => {
      const s = chunk.toString().trimEnd()
      app.debug(s)
      lastErr.push(s); while (lastErr.length > 5) lastErr.shift()
    })
    child.on('error', (e) => app.error('plugin.py spawn error: ' + e.message))
    child.on('exit', (code) => {
      // stopping = intentional; myGen !== gen = a newer child already replaced
      // this one (a normal Signal K restart on config save). Neither is a crash.
      if (stopping || myGen !== gen) return
      app.error('plugin.py exited (' + code + '): ' + lastErr.join(' | '))
      app.setPluginError && app.setPluginError('plugin.py exited ' + code)
      setTimeout(() => { if (!stopping && myGen === gen) { spawnChild(options); send({ type: 'config', options }) } }, 5000)
    })
    send({ type: 'config', options })
  }

  plugin.start = function (options) {
    stopping = false
    options = options || {}                 // enabled with nothing configured yet
    // a half-filled row in the config UI must not register a handler on
    // "undefined.state" — drop it here and say so
    const all = options.devices || []
    devices = all.filter((d) => d && d.id && d.basePath)
    for (let i = devices.length; i < all.length; i++) {
      app.error('device entry ignored: both a Device and a Signal K path are required')
    }
    spawnChild(options)

    for (const d of devices) {
      for (const p of putPaths(d)) {
        app.registerPutHandler('vessels.self', p.path, (ctx, pth, value, cb) => {
          const on = value === 1 || value === '1' || value === true ||
            value === 'on' || value === 'ON'
          // dispatched to the child (LAN or cloud) — the confirmed state returns
          // as a delta. FAILURE only when the worker is not there to take it.
          if (send({ type: 'cmd', deviceid: p.deviceid, outlet: p.outlet, on })) {
            return { state: 'COMPLETED', statusCode: 200 }
          }
          return { state: 'FAILURE', statusCode: 502,
            message: 'eWeLink worker not running' }
        }, plugin.id)
      }
    }
    // a starting point only; plugin.py replaces this with what is really missing
    app.setPluginStatus && app.setPluginStatus(devices.length
      ? `${devices.length} device(s), LAN-first`
      : 'No devices configured yet')
  }

  plugin.stop = function () {
    stopping = true
    if (child) { try { child.kill() } catch (e) {} child = null }
    app.setPluginStatus && app.setPluginStatus('stopped')
  }

  return plugin
}
