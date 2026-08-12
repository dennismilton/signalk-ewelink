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

  plugin.id = 'signalk-ewelink'
  plugin.name = 'eWeLink / Sonoff'
  plugin.description =
    'eWeLink/Sonoff devices as native Signal K — LAN-first with cloud fallback, ' +
    'push (WebSocket) not poll, live power streaming. No MQTT.'

  // schema is a function so the Device dropdown lists what discovery found.
  plugin.schema = function () {
    let disc = {}
    try { disc = JSON.parse(fs.readFileSync(path.join(__dirname, 'discovered.json'))) } catch (e) {}
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
      required: ['devices'],
      properties: {
        oauth: {
          type: 'object',
          title: 'eWeLink cloud (OAuth2.0)',
          properties: {
            appId: { type: 'string', title: 'App ID' },
            appSecret: { type: 'string', title: 'App secret', format: 'password' },
            region: { type: 'string', title: 'Region', default: 'eu',
              enum: ['eu', 'us', 'as', 'cn'] }
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
  const lastErr = []                     // ring buffer of recent stderr, for exit reporting

  const spawnChild = (options) => {
    const pyBin = (options && options.pythonPath) || 'python3'
    child = spawn(pyBin, ['-u', path.join(__dirname, 'plugin.py')], { cwd: __dirname })
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
        try { app.handleMessage(plugin.id, JSON.parse(line)) } catch (e) {
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
      if (stopping) return
      app.error('plugin.py exited (' + code + '): ' + lastErr.join(' | '))
      app.setPluginError && app.setPluginError('plugin.py exited ' + code)
      // respawn with a fixed backoff — never a tight restart loop
      setTimeout(() => { if (!stopping) { spawnChild(options); send({ type: 'config', options }) } }, 5000)
    })
    send({ type: 'config', options })
  }

  plugin.start = function (options) {
    stopping = false
    devices = options.devices || []
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
    app.setPluginStatus && app.setPluginStatus(`${devices.length} device(s), LAN-first`)
  }

  plugin.stop = function () {
    stopping = true
    if (child) { try { child.kill() } catch (e) {} child = null }
    app.setPluginStatus && app.setPluginStatus('stopped')
  }

  return plugin
}
