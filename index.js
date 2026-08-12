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

module.exports = function (app) {
  const plugin = {}
  let child = null
  let devices = []

  plugin.id = 'signalk-ewelink'
  plugin.name = 'eWeLink / Sonoff'
  plugin.description =
    'eWeLink/Sonoff devices as native Signal K — LAN-first with cloud fallback, ' +
    'push (WebSocket) not poll, live power streaming. No MQTT.'

  plugin.schema = {
    type: 'object',
    required: ['devices'],
    properties: {
      keysFile: {
        type: 'string',
        title: 'Device keys file',
        description:
          'Path to a JSON file of { deviceId: devicekey }. Kept out of this ' +
          'config so the secret localKeys are not stored in plaintext. Get a ' +
          "devicekey once from the cloud device list.",
        default: '/data/ewelink_keys.json'
      },
      oauth: {
        type: 'object',
        title: 'eWeLink cloud (OAuth2.0) — for power readings and cloud fallback',
        properties: {
          appId: { type: 'string', title: 'App ID (dev.ewelink.cc)' },
          appSecret: { type: 'string', title: 'App secret' },
          region: { type: 'string', title: 'Region', default: 'eu',
            enum: ['eu', 'us', 'as', 'cn'] },
          tokenFile: { type: 'string', title: 'OAuth token store',
            default: '/data/ewelink_tokens.json' }
        }
      },
      devices: {
        type: 'array',
        title: 'Devices',
        items: {
          type: 'object',
          required: ['id', 'kind', 'basePath'],
          properties: {
            id: { type: 'string', title: 'Device ID' },
            name: { type: 'string', title: 'Name (for logs)' },
            kind: { type: 'string', title: 'Kind', default: 'single',
              enum: ['single', 'multi'] },
            channels: { type: 'number', title: 'Channels (multi only)', default: 4 },
            basePath: {
              type: 'string',
              title: 'Signal K base path',
              description:
                'single → basePath.state/.power/.voltage/.current; ' +
                'multi → basePath.chN.state + basePath.online'
            }
          }
        }
      },
      cloudIntervalS: { type: 'number', title: 'Cloud reconcile poll (s)', default: 60 },
      uiActiveS: { type: 'number', title: 'Live-power nudge interval (s)', default: 110 }
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

  const send = (obj) => {
    if (child && child.stdin.writable) child.stdin.write(JSON.stringify(obj) + '\n')
  }

  plugin.start = function (options) {
    devices = options.devices || []

    child = spawn('python3', ['-u', path.join(__dirname, 'plugin.py')], {
      cwd: __dirname
    })
    child.stdout.on('data', (buf) => {
      buf.toString().split(/\r?\n/).forEach((line) => {
        if (!line) return
        try {
          app.handleMessage(plugin.id, JSON.parse(line))
        } catch (e) {
          app.error('bad delta from plugin.py: ' + e.message + ' :: ' + line)
        }
      })
    })
    child.stderr.on('data', (buf) => app.debug(buf.toString().trimEnd()))
    child.on('error', (e) => app.error('plugin.py spawn error: ' + e.message))
    child.on('exit', (code) =>
      app.setPluginError ? app.setPluginError('plugin.py exited ' + code) : null)

    // hand the child its config (it reads exactly one config line on start)
    send({ type: 'config', options })

    // one PUT handler per controllable path → forward to the child
    for (const d of devices) {
      for (const p of putPaths(d)) {
        app.registerPutHandler('vessels.self', p.path, (ctx, pth, value, cb) => {
          const on = value === 1 || value === '1' || value === true ||
            value === 'on' || value === 'ON'
          send({ type: 'cmd', deviceid: p.deviceid, outlet: p.outlet, on })
          // the confirmed state returns as a delta on the device's own cadence;
          // COMPLETED means the command was accepted and dispatched
          return { state: 'COMPLETED', statusCode: 200 }
        }, plugin.id)
      }
    }
    app.setPluginStatus &&
      app.setPluginStatus(`${devices.length} device(s), LAN-first`)
  }

  plugin.stop = function () {
    if (child) { try { child.kill() } catch (e) {} child = null }
  }

  return plugin
}
