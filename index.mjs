// dsh-github-guard — host plugin that keeps github.com reachable.
//
// Why this exists: on this machine the GitHub edge IPs a resolver hands out are
// routinely blackholed, and the reachable edge rotates every few minutes. The
// browser cannot pick a better edge, so something has to rewrite the hosts pins.
//
// Split of responsibilities:
//   * this plugin (non-elevated, inside the DSH host process) watches for GitHub
//     traffic, probes the candidate edges over TCP+TLS and decides which edge to
//     use. Node/OpenSSL can do TLS here; Schannel on this machine cannot.
//   * a tiny native helper runs as SYSTEM (installed once with UAC) and owns the
//     only privileged step: editing C:\Windows\System32\drivers\etc\hosts.
//
// The plugin never starts elevated work on its own and never touches files outside
// its own log ring; it only asks the helper to pin an address.

import { spawn } from 'node:child_process'
import net from 'node:net'
import tls from 'node:tls'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-github-guard'
export const inject = ['webServer']

const ROUTE_PATH = '/github-guard'
const HELPER_PORT = 8898
const HELPER_EXE = 'C:\\ProgramData\\DSHGuard\\dsh-github-guard.exe'
const HELPER_TOKEN_FILE = 'C:\\ProgramData\\DSHGuard\\token.txt'
const STATE_DIR = 'C:\\ProgramData\\DSHGuard'

const CANDIDATES = [
  '20.29.134.23', '140.82.114.3', '20.175.192.147', '20.217.135.5', '20.207.73.82',
  '140.82.112.3', '140.82.113.3', '140.82.116.3', '140.82.121.3', '20.27.177.113',
  '57.155.223.240', '20.6.7.17', '20.200.245.247', '4.237.22.38', '20.205.243.166',
  '20.205.243.168', '20.201.28.151', '20.26.156.215', '20.248.137.48', '20.233.83.145',
  '20.199.39.232', '4.208.26.197', '20.10.167.104', '20.44.10.50', '20.112.250.133',
  '20.50.68.99', '20.3.94.102', '20.85.128.180', '20.26.4.66', '20.96.76.66',
  '40.71.233.224', '20.99.184.214', '20.97.60.58', '20.115.5.5', '20.76.103.246',
  '20.207.73.83', '20.199.39.233', '20.26.156.216', '20.233.83.146', '4.228.31.149',
]

const TCP_TIMEOUT_MS = 2500
const TLS_TIMEOUT_MS = 4000
const TCP_CONCURRENCY = 16
const TLS_CANDIDATES = 8
const TRIGGER_COOLDOWN_MS = 60_000
const QUIET_AFTER_PROBE_MS = 30_000

function packageDir() {
  return path.dirname(fileURLToPath(import.meta.url))
}

function bundledExe() {
  return path.join(packageDir(), 'native', 'dsh-github-guard.exe')
}

function detectorExe() {
  return fs.existsSync(HELPER_EXE) ? HELPER_EXE : bundledExe()
}

// ---------------------------------------------------------------- monitoring

function createState() {
  return {
    startedAt: new Date().toISOString(),
    detectorPid: null,
    detectorExe: null,
    lastEventAt: null,
    lastEventIp: null,
    lastProbeAt: null,
    lastProbeMs: null,
    lastPin: null,
    lastError: null,
    runs: 0,
    helper: 'unknown',
    log: [],
  }
}

function remember(state, line) {
  state.log.push(new Date().toISOString().slice(11, 19) + ' ' + line)
  if (state.log.length > 40) state.log.splice(0, state.log.length - 40)
}

// ------------------------------------------------------------------ probing

function tcpLatency(ip, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now()
    const socket = net.connect({ host: ip, port: 443 })
    const finish = (value) => {
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(timeoutMs, () => finish(null))
    socket.on('connect', () => finish(Date.now() - started))
    socket.on('error', () => finish(null))
  })
}

function tlsLatency(ip, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now()
    const socket = tls.connect(
      { host: ip, port: 443, servername: 'github.com', rejectUnauthorized: false },
      () => {
        socket.write('GET /login HTTP/1.1\r\nHost: github.com\r\nUser-Agent: dsh-github-guard\r\nConnection: close\r\n\r\n')
      },
    )
    let head = ''
    const finish = (value) => {
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(timeoutMs, () => finish(null))
    socket.on('data', (chunk) => {
      head += chunk.toString('latin1')
      if (!head.includes('\r\n')) return
      const status = Number(head.split(' ')[1])
      finish(status >= 200 && status < 400 ? Date.now() - started : null)
    })
    socket.on('error', () => finish(null))
  })
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length)
  let cursor = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++
      results[index] = await worker(items[index], index)
    }
  })
  await Promise.all(runners)
  return results
}

async function bestEdge() {
  const started = Date.now()
  const latencies = await mapLimit(CANDIDATES, TCP_CONCURRENCY, (ip) => tcpLatency(ip, TCP_TIMEOUT_MS))
  const reachable = CANDIDATES.map((ip, index) => ({ ip, ms: latencies[index] }))
    .filter((entry) => typeof entry.ms === 'number')
    .sort((left, right) => left.ms - right.ms)
    .slice(0, TLS_CANDIDATES)
  if (reachable.length === 0) {
    return { endpoint: null, elapsed: Date.now() - started, tcp: 0, tls: 0, detail: 'no candidate answered on 443' }
  }
  const verified = await mapLimit(reachable, 4, async (entry) => {
    const ms = await tlsLatency(entry.ip, TLS_TIMEOUT_MS)
    return ms === null ? null : { ip: entry.ip, ms }
  })
  const alive = verified.filter(Boolean).sort((left, right) => left.ms - right.ms)
  return {
    endpoint: alive[0] ?? null,
    elapsed: Date.now() - started,
    tcp: latencies.filter((ms) => typeof ms === 'number').length,
    tls: alive.length,
    detail: alive.length === 0 ? 'none of the reachable edges completed a TLS handshake with 200' : null,
  }
}

// -------------------------------------------------------------- helper pipe

function helperToken() {
  try {
    return fs.readFileSync(HELPER_TOKEN_FILE, 'utf8').trim()
  } catch {
    return ''
  }
}

function askHelper(commands, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const token = helperToken()
    const lines = token.length > 0 ? ['AUTH ' + token, ...commands] : commands
    const socket = net.connect({ host: '127.0.0.1', port: HELPER_PORT })
    const replies = []
    let buffer = ''
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      socket.removeAllListeners()
      socket.destroy()
      resolve({ replies, ...value })
    }
    socket.setTimeout(timeoutMs, () => finish({ ok: false, error: 'helper timed out' }))
    socket.on('connect', () => socket.write(lines.join('\n') + '\n'))
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8')
      let index
      while ((index = buffer.indexOf('\n')) >= 0) {
        replies.push(buffer.slice(0, index).trim())
        buffer = buffer.slice(index + 1)
      }
      if (replies.length >= lines.length) {
        const last = replies[replies.length - 1]
        if (last.startsWith('OK ')) finish({ ok: true, value: last.slice(3) })
        else if (last.startsWith('PIN ')) finish({ ok: true, value: last })
        else finish({ ok: false, error: last, status: last })
      }
    })
    socket.on('error', (error) => finish({ ok: false, error: error.code || error.message }))
  })
}

async function helperStatus() {
  const answer = await askHelper(['status'])
  if (answer.replies.length === 0) return { state: 'down', error: answer.error }
  const last = answer.replies[answer.replies.length - 1]
  if (last.startsWith('PIN ')) {
    const pin = last.slice(4).trim()
    return { state: 'ok', pin: pin === '-' ? null : pin }
  }
  return { state: 'down', error: last }
}

// -------------------------------------------------------------------- plugin

export function apply(ctx) {
  const state = createState()
  let detector
  let disposed = false
  let lastTrigger = 0
  let quietUntil = 0
  let running = null

  const logger = typeof ctx.logger === 'function' ? ctx.logger('dsh-github-guard') : undefined
  const log = (line) => {
    remember(state, line)
    if (logger !== undefined) {
      if (typeof logger.info === 'function') logger.info(line)
    }
  }

  const refresh = async (reason) => {
    if (running !== null) return running
    running = (async () => {
      quietUntil = Date.now() + QUIET_AFTER_PROBE_MS
      state.lastProbeAt = new Date().toISOString()
      const probe = await bestEdge()
      state.lastProbeMs = probe.elapsed
      state.runs += 1
      if (probe.endpoint === null) {
        state.lastError = probe.detail
        log('probe found no usable edge (' + reason + ')')
        return { ok: false, reason, error: probe.detail }
      }
      const write = await askHelper(['pin ' + probe.endpoint.ip])
      if (write.ok) {
        state.lastPin = probe.endpoint.ip
        state.lastError = null
        state.helper = 'ok'
        log('pinned ' + probe.endpoint.ip + ' (' + probe.endpoint.ms + 'ms, ' + probe.elapsed + 'ms scan, ' + reason + ')')
        return { ok: true, ip: probe.endpoint.ip, reason }
      }
      state.helper = write.error === 'ECONNREFUSED' ? 'down' : state.helper
      state.lastError = write.error
      log('pin ' + probe.endpoint.ip + ' failed: ' + write.error)
      return { ok: false, reason, error: write.error, ip: probe.endpoint.ip }
    })().finally(() => {
      running = null
      quietUntil = Date.now() + QUIET_AFTER_PROBE_MS
    })
    return running
  }

  const startDetector = () => {
    const exe = detectorExe()
    state.detectorExe = exe
    if (!fs.existsSync(exe)) {
      log('detector missing at ' + exe)
      return
    }
    detector = spawn(exe, ['detect'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] })
    state.detectorPid = detector.pid ?? null
    log('detector started pid=' + state.detectorPid)
    let buffer = ''
    detector.stdout.setEncoding('utf8')
    detector.stdout.on('data', (chunk) => {
      buffer += chunk
      let index
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index).trim()
        buffer = buffer.slice(index + 1)
        if (!line.startsWith('EVENT ')) continue
        const ip = line.split(' ')[1]
        state.lastEventAt = new Date().toISOString()
        state.lastEventIp = ip
        if (Date.now() < quietUntil || Date.now() - lastTrigger < TRIGGER_COOLDOWN_MS) continue
        lastTrigger = Date.now()
        void refresh('traffic ' + ip)
      }
    })
    detector.on('exit', (code) => {
      state.detectorPid = null
      if (!disposed) log('detector exited rc=' + code)
    })
    detector.on('error', (error) => log('detector error: ' + error.message))
  }

  ctx.effect(() => {
    const disposeRoute = ctx.webServer.register({
      kind: 'exact',
      path: ROUTE_PATH,
      handler: async (request, response) => {
        const url = new URL(request.url ?? ROUTE_PATH, 'http://localhost')
        if (request.method === 'POST') {
          let body = ''
          for await (const chunk of request) body += chunk
          let action = 'refresh'
          try {
            action = JSON.parse(body || '{}').action ?? 'refresh'
          } catch {
            // ignore malformed bodies; refresh is the only supported action
          }
          if (action !== 'refresh') {
            response.writeHead(400, { 'content-type': 'application/json; charset=utf-8' })
            response.end(JSON.stringify({ error: 'action must be refresh' }))
            return
          }
          const result = await refresh('http')
          response.writeHead(result.ok ? 200 : 502, { 'content-type': 'application/json; charset=utf-8' })
          response.end(JSON.stringify(result))
          return
        }
        if (request.method !== 'GET') {
          response.writeHead(405, { 'content-type': 'application/json; charset=utf-8' })
          response.end(JSON.stringify({ error: 'method not allowed' }))
          return
        }
        const helper = url.searchParams.get('helper') === '0' ? { state: 'skipped' } : await helperStatus()
        state.helper = helper.state
        response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
        response.end(
          JSON.stringify({
            plugin: name,
            helper,
            detectorPid: state.detectorPid,
            detectorExe: state.detectorExe,
            lastEventAt: state.lastEventAt,
            lastEventIp: state.lastEventIp,
            lastProbeAt: state.lastProbeAt,
            lastProbeMs: state.lastProbeMs,
            lastPin: state.lastPin,
            lastError: state.lastError,
            runs: state.runs,
            startedAt: state.startedAt,
            log: state.log,
          }),
        )
      },
    })

    void refresh('startup')
    startDetector()

    return () => {
      disposed = true
      try {
        disposeRoute()
      } catch {
        // the webserver may already be gone during shutdown
      }
      if (detector !== undefined && detector.exitCode === null) {
        try {
          detector.kill()
        } catch {
          // best effort
        }
      }
    }
  })
}

// Exposed for the packaging script and for tests.
export const internals = { CANDIDATES, STATE_DIR, HELPER_EXE, HELPER_PORT, bestEdge, askHelper }
