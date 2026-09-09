'use strict'

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

/**
 * Client-side logging, matching the format the Rust components write so a
 * problem report can be read as one timeline.
 *
 * The same three rules apply here: a level filter, consecutive duplicates
 * collapsed into a count, and a size cap with one previous file kept. Nothing
 * that touches `safeStorage`, a node configuration, an enrollment token or the
 * service token is ever passed in.
 */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 }
const MAX_BYTES = 4 * 1024 * 1024
const REPEAT_WINDOW_MS = 30_000

let level = LEVELS.info
let logPath = null
let written = 0
let repeat = null
let mirrorToStderr = true

/** Matches the Rust side: everything lands in one directory. */
function defaultLogPath() {
  if (process.platform === 'win32') {
    const root = process.env.PROGRAMDATA || 'C:\\ProgramData'
    return path.join(root, 'GamePath', 'logs', 'client.log')
  }
  return path.join(os.homedir(), '.local', 'share', 'gamepath', 'client.log')
}

function init(targetPath = defaultLogPath(), { stderr = true } = {}) {
  mirrorToStderr = stderr
  const configured =
    LEVELS[
      String(process.env.GAMEPATH_LOG || '')
        .trim()
        .toLowerCase()
    ]
  if (configured !== undefined) level = configured
  try {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true })
    logPath = targetPath
    written = fs.existsSync(logPath) ? fs.statSync(logPath).size : 0
  } catch {
    // A client that cannot write its log still has to run.
    logPath = null
  }
  return logPath
}

function rotate() {
  try {
    const previous = `${logPath}.1`
    fs.rmSync(previous, { force: true })
    fs.renameSync(logPath, previous)
    written = 0
  } catch {
    // Losing rotation is survivable; losing the app over it is not.
  }
}

function emit(name, message) {
  const line = `${new Date().toISOString().replace('Z', 'Z')} ${name.toUpperCase().padEnd(5)} client ${message}\n`
  // The terminal copy is what a developer running `npm run dev` sees.
  if (mirrorToStderr) process.stderr.write(line)
  if (!logPath) return
  try {
    if (written + line.length > MAX_BYTES) rotate()
    fs.appendFileSync(logPath, line)
    written += line.length
  } catch {
    logPath = null
  }
}

function flushRepeat() {
  if (repeat && repeat.count > 0) {
    emit(repeat.name, `${repeat.message} (repeated ${repeat.count} times)`)
  }
  repeat = null
}

function write(name, message) {
  if (LEVELS[name] > level) return
  if (repeat && repeat.name === name && repeat.message === message) {
    repeat.count += 1
    if (Date.now() - repeat.since < REPEAT_WINDOW_MS) return
    const { count } = repeat
    repeat = null
    emit(name, `${message} (repeated ${count} times)`)
    repeat = { name, message, count: 0, since: Date.now() }
    return
  }
  flushRepeat()
  emit(name, message)
  repeat = { name, message, count: 0, since: Date.now() }
}

/** Emits any held repeat. Worth calling before the app quits. */
function flush() {
  flushRepeat()
}

module.exports = {
  init,
  flush,
  defaultLogPath,
  path: () => logPath,
  error: (message) => write('error', message),
  warn: (message) => write('warn', message),
  info: (message) => write('info', message),
  debug: (message) => write('debug', message),
}
