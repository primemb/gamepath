const { spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const readline = require('node:readline')

class EngineBridge {
  constructor(projectRoot, packaged = false) {
    this.projectRoot = projectRoot
    this.packaged = packaged
    this.process = null
    this.nextId = 1
    this.pending = new Map()
    this.runtimeBinary = null
    this.status = { status: 'offline', version: '', message: 'Native engine is not running', capabilities: null }
  }

  async start() {
    if (this.process) return this.status
    const binary = path.join(
      this.projectRoot,
      'engine',
      'target',
      this.packaged ? 'release' : 'debug',
      'gamepath-engine.exe',
    )
    const runtimeDirectory = path.join(require('node:os').tmpdir(), 'GamePath')
    fs.mkdirSync(runtimeDirectory, { recursive: true })
    this.runtimeBinary = path.join(runtimeDirectory, `gamepath-engine-${process.pid}-${Date.now()}.exe`)
    fs.copyFileSync(binary, this.runtimeBinary)
    this.process = spawn(this.runtimeBinary, [], {
      cwd: this.projectRoot,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.process.once('error', (error) => {
      this.status = { status: 'error', version: '', message: error.message, capabilities: null }
      this.rejectPending(error)
      this.process = null
      this.cleanupRuntime()
    })
    this.process.once('exit', (code) => {
      const error = new Error(`Native engine exited with code ${code}`)
      this.status = { status: 'offline', version: '', message: error.message, capabilities: null }
      this.rejectPending(error)
      this.process = null
      this.cleanupRuntime()
    })
    readline.createInterface({ input: this.process.stdout }).on('line', (line) => this.handleLine(line))

    try {
      const hello = await this.request('hello')
      const capabilities = await this.request('inspect-system')
      this.status = { status: 'ready', version: hello.version, message: 'Native engine ready', capabilities }
    } catch (error) {
      this.status = { status: 'error', version: '', message: error.message, capabilities: null }
    }
    return this.status
  }

  request(command, payload = {}, timeoutMs = 5000) {
    if (!this.process?.stdin?.writable) return Promise.reject(new Error('Native engine is unavailable'))
    const id = this.nextId++
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`Engine request timed out: ${command}`))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timeout })
      this.process.stdin.write(`${JSON.stringify({ id, command, payload })}\n`)
    })
  }

  handleLine(line) {
    let response
    try {
      response = JSON.parse(line)
    } catch {
      return
    }
    const pending = this.pending.get(response.id)
    if (!pending) return
    clearTimeout(pending.timeout)
    this.pending.delete(response.id)
    if (response.ok) pending.resolve(response.result)
    else pending.reject(new Error(response.error || 'Unknown engine error'))
  }

  rejectPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout)
      pending.reject(error)
    }
    this.pending.clear()
  }

  stop() {
    this.process?.kill()
    this.process = null
  }

  cleanupRuntime() {
    if (!this.runtimeBinary) return
    try {
      fs.unlinkSync(this.runtimeBinary)
    } catch {}
    this.runtimeBinary = null
  }
}

module.exports = { EngineBridge }
