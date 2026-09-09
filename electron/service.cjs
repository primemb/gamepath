const fs = require('node:fs')
const net = require('node:net')
const path = require('node:path')

class ServiceBridge {
  constructor(options = {}) {
    this.port = options.port ?? 47983
    this.tokenFile =
      options.tokenFile ?? path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'GamePath', 'service-token')
    this.nextId = 1
    this.status = { status: 'not-installed', version: '', message: 'Network service is not installed', elevated: false }
  }

  async inspect() {
    if (!fs.existsSync(this.tokenFile)) {
      this.status = {
        status: 'not-installed',
        version: '',
        message: 'Network service is not installed',
        elevated: false,
      }
      return this.status
    }
    try {
      const result = await this.request('status')
      this.status = {
        status: 'ready',
        version: result.version,
        message: 'Privileged network service ready',
        elevated: Boolean(result.elevated),
        sessionStatus: result.sessionStatus,
      }
    } catch (error) {
      this.status = { status: 'offline', version: '', message: error.message, elevated: false }
    }
    return this.status
  }

  request(command, payload = {}, timeoutMs = 5000) {
    if (!fs.existsSync(this.tokenFile)) return Promise.reject(new Error('GamePath Network Service is not installed'))
    const token = fs.readFileSync(this.tokenFile, 'utf8').trim()
    const id = this.nextId++
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port: this.port })
      let response = ''
      let settled = false
      const finish = (error, value) => {
        if (settled) return
        settled = true
        clearTimeout(timeout)
        socket.destroy()
        if (error) reject(error)
        else resolve(value)
      }
      const timeout = setTimeout(() => finish(new Error('Network service request timed out')), timeoutMs)
      socket.setEncoding('utf8')
      socket.on('connect', () => socket.write(`${JSON.stringify({ id, token, command, payload })}\n`))
      socket.on('data', (chunk) => {
        response += chunk
        const newline = response.indexOf('\n')
        if (newline < 0) return
        try {
          const message = JSON.parse(response.slice(0, newline))
          // The service answers with id 0 when it could not attribute the
          // request at all: a malformed line, a read that failed, a rejection
          // made before parsing. Its message is then the only account of what
          // happened, so it is surfaced instead of being replaced by a mismatch
          // that says nothing about the cause.
          if (message.id !== id && message.id !== 0) {
            return finish(new Error('Network service returned a mismatched response'))
          }
          if (!message.ok) return finish(new Error(message.error || 'Network service request failed'))
          finish(null, message.result)
        } catch (error) {
          finish(new Error(`Invalid network service response: ${error.message}`))
        }
      })
      socket.on('error', (error) => finish(new Error(`Network service unavailable: ${error.message}`)))
      socket.on('end', () => {
        if (!settled) finish(new Error('Network service closed the connection'))
      })
    })
  }
}

module.exports = { ServiceBridge }
