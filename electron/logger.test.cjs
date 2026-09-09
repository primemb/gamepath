const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const logger = require('./logger.cjs')

function scratch(context) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-logger-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  return path.join(directory, 'client.log')
}

function lines(file) {
  return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean)
}

test('writes a timestamped, levelled, component-tagged line', (context) => {
  const file = scratch(context)
  logger.init(file, { stderr: false })
  logger.info('session started: mode=relay routes=2')
  logger.flush()
  const [line] = lines(file)
  assert.match(line, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z INFO {2}client /)
  assert.match(line, /session started: mode=relay routes=2$/)
})

test('collapses a repeated message instead of writing it every time', (context) => {
  const file = scratch(context)
  logger.init(file, { stderr: false })
  for (let index = 0; index < 500; index += 1) {
    logger.warn('route 2 health check timed out')
  }
  logger.flush()
  const written = lines(file)
  // One line for the first occurrence, one for the collapsed remainder.
  assert.equal(written.length, 2)
  assert.match(written[1], /\(repeated 499 times\)$/)
})

test('a different message releases the held repeat in order', (context) => {
  const file = scratch(context)
  logger.init(file, { stderr: false })
  logger.warn('same')
  logger.warn('same')
  logger.info('something else')
  logger.flush()
  const written = lines(file)
  assert.match(written[0], /same$/)
  assert.match(written[1], /same \(repeated 1 times\)$/)
  assert.match(written[2], /something else$/)
})

test('rotation keeps one previous file and caps what is on disk', (context) => {
  const file = scratch(context)
  logger.init(file, { stderr: false })
  const padding = 'x'.repeat(1000)
  for (let index = 0; index < 4600; index += 1) {
    logger.info(`line ${index} ${padding}`)
  }
  logger.flush()
  const cap = 4 * 1024 * 1024
  assert.ok(fs.existsSync(`${file}.1`), 'the previous log should be kept')
  assert.ok(fs.statSync(file).size <= cap, 'the live log outgrew its cap')
  assert.ok(fs.statSync(`${file}.1`).size <= cap)
})

test('a log directory that cannot be created does not throw', () => {
  // A path under a file, so mkdir cannot succeed.
  const blocked = path.join(__filename, 'nested', 'client.log')
  assert.doesNotThrow(() => logger.init(blocked, { stderr: false }))
  assert.doesNotThrow(() => logger.info('still running without a log'))
})

test('the client and the Rust components agree on the log directory', () => {
  const rust = fs.readFileSync(path.join(__dirname, '..', 'engine', 'src', 'log.rs'), 'utf8')
  // Both put every component in one folder so a report is one directory.
  assert.match(rust, /join\("GamePath"\)\.join\("logs"\)/)
  if (process.platform === 'win32') {
    assert.match(logger.defaultLogPath(), /GamePath[\\/]logs[\\/]client\.log$/)
  }
})
