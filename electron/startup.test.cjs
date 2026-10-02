const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const { startWithWindows, setStartWithWindows, launchedAtLogin, HIDDEN_ARG, ENTRY_NAME } = require('./startup.cjs')

function fakeApp({ isPackaged = true, willLaunch = false } = {}) {
  const calls = []
  return {
    calls,
    isPackaged,
    getLoginItemSettings: (options) => {
      calls.push(['get', options])
      return { openAtLogin: willLaunch, executableWillLaunchAtLogin: willLaunch }
    },
    setLoginItemSettings: (settings) => {
      calls.push(['set', settings])
      willLaunch = settings.openAtLogin && settings.enabled
    },
  }
}

test('turning it on writes a background entry and reads it back from Windows', () => {
  const app = fakeApp()
  assert.deepEqual(setStartWithWindows(app, true), { available: true, enabled: true })
  const [, settings] = app.calls.find(([kind]) => kind === 'set')
  assert.equal(settings.openAtLogin, true)
  assert.equal(settings.enabled, true)
  assert.deepEqual(settings.args, [HIDDEN_ARG])
  assert.equal(settings.path, process.execPath)
  assert.equal(settings.name, ENTRY_NAME)
  // Read with the same path and arguments, or Windows reports another entry.
  const [, read] = app.calls.findLast(([kind]) => kind === 'get')
  assert.deepEqual(read, { path: process.execPath, args: [HIDDEN_ARG] })
})

test('an entry switched off in Task Manager shows as off', () => {
  const app = fakeApp({ willLaunch: false })
  app.getLoginItemSettings = () => ({ openAtLogin: true, executableWillLaunchAtLogin: false })
  assert.deepEqual(startWithWindows(app), { available: true, enabled: false })
})

test('an unpackaged run never registers itself', () => {
  const app = fakeApp({ isPackaged: false })
  assert.deepEqual(startWithWindows(app), { available: false, enabled: false })
  assert.throws(() => setStartWithWindows(app, true), /installed app/)
  assert.equal(app.calls.length, 0)
})

test('uninstalling removes the entry under the name it was written with', () => {
  const script = fs.readFileSync(path.join(__dirname, '..', 'build', 'installer.nsh'), 'utf8')
  const uninstall = script.slice(script.indexOf('!macro customUnInstall'))
  for (const key of ['Run', 'Explorer\\StartupApproved\\Run']) {
    const line = `DeleteRegValue HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\${key}" "${ENTRY_NAME}"`
    assert.ok(uninstall.includes(line), `uninstall does not remove ${key}`)
  }
})

test('a launch from the entry is recognised by its argument', () => {
  assert.equal(launchedAtLogin(['GamePath.exe', HIDDEN_ARG]), true)
  assert.equal(launchedAtLogin(['GamePath.exe']), false)
})
