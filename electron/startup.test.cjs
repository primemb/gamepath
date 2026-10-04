const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const {
  startWithWindows,
  refreshStartWithWindows,
  setStartWithWindows,
  launchedAtLogin,
  taskXml,
  readTask,
  HIDDEN_ARG,
  TASK_NAME,
  LEGACY_ENTRY_NAME,
} = require('./startup.cjs')

/** A Task Scheduler that keeps one task in memory, as schtasks would. */
function fakeScheduler() {
  const scheduler = { task: null, calls: [] }
  scheduler.run = async (args) => {
    scheduler.calls.push(args[0])
    if (args[0] === '/Query') {
      if (!scheduler.task) throw new Error('ERROR: The system cannot find the file specified.')
      return scheduler.task
    }
    if (args[0] === '/Create') {
      const file = args[args.indexOf('/XML') + 1]
      scheduler.task = fs.readFileSync(file, 'utf16le').replace(/^\ufeff/, '')
      return 'SUCCESS'
    }
    if (args[0] === '/Delete') scheduler.task = null
    return 'SUCCESS'
  }
  return scheduler
}

function fakeApp({ isPackaged = true, legacy = false } = {}) {
  const app = { isPackaged, legacy, removed: 0 }
  app.getLoginItemSettings = () => ({ executableWillLaunchAtLogin: app.legacy })
  app.setLoginItemSettings = (settings) => {
    assert.equal(settings.name, LEGACY_ENTRY_NAME)
    app.legacy = settings.openAtLogin
    app.removed += 1
  }
  return app
}

test('turning it on registers an elevated logon task that starts in the tray', async () => {
  const scheduler = fakeScheduler()
  const app = fakeApp()
  assert.deepEqual(await setStartWithWindows(app, true, scheduler.run), { available: true, enabled: true })
  assert.match(scheduler.task, /<RunLevel>HighestAvailable<\/RunLevel>/)
  assert.match(scheduler.task, /<LogonTrigger>/)
  assert.match(scheduler.task, new RegExp(`<Arguments>${HIDDEN_ARG}</Arguments>`))
  assert.equal(readTask(scheduler.task).command, process.execPath)
  assert.deepEqual(startWithWindows(), { available: true, enabled: true })
  assert.deepEqual(await setStartWithWindows(app, false, scheduler.run), { available: true, enabled: false })
  assert.equal(scheduler.task, null)
})

test('the task never stops, never waits for mains power and starts at normal priority', () => {
  const xml = taskXml('C:\\Program Files\\GamePath\\GamePath.exe', 'PC\\someone')
  assert.match(xml, /<ExecutionTimeLimit>PT0S<\/ExecutionTimeLimit>/)
  assert.match(xml, /<DisallowStartIfOnBatteries>false<\/DisallowStartIfOnBatteries>/)
  assert.match(xml, /<StopIfGoingOnBatteries>false<\/StopIfGoingOnBatteries>/)
  assert.match(xml, /<Priority>4<\/Priority>/)
  assert.match(taskXml('C:\\A&B\\GamePath.exe', 'PC\\someone'), /A&#38;B/)
})

test('a task disabled in Task Scheduler shows as off', async () => {
  const scheduler = fakeScheduler()
  scheduler.task = taskXml(process.execPath, 'PC\\someone').replace(
    '<Enabled>true</Enabled>\n  </Settings>',
    '<Enabled>false</Enabled>\n  </Settings>',
  )
  assert.deepEqual(await refreshStartWithWindows(fakeApp(), scheduler.run), { available: true, enabled: false })
})

test('a Run entry from an earlier release, which Windows never started, becomes the task', async () => {
  const scheduler = fakeScheduler()
  const app = fakeApp({ legacy: true })
  assert.deepEqual(await refreshStartWithWindows(app, scheduler.run), { available: true, enabled: true })
  assert.ok(scheduler.task)
  assert.equal(app.legacy, false)
})

test('a task left pointing at a moved install is pointed back at this one', async () => {
  const scheduler = fakeScheduler()
  scheduler.task = taskXml('D:\\Old\\GamePath.exe', 'PC\\someone')
  await refreshStartWithWindows(fakeApp(), scheduler.run)
  assert.equal(readTask(scheduler.task).command, process.execPath)
})

test('an unpackaged run never registers itself', async () => {
  const scheduler = fakeScheduler()
  const app = fakeApp({ isPackaged: false })
  assert.deepEqual(await refreshStartWithWindows(app, scheduler.run), { available: false, enabled: false })
  await assert.rejects(setStartWithWindows(app, true, scheduler.run), /installed app/)
  assert.deepEqual(scheduler.calls, [])
})

test('uninstalling deletes the task, but an update keeps it', () => {
  const script = fs.readFileSync(path.join(__dirname, '..', 'build', 'installer.nsh'), 'utf8')
  const uninstall = script.slice(script.indexOf('!macro customUnInstall'))
  const kept = uninstall.slice(uninstall.indexOf('${ifNot} ${isUpdated}'), uninstall.indexOf('${endIf}'))
  assert.ok(kept.includes(`schtasks.exe /Delete /TN "${TASK_NAME}" /F`), 'uninstall does not delete the task')
  for (const key of ['Run', 'Explorer\\StartupApproved\\Run']) {
    const line = `DeleteRegValue HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\${key}" "${LEGACY_ENTRY_NAME}"`
    assert.ok(kept.includes(line), `uninstall does not remove ${key}, or an update would`)
  }
})

test('a launch from the task is recognised by its argument', () => {
  assert.equal(launchedAtLogin(['GamePath.exe', HIDDEN_ARG]), true)
  assert.equal(launchedAtLogin(['GamePath.exe']), false)
})
