/**
 * "Start with Windows": a Task Scheduler logon task that opens GamePath in the
 * notification area at sign-in.
 *
 * Not a Run entry: GamePath's manifest requires administrator rights, and
 * Windows blocks every program that needs elevation from starting through the
 * Run keys or the Startup folder at logon, silently. A task registered with the
 * highest run level is the supported way to start such a program then.
 * https://learn.microsoft.com/archive/blogs/uac/elevations-are-now-blocked-in-the-users-logon-path
 *
 * The state is read back from Task Scheduler rather than remembered, so a task
 * disabled or deleted there shows here as off. Reads are asynchronous; the
 * last one is cached for `publicState`.
 */
const { execFile } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const HIDDEN_ARG = '--hidden'
/** The task's name; `build/installer.nsh` deletes it on uninstall. */
const TASK_NAME = 'GamePath'
/** The Run value earlier releases wrote, removed when the task replaces it. */
const LEGACY_ENTRY_NAME = 'GamePath'

let cached = { available: false, enabled: false }

function runSchtasks(args) {
  return new Promise((resolve, reject) => {
    execFile('schtasks.exe', args, { windowsHide: true, encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { output: `${stdout}${stderr}`.trim() }))
      else resolve(stdout)
    })
  })
}

function escapeXml(value) {
  return value.replace(/[<>&'"]/g, (char) => `&#${char.charCodeAt(0)};`)
}

function currentUser() {
  const domain = process.env.USERDOMAIN
  const name = os.userInfo().username
  return domain ? `${domain}\\${name}` : name
}

/**
 * Task Scheduler's defaults suit maintenance jobs, not a tray app: a 72-hour
 * run limit that would close GamePath mid-session, no start on battery, and
 * priority 7, which starts the process below normal.
 */
function taskXml(executable, user) {
  const account = escapeXml(user)
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Opens GamePath in the notification area at sign-in.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>${account}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>${account}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${escapeXml(executable)}</Command>
      <Arguments>${HIDDEN_ARG}</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

/** What a registered task says, or null when there is none. */
function readTask(xml) {
  const settings = xml.match(/<Settings>([\s\S]*?)<\/Settings>/)?.[1] ?? ''
  const command = xml.match(/<Command>([\s\S]*?)<\/Command>/)?.[1]?.replace(/^"|"$/g, '') ?? ''
  return { enabled: !/<Enabled>false<\/Enabled>/.test(settings), command }
}

function samePath(a, b) {
  return path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase()
}

async function queryTask(schtasks) {
  try {
    return readTask(await schtasks(['/Query', '/TN', TASK_NAME, '/XML']))
  } catch {
    return null
  }
}

async function registerTask(schtasks, executable) {
  // schtasks reads /XML as UTF-16 with a byte-order mark.
  const file = path.join(os.tmpdir(), `gamepath-startup-${process.pid}.xml`)
  fs.writeFileSync(file, `﻿${taskXml(executable, currentUser())}`, 'utf16le')
  try {
    await schtasks(['/Create', '/TN', TASK_NAME, '/XML', file, '/F'])
  } finally {
    fs.rmSync(file, { force: true })
  }
}

function removeLegacyEntry(app) {
  app.setLoginItemSettings({
    path: process.execPath,
    args: [HIDDEN_ARG],
    name: LEGACY_ENTRY_NAME,
    openAtLogin: false,
    enabled: false,
  })
}

function legacyEntryEnabled(app) {
  const settings = app.getLoginItemSettings({ path: process.execPath, args: [HIDDEN_ARG] })
  return Boolean(settings.executableWillLaunchAtLogin ?? settings.openAtLogin)
}

/**
 * Reads the task back, and repairs what an earlier release or a moved install
 * left: a Run entry that Windows never honoured, or a task starting a GamePath
 * that is no longer there.
 */
async function refreshStartWithWindows(app, schtasks = runSchtasks) {
  // An unpackaged run would register electron.exe and a source folder.
  if (!app.isPackaged) return (cached = { available: false, enabled: false })
  let task = await queryTask(schtasks)
  const legacy = legacyEntryEnabled(app)
  const stale = task?.enabled && !samePath(task.command, process.execPath)
  if ((legacy && !task) || stale) {
    await registerTask(schtasks, process.execPath)
    task = await queryTask(schtasks)
  }
  if (legacy) removeLegacyEntry(app)
  return (cached = { available: true, enabled: Boolean(task?.enabled) })
}

function startWithWindows() {
  return cached
}

async function setStartWithWindows(app, enabled, schtasks = runSchtasks) {
  if (!app.isPackaged) throw new Error('Start with Windows is available in the installed app.')
  if (enabled) {
    await registerTask(schtasks, process.execPath)
  } else if (await queryTask(schtasks)) {
    await schtasks(['/Delete', '/TN', TASK_NAME, '/F'])
  }
  removeLegacyEntry(app)
  return refreshStartWithWindows(app, schtasks)
}

/** Whether this launch came from the logon task, and so starts in the background. */
function launchedAtLogin(argv) {
  return argv.includes(HIDDEN_ARG)
}

module.exports = {
  startWithWindows,
  refreshStartWithWindows,
  setStartWithWindows,
  launchedAtLogin,
  taskXml,
  readTask,
  HIDDEN_ARG,
  TASK_NAME,
  LEGACY_ENTRY_NAME,
}
