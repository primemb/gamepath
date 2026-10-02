/**
 * "Start with Windows": a per-user Run entry, written through Electron's
 * login-item API, that opens GamePath in the notification area at sign-in.
 *
 * Read back from Windows every time rather than remembered, so turning the
 * entry off in Task Manager's Startup apps shows here as off.
 */
const HIDDEN_ARG = '--hidden'
/** The Run value's name; `build/installer.nsh` removes it on uninstall. */
const ENTRY_NAME = 'GamePath'

/** Electron matches an entry by path and arguments, so both are always given. */
function entry() {
  return { path: process.execPath, args: [HIDDEN_ARG] }
}

function startWithWindows(app) {
  // An unpackaged run would register electron.exe and a source folder.
  if (!app.isPackaged) return { available: false, enabled: false }
  const settings = app.getLoginItemSettings(entry())
  // `executableWillLaunchAtLogin` also reflects Task Manager's switch.
  return { available: true, enabled: Boolean(settings.executableWillLaunchAtLogin ?? settings.openAtLogin) }
}

function setStartWithWindows(app, enabled) {
  if (!app.isPackaged) throw new Error('Start with Windows is available in the installed app.')
  // `enabled` re-approves an entry the user switched off in Task Manager.
  app.setLoginItemSettings({
    ...entry(),
    name: ENTRY_NAME,
    openAtLogin: Boolean(enabled),
    enabled: Boolean(enabled),
  })
  return startWithWindows(app)
}

/** Whether this launch came from the Run entry, and so starts in the background. */
function launchedAtLogin(argv) {
  return argv.includes(HIDDEN_ARG)
}

module.exports = { startWithWindows, setStartWithWindows, launchedAtLogin, HIDDEN_ARG, ENTRY_NAME }
