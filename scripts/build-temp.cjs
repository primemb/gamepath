const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const PREFIX = 'GamePath-builder-'
const OWNER_FILE = '.gamepath-build.json'
const STALE_AFTER_MS = 24 * 60 * 60_000

function checkedDirectory(tempRoot, directory) {
  const root = fs.realpathSync(tempRoot)
  const target = path.resolve(directory)
  if (path.dirname(target) !== root || !/^GamePath-builder-[a-zA-Z0-9]{6}$/.test(path.basename(target)))
    throw new Error('Refusing to remove a directory outside GamePath build staging')
  const info = fs.lstatSync(target)
  if (!info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(target) !== target)
    throw new Error('Refusing to remove redirected build staging')
  return target
}

function removeBuildDirectory(tempRoot, directory) {
  fs.rmSync(checkedDirectory(tempRoot, directory), { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code !== 'ESRCH'
  }
}

function cleanStaleBuilds(tempRoot, now = Date.now()) {
  const root = fs.realpathSync(tempRoot)
  let removed = 0
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^GamePath-builder-[a-zA-Z0-9]{6}$/.test(entry.name)) continue
    const directory = path.join(root, entry.name)
    try {
      if (now - fs.lstatSync(directory).mtimeMs < STALE_AFTER_MS) continue
      let owner
      try {
        const file = path.join(directory, OWNER_FILE)
        if (fs.statSync(file).size <= 1024) owner = JSON.parse(fs.readFileSync(file, 'utf8'))
      } catch {}
      if (
        owner?.version === 1 &&
        Array.isArray(owner.pids) &&
        owner.pids.some((pid) => Number.isInteger(pid) && pid > 0 && processIsRunning(pid))
      )
        continue
      removeBuildDirectory(root, directory)
      removed += 1
    } catch (error) {
      console.warn(`Could not clean old build staging ${directory}: ${error.message}`)
    }
  }
  if (removed) console.log(`Removed ${removed} old GamePath build folder(s).`)
  return removed
}

function createBuildWorkspace(tempRoot) {
  const root = fs.realpathSync(tempRoot)
  const directory = fs.mkdtempSync(path.join(root, PREFIX))
  const output = path.join(directory, 'output')
  const temporary = path.join(directory, 'temp')
  const recordOwner = (builderPid) =>
    fs.writeFileSync(
      path.join(directory, OWNER_FILE),
      JSON.stringify({ version: 1, pids: [process.pid, ...(builderPid ? [builderPid] : [])] }),
    )
  try {
    recordOwner()
    fs.mkdirSync(output)
    fs.mkdirSync(temporary)
  } catch (error) {
    removeBuildDirectory(root, directory)
    throw error
  }
  return { directory, output, temporary, recordOwner, cleanup: () => removeBuildDirectory(root, directory) }
}

module.exports = { cleanStaleBuilds, createBuildWorkspace, removeBuildDirectory }

if (require.main === module) cleanStaleBuilds(os.tmpdir())
