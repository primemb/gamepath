const test = require('node:test')
const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { packageWindows } = require('../scripts/package-windows.cjs')
const { cleanStaleBuilds, createBuildWorkspace, removeBuildDirectory } = require('../scripts/build-temp.cjs')

function fixture(t, source = '') {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-package-test-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }))
  const tempRoot = path.join(root, 'temp')
  const projectRoot = path.join(root, 'project')
  fs.mkdirSync(tempRoot)
  const builder = path.join(projectRoot, 'node_modules', 'electron-builder', 'out', 'cli', 'cli.js')
  fs.mkdirSync(path.dirname(builder), { recursive: true })
  fs.writeFileSync(
    builder,
    `const fs = require('node:fs')
const path = require('node:path')
const output = process.argv.find(value => value.startsWith('--config.directories.output=')).split('=')[1]
const temporary = process.env.TEMP
if ([process.env.TMP, process.env.TMPDIR, process.env.APP_BUILDER_TMP_DIR].some(value => value !== temporary)) throw new Error('Temp mismatch')
if (path.dirname(temporary) !== path.dirname(output)) throw new Error('Temp escaped staging')
const owner = JSON.parse(fs.readFileSync(path.join(path.dirname(output), '.gamepath-build.json'), 'utf8'))
if (!owner.pids.includes(process.pid)) throw new Error('Builder PID was not recorded')
fs.mkdirSync(path.join(temporary, 'tool-leftover'))
fs.writeFileSync(path.join(temporary, 'tool-leftover', 'large.tmp'), 'tool temporary data')
${source}`,
  )
  return { root, tempRoot, projectRoot }
}

test('packaging keeps the finished installer and removes staging and tool temporary files', async (t) => {
  const h = fixture(t, `fs.writeFileSync(path.join(output, 'GamePath-Setup-test.exe'), 'installer')`)
  const unrelated = path.join(h.tempRoot, 'other-app')
  fs.mkdirSync(unrelated)
  fs.writeFileSync(path.join(unrelated, 'keep.txt'), 'keep')
  await packageWindows(h)
  assert.equal(fs.readFileSync(path.join(h.projectRoot, 'release', 'GamePath-Setup-test.exe'), 'utf8'), 'installer')
  assert.deepEqual(fs.readdirSync(h.tempRoot), ['other-app'])
  assert.equal(fs.readFileSync(path.join(unrelated, 'keep.txt'), 'utf8'), 'keep')
})

test('a failed builder removes partial files and preserves an existing installer', async (t) => {
  const h = fixture(
    t,
    `fs.writeFileSync(path.join(output, 'GamePath-Setup-test.exe'), 'partial'); process.exitCode = 7`,
  )
  const destination = path.join(h.projectRoot, 'release')
  fs.mkdirSync(destination)
  fs.writeFileSync(path.join(destination, 'GamePath-Setup-test.exe'), 'previous')
  await assert.rejects(packageWindows(h), { exitCode: 7 })
  assert.deepEqual(fs.readdirSync(h.tempRoot), [])
  assert.equal(fs.readFileSync(path.join(destination, 'GamePath-Setup-test.exe'), 'utf8'), 'previous')
})

test('missing or ambiguous installers fail with cleanup before publishing any file', async (t) => {
  for (const source of [
    '',
    `for (const name of ['GamePath-Setup-one.exe', 'GamePath-Setup-two.exe']) fs.writeFileSync(path.join(output, name), 'installer')`,
  ]) {
    const h = fixture(t, source)
    await assert.rejects(packageWindows(h), /Expected one Windows installer/)
    assert.deepEqual(fs.readdirSync(h.tempRoot), [])
    assert.deepEqual(fs.readdirSync(path.join(h.projectRoot, 'release')), [])
  }
})

test('stale cleanup removes abandoned legacy folders while keeping fresh and active builds', (t) => {
  const h = fixture(t)
  const old = new Date(Date.now() - 48 * 60 * 60_000)
  const legacy = path.join(h.tempRoot, 'GamePath-builder-AbCd12')
  fs.mkdirSync(legacy)
  fs.writeFileSync(path.join(legacy, 'leftover.tmp'), 'old')
  fs.utimesSync(legacy, old, old)
  const active = createBuildWorkspace(h.tempRoot)
  fs.utimesSync(active.directory, old, old)
  const fresh = createBuildWorkspace(h.tempRoot)
  const childOwned = createBuildWorkspace(h.tempRoot)
  const exitedPid = spawnSync(process.execPath, ['-e', '']).pid
  fs.writeFileSync(
    path.join(childOwned.directory, '.gamepath-build.json'),
    JSON.stringify({ version: 1, pids: [exitedPid, process.pid] }),
  )
  fs.utimesSync(childOwned.directory, old, old)
  const abandoned = createBuildWorkspace(h.tempRoot)
  fs.writeFileSync(
    path.join(abandoned.directory, '.gamepath-build.json'),
    JSON.stringify({ version: 1, pids: [exitedPid] }),
  )
  fs.utimesSync(abandoned.directory, old, old)
  const unrelated = path.join(h.tempRoot, 'unrelated')
  fs.mkdirSync(unrelated)
  fs.utimesSync(unrelated, old, old)
  assert.equal(cleanStaleBuilds(h.tempRoot), 2)
  assert.ok(!fs.existsSync(legacy))
  assert.ok(!fs.existsSync(abandoned.directory))
  for (const directory of [active.directory, fresh.directory, childOwned.directory, unrelated])
    assert.ok(fs.existsSync(directory))
})

test('cleanup refuses the temp root, unrelated names, outside directories, and junctions', (t) => {
  const h = fixture(t)
  const outside = path.join(h.root, 'outside')
  fs.mkdirSync(outside)
  fs.writeFileSync(path.join(outside, 'keep.txt'), 'keep')
  const unrelated = path.join(h.tempRoot, 'unrelated')
  fs.mkdirSync(unrelated)
  assert.throws(() => removeBuildDirectory(h.tempRoot, h.tempRoot), /Refusing/)
  assert.throws(() => removeBuildDirectory(h.tempRoot, outside), /Refusing/)
  assert.throws(() => removeBuildDirectory(h.tempRoot, unrelated), /Refusing/)
  const link = path.join(h.tempRoot, 'GamePath-builder-Link12')
  fs.symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => removeBuildDirectory(h.tempRoot, link), /Refusing/)
  assert.equal(fs.readFileSync(path.join(outside, 'keep.txt'), 'utf8'), 'keep')
})
