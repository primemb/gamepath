const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const projectRoot = path.join(__dirname, '..')
const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'GamePath-builder-'))
const destination = path.join(projectRoot, 'release')
fs.mkdirSync(destination, { recursive: true })

const builder = path.join(projectRoot, 'node_modules', 'electron-builder', 'out', 'cli', 'cli.js')
const result = spawnSync(process.execPath, [builder, '--win', 'nsis', `--config.directories.output=${staging}`], {
  cwd: projectRoot,
  stdio: 'inherit',
})
if (result.status !== 0) process.exit(result.status ?? 1)

for (const name of fs.readdirSync(staging)) {
  if (/^GamePath-Setup-.*\.exe$/i.test(name)) {
    fs.copyFileSync(path.join(staging, name), path.join(destination, name))
    console.log(`Installer ready: ${path.join(destination, name)}`)
  }
}
