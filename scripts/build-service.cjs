const { spawnSync } = require('node:child_process')
const os = require('node:os')
const path = require('node:path')

const cargo = process.platform === 'win32' ? path.join(os.homedir(), '.cargo', 'bin', 'cargo.exe') : 'cargo'
const result = spawnSync(cargo, ['build', '--manifest-path', 'service/Cargo.toml'], {
  cwd: path.join(__dirname, '..'),
  stdio: 'inherit',
  windowsHide: true,
})
if (result.error) {
  console.error(`Unable to build GamePath service: ${result.error.message}`)
  process.exit(1)
}
process.exit(result.status ?? 1)

