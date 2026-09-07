const { spawnSync } = require('node:child_process')
const os = require('node:os')
const path = require('node:path')

const executable = process.platform === 'win32' ? path.join(os.homedir(), '.cargo', 'bin', 'cargo.exe') : 'cargo'
const result = spawnSync(executable, ['build', '--manifest-path', 'engine/Cargo.toml'], {
  cwd: path.join(__dirname, '..'),
  stdio: 'inherit',
  windowsHide: true,
})
if (result.error) {
  console.error(`Unable to start Rust compiler: ${result.error.message}`)
  process.exit(1)
}
process.exit(result.status ?? 1)
