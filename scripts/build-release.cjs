const { spawnSync } = require('node:child_process')
const os = require('node:os')
const path = require('node:path')

const cargo = process.platform === 'win32'
  ? path.join(os.homedir(), '.cargo', 'bin', 'cargo.exe')
  : 'cargo'

for (const manifest of ['engine/Cargo.toml', 'service/Cargo.toml']) {
  const result = spawnSync(cargo, ['build', '--release', '--manifest-path', manifest], {
    cwd: path.join(__dirname, '..'),
    stdio: 'inherit',
  })
  if (result.status !== 0) process.exit(result.status ?? 1)
}
