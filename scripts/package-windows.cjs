const { spawn } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { cleanStaleBuilds, createBuildWorkspace } = require('./build-temp.cjs')

function runBuilder(projectRoot, workspace) {
  return new Promise((resolve, reject) => {
    const builder = path.join(projectRoot, 'node_modules', 'electron-builder', 'out', 'cli', 'cli.js')
    const child = spawn(
      process.execPath,
      [builder, '--win', 'nsis', '--x64', '--publish', 'never', `--config.directories.output=${workspace.output}`],
      {
        cwd: projectRoot,
        stdio: 'inherit',
        env: {
          ...process.env,
          TEMP: workspace.temporary,
          TMP: workspace.temporary,
          TMPDIR: workspace.temporary,
          APP_BUILDER_TMP_DIR: workspace.temporary,
        },
      },
    )
    child.on('error', reject)
    child.on('close', (code, signal) => {
      if (code === 0) resolve()
      else reject(Object.assign(new Error(`Installer build failed (${signal ?? code}).`), { exitCode: code ?? 1 }))
    })
    if (child.pid) {
      try {
        workspace.recordOwner(child.pid)
      } catch (error) {
        console.warn(`Could not record the builder process: ${error.message}`)
      }
    }
  })
}

async function packageWindows({ projectRoot = path.join(__dirname, '..'), tempRoot = os.tmpdir() } = {}) {
  cleanStaleBuilds(tempRoot)
  const workspace = createBuildWorkspace(tempRoot)
  try {
    const destination = path.join(projectRoot, 'release')
    fs.mkdirSync(destination, { recursive: true })
    await runBuilder(projectRoot, workspace)

    const installers = fs.readdirSync(workspace.output).filter((name) => /^GamePath-Setup-.*\.exe$/i.test(name))
    if (installers.length !== 1) throw new Error(`Expected one Windows installer, found ${installers.length}.`)
    const name = installers[0]
    fs.copyFileSync(path.join(workspace.output, name), path.join(destination, name))
    console.log(`Installer ready: ${path.join(destination, name)}`)
  } finally {
    try {
      workspace.cleanup()
    } catch (error) {
      console.warn(`Could not clean build staging ${workspace.directory}: ${error.message}`)
    }
  }
}

if (require.main === module) {
  packageWindows().catch((error) => {
    console.error(error.message)
    process.exitCode = error.exitCode ?? 1
  })
}

module.exports = { packageWindows }
