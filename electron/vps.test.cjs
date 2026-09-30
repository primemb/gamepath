const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const { deploymentFiles } = require('./vps.cjs')

test('the VPS upload includes nested Rust sources and no directories', () => {
  const projectRoot = path.join(__dirname, '..')
  const files = deploymentFiles(projectRoot)

  assert.ok(files.includes('engine/src/openvpn/mod.rs'))
  assert.ok(files.includes('relay/src/main.rs'))
  assert.ok(files.every((relative) => fs.statSync(path.join(projectRoot, relative)).isFile()))
})

test('enrolling on an existing relay reads the token and the port the service binds', () => {
  const { parseEnrollOutput } = require('./vps.cjs')
  const token = `gpe1_${'a'.repeat(90)}`
  assert.deepEqual(parseEnrollOutput(`noise\nGAMEPATH_BIND=0.0.0.0:40000\nGAMEPATH_TOKEN=${token}\n`), {
    token,
    port: 40000,
  })
  assert.deepEqual(parseEnrollOutput(`GAMEPATH_BIND=\nGAMEPATH_TOKEN=${token}`), { token, port: null })
})
