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
