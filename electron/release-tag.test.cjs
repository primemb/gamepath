const test = require('node:test')
const assert = require('node:assert/strict')
const { validateReleaseTag } = require('../scripts/validate-release-tag.cjs')

test('release tags match the installer version, including prereleases', () => {
  for (const version of ['0.1.16', '1.0.0', '0.1.16-beta.1', '0.1.16-rc.0']) {
    assert.doesNotThrow(() => validateReleaseTag(`v${version}`, version))
  }
})

test('reject missing, mismatched and malformed release tags', () => {
  for (const tag of [undefined, '', '0.1.16', 'v0.1.15', 'v0.1.16-beta.1', 'v0.1.16\n']) {
    assert.throws(() => validateReleaseTag(tag, '0.1.16'))
  }
  for (const version of ['01.1.0', '1.0', '1.0.0-beta.01', '1.0.0-', '1.0.0-rc..1']) {
    assert.throws(() => validateReleaseTag(`v${version}`, version))
  }
})
