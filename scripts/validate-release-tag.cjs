const semver =
  /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$/

function validateReleaseTag(tag, version) {
  if (!tag || !semver.test(tag) || tag !== `v${version}`) {
    throw new Error(`Release tag must be v${version}, matching package.json (received ${JSON.stringify(tag)}).`)
  }
}

if (require.main === module) {
  const { version } = require('../package.json')
  const tag = process.env.GITHUB_REF_NAME
  try {
    validateReleaseTag(tag, version)
    console.log(`Validated release ${tag}`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}

module.exports = { validateReleaseTag }
