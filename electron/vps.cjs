const { Client } = require('ssh2')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const quote = (value) => `'${String(value).replace(/'/g, `'"'"'`)}'`

function connectSsh(input) {
  return new Promise((resolve, reject) => {
    const connection = new Client()
    let fingerprint = ''
    connection.on('ready', () => resolve({ connection, fingerprint }))
    connection.on('error', reject)
    connection.connect({
      host: input.host,
      port: input.sshPort,
      username: input.username,
      password: input.password,
      readyTimeout: 20_000,
      keepaliveInterval: 10_000,
      hostHash: 'sha256',
      hostVerifier: (hash) => {
        fingerprint = hash
        if (!input.expectedFingerprint) return true
        const actual = Buffer.from(hash)
        const expected = Buffer.from(input.expectedFingerprint)
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected)
      },
    })
  })
}

function execute(connection, command, stdin = '') {
  return new Promise((resolve, reject) => {
    connection.exec(command, (error, stream) => {
      if (error) return reject(error)
      let stdout = ''
      let stderr = ''
      stream.on('data', (chunk) => { stdout += chunk.toString(); if (stdout.length > 2_000_000) stdout = stdout.slice(-2_000_000) })
      stream.stderr.on('data', (chunk) => { stderr += chunk.toString(); if (stderr.length > 2_000_000) stderr = stderr.slice(-2_000_000) })
      stream.on('close', (code) => code === 0 ? resolve(stdout) : reject(new Error((stderr || stdout || `Remote command exited with code ${code}`).trim())))
      stream.end(stdin)
    })
  })
}

async function uploadFiles(connection, root, remoteRoot, files) {
  const sftp = await new Promise((resolve, reject) => connection.sftp((error, value) => error ? reject(error) : resolve(value)))
  const mkdir = (remote) => new Promise((resolve, reject) => sftp.mkdir(remote, { mode: 0o700 }, (error) => error && error.code !== 4 ? reject(error) : resolve()))
  const put = (local, remote) => new Promise((resolve, reject) => {
    const content = fs.readFileSync(local).toString('utf8').replace(/\r\n/g, '\n')
    sftp.writeFile(remote, content, { mode: 0o600, encoding: 'utf8' }, (error) => error ? reject(error) : resolve())
  })
  await mkdir(remoteRoot)
  const made = new Set([remoteRoot])
  for (const relative of files) {
    const remote = `${remoteRoot}/${relative.replaceAll('\\', '/')}`
    const parent = remote.slice(0, remote.lastIndexOf('/'))
    let current = ''
    for (const part of parent.split('/').filter(Boolean)) {
      current += `/${part}`
      if (!made.has(current)) { await mkdir(current); made.add(current) }
    }
    await put(path.join(root, relative), remote)
  }
  sftp.end()
}

function deploymentFiles(root) {
  const result = ['deploy/install-relay.sh', 'deploy/uninstall-relay.sh', 'relay/Cargo.toml', 'relay/Cargo.lock', 'engine/Cargo.toml', 'engine/Cargo.lock']
  for (const folder of ['relay/src', 'engine/src']) {
    for (const name of fs.readdirSync(path.join(root, folder))) result.push(`${folder}/${name}`)
  }
  return result
}

async function rootCommand(connection, command, password, isRoot) {
  if (isRoot) return execute(connection, `bash -lc ${quote(command)}`)
  return execute(connection, `sudo -S -p '' bash -lc ${quote(command)}`, `${password}\n`)
}

async function provisionRelay(projectRoot, input) {
  const { connection, fingerprint } = await connectSsh(input)
  const remoteRoot = `/tmp/gamepath-deploy-${crypto.randomBytes(8).toString('hex')}`
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    await uploadFiles(connection, projectRoot, remoteRoot, deploymentFiles(projectRoot))
    const enrollment = `${remoteRoot}/windows-client.enroll`
    await rootCommand(connection, `chmod +x ${quote(remoteRoot)}/deploy/install-relay.sh && bash ${quote(remoteRoot)}/deploy/install-relay.sh --port ${input.relayPort} --client-name windows-client --enrollment-output ${quote(enrollment)}`, input.password, isRoot)
    const token = (await rootCommand(connection, `cat ${quote(enrollment)}`, input.password, isRoot)).trim()
    if (!token.startsWith('gpe1_') || token.length < 80) throw new Error('The server returned an invalid enrollment credential')
    await rootCommand(connection, `rm -rf ${quote(remoteRoot)}`, input.password, isRoot)
    return { token, fingerprint }
  } finally {
    connection.end()
  }
}

async function removeRelay(projectRoot, input) {
  const { connection, fingerprint } = await connectSsh(input)
  const remoteRoot = `/tmp/gamepath-remove-${crypto.randomBytes(8).toString('hex')}`
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    await uploadFiles(connection, projectRoot, remoteRoot, ['deploy/uninstall-relay.sh'])
    await rootCommand(connection, `chmod +x ${quote(remoteRoot)}/deploy/uninstall-relay.sh && bash ${quote(remoteRoot)}/deploy/uninstall-relay.sh; rm -rf ${quote(remoteRoot)}`, input.password, isRoot)
    return { fingerprint }
  } finally {
    connection.end()
  }
}

module.exports = { provisionRelay, removeRelay }
