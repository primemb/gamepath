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

function execute(connection, command, stdin = '', onOutput) {
  return new Promise((resolve, reject) => {
    connection.exec(command, (error, stream) => {
      if (error) return reject(error)
      let stdout = ''
      let stderr = ''
      stream.on('data', (chunk) => {
        const text = chunk.toString()
        stdout += text
        onOutput?.(text)
        if (stdout.length > 2_000_000) stdout = stdout.slice(-2_000_000)
      })
      stream.stderr.on('data', (chunk) => {
        const text = chunk.toString()
        stderr += text
        onOutput?.(text)
        if (stderr.length > 2_000_000) stderr = stderr.slice(-2_000_000)
      })
      stream.on('close', (code) =>
        code === 0
          ? resolve(stdout)
          : reject(new Error((stderr || stdout || `Remote command exited with code ${code}`).trim())),
      )
      stream.end(stdin)
    })
  })
}

async function uploadFiles(connection, root, remoteRoot, files, onProgress) {
  const sftp = await new Promise((resolve, reject) =>
    connection.sftp((error, value) => (error ? reject(error) : resolve(value))),
  )
  const mkdir = (remote) =>
    new Promise((resolve, reject) =>
      sftp.mkdir(remote, { mode: 0o700 }, (error) => (error && error.code !== 4 ? reject(error) : resolve())),
    )
  const put = (local, remote) =>
    new Promise((resolve, reject) => {
      const content = fs.readFileSync(local).toString('utf8').replace(/\r\n/g, '\n')
      sftp.writeFile(remote, content, { mode: 0o600, encoding: 'utf8' }, (error) => (error ? reject(error) : resolve()))
    })
  await mkdir(remoteRoot)
  const made = new Set([remoteRoot])
  for (const [index, relative] of files.entries()) {
    const remote = `${remoteRoot}/${relative.replaceAll('\\', '/')}`
    const parent = remote.slice(0, remote.lastIndexOf('/'))
    let current = ''
    for (const part of parent.split('/').filter(Boolean)) {
      current += `/${part}`
      if (!made.has(current)) {
        await mkdir(current)
        made.add(current)
      }
    }
    await put(path.join(root, relative), remote)
    onProgress?.({
      stage: 'upload',
      percent: 10 + Math.round(((index + 1) / files.length) * 20),
      message: `Uploading relay files (${index + 1}/${files.length})`,
    })
  }
  sftp.end()
}

function deploymentFiles(root) {
  const result = [
    'deploy/install-relay.sh',
    'deploy/uninstall-relay.sh',
    'relay/Cargo.toml',
    'relay/Cargo.lock',
    'engine/Cargo.toml',
    'engine/Cargo.lock',
  ]
  const visit = (folder) => {
    for (const entry of fs.readdirSync(path.join(root, folder), { withFileTypes: true })) {
      const relative = `${folder}/${entry.name}`
      if (entry.isDirectory()) visit(relative)
      else if (entry.isFile()) result.push(relative)
    }
  }
  for (const folder of ['relay/src', 'engine/src']) visit(folder)
  return result
}

async function rootCommand(connection, command, password, isRoot, onOutput) {
  if (isRoot) return execute(connection, `bash -lc ${quote(command)}`, '', onOutput)
  return execute(connection, `sudo -S -p '' bash -lc ${quote(command)}`, `${password}\n`, onOutput)
}

async function provisionRelay(projectRoot, input, onProgress = () => {}) {
  onProgress({ stage: 'connect', percent: 2, message: 'Connecting to the VPS over SSH' })
  const { connection, fingerprint } = await connectSsh(input)
  const remoteRoot = `/tmp/gamepath-deploy-${crypto.randomBytes(8).toString('hex')}`
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    onProgress({ stage: 'verify', percent: 7, message: 'SSH identity verified' })
    await uploadFiles(connection, projectRoot, remoteRoot, deploymentFiles(projectRoot), onProgress)
    const enrollment = `${remoteRoot}/windows-client.enroll`
    let outputBuffer = ''
    const progressOutput = (text) => {
      outputBuffer += text
      const stages = {
        dependencies: [38, 'Installing Linux dependencies'],
        compile: [55, 'Compiling the optimized relay'],
        network: [72, 'Configuring forwarding and firewall'],
        service: [84, 'Installing and starting the relay service'],
        enrollment: [92, 'Creating this PC’s enrollment'],
      }
      for (const line of outputBuffer.split(/\r?\n/).slice(0, -1)) {
        const match = line.match(/GAMEPATH_PROGRESS:([a-z]+)/)
        if (match && stages[match[1]])
          onProgress({ stage: match[1], percent: stages[match[1]][0], message: stages[match[1]][1] })
      }
      outputBuffer = outputBuffer.split(/\r?\n/).at(-1) ?? ''
    }
    onProgress({ stage: 'install', percent: 32, message: 'Starting relay installation' })
    const enrollmentArgs = input.existingEnrollmentToken
      ? '--no-enroll'
      : `--client-name windows-client-${crypto.randomBytes(16).toString('hex')} --enrollment-output ${quote(enrollment)}`
    await rootCommand(
      connection,
      `chmod +x ${quote(remoteRoot)}/deploy/install-relay.sh && bash ${quote(remoteRoot)}/deploy/install-relay.sh --port ${input.relayPort} ${enrollmentArgs}`,
      input.password,
      isRoot,
      progressOutput,
    )
    onProgress({ stage: 'credential', percent: 96, message: 'Importing and protecting the enrollment credential' })
    const token =
      input.existingEnrollmentToken ??
      (await rootCommand(connection, `cat ${quote(enrollment)}`, input.password, isRoot)).trim()
    if (!token.startsWith('gpe1_') || token.length < 80)
      throw new Error('The server returned an invalid enrollment credential')
    await rootCommand(connection, `rm -rf ${quote(remoteRoot)}`, input.password, isRoot)
    onProgress({ stage: 'complete', percent: 100, message: 'VPS relay is ready' })
    return { token, fingerprint }
  } finally {
    connection.end()
  }
}

// Check the executable the service is actually running, rather than a newer
// binary copied onto disk but not yet started. Never restart for enrollment.
function existingEnrollmentScript(clientName, clientLabel) {
  if (!/^[a-z0-9-]{1,80}$/.test(clientName)) throw new Error('Invalid enrollment client name')
  if (
    clientLabel !== undefined &&
    (typeof clientLabel !== 'string' ||
      !clientLabel.trim() ||
      clientLabel.length > 80 ||
      /[\x00-\x1f\x7f]/.test(clientLabel))
  )
    throw new Error('Invalid enrollment client label')
  return `set -euo pipefail
if [[ ! -x /usr/local/bin/gamepath-relay || ! -f /etc/gamepath/relay.env ]]; then
  echo "GamePath relay is not installed on this VPS. Turn off 'already installed' to run the full setup." >&2
  exit 3
fi
pid=$(systemctl show --property MainPID --value gamepath-relay.service)
if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! "/proc/$pid/exe" capabilities 2>/dev/null | grep -Fx 'live-client-reload-v1' >/dev/null; then
  echo "Update this VPS relay once to enable invitations without restarting. Use Update VPS between games; existing client credentials are preserved." >&2
  exit 4
fi
. /etc/gamepath/relay.env
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
umask 077
exec 9>/var/lock/gamepath-enrollment.lock
flock -x 9
label_args=()
${clientLabel === undefined ? '' : `if "/proc/$pid/exe" capabilities 2>/dev/null | grep -Fx 'client-access-management-v1' >/dev/null; then label_args=(--label ${quote(clientLabel)}); fi`}
"/proc/$pid/exe" enroll --name ${quote(clientName)} "\${label_args[@]}" --clients-dir "\${GAMEPATH_CLIENTS:-/etc/gamepath/clients}" --output "$dir/client.enroll" >/dev/null
chmod 0640 "\${GAMEPATH_CLIENTS:-/etc/gamepath/clients}"/*.json
chown root:gamepath "\${GAMEPATH_CLIENTS:-/etc/gamepath/clients}"/*.json
echo "GAMEPATH_BIND=\${GAMEPATH_BIND:-}"
echo "GAMEPATH_TOKEN=$(cat "$dir/client.enroll")"`
}

function parseEnrollOutput(output) {
  const value = (key) => output.match(new RegExp(`^${key}=(.*)$`, 'm'))?.[1].trim() ?? ''
  const port = Number(value('GAMEPATH_BIND').match(/:(\d+)$/)?.[1])
  return { token: value('GAMEPATH_TOKEN'), port: Number.isInteger(port) && port > 0 && port < 65536 ? port : null }
}

async function enrollExistingRelay(input, onProgress = () => {}) {
  onProgress({ stage: 'connect', percent: 5, message: 'Connecting to the VPS over SSH' })
  const { connection, fingerprint } = await connectSsh(input)
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    onProgress({ stage: 'verify', percent: 30, message: 'SSH identity verified' })
    onProgress({
      stage: 'enrollment',
      percent: 60,
      message: input.clientName ? 'Creating your friend’s relay access' : 'Enrolling this PC on the existing relay',
    })
    const { token, port } = parseEnrollOutput(
      await rootCommand(
        connection,
        existingEnrollmentScript(
          input.clientName ?? `windows-client-${crypto.randomBytes(16).toString('hex')}`,
          input.clientLabel,
        ),
        input.password,
        isRoot,
      ),
    )
    if (!token.startsWith('gpe1_') || token.length < 80)
      throw new Error('The server returned an invalid enrollment credential')
    onProgress({
      stage: 'complete',
      percent: 100,
      message: input.clientName ? 'Invitation ready' : 'This PC is enrolled on the relay',
    })
    return { token, fingerprint, port: port ?? input.relayPort }
  } finally {
    connection.end()
  }
}

async function removeRelay(projectRoot, input, onProgress = () => {}) {
  onProgress({ stage: 'connect', percent: 5, message: 'Connecting to the VPS over SSH' })
  const { connection, fingerprint } = await connectSsh(input)
  const remoteRoot = `/tmp/gamepath-remove-${crypto.randomBytes(8).toString('hex')}`
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    await uploadFiles(connection, projectRoot, remoteRoot, ['deploy/uninstall-relay.sh'], onProgress)
    onProgress({ stage: 'remove', percent: 45, message: 'Stopping and removing the relay deployment' })
    await rootCommand(
      connection,
      `chmod +x ${quote(remoteRoot)}/deploy/uninstall-relay.sh && bash ${quote(remoteRoot)}/deploy/uninstall-relay.sh; rm -rf ${quote(remoteRoot)}`,
      input.password,
      isRoot,
    )
    onProgress({ stage: 'complete', percent: 100, message: 'Relay deployment removed' })
    return { fingerprint }
  } finally {
    connection.end()
  }
}

module.exports = {
  connectSsh,
  execute,
  rootCommand,
  quote,
  deploymentFiles,
  enrollExistingRelay,
  existingEnrollmentScript,
  parseEnrollOutput,
  provisionRelay,
  removeRelay,
}
