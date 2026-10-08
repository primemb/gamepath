const net = require('node:net')

const INVITE_PREFIX = 'gamepath://relay/'
const MAX_INVITE_BYTES = 16_384

function decodeBase64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid encoding')
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.toString('base64url') !== value) throw new Error('Invalid encoding')
  return bytes
}

function validateEnrollmentToken(value) {
  try {
    if (typeof value !== 'string' || value.length > MAX_INVITE_BYTES || !value.startsWith('gpe1_'))
      throw new Error('Invalid token')
    const token = JSON.parse(decodeBase64(value.slice(5)).toString('utf8'))
    if (
      token.version !== 1 ||
      decodeBase64(token.clientId).length !== 16 ||
      decodeBase64(token.preSharedKey).length !== 32 ||
      net.isIP(token.virtualIpv4) !== 4
    )
      throw new Error('Invalid token')
    return value
  } catch {
    throw new Error('The enrollment token is not a valid GamePath token')
  }
}

function invitePayload(input) {
  const label = (value) =>
    typeof value === 'string' && value.trim().length > 0 && value.length <= 120 && !/[\x00-\x1f\x7f]/.test(value)
  const address = input?.address
  if (
    input?.version !== 1 ||
    !label(input.city) ||
    !label(input.country) ||
    !label(input.recipientName) ||
    typeof address !== 'string' ||
    address.length > 253 ||
    !(
      net.isIP(address) === 4 ||
      (net.isIP(address) === 0 &&
        address.split('.').every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part)))
    ) ||
    !Number.isInteger(input.port) ||
    input.port < 1 ||
    input.port > 65535
  )
    throw new Error('This is not a valid GamePath relay invitation')
  return {
    version: 1,
    city: input.city.trim(),
    country: input.country.trim(),
    address,
    port: input.port,
    recipientName: input.recipientName.trim(),
    enrollmentToken: validateEnrollmentToken(input.enrollmentToken),
  }
}

function encodeInvite(input) {
  return INVITE_PREFIX + Buffer.from(JSON.stringify(invitePayload(input))).toString('base64url')
}

function decodeInvite(text) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_INVITE_BYTES) throw new Error('Too large')
    const link = text.trim()
    if (!link.startsWith(INVITE_PREFIX)) throw new Error('Invalid prefix')
    return invitePayload(JSON.parse(decodeBase64(link.slice(INVITE_PREFIX.length)).toString('utf8')))
  } catch {
    // Never include the pasted link or a JSON parser's secret-bearing input in errors.
    throw new Error('This is not a valid GamePath relay invitation')
  }
}

module.exports = { encodeInvite, decodeInvite, validateEnrollmentToken, MAX_INVITE_BYTES }
