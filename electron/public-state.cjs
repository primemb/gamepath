'use strict'

/**
 * Every persisted secret is stored under a key starting with `encrypted`.
 * Stripping by prefix rather than by name means a secret added later cannot
 * reach the renderer because someone forgot to list it here.
 */
const SECRET_PREFIX = 'encrypted'

function withoutSecrets(state) {
  return Object.fromEntries(Object.entries(state).filter(([key]) => !key.startsWith(SECRET_PREFIX)))
}

module.exports = { withoutSecrets, SECRET_PREFIX }
