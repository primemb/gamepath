const crypto = require('node:crypto')
const path = require('node:path')
const { app } = require('electron')

// Kept for the life of the app: an executable's icon does not change while it
// runs, and the set of executables a user routes is small.
const icons = new Map()
let genericIcon

/**
 * Windows answers an executable without an icon resource with its stock
 * executable icon rather than nothing. A path that cannot exist gets exactly
 * that icon, so it is the reference for "this program has no icon of its own".
 */
function genericExecutableIcon() {
  genericIcon ??= app
    .getFileIcon(path.join(app.getPath('temp'), `${crypto.randomUUID()}.exe`), { size: 'normal' })
    .then((image) => image.toBitmap())
    .catch(() => null)
  return genericIcon
}

/**
 * The shell icon of an executable, as a data URL, or `null` when it has no
 * icon of its own and the UI should draw its placeholder. Only absolute `.exe`
 * paths are accepted: the path comes from the renderer, and nothing else in
 * the UI needs an icon.
 */
function fileIconDataUrl(target) {
  const filePath = typeof target === 'string' ? target.slice(0, 1024) : ''
  if (!path.win32.isAbsolute(filePath) || path.extname(filePath).toLowerCase() !== '.exe') {
    return Promise.resolve(null)
  }
  const key = filePath.toLowerCase()
  let icon = icons.get(key)
  if (!icon) {
    icon = Promise.all([app.getFileIcon(filePath, { size: 'normal' }), genericExecutableIcon()])
      .then(([image, generic]) => {
        if (image.isEmpty() || generic?.equals(image.toBitmap())) return null
        return image.toDataURL()
      })
      .catch(() => null)
    icons.set(key, icon)
  }
  return icon
}

module.exports = { fileIconDataUrl }
