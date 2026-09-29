const path = require('node:path')
const { nativeImage } = require('electron')

/**
 * Icons of executables, as data URLs, read by the unprivileged engine.
 *
 * Electron's `app.getFileIcon` returns the stock Windows icon for some
 * executables that have their own (BsgLauncher.exe, for one), so the engine
 * reads the icon resource directly. `null` means the file has no icon and the
 * UI draws its placeholder.
 *
 * Answers are kept for the life of the app: an executable's icon does not
 * change while it runs. A failed request is not kept, so an engine that was
 * briefly unavailable does not leave a placeholder behind for good.
 */
function createFileIconLookup(request) {
  const icons = new Map()

  return function fileIconDataUrl(target) {
    const filePath = typeof target === 'string' ? target.slice(0, 1024) : ''
    // A drive path only: the path comes from the renderer, and reading a UNC
    // path would make Windows authenticate to whatever server it names.
    if (!/^[a-z]:\\/i.test(filePath) || path.win32.extname(filePath).toLowerCase() !== '.exe') {
      return Promise.resolve(null)
    }
    const key = filePath.toLowerCase()
    let icon = icons.get(key)
    if (!icon) {
      icon = Promise.resolve(filePath)
        .then(request)
        .then((result) =>
          result?.bgra
            ? nativeImage
                .createFromBitmap(Buffer.from(result.bgra, 'base64'), { width: result.width, height: result.height })
                .toDataURL()
            : null,
        )
      icon.catch(() => icons.delete(key))
      icons.set(key, icon)
    }
    return icon.catch(() => null)
  }
}

module.exports = { createFileIconLookup }
