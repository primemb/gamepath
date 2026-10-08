// Run with: electron scripts/generate-status-icons.cjs
const { app, BrowserWindow } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { MODES, INDICATORS } = require('../electron/desktop-status.cjs')

const sizes = [16, 20, 24, 32, 40, 48, 64, 256]
const dpi = new Map([
  [16, ''],
  [20, '@1.25x'],
  [24, '@1.5x'],
  [32, '@2x'],
  [40, '@2.5x'],
  [48, '@3x'],
  [64, '@4x'],
])

function statusSvg(mode, indicator) {
  const shield = '<path d="M32 9 49 16v14c0 12-9 20-17 25-8-5-17-13-17-25V16Z" fill="#38bdf8"/>'
  const controller =
    '<path d="M20 22h24c6 0 9 5 10 12l2 10c1 7-5 10-9 5l-5-5H22l-5 5c-4 5-10 2-9-5l2-10c1-7 4-12 10-12Z" fill="#6ee7b7"/><path d="M19 29v10m-5-5h10" stroke="#102136" stroke-width="4" stroke-linecap="round"/><circle cx="43" cy="31" r="2.5" fill="#102136"/><circle cx="48" cy="37" r="2.5" fill="#102136"/>'
  const symbol = {
    off: '<path d="M22 18a18 18 0 1 0 20 0M32 10v23" fill="none" stroke="#cbd5e1" stroke-width="6" stroke-linecap="round"/>',
    vpn: `${shield}<path d="m24 31 6 6 11-13" fill="none" stroke="#102136" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>`,
    game: controller,
    both: `${shield}<g transform="translate(6.4 15) scale(.8)"><g stroke="#102136" stroke-width="5" stroke-linejoin="round">${controller}</g>${controller}</g>`,
  }[mode]
  const mark = {
    normal: '',
    busy: '<circle cx="49" cy="14" r="12" fill="#fbbf24" stroke="#102136" stroke-width="3"/><path d="M49 7v7l4 3" fill="none" stroke="#102136" stroke-width="3" stroke-linecap="round"/>',
    warning:
      '<path d="m49 2 14 24H35Z" fill="#fbbf24" stroke="#102136" stroke-width="2" stroke-linejoin="round"/><path d="M49 10v6" stroke="#102136" stroke-width="3" stroke-linecap="round"/><circle cx="49" cy="21" r="1.8" fill="#102136"/>',
    paused:
      '<circle cx="49" cy="14" r="12" fill="#fbbf24" stroke="#102136" stroke-width="3"/><path d="M45 8v12m8-12v12" stroke="#102136" stroke-width="4"/>',
    error:
      '<circle cx="49" cy="14" r="12" fill="#fb7185" stroke="#102136" stroke-width="3"/><path d="m44 9 10 10m0-10L44 19" stroke="#102136" stroke-width="3" stroke-linecap="round"/>',
  }[indicator]
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="1" y="1" width="62" height="62" rx="16" fill="#102136" stroke="#64748b" stroke-width="2"/>${symbol}${mark}</svg>`
}

function ico(images) {
  const header = Buffer.alloc(6 + images.length * 16)
  header.writeUInt16LE(1, 2)
  header.writeUInt16LE(images.length, 4)
  let offset = header.length
  images.forEach(({ size, png }, index) => {
    const entry = 6 + index * 16
    header[entry] = size === 256 ? 0 : size
    header[entry + 1] = header[entry]
    header.writeUInt16LE(1, entry + 4)
    header.writeUInt16LE(32, entry + 6)
    header.writeUInt32LE(png.length, entry + 8)
    header.writeUInt32LE(offset, entry + 12)
    offset += png.length
  })
  return Buffer.concat([header, ...images.map(({ png }) => png)])
}

app
  .whenReady()
  .then(async () => {
    const window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true } })
    try {
      await window.loadURL('about:blank')
      const destination = path.join(__dirname, '..', 'electron', 'assets', 'status')
      fs.mkdirSync(destination, { recursive: true })
      for (const mode of MODES) {
        for (const indicator of INDICATORS) {
          const key = `${mode}-${indicator}`
          const svg = statusSvg(mode, indicator)
          fs.writeFileSync(path.join(destination, `${key}.svg`), `${svg}\n`)
          const images = []
          for (const size of sizes) {
            const pngUrl = await window.webContents.executeJavaScript(`(async () => {
            const image = new Image()
            image.src = ${JSON.stringify(`data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`)}
            await image.decode()
            const canvas = document.createElement('canvas')
            canvas.width = canvas.height = ${size}
            canvas.getContext('2d').drawImage(image, 0, 0, ${size}, ${size})
            return canvas.toDataURL('image/png')
          })()`)
            const png = Buffer.from(pngUrl.split(',')[1], 'base64')
            images.push({ size, png })
            if (dpi.has(size)) fs.writeFileSync(path.join(destination, `${key}${dpi.get(size)}.png`), png)
          }
          fs.writeFileSync(path.join(destination, `${key}.ico`), ico(images))
        }
      }
      console.log(`Generated ${MODES.length * INDICATORS.length} status icons in ${destination}`)
    } finally {
      window.destroy()
      app.quit()
    }
  })
  .catch((error) => {
    console.error(error)
    app.exit(1)
  })
