import { useEffect, useState } from 'react'
import { AppWindow } from 'lucide-react'
import { api } from '../api'

// Remembered here as well as in the main process so a remount paints the icon
// on its first frame instead of flashing the fallback during the IPC round trip.
const loadedIcons = new Map<string, string | null>()

/** The executable's own icon, or a generic window glyph until one loads or when there is none. */
export function AppIcon({ path, size = 16 }: { path?: string; size?: number }) {
  const [icon, setIcon] = useState<string | null>(() => (path && loadedIcons.get(path)) || null)

  useEffect(() => {
    const cached = path ? loadedIcons.get(path) : null
    if (!path || cached !== undefined) {
      setIcon(cached ?? null)
      return
    }
    let active = true
    setIcon(null)
    void api
      .getFileIcon(path)
      .then((result) => {
        loadedIcons.set(path, result)
        if (active) setIcon(result)
      })
      .catch(() => undefined)
    return () => {
      active = false
    }
  }, [path])

  return icon ? (
    <img className="app-icon" src={icon} width={size} height={size} alt="" draggable={false} />
  ) : (
    <AppWindow size={size - 2} aria-hidden="true" />
  )
}
