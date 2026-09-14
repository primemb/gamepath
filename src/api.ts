import { mockApi } from './mockApi'
import type { GamePathApi } from './types'

/**
 * The bridge the preload script exposes, or the mock when there is none.
 *
 * Opening the Vite dev server in a plain browser has no Electron bridge, and
 * the mock keeps every screen explorable there rather than leaving the whole
 * app dead on the first call.
 */
export const api: GamePathApi = window.gamepath ?? mockApi
