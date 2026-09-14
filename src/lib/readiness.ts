import { activeNodes } from './nodes'
import type { AppState, Tunnel } from '../types'

export type Readiness = {
  /** The nodes that will actually carry traffic, group switches included. */
  carrying: Tunnel[]
  /** In direct mode, the single node that will carry traffic — or null. */
  directNode: Tunnel | null
  enabledRules: number
  routesReady: boolean
  rulesReady: boolean
  /** Undefined in direct mode, which has no relay to set up. */
  relayReady: boolean | undefined
  readyCount: number
  stepCount: number
  direct: boolean
}

/**
 * What still stands between the user and a session that starts.
 *
 * Every screen that reports progress reads from here, so the dashboard's
 * counter, the setup drawer's steps and the start button all agree — and all
 * of them agree with the checks the main process makes when a session starts.
 */
export function deriveReadiness(state: AppState): Readiness {
  const direct = state.connectionMode === 'direct'
  const carrying = activeNodes(state.tunnels, state.nodeGroups)
  // Direct mode is ready when exactly one node is carrying and that node can
  // actually route, which is the same rule the engine enforces.
  const directNode = carrying.length === 1 && carrying[0].kind !== 'socks5' ? carrying[0] : null

  const enabledRuleGroupIds = new Set(state.ruleGroups.filter((group) => group.enabled).map((group) => group.id))
  const enabledRules = state.rules.filter(
    (rule) => rule.enabled && (!rule.groupId || enabledRuleGroupIds.has(rule.groupId)),
  ).length

  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const routesReady = direct ? directNode != null : carrying.length >= 1
  const rulesReady = state.trafficMode === 'all' || enabledRules >= 1
  const relayReady = direct ? undefined : relay?.status === 'ready'

  const steps = [routesReady, rulesReady, ...(direct ? [] : [relayReady === true])]
  return {
    carrying,
    directNode,
    enabledRules,
    routesReady,
    rulesReady,
    relayReady,
    readyCount: steps.filter(Boolean).length,
    stepCount: steps.length,
    direct,
  }
}
