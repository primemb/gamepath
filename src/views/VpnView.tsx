import { useState } from 'react'
import { api } from '../api'
import { PageTabs, TabPanel, type TabExtras } from '../components/PageTabs'
import { errorMessage, type Notify } from '../components/Toast'
import { VpnCoexistence } from '../components/vpn/VpnCoexistence'
import { VpnCommandCard } from '../components/vpn/VpnCommandCard'
import { VpnNodePanel } from '../components/vpn/VpnNodePanel'
import { VpnOverview } from '../components/vpn/VpnOverview'
import { VpnTargetList } from '../components/vpn/VpnTargetList'
import { VpnTargetModal } from '../components/vpn/VpnTargetModal'
import { VpnTrafficCard } from '../components/vpn/VpnTrafficCard'
import { vpnTabs, type VpnTab } from '../lib/views'
import { vpnLive, vpnOn } from '../lib/vpn'
import { L2tpModal } from '../modals/L2tpModal'
import { OpenVpnLoginModal } from '../modals/OpenVpnLoginModal'
import { Socks5Modal } from '../modals/Socks5Modal'
import type { AppState, NodeKind, OpenVpnCandidate, RuleKind, VpnProxyProbe } from '../types'

const describeProxyProbe = (probe: VpnProxyProbe) =>
  `Logged in to ${probe.proxy} in ${Math.round(probe.setupLatencyMs)} ms, and reached the Internet through it in ${Math.round(probe.latencyMs)} ms.`

type Modal =
  | { kind: 'socks5' }
  | { kind: 'l2tp' }
  | { kind: 'openvpn-login'; file: OpenVpnCandidate }
  | { kind: 'target'; initial: RuleKind }
  | null

/**
 * The VPN section: one node connected directly, beside the game session and
 * never in its way.
 */
export function VpnView({
  state,
  setState,
  notify,
  tab,
  onTabChange,
  onOpenGameTraffic,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
  tab: VpnTab
  onTabChange: (tab: VpnTab) => void
  onOpenGameTraffic: () => void
}) {
  const [modal, setModal] = useState<Modal>(null)
  const [toggling, setToggling] = useState(false)
  const { vpn } = state

  const guard = async (work: () => Promise<AppState | void>) => {
    try {
      const next = await work()
      if (next) setState(next)
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const toggle = async () => {
    setToggling(true)
    try {
      const next = vpnOn(vpn.session.status) ? await api.vpn.disconnect() : await api.vpn.connect()
      setState(next)
      if (next.vpn.session.status === 'error' && next.vpn.session.message) notify(next.vpn.session.message, 'error')
    } catch (error) {
      notify(errorMessage(error), 'error')
    } finally {
      setToggling(false)
    }
  }

  const chooseNode = (kind: NodeKind) => {
    if (kind === 'socks5' || kind === 'l2tp') {
      setModal({ kind })
      return
    }
    if (kind === 'wireguard') {
      void guard(async () => {
        const result = await api.vpn.importWireGuard()
        if (result.state) notify('WireGuard node saved for the VPN.', 'success')
        return result.state
      })
      return
    }
    void guard(async () => {
      const result = await api.vpn.chooseOpenVpn()
      if (result.canceled || !result.file) return
      if (result.file.wantsCredentials) {
        setModal({ kind: 'openvpn-login', file: result.file })
        return
      }
      const next = await api.vpn.addOpenVpn({ filePath: result.file.path })
      notify('OpenVPN node saved for the VPN.', 'success')
      return next
    })
  }

  const testSavedNode =
    vpn.node?.kind === 'l2tp' || vpn.node?.kind === 'socks5'
      ? async () => {
          try {
            if (vpn.node?.kind === 'socks5') {
              notify(describeProxyProbe(await api.vpn.testSocks5()), 'success')
              return
            }
            const probe = await api.vpn.testL2tp()
            notify(
              `L2TP/IPsec works: connected in ${Math.round(probe.setupLatencyMs)} ms, data returned in ${Math.round(probe.dataLatencyMs)} ms.`,
              'success',
            )
          } catch (error) {
            notify(errorMessage(error), 'error')
          }
        }
      : null

  const saved = (next: AppState, what: string) => {
    setState(next)
    setModal(null)
    notify(`${what} node saved for the VPN.`, 'success')
  }

  const handled = vpn.session.capture?.diagnostics?.handledConnections?.length ?? 0
  const extras: Partial<Record<VpnTab, TabExtras>> = {
    overview: { badge: vpnLive(vpn.session.status) && vpn.trafficMode === 'split' ? handled : null },
    node: { dot: vpn.node ? null : 'warning' },
    split: {
      badge: vpn.trafficMode === 'split' ? vpn.rules.filter((rule) => rule.enabled).length : null,
      dot: Object.keys(vpn.limitations).length ? 'warning' : null,
    },
  }

  return (
    <div className="vpn-page">
      <VpnCommandCard vpn={vpn} onToggle={toggle} busy={toggling} />
      <VpnCoexistence state={state} onOpenGame={onOpenGameTraffic} />
      <PageTabs scope="vpn" label="VPN sections" tabs={vpnTabs} active={tab} onChange={onTabChange} extras={extras} />
      <TabPanel scope="vpn" id={tab}>
        {tab === 'overview' && <VpnOverview vpn={vpn} onOpenTab={onTabChange} />}
        {tab === 'node' && (
          <VpnNodePanel
            node={vpn.node}
            connected={vpnLive(vpn.session.status)}
            onChoose={chooseNode}
            onTest={testSavedNode}
            onRemove={() => guard(() => api.vpn.removeNode())}
          />
        )}
        {tab === 'split' && (
          <div className="vpn-columns">
            <VpnTrafficCard
              vpn={vpn}
              onTrafficMode={(mode) => void guard(() => api.vpn.setTrafficMode(mode))}
              onRemoteDns={(enabled) => void guard(() => api.vpn.setRemoteDns(enabled))}
              onKillSwitch={(enabled) => void guard(() => api.vpn.setKillSwitch(enabled))}
            />
            <VpnTargetList
              vpn={vpn}
              onAdd={(initial) => setModal({ kind: 'target', initial })}
              onToggle={(id, enabled) => void guard(() => api.vpn.setRuleEnabled(id, enabled))}
              onRemove={(id) => void guard(() => api.vpn.removeRule(id))}
            />
          </div>
        )}
      </TabPanel>

      {modal?.kind === 'socks5' && (
        <Socks5Modal
          intro="Everything the VPN carries is forwarded to this proxy, TCP and UDP alike. Name lookups go over TCP through it, so they work even when the proxy has no UDP support."
          onClose={() => setModal(null)}
          onAdd={async (input) => saved(await api.vpn.addSocks5(input), 'SOCKS5')}
          onTest={(input) => api.vpn.testSocks5(input)}
          testLabel="Test proxy"
          resultTitle="The proxy works"
          describeResult={describeProxyProbe}
        />
      )}
      {modal?.kind === 'l2tp' && (
        <L2tpModal
          intro="The VPN uses the Windows L2TP/IPsec client. In split mode it routes websites and IP ranges; for individual apps use all-traffic mode or another kind of node."
          onClose={() => setModal(null)}
          onAdd={async (input) => saved(await api.vpn.addL2tp(input), 'L2TP/IPsec')}
          onTest={(input) => api.vpn.testL2tp(input)}
        />
      )}
      {modal?.kind === 'openvpn-login' && (
        <OpenVpnLoginModal
          files={[modal.file]}
          rejected={[]}
          onClose={() => setModal(null)}
          onConfirm={async (credentials) => {
            saved(await api.vpn.addOpenVpn({ filePath: modal.file.path, ...credentials }), 'OpenVPN')
            return []
          }}
        />
      )}
      {modal?.kind === 'target' && (
        <VpnTargetModal
          canSelectApps={vpn.canSelectApps}
          initialKind={modal.initial}
          onClose={() => setModal(null)}
          onSave={async (input) => {
            setState(await api.vpn.addRule(input))
            setModal(null)
          }}
        />
      )}
    </div>
  )
}
