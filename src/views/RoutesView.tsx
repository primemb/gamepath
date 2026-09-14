import { useState } from 'react'
import {
  ChevronDown,
  FolderPlus,
  HardDrive,
  Import,
  Layers,
  Pencil,
  Plus,
  Share2,
  ShieldCheck,
  Trash2,
  Unlink,
} from 'lucide-react'
import { api } from '../api'
import { NodeCard } from '../components/NodeCard'
import { Toggle } from '../components/Toggle'
import { errorMessage, type Notify } from '../components/Toast'
import { GroupModal } from '../modals/GroupModal'
import { L2tpModal } from '../modals/L2tpModal'
import { OpenVpnLoginModal } from '../modals/OpenVpnLoginModal'
import { Socks5Modal } from '../modals/Socks5Modal'
import { activeNodes, nodeSections, type NodeSection } from '../lib/nodes'
import type { AppState, NodeGroup, OpenVpnCandidate, OpenVpnRejection } from '../types'

type OpenVpnLogin = { files: OpenVpnCandidate[]; rejected: OpenVpnRejection[] }

/**
 * A group of nodes, or the ungrouped remainder, as one collapsible block.
 *
 * The group's switch sits in the header next to its own count so the effect of
 * flipping it is visible without opening the section — and the header stays
 * useful collapsed, which is the point of grouping a fleet in the first place.
 */
function NodeGroupSection({
  section,
  groups,
  direct,
  collapsed,
  onCollapse,
  onToggleGroup,
  onRename,
  onRemoveGroup,
  onAddNodes,
  children,
}: {
  section: NodeSection
  groups: NodeGroup[]
  direct: boolean
  collapsed: boolean
  onCollapse: () => void
  onToggleGroup: (enabled: boolean) => void
  onRename: () => void
  onRemoveGroup: () => void
  onAddNodes: () => void
  children: React.ReactNode
}) {
  const { group, nodes, activeCount } = section
  const paused = group ? !group.enabled : false
  const bodyId = `node-group-${group?.id ?? 'ungrouped'}`
  const summary = nodes.length
    ? paused
      ? `Paused · ${nodes.length} node${nodes.length === 1 ? '' : 's'}`
      : `${activeCount} of ${nodes.length} carrying`
    : 'No nodes yet'

  return (
    <section
      className={`node-group ${paused ? 'is-paused' : ''} ${collapsed ? 'is-collapsed' : ''} ${group ? '' : 'is-ungrouped'}`}
    >
      <div className="node-group-head">
        <button
          className="node-group-disclosure"
          onClick={onCollapse}
          aria-expanded={!collapsed}
          aria-controls={bodyId}
        >
          <ChevronDown className="node-group-chevron" size={16} aria-hidden="true" />
          <span className="node-group-icon" aria-hidden="true">
            {group ? <Layers size={17} /> : <Unlink size={17} />}
          </span>
          <span className="node-group-name">
            <strong>{group ? group.name : 'Ungrouped nodes'}</strong>
            <small>{summary}</small>
          </span>
        </button>

        <div className="node-group-actions">
          {group ? (
            <>
              <button className="icon-button" onClick={onRename} aria-label={`Rename ${group.name}`}>
                <Pencil size={14} aria-hidden="true" />
              </button>
              <button
                className="icon-button danger"
                onClick={onRemoveGroup}
                title="Removing the group keeps its nodes; they become ungrouped."
                aria-label={`Remove the ${group.name} group`}
              >
                <Trash2 size={14} aria-hidden="true" />
              </button>
              <span className="node-group-switch">
                <span>{group.enabled ? 'On' : 'Off'}</span>
                <Toggle
                  checked={group.enabled}
                  onChange={onToggleGroup}
                  label={`${group.enabled ? 'Disable' : 'Enable'} every node in ${group.name}`}
                />
              </span>
            </>
          ) : (
            <small className="node-group-hint">These answer to their own switch</small>
          )}
        </div>
      </div>

      {!collapsed && (
        <div className="node-group-body" id={bodyId}>
          {nodes.length ? (
            children
          ) : (
            <div className="node-group-empty">
              <p>
                Nothing here yet. Move a node into <strong>{group?.name}</strong> with the picker on its card, or add a
                new one.
              </p>
              <button className="button secondary" onClick={onAddNodes}>
                <Import size={15} aria-hidden="true" /> Add nodes
              </button>
            </div>
          )}
          {group && !group.enabled && nodes.length > 0 && (
            <p className="node-group-note">
              Every node in this group is out of the session while the group is off. Their own switches are untouched,
              so turning the group back on restores exactly this selection.
            </p>
          )}
        </div>
      )}
      {/* Direct mode carries traffic through one node, so a group switch here
          selects at most one rather than waking the whole group. */}
      {group && direct && !collapsed && nodes.length > 1 && (
        <p className="node-group-note">Direct mode uses one node, so switching this group on picks a single node.</p>
      )}
    </section>
  )
}

export function RoutesView({
  state,
  setState,
  notify,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
}) {
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set())
  const [showSocks5, setShowSocks5] = useState(false)
  const [showL2tp, setShowL2tp] = useState(false)
  const [openVpnLogin, setOpenVpnLogin] = useState<OpenVpnLogin | null>(null)
  const [creatingGroup, setCreatingGroup] = useState(false)
  const [renamingGroup, setRenamingGroup] = useState<NodeGroup | null>(null)

  const direct = state.connectionMode === 'direct'
  const sections = nodeSections(state.tunnels, state.nodeGroups)
  const carrying = activeNodes(state.tunnels, state.nodeGroups).filter(
    (node) => !(direct && node.kind === 'socks5'),
  ).length

  const toggleCollapsed = (key: string) =>
    setCollapsed((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  const guard = async (work: () => Promise<void>) => {
    try {
      await work()
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const importTunnels = () =>
    guard(async () => {
      const result = await api.importWireGuard()
      if (result.state) setState(result.state)
      if (result.errors?.length) notify(result.errors.join('\n'), 'warning')
    })

  /**
   * Chooses `.ovpn` files, then asks for a login only if they need one.
   *
   * A certificate-based file is added straight away with nothing to fill in;
   * only `auth-user-pass` brings up a dialog, and by then the files are known
   * and can be named in it.
   */
  const chooseAndAddOpenVpn = () =>
    guard(async () => {
      const choice = await api.chooseOpenVpnFiles()
      if (choice.canceled) return
      const files = choice.files ?? []
      const rejected = choice.failures ?? []
      if (!files.length) {
        notify(
          rejected.length
            ? rejected.map((failure) => `${failure.file}: ${failure.message}`).join('\n')
            : 'No files were chosen.',
          rejected.length ? 'error' : 'info',
        )
        return
      }
      if (files.some((file) => file.wantsCredentials)) {
        setOpenVpnLogin({ files, rejected })
        return
      }
      const result = await api.addOpenVpnNodes({ filePaths: files.map((file) => file.path) })
      setState(result.state)
      const failures = [...rejected, ...result.failures]
      if (failures.length)
        notify(failures.map((failure) => `${failure.file}: ${failure.message}`).join('\n'), 'warning')
    })

  const addButtons = (
    <>
      {/* Adding a proxy in direct mode would only produce a node that cannot be
          started, so it is offered in relay mode. */}
      {!direct && (
        <button className="button secondary" onClick={() => setShowSocks5(true)}>
          <Share2 size={15} aria-hidden="true" /> SOCKS5
        </button>
      )}
      <button className="button secondary" onClick={() => setShowL2tp(true)}>
        <ShieldCheck size={15} aria-hidden="true" /> L2TP
      </button>
      <button className="button secondary" onClick={chooseAndAddOpenVpn}>
        <Import size={15} aria-hidden="true" /> OpenVPN
      </button>
      <button className="button primary" onClick={importTunnels}>
        <Import size={15} aria-hidden="true" /> Import .conf
      </button>
    </>
  )

  return (
    <section className="page-section">
      <div className="node-fleet-bar">
        <div className="node-fleet-count">
          <strong>{carrying}</strong>
          <span>
            of {state.tunnels.length} node{state.tunnels.length === 1 ? '' : 's'} carrying
          </span>
        </div>
        <p className="node-fleet-copy">
          {direct
            ? 'Direct mode sends your traffic through one WireGuard, OpenVPN or L2TP/IPsec node. SOCKS5 proxies need a relay.'
            : 'Each carrying node moves relay traffic through its own VPN or proxy hop. Group nodes to switch a whole set on or off at once.'}
        </p>
        <div className="node-fleet-actions">
          <button className="button secondary" onClick={() => setCreatingGroup(true)}>
            <FolderPlus size={15} aria-hidden="true" /> New group
          </button>
          {addButtons}
        </div>
      </div>

      {state.tunnels.length || state.nodeGroups.length ? (
        <div className="node-group-list">
          {sections.map((section) => {
            const key = section.group?.id ?? '__ungrouped__'
            return (
              <NodeGroupSection
                key={key}
                section={section}
                groups={state.nodeGroups}
                direct={direct}
                collapsed={collapsed.has(key)}
                onCollapse={() => toggleCollapsed(key)}
                onToggleGroup={(enabled) =>
                  guard(async () => setState(await api.setNodeGroupEnabled(section.group!.id, enabled)))
                }
                onRename={() => setRenamingGroup(section.group)}
                onRemoveGroup={() => guard(async () => setState(await api.removeNodeGroup(section.group!.id)))}
                onAddNodes={importTunnels}
              >
                <div className="node-list">
                  {section.nodes.map((tunnel) => (
                    <NodeCard
                      key={tunnel.id}
                      tunnel={tunnel}
                      groups={state.nodeGroups}
                      groupEnabled={section.group ? section.group.enabled : true}
                      direct={direct}
                      onTest={() =>
                        tunnel.kind === 'l2tp' ? api.testSavedL2tpNode(tunnel.id) : api.testSavedSocks5Node(tunnel.id)
                      }
                      onToggle={(enabled) =>
                        guard(async () => setState(await api.setTunnelEnabled(tunnel.id, enabled)))
                      }
                      onMove={(groupId) => guard(async () => setState(await api.setTunnelGroup(tunnel.id, groupId)))}
                      onRemove={() => guard(async () => setState(await api.removeTunnel(tunnel.id)))}
                    />
                  ))}
                </div>
              </NodeGroupSection>
            )
          })}
        </div>
      ) : (
        <div className="empty-state">
          <span>
            <HardDrive size={28} aria-hidden="true" />
          </span>
          <h2>No nodes yet</h2>
          <p>
            {direct
              ? 'Add a WireGuard, OpenVPN or L2TP/IPsec node from your VPN provider. Direct mode routes through it, so it is all you need. Secrets are protected with Windows secure storage.'
              : 'Add a WireGuard, OpenVPN, L2TP/IPsec or SOCKS5 node. Private keys and passwords are protected with Windows secure storage.'}
          </p>
          <div className="empty-actions">
            <button className="button primary" onClick={importTunnels}>
              <Import size={16} aria-hidden="true" /> Import .conf files
            </button>
            <button className="button secondary" onClick={chooseAndAddOpenVpn}>
              <Import size={16} aria-hidden="true" /> Add an OpenVPN node
            </button>
            <button className="button secondary" onClick={() => setShowL2tp(true)}>
              <ShieldCheck size={16} aria-hidden="true" /> Add an L2TP/IPsec node
            </button>
            {/* A proxy cannot carry a direct session, so offering one here would
                only lead to a node that will not start. */}
            {!direct && (
              <button className="button secondary" onClick={() => setShowSocks5(true)}>
                <Share2 size={16} aria-hidden="true" /> Add a SOCKS5 proxy
              </button>
            )}
          </div>
        </div>
      )}

      {state.tunnels.length > 0 && !state.nodeGroups.length && (
        <button className="node-group-invite" onClick={() => setCreatingGroup(true)}>
          <span aria-hidden="true">
            <Plus size={18} />
          </span>
          <span>
            <strong>Group these nodes</strong>
            <small>Put a fleet under one switch so you can pause all of it at once.</small>
          </span>
        </button>
      )}

      <div className="info-banner">
        <ShieldCheck size={18} aria-hidden="true" />
        <div>
          <strong>Your VPN secrets stay on this PC</strong>
          <p>GamePath only decrypts a configuration or login when the local network service needs it.</p>
        </div>
      </div>

      {showSocks5 && (
        <Socks5Modal
          onClose={() => setShowSocks5(false)}
          onAdd={async (input) => {
            const result = await api.addSocks5Node(input)
            setState(result.state)
            setShowSocks5(false)
          }}
          onTest={(input) => api.testSocks5Node(input)}
        />
      )}
      {showL2tp && (
        <L2tpModal
          onClose={() => setShowL2tp(false)}
          onAdd={async (input) => {
            const result = await api.addL2tpNode(input)
            setState(result.state)
            setShowL2tp(false)
          }}
          onTest={(input) => api.testL2tpNode(input)}
        />
      )}
      {openVpnLogin && (
        <OpenVpnLoginModal
          files={openVpnLogin.files}
          rejected={openVpnLogin.rejected}
          onClose={() => setOpenVpnLogin(null)}
          onConfirm={async (credentials) => {
            const result = await api.addOpenVpnNodes({
              filePaths: openVpnLogin.files.map((file) => file.path),
              ...credentials,
            })
            // Whatever was added is saved either way, so the list is refreshed
            // before the dialog decides whether it still has something to say.
            setState(result.state)
            if (!result.failures.length) setOpenVpnLogin(null)
            return result.failures
          }}
        />
      )}
      {creatingGroup && (
        <GroupModal
          eyebrow="Node collection"
          createTitle="Create a node group"
          createIntro="Bundle the nodes of one provider or region under a single switch."
          editIntro="Give this group a clear, recognizable name."
          placeholder="e.g. Istanbul fleet"
          onClose={() => setCreatingGroup(false)}
          onSave={async (name) => {
            const result = await api.addNodeGroup(name)
            setState(result.state)
            setCreatingGroup(false)
          }}
        />
      )}
      {renamingGroup && (
        <GroupModal
          eyebrow="Node collection"
          createTitle="Create a node group"
          createIntro="Bundle the nodes of one provider or region under a single switch."
          editIntro="Give this group a clear, recognizable name."
          placeholder="e.g. Istanbul fleet"
          initialName={renamingGroup.name}
          onClose={() => setRenamingGroup(null)}
          onSave={async (name) => {
            setState(await api.renameNodeGroup(renamingGroup.id, name))
            setRenamingGroup(null)
          }}
        />
      )}
    </section>
  )
}
