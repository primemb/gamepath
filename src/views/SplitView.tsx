import { useState } from 'react'
import {
  AppWindow,
  ArrowLeft,
  ChevronRight,
  FolderOpen,
  Gamepad2,
  Globe2,
  Layers,
  Network,
  Pencil,
  Plus,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import { api } from '../api'
import { AddressWithCountry } from '../IpLocation'
import { Toggle } from '../components/Toggle'
import { errorMessage, type Notify } from '../components/Toast'
import { GroupModal } from '../modals/GroupModal'
import { RuleModal } from '../modals/RuleModal'
import type { AppState, SplitRule, SplitRuleGroup } from '../types'

/** The ungrouped bucket stands in for a group so one screen renders both. */
type SelectedGroup = { id: string | null; name: string; enabled: boolean }

const UNGROUPED = '__ungrouped__'

const ruleIcons = { application: AppWindow, folder: FolderOpen, hostname: Globe2, ip: Network }

function RuleRow({
  rule,
  groups,
  groupEnabled,
  onToggle,
  onMove,
  onRemove,
}: {
  rule: SplitRule
  groups: SplitRuleGroup[]
  groupEnabled: boolean
  onToggle: (enabled: boolean) => void
  onMove: (groupId: string | null) => void
  onRemove: () => void
}) {
  const Icon = ruleIcons[rule.kind]
  const active = rule.enabled && groupEnabled

  return (
    <div className={`table-row ${groupEnabled ? '' : 'is-group-paused'}`}>
      <span className="target-cell">
        <i aria-hidden="true">
          <Icon size={16} />
        </i>
        <strong>{rule.label}</strong>
      </span>
      <span className="kind-label">{rule.kind}</span>
      <span className="truncate">{rule.kind === 'ip' ? <AddressWithCountry value={rule.value} /> : rule.value}</span>
      <label className="rule-group-field">
        <span className="sr-only">Group for {rule.label}</span>
        <select value={rule.groupId ?? ''} onChange={(event) => onMove(event.target.value || null)}>
          <option value="">Ungrouped</option>
          {groups.map((group) => (
            <option key={group.id} value={group.id}>
              {group.name}
            </option>
          ))}
        </select>
      </label>
      <span className="rule-status-control">
        {!groupEnabled && <small>Paused</small>}
        <Toggle
          checked={rule.enabled}
          onChange={onToggle}
          label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.label}`}
        />
        <span className="sr-only">{active ? 'Active' : 'Inactive'}</span>
      </span>
      <button className="icon-button danger" onClick={onRemove} aria-label={`Remove ${rule.label}`}>
        <Trash2 size={16} aria-hidden="true" />
      </button>
    </div>
  )
}

function TrafficModeCard({ state, onChange }: { state: AppState; onChange: (mode: 'all' | 'split') => void }) {
  return (
    <div className="traffic-mode-card">
      <div>
        <span className="eyebrow">Routing scope</span>
        <h2>Choose what enters GamePath</h2>
        <p>Switch modes at any time before starting a session.</p>
      </div>
      <div className="segmented-control" role="group" aria-label="Traffic routing mode">
        <button className={state.trafficMode === 'split' ? 'active' : ''} onClick={() => onChange('split')}>
          <Gamepad2 size={15} />
          <span>
            Split tunnel<small>Selected targets</small>
          </span>
        </button>
        <button className={state.trafficMode === 'all' ? 'active' : ''} onClick={() => onChange('all')}>
          <Globe2 size={15} />
          <span>
            All IPv4 traffic<small>Whole system</small>
          </span>
        </button>
      </div>
    </div>
  )
}

export function SplitView({
  state,
  setState,
  notify,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
}) {
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null)
  const [addingTo, setAddingTo] = useState<{ groupId: string | null } | null>(null)
  const [creatingGroup, setCreatingGroup] = useState(false)
  const [editingGroup, setEditingGroup] = useState<SplitRuleGroup | null>(null)

  const guard = async (work: () => Promise<void>) => {
    try {
      await work()
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const enabledGroupIds = new Set(state.ruleGroups.filter((group) => group.enabled).map((group) => group.id))
  const enabledRules = state.rules.filter(
    (rule) => rule.enabled && (!rule.groupId || enabledGroupIds.has(rule.groupId)),
  ).length
  const ungroupedRules = state.rules.filter((rule) => !rule.groupId)
  // The engine reports this when capture starts. GamePath tunnels IPv4, so a
  // machine with a working IPv6 route keeps sending IPv6 outside the session.
  const ipv6Exposed = state.session.capture?.ipv6?.systemHasRoute === true

  const selectedGroup: SelectedGroup | null =
    selectedGroupId === UNGROUPED
      ? { id: null, name: 'Ungrouped targets', enabled: true }
      : (state.ruleGroups.find((group) => group.id === selectedGroupId) ?? null)
  const selectedGroupRules = selectedGroup
    ? state.rules.filter((rule) => (rule.groupId ?? null) === selectedGroup.id)
    : []

  const groupModalCopy = {
    eyebrow: 'Target collection',
    createTitle: 'Create a split group',
    createIntro: 'Bundle related apps, services, and destinations under one switch.',
    editIntro: 'Give this group a clear, recognizable name.',
    placeholder: 'e.g. Competitive games',
  }

  return (
    <section className="page-section">
      <TrafficModeCard state={state} onChange={(mode) => guard(async () => setState(await api.setTrafficMode(mode)))} />

      {state.trafficMode === 'all' && (
        <>
          <div className="all-traffic-banner">
            <Globe2 size={19} />
            <div>
              <strong>All-IPv4-traffic mode is active</strong>
              <p>
                Every IPv4 connection on this PC will use the multipath relay. The rules below are saved but ignored.
              </p>
            </div>
          </div>
          {ipv6Exposed && (
            <div className="all-traffic-banner is-warning">
              <ShieldAlert size={19} />
              <div>
                <strong>IPv6 is not carried</strong>
                <p>
                  This PC has a working IPv6 route, and IPv6 connections keep using your normal connection while
                  GamePath is running. Disable IPv6 on the adapter if every connection must go through the relay.
                </p>
              </div>
            </div>
          )}
        </>
      )}

      <div className={state.trafficMode === 'all' ? 'rules-disabled' : ''}>
        {selectedGroup ? (
          <div className="group-detail">
            <button className="back-button" onClick={() => setSelectedGroupId(null)}>
              <ArrowLeft size={16} aria-hidden="true" /> All groups
            </button>
            <div className={`group-detail-hero ${selectedGroup.enabled ? '' : 'is-paused'}`}>
              <span className="group-detail-icon" aria-hidden="true">
                <Layers size={24} />
              </span>
              <div>
                <span className="eyebrow">Split group</span>
                <h2>{selectedGroup.name}</h2>
                <p>
                  {selectedGroupRules.length} target{selectedGroupRules.length === 1 ? '' : 's'} ·{' '}
                  {selectedGroupRules.filter((rule) => rule.enabled && selectedGroup.enabled).length} active
                </p>
              </div>
              <div className="group-detail-actions">
                {selectedGroup.id !== null && (
                  <>
                    <button
                      className="button secondary"
                      onClick={() => setEditingGroup(selectedGroup as SplitRuleGroup)}
                    >
                      <Pencil size={15} aria-hidden="true" /> Edit name
                    </button>
                    <span className="group-power">
                      <span>{selectedGroup.enabled ? 'Group on' : 'Group off'}</span>
                      <Toggle
                        checked={selectedGroup.enabled}
                        onChange={(enabled) =>
                          guard(async () => setState(await api.setRuleGroupEnabled(selectedGroup.id!, enabled)))
                        }
                        label={`${selectedGroup.enabled ? 'Disable' : 'Enable'} ${selectedGroup.name} group`}
                      />
                    </span>
                  </>
                )}
                <button className="button primary" onClick={() => setAddingTo({ groupId: selectedGroup.id })}>
                  <Plus size={16} aria-hidden="true" /> Add target
                </button>
              </div>
            </div>
            {selectedGroupRules.length ? (
              <div className="rules-table">
                <div className="table-head">
                  <span>Target</span>
                  <span>Type</span>
                  <span>Destination</span>
                  <span>Group</span>
                  <span>Status</span>
                  <span />
                </div>
                {selectedGroupRules.map((rule) => (
                  <RuleRow
                    key={rule.id}
                    rule={rule}
                    groups={state.ruleGroups}
                    groupEnabled={selectedGroup.enabled}
                    onToggle={(enabled) => guard(async () => setState(await api.setRuleEnabled(rule.id, enabled)))}
                    onMove={(groupId) => guard(async () => setState(await api.setRuleGroup(rule.id, groupId)))}
                    onRemove={() => guard(async () => setState(await api.removeRule(rule.id)))}
                  />
                ))}
              </div>
            ) : (
              <div className="group-detail-empty">
                <Network size={24} aria-hidden="true" />
                <h3>This group is ready for targets</h3>
                <p>Add an app, folder, hostname, or IP range. You can move targets between groups later.</p>
                <button className="button primary" onClick={() => setAddingTo({ groupId: selectedGroup.id })}>
                  <Plus size={16} aria-hidden="true" /> Add first target
                </button>
              </div>
            )}
            {selectedGroup.id !== null && (
              <div className="group-danger-zone">
                <span>Removing this group keeps its targets in Ungrouped.</span>
                <button
                  className="button danger-text"
                  onClick={() =>
                    guard(async () => {
                      setState(await api.removeRuleGroup(selectedGroup.id!))
                      setSelectedGroupId(null)
                    })
                  }
                >
                  <Trash2 size={15} aria-hidden="true" /> Remove group
                </button>
              </div>
            )}
          </div>
        ) : (
          <>
            <div className="toolbar group-overview-toolbar">
              <div>
                <span className="count-badge">{enabledRules} active</span>
                <span className="muted">Open a group to manage its traffic targets.</span>
              </div>
              <button className="button primary" onClick={() => setCreatingGroup(true)}>
                <Plus size={16} aria-hidden="true" /> New group
              </button>
            </div>
            {state.ruleGroups.length || ungroupedRules.length ? (
              <div className="split-group-grid">
                {state.ruleGroups.map((group) => {
                  const rules = state.rules.filter((rule) => rule.groupId === group.id)
                  const activeCount = rules.filter((rule) => rule.enabled && group.enabled).length
                  return (
                    <article className={`split-group-card ${group.enabled ? '' : 'is-paused'}`} key={group.id}>
                      <button className="split-group-open" onClick={() => setSelectedGroupId(group.id)}>
                        <span className="split-group-card-icon" aria-hidden="true">
                          <Layers size={22} />
                        </span>
                        <span className="split-group-card-copy">
                          <strong>{group.name}</strong>
                          <small>
                            {group.enabled ? `${activeCount} active` : 'Paused'} · {rules.length} targets
                          </small>
                        </span>
                        <ChevronRight size={18} aria-hidden="true" />
                      </button>
                      <div className="split-group-card-footer">
                        <span>{group.enabled ? 'Traffic enabled' : 'Traffic paused'}</span>
                        <Toggle
                          checked={group.enabled}
                          onChange={(enabled) =>
                            guard(async () => setState(await api.setRuleGroupEnabled(group.id, enabled)))
                          }
                          label={`${group.enabled ? 'Disable' : 'Enable'} ${group.name} group`}
                        />
                      </div>
                    </article>
                  )
                })}
                {ungroupedRules.length > 0 && (
                  <article className="split-group-card is-ungrouped">
                    <button className="split-group-open" onClick={() => setSelectedGroupId(UNGROUPED)}>
                      <span className="split-group-card-icon" aria-hidden="true">
                        <Network size={22} />
                      </span>
                      <span className="split-group-card-copy">
                        <strong>Ungrouped targets</strong>
                        <small>
                          {ungroupedRules.filter((rule) => rule.enabled).length} active · {ungroupedRules.length}{' '}
                          targets
                        </small>
                      </span>
                      <ChevronRight size={18} aria-hidden="true" />
                    </button>
                    <div className="split-group-card-footer">
                      <span>Move these into a group anytime</span>
                    </div>
                  </article>
                )}
                <button className="create-group-card" onClick={() => setCreatingGroup(true)}>
                  <span aria-hidden="true">
                    <Plus size={21} />
                  </span>
                  <strong>Create another group</strong>
                  <small>Bundle targets under one on/off switch</small>
                </button>
              </div>
            ) : (
              <div className="empty-state group-empty-state">
                <span>
                  <Layers size={28} aria-hidden="true" />
                </span>
                <h2>Create your first split group</h2>
                <p>Keep each game and its related services together, then turn the whole group on or off.</p>
                <button className="button primary" onClick={() => setCreatingGroup(true)}>
                  <Plus size={16} aria-hidden="true" /> Create group
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {addingTo && (
        <RuleModal
          groups={state.ruleGroups}
          initialGroupId={addingTo.groupId}
          onClose={() => setAddingTo(null)}
          onSave={async (input) => {
            setState(await api.addRule(input))
            setAddingTo(null)
          }}
        />
      )}
      {creatingGroup && (
        <GroupModal
          {...groupModalCopy}
          onClose={() => setCreatingGroup(false)}
          onSave={async (name) => {
            setState(await api.addRuleGroup(name))
            setCreatingGroup(false)
          }}
        />
      )}
      {editingGroup && (
        <GroupModal
          {...groupModalCopy}
          initialName={editingGroup.name}
          onClose={() => setEditingGroup(null)}
          onSave={async (name) => {
            setState(await api.renameRuleGroup(editingGroup.id, name))
            setEditingGroup(null)
          }}
        />
      )}
    </section>
  )
}
