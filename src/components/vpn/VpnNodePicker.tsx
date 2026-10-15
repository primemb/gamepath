import type { VpnState } from '../../types'

/**
 * Chooses the node a target goes through. A native select, like the game's
 * group picker, so the keyboard, screen readers and RTL behave as Windows
 * does. L2TP/IPsec is offered only as the default node: Windows routes it for
 * the whole VPN, so it cannot carry one target beside other nodes.
 */
export function VpnNodePicker({
  vpn,
  value,
  label,
  hint,
  compact = false,
  onChange,
}: {
  vpn: VpnState
  /** The node the target names; null follows the default node. */
  value: string | null
  label: string
  hint?: string
  compact?: boolean
  onChange: (nodeId: string | null) => void
}) {
  const current = value && value !== vpn.selectedNodeId ? value : ''
  return (
    <label className={compact ? 'vpn-node-picker is-compact' : 'field-label vpn-node-picker'}>
      <span className={compact ? 'sr-only' : undefined}>{label}</span>
      <select value={current} onChange={(event) => onChange(event.target.value || null)}>
        <option value="">{vpn.node ? `Default · ${vpn.node.name}` : 'Default node'}</option>
        {vpn.nodes
          .filter((node) => node.id !== vpn.selectedNodeId)
          .map((node) =>
            node.kind === 'l2tp' ? (
              <option key={node.id} value={node.id} disabled>
                {`${node.name} (default only)`}
              </option>
            ) : (
              <option key={node.id} value={node.id} data-no-translate>
                {node.name}
              </option>
            ),
          )}
      </select>
      {hint && <small>{hint}</small>}
    </label>
  )
}
