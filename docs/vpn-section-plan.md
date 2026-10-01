# VPN section — implementation plan

Status: implemented (phases 0–7), awaiting hardware testing · Owner: GamePath client · Target: 0.3.0

Owner decisions: sessions stop on quit; SOCKS5 forwards all UDP to the proxy and never blocks or bypasses it;
the kill switch is a user toggle, off by default. The behaviour as built is described in the README's _VPN_
section and in `docs/architecture.md` under _Concurrent sessions_; where this plan and those differ, they win.

## 1. Goal

Add a second, independent connection next to the game session: a **VPN** for everyday use on a
restricted network. It runs at the same time as the game session and never weakens it.

| Traffic                         | Goes through                        |
| ------------------------------- | ----------------------------------- |
| Apps selected in the game rules | Game session (relay or direct)      |
| Apps selected in the VPN rules  | VPN node                            |
| Everything else                 | Normal internet                     |
| App selected in both            | **Game session** — game always wins |

VPN rules:

- Exactly **one** node, connected **directly** (no relay, no duplication, no loss repair).
- Node kinds: WireGuard, OpenVPN, L2TP/IPsec, SOCKS5.
- Split tunnel by application, folder, hostname or IP — the same selectors as the game, with the
  same per-protocol limits (L2TP split cannot select apps; see §6.4).
- Optional all-traffic mode ("everything that is not the game goes through the VPN").
- Connect/disconnect, rule edits and node changes in the VPN never restart, reconfigure or slow down
  the game session.

Non-goals for this version: IPv6 tunnelling (the project is IPv4 end to end), more than one VPN
node, a LAN proxy for the VPN, VPN through the relay.

## 2. Design decisions

### 2.1 Two service slots, two engine children

The service gets two independent **session slots**, `game` and `vpn`. Each slot owns its own
engine child (own Job Object), lease, rules, L2TP connections and status. A crash, hang or slow
dial in the VPN slot cannot block or tear down the game slot.

Rejected alternative: one engine process with a three-way classifier. It would save one user-space
round trip for unselected traffic, but it couples the two lifecycles — a VPN restart or panic would
take the game down — which conflicts with "avoid user lost connection".

### 2.2 Priority is enforced by WinDivert, not by coordination

WinDivert (2.2 docs, `WinDivertOpen`): _"Packets are diverted to higher priority handles before
lower priority handles"_ and _"Injected packets can be captured and diverted again by other
WinDivert handles with lower priorities."_

So:

- Game capture handles keep priority **0** (unchanged — the game session behaves exactly as today).
- VPN capture handles open at priority **−1000**.
- The game handle sees every packet first. What it selects never reaches the VPN. What it
  reinjects as unselected falls through to the VPN handle, which selects or reinjects it again.

No cross-process lock or message is needed on the packet path.

### 2.3 Each slot excludes the other slot's transport ("foreign bypass")

Neither engine may capture the other's tunnel sockets (relay, WireGuard endpoint, OpenVPN server,
SOCKS5 proxy, L2TP server). Each engine already excludes its **own** transport by destination IP
(`bypass_clause` in `split_capture.rs`). The service extends that with the **other** slot's
`bypass_ips`, passed as `foreignBypass`:

- Split capture puts them in the kernel filter (`ip.DstAddr != …`), so they never reach user space.
- All-traffic capture (Wintun) and native L2TP all-traffic install them as `/32` routes via the
  physical gateway, exactly like the engine's own bypass routes today.
- When the game slot starts or its relay changes (relay failover), the service pushes the new set to
  the VPN slot with a new engine command, `set-foreign-bypass`. The VPN may rebuild its filter (a
  sub-second blip is acceptable in the lower-priority slot). The game slot is never rebuilt because
  of the VPN; for the game the foreign bypass is only an optimisation, applied on its next start.

### 2.4 Mode compatibility (game wins)

| Game \ VPN                           | VPN split | VPN all-traffic |
| ------------------------------------ | --------- | --------------- |
| Game idle                            | ✔         | ✔               |
| Game split (WireGuard/OpenVPN/relay) | ✔         | ✔ (§6.3)        |
| Game direct L2TP split (routes)      | ✔         | ✔ (§6.3)        |
| Game all-traffic (any)               | paused    | paused          |

"Paused" means the VPN slot is stopped with reason `game-all-traffic`, the UI says why, and the VPN
resumes automatically when the game session stops or changes to split. Starting the game is never
refused because of the VPN.

The policy lives in one pure function, `sessionCompatibility(game, vpn)` in
`electron/session-coordinator.cjs`, unit-tested over the whole matrix.

### 2.5 DNS

Today a split session tunnels every public port-53 query, whatever process sent it (Windows sends
DNS from `svchost.exe`). With two slots this falls out of priority: while the game slot has remote
DNS on, it carries every public query; otherwise the VPN slot does (if its remote DNS is on);
otherwise normal resolution. Hostname rules are unaffected, because each engine's DNS observer is a
copy-only sniff handle and sees every reply.

Each slot that needs a resolver adapter uses its **own** Wintun adapter (§2.6), so the two never
overwrite each other's DNS settings.

### 2.6 Engine role

One new CLI argument, `gamepath-engine.exe --role vpn` (no argument = `game`, so every existing
caller is unchanged), selects a `Role` (`engine/src/role.rs`) that owns everything that must differ:

| Property                 | game (default)             | vpn                             |
| ------------------------ | -------------------------- | ------------------------------- |
| Log component / file     | `engine` / `engine.log`    | `engine-vpn` / `engine-vpn.log` |
| WinDivert priority       | 0                          | −1000                           |
| Wintun adapter name/GUID | `GamePath` / existing GUID | `GamePath VPN` / new fixed GUID |
| Data-plane thread prio   | `THREAD_PRIORITY_HIGHEST`  | `THREAD_PRIORITY_ABOVE_NORMAL`  |

The lower thread priority keeps the game's packet threads ahead of the VPN's when CPU is contended
(a game in the foreground is exactly that case).

### 2.7 SOCKS5 as a VPN node (tun2socks)

A SOCKS5 proxy cannot route raw packets, which is why direct mode refuses it today. The VPN gets a
new direct path, `DirectPath::Socks5Stack`, that **terminates** the captured IP traffic locally in a
smoltcp stack (already a dependency, used by the LAN proxy) and replays it through the proxy:

- TCP: each SYN creates a listening socket on its destination (`set_any_ip(true)`); the accepted
  connection is bridged to a SOCKS5 `CONNECT` to the original destination.
- UDP: always forwarded to the proxy with `UDP ASSOCIATE`, whether or not the proxy is known to
  support it (owner decision: GamePath forwards, what the proxy does with it is the proxy's
  business). Nothing is blocked and nothing is sent around the proxy.
- DNS over UDP is always converted to **DNS over TCP through `CONNECT`** to the configured
  resolver, so name lookups work through TCP-only proxies and are not hijacked locally.

Because it implements the same `send_packet` / `receive_packets` contract as WireGuard and OpenVPN,
the capture layer does not change. The game keeps refusing SOCKS5 in direct mode (game traffic is
UDP and must not be TCP-terminated); only the `vpn` slot accepts it.

### 2.8 Renderer stays a view

All decisions (compatibility, pause reasons, conflicts between game and VPN rules, "can this node
do app split") are computed in the main process in tested `.cjs` modules and published in
`publicState().vpn`. The renderer only displays them, so behaviour is covered by `node --test` even
though the renderer has no test runner.

## 3. Bugs found during the survey

| #   | Where                                    | Problem                                                                                                                                                                                                 | Action                                                                                        |
| --- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| B1  | `electron/main.cjs` `loadState`          | Any parse/normalise error reset to defaults and the next save overwrote the user's nodes and encrypted configs.                                                                                         | **Fixed now**: an unreadable file is kept as `gamepath-state.json.corrupt-<ts>` and logged.   |
| B2  | `service/src/main.rs` `start_session`    | Kills a running engine child without `stop-wireguard-session`, so `Drop` never removes its `0.0.0.0/1`/`128.0.0.0/1` routes; a following split session could be black-holed until the service restarts. | Fix in Phase 1 (slot restart goes through the normal stop path).                              |
| B3  | `service/src/main.rs` `validate_runtime` | Writes `session_status = "validated"` into the live state, which would knock a connected session out of `connected`. Harmless today, fatal with two slots.                                              | Fix in Phase 1 (validation becomes pure).                                                     |
| B4  | `service/src/main.rs`                    | `start_session` holds the single state lock for the whole start (L2TP dial can take tens of seconds); `session-status` for the other slot would time out and the client would tear it down.             | Fix in Phase 1 (per-slot locks).                                                              |
| B5  | `electron/main.cjs` `before-quit`        | Quitting does not stop the session; capture and routes stay up until the 30 s lease expires.                                                                                                            | Phase 0: stop both slots on quit with a 3 s cap, lease stays the safety net (owner approved). |

## 4. Architecture changes by component

### 4.1 Engine (`engine/`)

| File                                                                 | Change                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/role.rs` (new)                                                  | `Role { Game, Vpn }`, parsed from `--role`; accessors for log component, adapter identity, capture priority, data-plane thread priority. Unit tests for parsing and the table in §2.6.                                                                                                                                                                                          |
| `src/main.rs`                                                        | Parse `--role` before `log::init`; pass `Role` into `PacketCaptureManager` and `WireGuardSessionManager`. New command `set-foreign-bypass`.                                                                                                                                                                                                                                     |
| `src/split_capture.rs`                                               | `Handle::open(.., priority: i16)`; filter builder takes `own_bypass + foreign_bypass`; `update` accepts a new foreign bypass. Extract the filter builder into a pure function so it is unit-tested without WinDivert.                                                                                                                                                           |
| `src/capture.rs`                                                     | Adapter name/GUID from `Role`; all-traffic bypass routes include `foreign_bypass`; `set_foreign_bypass` adds/removes only the delta routes.                                                                                                                                                                                                                                     |
| `src/thread_priority.rs`                                             | `raise_current_for_data_plane(role)`.                                                                                                                                                                                                                                                                                                                                           |
| `src/relay_path.rs`                                                  | `NodeSpec::open_direct(role)` accepts SOCKS5 for `Role::Vpn` → `DirectPath::Socks5Stack`.                                                                                                                                                                                                                                                                                       |
| `src/tun2socks/` (new, Windows, behind the existing smoltcp feature) | `mod.rs` (`Socks5Stack`: the `DirectPath` contract), `stack.rs` (smoltcp any-IP interface, SYN → listener), `connect.rs` (SOCKS5 `CONNECT` client, reuses RFC 1929 auth from `socks5.rs`), `udp.rs` (per-flow `UDP ASSOCIATE`, generic destination header), `dns.rs` (UDP DNS → DNS-over-TCP), `health.rs` (periodic `CONNECT` latency to the resolver; three failures = down). |
| `src/session/direct_worker.rs`                                       | Health for the SOCKS5 path from `tun2socks::health` instead of the ICMP echo (ICMP cannot cross a proxy).                                                                                                                                                                                                                                                                       |

### 4.2 Service (`service/src/main.rs`)

Split the 2335-line file while touching it, without behaviour change for the game slot:

| File                | Content                                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `main.rs`           | Service entry, listener, dispatcher.                                                                                                                                                   |
| `slot.rs`           | `SlotId { Game, Vpn }`, `SessionSlot` (today's `RuntimeState` fields), start/stop/status/update for one slot.                                                                          |
| `registry.rs`       | `SlotRegistry { game: Mutex<SessionSlot>, vpn: Mutex<SessionSlot>, shared: Mutex<SharedNet> }`; `SharedNet` holds each slot's bypass set and pushes `set-foreign-bypass` to the other. |
| `lease.rs`          | Watchdog: one deadline per slot, checked every 250 ms, tears down only the expired slot.                                                                                               |
| `l2tp.rs`           | RAS profile, dial, routes, probe (moved, unchanged).                                                                                                                                   |
| `engine_process.rs` | `EngineProcess::start(role)` — passes `--role`.                                                                                                                                        |

Wire protocol: every session command (`validate-runtime`, `start-session`, `update-session-rules`,
`update-lan-proxy`, `session-status`, `stop-session`) gains an optional `"slot": "game" | "vpn"`,
default `game`. Old clients and every existing test keep working. `status` reports
`sessionStatus` (game, unchanged) plus `slots: { game, vpn }`.

Rules enforced by the service, not trusted from the client:

- `vpn` slot: `mode` must be `direct`, exactly one node, no LAN proxy.
- `vpn` slot refuses to start while the game slot is all-traffic (error code `game-all-traffic`),
  and the service stops the VPN slot itself if the game switches to all-traffic.
- `validate-runtime` writes nothing (B3).

### 4.3 Electron main (`electron/`)

Keep `main.cjs` from growing: it only wires new modules.

| File                            | Content                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vpn-state.cjs` (new)           | `defaultVpn()`, `normalizeVpn(saved)` (never throws, garbage → defaults), `publicVpn(vpn, game)`, rule add/toggle/remove as pure functions, `ruleConflicts(vpnRules, gameRules)`.                                                                                                                                                                                               |
| `session-coordinator.cjs` (new) | `sessionCompatibility(game, vpn)` → `{ allowed, pauseReason }`; decides pause/resume.                                                                                                                                                                                                                                                                                           |
| `vpn-session.cjs` (new)         | `VpnSessionController` with injected `{ service, logger, usage, now, setInterval }`: `start`, `stop`, `applyRules`, keep-alive poll (`VPN_POLL_MS = 3000`, same lease headroom as the game), 3-failure teardown, reconnect with backoff 1 s → 2 s → 5 s → 10 s → 30 s while the user wants it on, resume after `powerMonitor` `resume`, pause/resume driven by the coordinator. |
| `vpn-ipc.cjs` (new)             | `registerVpnIpc({ ipcMain, dialog, state, save, encrypt, controller, ... })` — all `vpn:*` channels. Reuses the existing parsers in `wireguard.cjs`, `openvpn.cjs`, `socks5.cjs`, `l2tp.cjs`.                                                                                                                                                                                   |
| `usage.cjs`                     | Split into `UsageStore` (DB, upsert, query) and a per-session `UsageSession` (baselines) with a category prefix. Game keeps the current categories; VPN writes `vpn-total`, `vpn-node`, `vpn-app`.                                                                                                                                                                              |
| `logger.cjs`                    | `logger.scope('vpn')` returns the same API with a `[vpn <sessionId>]` prefix.                                                                                                                                                                                                                                                                                                   |
| `main.cjs`                      | Strip **every** `encrypted*` key in `publicState()` (generic, so a new secret field cannot leak); call `registerVpnIpc`; notify the coordinator when the game session changes; stop both slots on quit (B5).                                                                                                                                                                    |
| `preload.cjs`                   | `window.gamepath.vpn = { … }` namespace.                                                                                                                                                                                                                                                                                                                                        |

Persisted state (`gamepath-state.json`):

```js
vpn: {
  node: null | { id, kind, name, endpoint, ..., hasCredentials },   // same public shape as a tunnel
  trafficMode: 'split' | 'all',          // default 'split'
  remoteDns: true,
  killSwitch: false,                     // user toggle, §6.2
  rules: [{ id, kind, value, label, enabled }],
  wantConnected: false,                  // user intent, drives auto-reconnect
},
encryptedVpnConfig: '<safeStorage base64>' // stripped by publicState
```

Runtime-only (`publicState().vpn.session`): `status` (`idle | connecting | connected | degraded |
paused | error`), `pauseReason`, `message`, `sessionId`, `startedAt`, `pathMetrics`, `capture`,
`metrics`, `conflicts` (VPN rules also selected by the game).

IPC channels (all return `publicState()` unless noted):

```
vpn:import-wireguard   vpn:choose-openvpn   vpn:add-openvpn   vpn:add-socks5   vpn:add-l2tp
vpn:test-node          vpn:remove-node
vpn:set-traffic-mode   vpn:set-remote-dns   vpn:set-kill-switch
vpn:add-rule           vpn:set-rule-enabled vpn:remove-rule
vpn:connect            vpn:disconnect       vpn:status
```

Adding a node while one exists replaces it (after confirmation in the UI); a connected VPN
reconnects on the new node.

### 4.4 Renderer (`src/`)

| File                                | Content                                                                                                                                                                                  |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/views.ts`                      | New view `vpn`, nav item "VPN" (`ShieldCheck` icon) directly under Overview, with a live dot when connected.                                                                             |
| `views/VpnView.tsx`                 | Page composition only.                                                                                                                                                                   |
| `components/vpn/VpnCommandCard.tsx` | Status, node, latency, ↑/↓ rate, uptime, connect button.                                                                                                                                 |
| `components/vpn/VpnCoexistence.tsx` | Game-session chip / paused banner.                                                                                                                                                       |
| `components/vpn/VpnNodePanel.tsx`   | Empty state with the four node kinds; node details, Test, Replace, Remove. Reuses `Socks5Modal`, `L2tpModal`, `OpenVpnLoginModal` (they already take `onAdd` / `onTest` props).          |
| `components/vpn/VpnTrafficCard.tsx` | Split / All segmented control, remote DNS, kill switch.                                                                                                                                  |
| `components/vpn/VpnTargetList.tsx`  | Apps and targets with real exe icons (`AppIcon`), toggles, conflict badges. Reuses `RuleModal` (its group selector becomes optional).                                                    |
| `components/VpnStatusCard.tsx`      | Small Overview card, same pattern as `LanProxyCard`.                                                                                                                                     |
| `lib/usePathTelemetry.ts`           | The body of `useSessionTelemetry`, taking a session object; the game hook becomes a one-line wrapper (no behaviour change).                                                              |
| `vpn.css`                           | Feature stylesheet, imported in `main.tsx`.                                                                                                                                              |
| `types.ts`, `api.ts`, `mockApi.ts`  | `VpnState`, `VpnSession`, `GamePathApi['vpn']`; a mock VPN that connects, animates latency/bytes and can simulate `paused` and `error`, so the section is explorable in a plain browser. |
| `lib/persian.ts`                    | Every new string, plus an RTL check of the page.                                                                                                                                         |

Tray: add "Connect VPN" / "Disconnect VPN" so a player in a fullscreen game does not have to
alt-tab.

## 5. UI design

Guidance from the ui-ux-pro-max skill, applied to the **existing** tokens in `styles.css` (the
generated palette is not adopted; it would clash with the current dark theme).

**Identity.** The game uses cyan (`--cyan`). The VPN uses **violet** (`--violet`) everywhere it is
represented — nav dot, command card glow, Overview card, tray label — so the two sessions are never
confused at a glance. Tokens added in `vpn.css`: `--vpn-accent: var(--violet)`,
`--vpn-accent-soft: rgba(138, 124, 255, 0.12)`.

**Layout of the VPN page** (top to bottom, in `.page-section`):

1. **Command card** — shield icon, headline state ("Protected" / "Connecting…" / "Paused" /
   "Not connected"), node name + kind pill + endpoint, three stats (latency, ↓/↑ rate, uptime), and a
   single primary button. The state is always text + icon, never colour alone.
2. **Coexistence strip** — "Game session · Connected · takes priority" chip when the game is on.
   When paused: warning banner "Your game session is carrying all traffic. The VPN resumes when it
   stops." with a button to open the game's traffic settings.
3. **Node panel** — empty state: "Add your VPN node" with four large kind buttons (WireGuard,
   OpenVPN, SOCKS5, L2TP/IPsec), each with a one-line hint. With a node: details, Test, Replace,
   Remove.
4. **Traffic card** — Split apps / All traffic segmented control; remote DNS toggle; kill switch.
5. **Apps and targets** — rows with real application icons; "Add app", "Add folder",
   "Add website or IP". A row also selected by the game gets the badge "Game rule wins". For L2TP
   nodes in split mode, app/folder buttons are disabled with the reason written next to them.
6. **Live connections** — `HandledConnections` fed by the VPN capture.

**Rules applied (priority order from the skill):**

- Accessibility: 4.5:1 text contrast on `--panel`; visible focus rings; `aria-label` on every
  icon-only button; status changes announced through `aria-live="polite"`, errors through
  `role="alert"` next to the control that failed, with a recovery action ("Try again",
  "Test node").
- Interaction: targets ≥ 44 px high; the connect button is disabled with a spinner while a request
  is in flight (no double submission); every async action gives feedback within 100 ms.
- Motion: 150–250 ms transitions on state and hover; the connected glow reuses
  `@keyframes command-pulse`; all motion respects `prefers-reduced-motion`.
- Forms: visible labels, inline errors under the field, helper text for protocol limits.
- Navigation: the active nav item is highlighted; the Overview card deep-links to the VPN page.
- Layout: works at the app's 1000 px minimum width and in RTL.
- Icons: `lucide-react` only, decorative icons `aria-hidden`.

## 6. Networking details

### 6.1 Packet path with both slots in split mode

```
app packet ─▶ WinDivert game handle (prio 0)
               ├─ selected by game ─▶ game engine ─▶ relay / node
               └─ reinject ─▶ WinDivert vpn handle (prio −1000)
                               ├─ selected by VPN ─▶ vpn engine ─▶ VPN node
                               └─ reinject ─▶ normal internet
```

Cost: normal traffic pays one extra user-space round trip **only** when both slots run in the
`all-outbound` scope (app/folder/hostname rules). Game packets are unaffected — they are taken by
the first handle. The harness in §8.3 measures this.

### 6.2 Fail-open vs kill switch

Today a split session fails open: if no path is up, `enqueue_data_packet` errors and the packet is
reinjected. The game keeps that. The VPN offers a **kill switch** (off by default): while the VPN
is down, packets selected by the VPN are dropped instead of leaking to the filtered network.

### 6.3 VPN all-traffic next to a game split session

The VPN installs `0.0.0.0/1` and `128.0.0.0/1` on its own adapter (`GamePath VPN`). The game's
packets are still taken by the game handle first, because WinDivert's network layer sees the packet
after route selection but before it leaves. The game engine's own transport sockets would follow
the VPN routes, so the VPN installs the game's `bypass_ips` as `/32` routes via the physical gateway
(§2.3). Replies for game flows are injected with the interface index the packet was captured on,
which is now the VPN adapter. **This needs hardware verification** (§8.3) before the mode ships;
if inbound injection on the VPN adapter misbehaves, the fallback is to pin the game engine's
transport sockets with `IP_UNICAST_IF` (already implemented as `transport::bind_to_interface`).

### 6.4 L2TP as the VPN node

Uses the existing native RAS path per slot. Split mode installs Windows routes, so it accepts IP
and exact-hostname rules only (same limit as game direct L2TP); the UI says so instead of failing
at connect. All-traffic mode lets RAS own the default route; the service adds the game's bypass
routes. Profile names are already unique per dial (`GamePath-L2TP-{pid}-{route}-{seq}`).

### 6.5 Reconnect and recovery

- WireGuard/OpenVPN paths already re-handshake on their own.
- The VPN controller reconnects with backoff while `wantConnected` is true: after the service
  reports the slot idle or failed, after three failed status polls, and after `powerMonitor`
  `resume`.
- When the game pauses the VPN, the controller resumes it without user action.
- Uplink changes (Wi-Fi ↔ Ethernet): bypass routes are recomputed by the slot that owns them on the
  next `set-foreign-bypass` or restart; tracked as a follow-up if testing shows a gap.

### 6.6 IPv6

Unchanged project rule: IPv4 only. On a restricted network an IPv6 path lets VPN-selected apps
reach a filtered site directly, so the VPN page shows the same IPv6 warning as the game. A
follow-up (not in this version) can drop IPv6 from VPN-selected processes so they fall back to IPv4.

## 7. Logging

Goal: one session can be followed end to end from the log files alone, without secrets.

- **Session id**: Electron creates a short id per VPN start (`vpn-3f9a1c`). It is passed to the
  service and engine and appears on every line about that session in `client.log`, `service.log`
  and `engine-vpn.log`.
- **Separate engine log**: `engine-vpn.log` (role component), so the two engines never interleave or
  race on rotation.
- **Service**: every slot line is prefixed `[game]` or `[vpn]`.
- **What is logged** (info): start requested (node kind, traffic mode, rule count), each start step
  with its duration (dial, handshake, capture), connected, state transitions (degraded / recovered
  / paused with reason / resumed), reconnect attempts with backoff, rule changes (counts), foreign
  bypass updates (count), stop with reason (user, lease, pause, quit, error).
- **Errors** carry the step that failed and what to check ("no WireGuard handshake reply within 3 s
  — check the endpoint and public key"), never a bare timeout.
- **Never logged**: configs, keys, passwords, PSKs, tokens. Endpoints use `log::fingerprint` where
  they must be correlated.
- **Debug level** (`GAMEPATH_LOG=debug`): per-packet decisions stay out; only aggregated counters
  every 30 s (selected / reinjected / dropped by kill switch / tunnelled DNS).

## 8. Testing

### 8.1 Rust (`cargo test`)

- `role.rs`: parsing, defaults, the property table.
- `split_capture.rs`: filter builder with own + foreign bypass, empty sets, the 48-range limit.
- `tun2socks`: TCP through a fake SOCKS5 `CONNECT` proxy using the existing smoltcp `Internet` rig;
  UDP associate forwarding; DNS-over-TCP conversion; proxy auth failure; proxy
  disappearing mid-connection.
- `socks5.rs`: CONNECT client against `spawn_proxy`, extended with CONNECT support.
- Service `slot.rs` / `registry.rs`: default slot is `game`; start/stop of one slot never touches the
  other; per-slot lease expiry; `validate-runtime` writes nothing; VPN refused while game is
  all-traffic; VPN refuses relay mode, two nodes and LAN proxy; SOCKS5 accepted only in the VPN slot.
- Existing tests keep passing unchanged (backward-compatible wire protocol).

### 8.2 Node (`npm test`)

- `vpn-state.test.cjs`: normalisation of every malformed shape; rule operations; conflicts.
- `session-coordinator.test.cjs`: the full matrix in §2.4, pause and resume transitions.
- `vpn-session.test.cjs`: fake service on a real loopback socket (like `service.test.cjs`); fake
  clock; poll interval, 3-failure teardown, rollback on failed start, reconnect backoff, resume
  after sleep, no reconnect after user disconnect.
- `usage.test.cjs`: game and VPN sessions recorded at once do not disturb each other's baselines.
- `main-public-state.test.cjs`: every `encrypted*` key is stripped (source scan, like the existing
  cross-component tests).
- `service.test.cjs`: lease headroom also asserted for `VPN_POLL_MS`; the service dispatcher accepts
  `slot`.

### 8.3 Manual harness (not CI)

`scripts/test-vpn-coexist.cjs` (`npm run vpn:coexist-test`), run under Electron with real saved
state, elevated:

1. Start the game session; record latency to its relay for 30 s.
2. Start the VPN with one selected app; check that the app's public IPv4 is the VPN's
   (TCP request through the app path — **not** a DNS test, which a TCP-only proxy invalidates).
3. Check a non-selected process still shows the normal public IPv4.
4. Record game latency again for 30 s; fail if p50 rises by more than 1 ms or loss appears.
5. Toggle VPN rules 20 times; game session id and paths must not change.
6. Kill the VPN engine child; game must stay connected.
7. Switch the game to all-traffic; VPN must report `paused`, then resume when the game stops.

Run it on a restricted connection with each node kind.

## 9. Delivery phases

Each phase is one or more commits that leave `npm run check` and all `cargo test` suites green.

| Phase | Scope                                                                                                                           | Done when                                                                                |
| ----- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| 0     | B1 (done), B5; generic `encrypted*` stripping in `publicState`; `logger.scope`.                                                 | Tests in §8.2 for these pass.                                                            |
| 1     | Service split into modules; `SlotRegistry` with per-slot locks and leases; `slot` on the wire; B2–B4. Game behaviour identical. | Existing tests pass unchanged; new slot tests pass; manual game session works as before. |
| 2     | Engine `Role`, WinDivert priority, per-role adapter/log/thread priority, foreign bypass + `set-foreign-bypass`.                 | Rust tests; two engines capture together on a test machine.                              |
| 3     | Electron VPN modules, state, IPC, coordinator, usage scopes; mock API.                                                          | Node tests; VPN connects with WireGuard and OpenVPN in split mode.                       |
| 4     | Renderer VPN section, Overview card, tray item, Persian strings.                                                                | Typecheck/build; walkthrough in the browser mock and in Electron, LTR and RTL.           |
| 5     | L2TP VPN node; VPN all-traffic next to a game split session (§6.3 verification).                                                | Harness steps 1–7 pass with WireGuard, OpenVPN, L2TP.                                    |
| 6     | SOCKS5 VPN node (tun2socks), UDP forwarding, DNS-over-TCP.                                                                      | Rust tests; harness passes with a TCP-only proxy.                                        |
| 7     | Kill switch, reconnect polish, README "VPN section" and `docs/architecture.md` "Concurrent sessions".                           | Docs reviewed; release notes.                                                            |

## 10. Risks

| Risk                                                           | Mitigation                                                                                                               |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Third-party WinDivert apps at priority 0 interleave with ours. | Game stays at 0 as today; VPN only goes lower.                                                                           |
| Double reinjection cost for normal traffic in broad scope.     | Measured in the harness; game packets unaffected; prefer destination rules where possible.                               |
| Inbound injection on the VPN adapter (§6.3).                   | Hardware verification before shipping; `IP_UNICAST_IF` fallback.                                                         |
| tun2socks bugs (TCP state, half-close) on long sessions.       | Contained to the VPN slot; smoltcp rig tests; soak test 2 h in the harness.                                              |
| `service/src/main.rs` refactor regresses the game.             | Phase 1 changes structure only, game behaviour checked by existing tests and a manual session before any VPN code lands. |
