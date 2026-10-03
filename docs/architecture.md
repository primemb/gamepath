# Client networking architecture

GamePath uses separate components for policy, capture, and transport so the GUI never needs administrator privileges.

## Split-tunnel mode

The privileged Windows service installs filters based on Windows Filtering Platform (WFP) semantics:

1. ALE flow/socket events associate each network five-tuple with its originating process.
2. Application rules match the full executable path. Folder rules match the normalized process-path prefix in the service policy layer.
3. Hostname rules are correlated through the client's DNS policy cache and compiled to current address sets. IP and CIDR rules match destinations directly.
4. Selected UDP and TCP packets are passed to the GamePath transport. Unselected packets continue unchanged.

The current implementation uses the signed WinDivert callout driver as the WFP capture layer, in one of two scopes reported as `captureScope` in capture diagnostics:

- **`destinations`** — every rule in the plan names an address or CIDR, so the whole set is compiled into the kernel filter. Unrelated traffic stays in the kernel and is never handed to the client.
- **`all-outbound`** — the plan contains application, folder or hostname rules. A WinDivert filter is fixed when the handle opens, while those rules learn new ports and addresses while the session runs, so the filter admits all outbound IPv4 and the client classifies in user space. Unselected packets are reinjected. This costs a user-space round trip on traffic that was never selected, which is measurable as latency and CPU under load; it is a compatibility backend, not the intended steady state.

Classification itself is a hash lookup and a binary search against an immutable snapshot, rebuilt only when a connection opens or closes, so it does not hold a lock on the packet path. DNS observation is copy-only.

Process flow selectors retain both the WinDivert endpoint ID and owning PID. An
endpoint close removes only that socket's ownership; a background reaper also
removes selectors, reply paths, and diagnostic rows only after 15 consecutive
socket snapshots confirm they are stale, covering abrupt termination or a missed
driver notification without trusting a transient query failure. Recent packet
activity vetoes fallback cleanup even when a socket snapshot misses the flow.
Reply-path state
is hard-limited to 4096 entries and evicts the least-recently-used entry at the
ceiling, so a long-running session cannot grow without bound. Application labels
are borrowed from the immutable read snapshot rather than allocated again for
every packet. The UI connection list contains only flows active within the last
30 seconds without adding cleanup bookkeeping to the normal interface. The
4096-entry reply-path target evicts only inactive destination-only state;
process-owned game routes are left exclusively to exact or confirmed-stale
cleanup.

Replacing the `all-outbound` scope properly means a signed WFP callout using ALE process classification and network-layer redirection, which can drop in behind the same policy compiler without changing the GUI or the relay protocol.

## All-traffic mode

All IPv4 traffic is routed into the signed Wintun adapter. This avoids process correlation overhead when every connection has the same policy. Relay endpoint routes and local-network bypass routes are installed before the default route changes.

**IPv6 is not carried.** Capture, address rewriting and relay framing are IPv4 throughout, and the mode installs only the IPv4 `0.0.0.0/1` and `128.0.0.0/1` routes. On a dual-stack connection, IPv6 keeps using the normal route while a session runs. The engine probes for a globally routable IPv6 source address when capture starts and reports it as `ipv6.systemHasRoute`; the client shows a warning when it is true. Carrying IPv6 end to end is a separate milestone.

## Capture throughput

On an `all-outbound` scope every outbound packet on the machine passes through
the capture layer, so the cost of handling one is latency the _next_ selected
packet inherits. Two things keep the game's traffic off that critical path:

- **Reinjection runs on its own thread.** Putting a packet that is not ours back
  on the network stack is a syscall, and it happened on the same loop that
  carries game packets. Unselected packets are now handed to a bounded queue and
  reinjected by a single dedicated thread, which preserves their order. A full
  queue never drops: the packet is handed back and reinjected inline, because
  losing it would break some other application's connection. `bypassQueueFull`
  counts how often that happens.
- **Several capture threads share the handle.** WinDivert allows concurrent
  receives on one handle, so a burst of unrelated traffic no longer queues ahead
  of the game's packets waiting for a single reader. The count is 2-4, because
  the per-packet work is a parse and a hash lookup and the tunnel enqueue
  serialises regardless.

The second one admits reordering in principle: two packets taken by different
threads can reach the tunnel in the opposite order. In practice the window is
the few microseconds between a receive returning and the session lock being
taken, while consecutive packets of one game flow are milliseconds apart, so it
only applies inside a burst — and the relay's replay window accepts reordering
by design.

Neither of these removes the underlying cost of classifying in user space. That
needs the WFP callout described under _Split-tunnel capture_; a plan built only
from destination rules avoids it entirely.

## Replay window

Every frame in a session is numbered from one counter, which is what lets the
relay recognise the same packet arriving down two paths and forward only the
first copy. The receiver keeps a sliding window of sequences it has already
accepted.

That window has to be wide, because a frame's sequence says very little about
when it will arrive:

- A data frame is numbered when the capture layer hands it over and then waits
  in its path's send queue. A control probe is numbered _later_ but sent
  immediately, so it overtakes everything still queued ahead of it.
- Paths have different latencies, so a frame sent earlier on a slow path can
  land after later frames on a fast one.

`replay::WINDOW` is therefore 8192 and a compile-time assertion ties it to
`PATH_QUEUE_DEPTH`: a probe that overtakes a full outbound queue must still find
the oldest frame in that queue inside the window. Too narrow a window does not
look like a replay problem from either end — the relay silently drops real
frames, so the client sees unanswered health probes and unexplained loss. The
relay counts every frame the window turns away and reports it alongside session
and endpoint counts, so that case is distinguishable from ordinary duplicate
suppression.

## Logging

All four components write the same line format to one directory, so a problem
report is a single folder rather than four places to look:

```
C:\ProgramData\GamePath\logs\   service.log  engine.log  client.log   (+ .1 rotations)
/var/log/gamepath/                relay.log
```

```
2026-09-09T06:56:15.042Z INFO  engine relay session 8f2a up: 2 route(s) [...], mtu 1356 overhead 144, 0 skipped
2026-09-09T06:57:15.108Z WARN  engine route 2 health check timed out (3 in a row)
2026-09-09T06:57:21.004Z INFO  engine route 2 is reconnecting
```

What is logged is **transitions and decisions** — a session coming up with the
routes and MTU it settled on, a route failing to join and why, a path going
unhealthy or recovering, a reconnect being attempted, the lease expiring — plus
one summary line a minute per session giving every path's state, latency, lost
probes, queue depth and drop count. Nothing is logged per packet.

Three things keep it useful rather than noisy:

- **Level filter.** `info` by default; `GAMEPATH_LOG=debug` raises it, and an
  unrecognised value leaves the default rather than silently disabling the log.
- **Repeat collapsing.** Consecutive identical messages become one line and a
  count, so a path failing every two seconds costs one line, not eighteen
  hundred an hour.
- **Rotation.** 4 MB per component with one previous file kept, so a machine
  left running for a month cannot fill its disk.

Secrets never go in. Node configurations, enrollment tokens, pre-shared keys and
the service token stay out entirely; where a value has to be correlated across
lines, `log::fingerprint` gives a short stable tag instead of the value.

Packet failures are counted on the data plane and reported by background threads,
at most once every ten seconds per reporter, with pending counts drained at orderly
shutdown. `+N` is the increase since that reporter's previous warning; status exposes
cumulative counters under `packetFailures`. UDP/TCP refer to the inner IPv4 packet,
including fragments. Encrypted frames and control traffic with no readable inner
protocol are counted as `other`. Samples contain bounded API errors, never payloads.

| Log field                                             | What it tells us                                                                                                              |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `outbound-no-queue`                                   | No selected path queue accepted this user packet. Repair may still rescue it.                                                 |
| `outbound-no-worker`                                  | No workers were selected, or every selected worker queue was disconnected.                                                    |
| `send-failed` / `transport-copy-send-failed`          | A transport rejected a copy; the warning preserves an API error even if later traffic clears path status.                     |
| `stream-stale` / `stream-full`                        | OpenVPN over TCP shed encrypted copies from its own backlog by age or byte budget. This includes game UDP carried inside TCP. |
| `wintun-return-injection-failed`                      | A reply reached GamePath but could not enter the Windows adapter ring.                                                        |
| `bypass-injection-failed` / `return-injection-failed` | WinDivert could not put an ordinary or tunnelled packet back into Windows.                                                    |
| `outbound-checksum-failed`                            | Rewriting a selected packet failed before it could enter the tunnel.                                                          |
| `relay-return-too-old`                                | An authenticated reply copy arrived outside the replay window. Ordinary duplicate copies remain quiet.                        |
| `repair-inbound-queue-rejected`                       | A rebuilt reply could not enter the local receiver.                                                                           |
| `fragments-discarded` / `pmtu-feedback-failed`        | Split capture abandoned fragment data or could not inject fragmentation-needed feedback.                                      |

Per-route `drop` counts rejected copies, including queue and OpenVPN stream shedding;
it is not a count of packets lost by the game. Another path or repair can rescue a
copy. Probe loss measures the probe exchange rather than game UDP delivery. No local
send success proves that a provider, relay or game server delivered the packet:
[Winsock documents that successful `sendto` does not confirm delivery](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto).
These logs identify observed local failures; a clean log cannot rule out filtering,
remote loss, or a UDP application intentionally sending without a reply.

If a Rust log cannot be opened or written, the logger reports the failure and falls
back to stderr, retrying the file after thirty seconds. Dispatcher depth is reserved
before publishing to a worker, so an immediate receive cannot underflow the counter
and produce a false saturation peak.

## Session lease

The privileged service holds a lease on every session and tears down capture and
routes when it expires, so a client that crashes cannot leave the machine's
routing table rewritten. Only `session-status` renews it.

That renewal runs on a **main-process** timer. It cannot be driven from the
renderer: Chromium throttles timers in a window that is hidden, occluded or
minimized, which is exactly what a fullscreen game does to this one, and a
throttled poll lets the lease expire a few minutes into play. The client renews
every `SESSION_POLL_MS`, the service allows `SESSION_LEASE`, and a test asserts
the first leaves several retries of headroom inside the second.

## Packet size

A captured packet is not what leaves the machine, so the tunnel MTU is derived from what the selected transports actually add rather than fixed at a constant. `EffectiveMtu::for_session` costs the outer IPv4/UDP header, the transport's own framing, and — for a relay session — the inner IPv4/UDP datagram, the 40-byte GamePath header, its 16-byte AEAD tag and the 15-byte loss-repair reserve. Relay over WireGuard therefore costs 159 bytes and yields a 1341-byte MTU on a 1500-byte link; direct WireGuard costs 60 and yields 1440. A mixed route set takes the smallest, because the scheduler may move a packet onto any of them. The Wintun adapter is sized from this, and split mode clamps the TCP MSS to `mtu - 40` rather than to a fixed conservative value.

The link MTU is read per endpoint from the route Windows would actually take, because a laptop can have Ethernet, Wi-Fi and a mobile interface up at once.

The interface MTU only describes the first hop, so each session also measures the path to every endpoint (`path_mtu`), the way Windscribe's `PacketSizeController` does: echo requests with Don't Fragment set, full size first, then a binary search down to the 1280 floor. Observed live on an Iranian uplink: Ethernet reported 1500, but nothing over 1445 bytes reached either node, so every full-size packet of a 1341-byte relay tunnel fragmented on the way out. Measuring never delays a session: it runs beside setup within a 2-second budget, and capture, which opens after the relay handshake and benchmark, takes the result if it has arrived. It only ever lowers the MTU, and an endpoint that ignores echo requests leaves the interface value in place, because no answer means unknown, not small. Endpoints reached over a byte stream (OpenVPN over TCP) are not measured: the outer TCP connection sizes its own segments, so its path MTU never fragments what it carries. A native L2TP/IPsec session needs none of this, in either slot: Windows' own PPP adapter carries it, with its own MTU, so Windows fragments and reassembles as for any interface.

UDP has no MSS to clamp, so split mode does for UDP what a tunnel adapter with this MTU would make Windows do. Observed live with Rust, whose RakNet transport probes 1492, 1200 and 576-byte packets with Don't Fragment set: the 1492 probe was carried, the server agreed to 1492, and the relay's tunnel interface fragmented every snapshot that followed. Every fragmented reply was lost, half counted as injection errors and half as replies with no flow, and joining a server never completed. Four things now handle it, in `ipv4_fragments`, `icmp` and the split capture:

- **The size split mode enforces is what crosses unfragmented** (`EffectiveMtu::unfragmented`): the link's budget after encapsulation, which on a narrow link is under the 1280 floor the tunnel MTU keeps. Measured live: a 1445-byte path carrying L2TP routes (215 bytes) leaves 1230, and a 1280-byte packet would leave as 1495. It never goes under 1228, QUIC's mandatory 1200 bytes of UDP payload with its headers (RFC 9000 §14). The TCP MSS clamp, in both directions, uses the same figure.
- **A selected Don't Fragment packet larger than that is answered, not sent**: ICMP "fragmentation needed" carrying the size, quoting the packet as the application sent it, built as WinDivert's driver builds its own (`windivert_inject_packet_too_big`). Windows records the smaller path MTU for that destination, so a later oversized send can fail with `WSAEMSGSIZE` (measured: a 1500-byte Don't Fragment send refused with 10040 once the path MTU was known), and RakNet treats exactly that error as "use the next size". The send that triggered it has already succeeded from the application's view, so the first probe to a new destination is lost and RakNet's own retry moves on. Without the answer the packet would simply vanish, the failure WinDivert issue #278 describes; if the answer cannot be injected, the packet is carried after all.
- **ICMP errors that come back through the tunnel are matched by the packet they quote**, rewritten to the local address and delivered. A router's "fragmentation needed" or "unreachable" for a tunnelled packet is addressed to the virtual address, and matched by its own header, as an echo reply is, it fit no flow: the log's `ICMP ... -> :0` replies with no flow were these. Path MTU discovery now works beyond the relay too.
- **Fragments are handled in both directions.** Inbound, a datagram is reassembled before it is matched to a flow, because a fragment cannot pass through the injector as it is: `WinDivertHelperCalcChecksums` returns `FALSE` for a TCP or UDP fragment, and only the first fragment carries the ports. Windows accepts an injected inbound datagram above the link MTU, which is what WinDivert's default reassembled capture hands out anyway. Only an exact copy of a fragment counts as a duplicate (multipath delivers them); a conflicting one discards the datagram. Outbound, a first fragment's transport checksum is corrected incrementally for the rewritten address (RFC 1624), every first fragment records where it went, and the later fragments follow it, identified by source, destination, protocol and IP ID, with a reused ID always following the newest datagram. A later fragment whose first went into the tunnel never fails open: half a datagram on each path reassembles nowhere. Known limit: a later fragment sent before its first takes the normal route, which Windows does not do.

The capture status reports these under `fragments`, including datagrams given up on (`discarded`) and answers that could not be injected (`fragmentationNeededFailed`).

`MIN_TUNNEL_MTU` (1280) is a hard floor, not a preference: no session is configured below it whatever the link and encapsulation leave room for. 1280 is the minimum every IPv6-capable link must carry, and the size games, engines and middleboxes assume they can send without discovering a path MTU first, so a tunnel advertised under it tends to surface as connection failures rather than as the slower path it ought to be. On a link too narrow to hold the floor plus its encapsulation — a 1280-byte uplink carrying a relay session over L2TP/IPsec, where 200 bytes of encapsulation leave 1080 — the remainder fragments instead. That is the deliberate trade, and it is the less obvious failure of the two, so `EffectiveMtu::below_link_budget` records it and both session-start paths log it rather than letting it appear as unexplained loss.

## Windows network configuration

Interface MTUs, route installation and adapter lookups go through the IP Helper
API in `engine/src/netconfig.rs`, not through the `Net*` PowerShell cmdlets.

Documented Windows calls use Microsoft's generated `windows-sys` bindings
from the `windows-rs` project. `engine/src/socket_table.rs` shares the TCP/UDP
owner inventory reader across capture, proxy identification and TCP resets,
using SDK row types and retrying when the table grows during a read. ICMP
probes and session timer resolution use the same bindings. WinDivert's own
DLL interface and the undocumented `DnsFlushResolverCache` export remain
separate because they are not covered by those Windows bindings.

The cmdlets are the obvious way to do this and were the original
implementation. Each call starts a PowerShell engine plus the CIM/WMI machinery
the NetTCPIP module sits on, which measures at 850-1000 ms on an ordinary
desktop — per call, and bringing a session up made several in a row. Dialling
one L2TP/IPsec node cost five, and the engine looked up a route MTU once per
tunnel endpoint on top of that. On a three-route session most of the wait to
connect was process startup rather than anything to do with the network.
`GetBestRoute2`, `GetUnicastIpAddressTable`, `Get`/`SetIpInterfaceEntry` and
`Create`/`DeleteIpForwardEntry2` answer the same questions from the same tables
in microseconds, so this is a substitution rather than a change of behaviour.
Creating the Windows VPN profile is the one thing still done through PowerShell,
because `Add-VpnConnection` has no public API.

**One of those delays was load-bearing.** A Wintun adapter is configured
immediately after it is created, and the `Set-NetIPInterface` call that did it
was slow enough to cover the gap before Windows finished binding the new adapter
to TCP/IP. Reading the interface row directly can now arrive first and fail,
which would break session start — most visibly on the first session after an
install or a reboot, when the adapter is genuinely new. So
`configure_tunnel_interface` waits for the row with a stated deadline. Removing
an accidental delay means restoring it deliberately wherever something quietly
depended on it.

Route MTU lookups are cached for `ROUTE_MTU_TTL`. The cache is not there to save
time any more — a lookup is effectively free — but to bound how long a stale
answer can survive, and the TTL is chosen from that direction. A cached MTU that
is too _large_ is the harmful case, fragmenting or dropping every full-size
packet, and moving from Ethernet to Wi-Fi or onto a phone hotspot produces
exactly that. So the window is long enough to cover one session start's lookups
and a quick restart, and no longer. `invalidate_route_mtu_cache` drops it
outright for anything that knows the uplink changed.

Dialling L2TP/IPsec and starting the privileged engine child do not depend on
each other, so the service runs them concurrently: RAS negotiation is the long
pole in bringing a session up, and the child only has to exist before it is
asked to start the session. A failed dial still joins the thread, because
`EngineProcess` kills its child when dropped and an orphaned engine would
outlive the session that failed.

### Picking the default route

All-traffic capture needs the gateway and interface the machine currently
leaves by, so it can pin the relay and node endpoints outside the tunnel it is
about to install. This was a `Get-NetRoute` pipeline ending in `Sort-Object
RouteMetric | Select-Object -First 1`, measured at 450-830 ms, with a
`route.exe` launch per installed route on top at 135-175 ms each — six routes on
a three-node session, so well over a second of process startup before a packet
could move.

`default_ipv4_route` walks `GetIpForwardTable2` instead, and does not reproduce
that pipeline's ranking. Windows chooses between default routes on the route
metric _plus_ the metric of the interface they leave by, and sorting on the
route metric alone cannot see the second half: with Ethernet and Wi-Fi both up,
both default routes commonly carry route metric 0, so the old sort was a tie
broken by whatever order the table came back in. Losing that coin flip pins the
bypass routes to an interface whose gateway cannot reach the relay, which
strands the session with no route out. Only `0.0.0.0/0` rows are considered, so
the two halves of GamePath's own split default (`0.0.0.0/1` and `128.0.0.0/1`)
can never be mistaken for the physical route.

Installing routes through `CreateIpForwardEntry2` also made them idempotent,
which `route ADD` is not: it fails on a duplicate, so a bypass route left behind
by a session that did not get to clean up used to fail the next capture start
outright instead of being replaced.

### Name resolution goes through the tunnel

Windows picks a resolver per interface. The tunnel adapter had none, so lookups
fell back to the physical adapter's — typically the home router, which sits on
an on-link `/24` far more specific than the `0.0.0.0/1` capture installs. Every
lookup therefore left outside the tunnel no matter how much traffic went
through it.

The reason this is worth doing on the connect path is not privacy. Where DNS
answers are filtered by name, the filtered answer is a blackhole address, so a
game resolves its own servers to somewhere dead while the tunnel beside it is
healthy and carrying traffic. Measured on such a connection: `steamcommunity.com`
and `discord.com` resolved to `10.10.34.36` from every resolver asked, while
`github.com` and `example.com` resolved correctly — a name blocklist applied in
transit, not blanket interception, which is exactly the case a tunnel fixes and
an untunnelled lookup does not.

All-traffic mode sets the adapter's servers with `SetInterfaceDnsSettings`
(`netconfig::set_interface_dns`) once the routes exist — before them, there
would be no path to the resolver it just named. It prefers the relay's own
resolver at the tunnel gateway, whose address exists only inside the tunnel and
therefore cannot leak by any route, and proves it first: `tunnel_resolver_answers`
sends a real query over the live data plane and waits
`RESOLVER_PROBE_TIMEOUT`. A DNS round trip is normally weak evidence — a proxy
or a filter can answer one without forwarding anything, which is why
`answers_dns_without_forwarding` exists — but it is strong evidence here
precisely because nothing between the client and the relay can see that address,
let alone reply from it. A public resolver always follows the relay in the list,
because the relay's resolver can die while a session is up and the machine
should not stop resolving until someone notices. Teardown clears the servers
before removing the routes, so there is never a moment pointing at a resolver
the tunnel can no longer reach.

Split mode has no tunnel adapter to configure, so it selects name resolution in
the classifier instead. Queries already addressed to a public resolver travel
unchanged. A query to `192.168.1.1` would mean the relay's own LAN once it
arrived there, so remote DNS rewrites LAN and ISP resolver destinations to
`TUNNEL_RESOLVER`, then rewrites replies to come from the original resolver.
Local names stay local, and unanswered redirected lookups fall back after two
seconds while occasional tunnel queries check for recovery. See _Remote DNS
and the router's resolver_ for the concurrent-session and bootstrap exceptions.
Selection is over UDP and TCP — TCP because a truncated answer is
retried there and selecting only UDP would leak the largest replies. Narrow
kernel filters carry `DNS_CLAUSE` for the same reason: a packet the kernel never
hands up cannot be selected. **An application rule cannot do this on its own.**
Windows applications do not send DNS themselves; they call the resolver, and the
DNS Client service inside `svchost.exe` sends the query. A rule naming a game
therefore selects every packet that game sends and still leaves its name lookups
going out untunnelled, owned by a process the user never selected. Queries the
session cannot carry fail open to the normal route, so this costs a lookup
latency at worst, never the ability to resolve.

The probe asks for `example.com`, which is IANA-reserved and belongs to nobody
whose service could disappear. The first version asked for `dns.google`, which
turned out to be on the blocklist of the very networks this feature exists to
work around.

## Relay and direct sessions

A session runs in one of two modes, chosen by the client and carried through
`prepare-session`, `validate-runtime` and `start-wireguard-session` as `mode`.
A request without a `mode` is a relay session, which is what every caller
written before direct mode meant.

A **relay session** seals each captured packet under the enrollment key, gives
it a session ID and sequence number, and hands it to the scheduler, which sends
it over one or more node transports to the relay. The relay authenticates the
frame, writes the inner packet to its TUN, and the kernel there does the
routing and NAT.

A **direct session** has no relay, so a node has to do that work itself. A
WireGuard, OpenVPN or L2TP/IPsec server already routes and NATs traffic that
comes out of its tunnel. WireGuard and OpenVPN run through the userspace packet
engine: captured packets are rewritten to the tunnel address and sent without
GamePath framing, sequence numbers or duplication. L2TP/IPsec is different:
Windows RAS owns the tunnel and Windows routes the selected traffic natively.
A SOCKS5 node is refused before anything is opened, since a proxy has nothing
to route with.

The userspace WireGuard/OpenVPN modes meet at `enqueue_data_packet` and
`DataReceiver::receive`, so their capture layer is identical. Native L2TP direct
mode intentionally bypasses that layer.

Health is judged differently because the evidence differs. A relay session
exchanges authenticated control frames with a relay it owns, so a silent path
is a broken path. A userspace direct session's node belongs to a provider and
answers nothing at the application layer, so the engine sends an ICMP echo
through the tunnel to `BENCHMARK_TARGET` every second and works from two
signals:

- The **WireGuard handshake** says the node is there at all. It is what the
  session waits for at startup, and a peer that has not answered within three
  seconds is reported with the part of the configuration to check, rather than
  as a bare timeout.
- The **echo** measures the whole trip to the Internet and, once one has been
  answered, becomes the liveness signal: three consecutive misses mark the path
  down, the same conclusion a relay path reaches from its own probes.

A completed handshake is deliberately not treated as lasting proof. It never
expires on its own, so a node that dies mid-session would otherwise keep
reporting itself healthy for as long as the process ran.

The echo target is one constant, `gamepath_engine::BENCHMARK_TARGET`, shared by
this probe, the data-plane benchmark and the L2TP direct-mode DNS probe. The
only requirement of it is that it answers from wherever a user connects, and
that is a stricter requirement than it sounds: it was `1.1.1.1`, which several
national filters blackhole or hijack outright, so a perfectly healthy tunnel
measured as silent for the users behind them. It is `8.8.8.8`.

Some providers filter ICMP while routing everything else perfectly. If no echo
is ever answered, the engine backs off to one attempt every fifteen seconds and stops
counting them as loss — reporting such a node as totally lossy would be wrong —
and the handshake round trip stands in for the route latency. **The cost is
that a node in this state has no liveness signal at all** and stays reported as
up while the tunnel is established. Authenticated return traffic also proves
liveness for five seconds regardless of ICMP loss. Probe counters stay unpublished until one
echo is answered, so the client never shows probes it could not measure.

Direct probes match both echo identifier and sequence, so a delayed reply cannot
consume a newer probe's timer. Direct OpenVPN probes use reliable stream writes
and the same transport-specific deadline floor as relay probes.

Routes into the Wintun adapter derive their next hop from the session address
rather than a fixed one. A relay hands out `10.203.0.x` and gets `10.203.0.1`
as before; a direct session's address comes from the provider and gets the
first host of its own `/24`.

### L2TP/IPsec through Windows RAS

The privileged service creates a temporary Windows VPN profile, passes the
pre-shared key to PowerShell over anonymous stdin, and dials with `RasDialW`.
The password is cleared from the RAS parameter buffer after the call. The
profile, connection and any explicit routes are removed when the user stops,
the client disappears and its lease expires, or setup fails.

In relay mode the RAS profile is split-tunnel and has only a host route to the
relay. The engine binds its relay UDP socket to the assigned PPP address and
pins it to the RAS interface with `IP_UNICAST_IF`; encrypted GamePath frames
therefore traverse L2TP/IPsec without changing the machine's default route. A
worker whose RAS adapter disappears redials the same temporary profile with the
credentials held inside the privileged engine child, reapplies its MTU and
relay route, and rejoins after an authenticated probe. Other relay paths remain
up during that recovery.

That adapter is also stripped of IPv6. Providers advertise a router on the PPP
link, and Windows acts on it, so the temporary adapter acquires a `::/0` route —
on one observed session it was the machine's only IPv6 default route. Nothing
breaks while the link hands out no global address, because Windows cannot select
an IPv6 source and falls back to IPv4, but a server that did advertise a prefix
would have IPv6 routed into a tunnel this client carries no IPv6 through.
`netconfig::disable_ipv6_default_route` turns off router discovery and sweeps any
route that already arrived — both halves, because a server usually advertises as
soon as the link comes up, which is before the adapter can be configured. It is
best-effort: a session that carries traffic is worth more than this.

A **direct** L2TP session is deliberately left alone. There Windows routes the
user's own traffic through the adapter natively, so removing IPv6 from it would
push that traffic onto the physical interface instead — turning a tunnelled
protocol into a leak rather than fixing one. The relay case is the one where the
adapter exists solely to carry GamePath's IPv4 frames.

In direct all-traffic mode RAS owns the default route. In direct split mode the
service installs native IPv4 routes for CIDRs and the current A records of exact
hostnames. Windows routes alone cannot express application/folder ownership or
keep wildcard DNS sets correlated with processes, so those selectors are
rejected with an actionable error; users can choose all-traffic mode or a
WireGuard/OpenVPN direct node for them. Exact hostname routes are refreshed
when the live target set is applied again. The service sets the RAS interface to
the MTU derived from the uplink route it measured before dialling — 1384 bytes
on an ordinary 1500-byte link, and never below the 1280-byte floor — then probes
`BENCHMARK_TARGET` on port 53 with an interface-pinned UDP socket. This measures
startup and live data-plane latency without installing a hidden route; three
consecutive failures mark the route degraded. IPv6 exposure
is derived from the interface selected for a public IPv6 destination, so the
result distinguishes traffic carried by RAS from traffic bypassing it. The RAS
connection remains protected by the same service lease.

## Multipath transport

Every relay node becomes one path behind a common `RelayPath` transport interface, so the scheduler, the sequence allocator, and the session's authenticated framing work the same whichever transport a route uses. The relay transports are user-space WireGuard, user-space OpenVPN, SOCKS5 UDP association, and an interface-pinned L2TP/IPsec RAS path. A session may mix them when their endpoint identities do not conflict.

Each distinct imported configuration creates an independent user-space WireGuard protocol instance. This allows different provider endpoints to run simultaneously even when their tunnel addresses overlap, a combination Windows rejects as duplicate adapters. The implementation uses BoringTun's portable WireGuard protocol core and ordinary Winsock UDP sockets for the outer provider connections.

The direct ISP path is always available alongside provider routes. If two files resolve to the same endpoint and reuse the same client identity, their WireGuard handshakes would replace one another at the provider. GamePath detects that conflict, keeps one live, and holds the overlap as standby. Distinct endpoint/key pairs become additional live paths.

Authenticated GamePath frames are wrapped in an inner IPv4/UDP packet addressed to the relay, then encrypted independently by each WireGuard instance. Packets receive a session ID and monotonically increasing sequence number before adaptive scheduling sends them on one or two routes. The relay sees two authenticated endpoints and fans replies back across both.

Direct and WireGuard workers share one atomic sequence allocator, so control traffic and data traffic never reuse an authenticated nonce or fall behind the relay replay window. The client sends one encrypted data frame to every selected path and accepts the first authenticated reply; later copies are discarded by sequence number.

## Loss repair

Duplication covers one path failing. It cannot cover a loss both copies share,
and that is the common kind: the copies leave at the same instant through the
same Wi-Fi radio, router and ISP line, so one hiccup there takes both. A
session whose second path is down, or too slow to duplicate onto, has no
protection from duplication at all.

Both ends of a relay session therefore send repair frames (`FLAG_REPAIR`,
`engine/src/fec.rs`). A repair is the XOR of a group of recent data frames,
length-prefixed so members of different sizes can be rebuilt exactly, and it
names its members by sequence. When exactly one member was lost the receiver
rebuilds it from the repair and the members that arrived, and admits it
through the same replay window as a delivered frame, so the original arriving
late by a slower path is discarded as a duplicate.

- **Group size follows the healthy paths.** With two or more healthy paths
  duplication already covers a path failing, so one repair per
  `MULTIPATH_GROUP` (4) packets is enough for the loss both copies share, at a
  quarter of the bandwidth. With one healthy path every packet gets its own
  repair (`SINGLE_PATH_GROUP`, 1). The client reads the health mask for every
  packet it sends, so the size changes on the next packet when a path fails or
  comes back, and a group already open is closed first so nothing in it goes
  unprotected.
- **Multipath shrinks to 2 only when every path is bad, and slowly.**
  `MultipathPolicy` reads, after every probe, the lowest loss among the paths
  carrying data, since a packet is lost for good only when every copy of it
  is; a clean standby the scheduler is not sending on rescues nothing, so it
  does not count. When even the best carrying path has stayed at
  `LOSSY_PATH_LOSS` (10%) or more for `LOSSY_AFTER` (10 s), two losses in one
  group of four become likely, so the multipath group drops to
  `LOSSY_MULTIPATH_GROUP` (2). It goes back to 4 only after the best path has
  stayed under `RECOVERED_PATH_LOSS` (4%) for `RECOVERED_AFTER` (60 s). The gap
  between the two thresholds and the two holds stops a session sitting near
  either edge from flapping, and any clean reading while shrinking, or lossy
  one while growing, restarts that clock. All of these are constants in
  `engine/src/fec.rs`.

  The loss it reads is each path's `ProbeHistory` — the last `LOSS_WINDOW`
  (60) probes, counted only after `MIN_LOSS_SAMPLES` (30) — and not the
  scheduler's average, because an outage is not a path in bad condition. Seen
  live: two five-second international blackouts took all four routes of a
  session, on two providers, down within 200 ms of each other, with the
  outside-the-tunnel uplink probe failing too. Probes on a path in doubt go out
  every 150 ms, so the scheduler's average read 25-49% on clean paths
  afterwards, and a policy fed from it shrank the group for 37 s after each
  blackout had ended. The history forgets the run of losses that ended in a
  path being declared down, and the policy sets its clock back while nothing
  is carrying, so what shrinks the group is scattered loss on paths that stay
  up.

- **Data never waits.** Packets leave the moment they are captured, as before.
  A group closes when the next packet cannot join it or after
  `GROUP_MAX_AGE` (5 ms), whichever is first, and a flusher thread on each end
  closes groups that stopped growing. Only a lost packet pays latency, and at
  most that. A game sending one packet per tick gets a repair per packet a few
  milliseconds behind it, which is cheap at game rates and is the spacing that
  lets a repair survive the burst that took the original.
- **Repairs go to every healthy path**, not only the ones the scheduler picked
  for data. A backup too slow to be picked for game packets still carries their
  repairs, and a burst on the fast path cannot take a packet and its repair
  together. A path whose queue is past `REPAIR_QUEUE_LIMIT` (a quarter full)
  gets no repairs: it is saturated, and a repair must never take queue space a
  game packet then cannot get.
- **Negotiated, never assumed.** Path workers send an `offer` control frame
  naming the group size the relay should use for its replies and this
  session's tunnel MTU, repeat it within `OFFER_RETRY` whenever the size
  changes, and refresh it every `OFFER_REFRESH` so a relay that restarted picks
  it up again. The relay applies an offer only if it is newer
  than the last one it applied, since offers travel every path and can arrive
  out of order, and answers on the path the offer came by. The client sends no
  repairs of its own until a relay has answered. A relay from before loss
  repair ignores offers; after `OFFER_LIMIT` unanswered ones the session is
  reported as `unsupported` and runs exactly as it did before, while offers
  continue every `LEGACY_OFFER_RETRY` in case a bad network ate the answers.
  A repair payload starts with a byte that can never read as IPv4, so an old
  relay that treats one as data drops it at its source-address check.
- **Budget.** A repair covering a full-size packet is larger than that packet
  by `REPAIR_HEADER_MAX` (15) bytes, and `RELAY_OVERLAY` reserves them, so the
  tunnel MTU is sized for the repair and not only the packet. A packet above the
  tunnel MTU would fragment anyway and is left out of its group. The tunnel MTU
  is derived per session from the client's own link and transports, which the
  relay cannot see, so the offer carries it and the relay leaves replies larger
  than it out of its groups too, instead of sizing them for the 1500-byte link
  it assumes for its TUN.
- **History.** The receiver keeps recent delivered packets to rebuild from, but
  only once the peer has sent a group of more than one: a group of one carries
  its packet whole. A repair that arrives while two members are still missing
  waits for a slower path to deliver one of them, for up to 500 ms.

Session status reports `lossRepair` with the state, both group sizes, repairs
sent and received, packets rebuilt, and repairs that arrived too late or with
too much missing to use. The relay logs `recovered_frames` in its periodic
counters line.

## Queueing

Each path has a bounded outbound queue. The dispatcher offers a packet with a
non-blocking send and, when the queue is full, drops it and counts it rather
than letting the backlog grow: a saturated path is already behind, and a game
packet that waits for the backlog to drain is stale by the time it arrives.
Workers also send at most `PATH_SEND_BATCH` packets per iteration, so a burst
cannot delay the inbound frames, probes and timers that decide whether a path is
still alive, and they shed any packet that has waited past `PATH_QUEUE_MAX_AGE`.
Queue depth and drop counts per path are reported in session status.

## Declaring a path down

A path is taken out of service after `HEALTH_FAILURE_THRESHOLD` consecutive
unanswered probes, not after one.

The control probe is a bare UDP datagram on a real network and losing one
occasionally is ordinary. Measured over an 85-minute session, a healthy
WireGuard route lost 57 probes — about one every ninety seconds — while needing
exactly one genuine reconnect; across both routes, 215 of 228 recoveries were
after a single lost probe. Acting on the first loss pulled the route out of the
dispatcher and showed it offline each time, which reads to a user as the tunnel
dropping and reconnecting when nothing of the sort has happened.

The scheduler still sees the first loss immediately through `record_loss`, so a
path that begins dropping packets is de-prioritised by its score straight away.
The threshold governs only the harder decision to stop using the path at all,
and two in a row is reached inside four seconds.

A path already declared down stops feeding its losses to the scheduler. It is
out of the pick either way, and the probes it keeps losing at the degraded
cadence only wrecked its score for the moment it came back: after a shared
blackout the route that kept probing throughout, and recovered first, read
49% loss and was the one the scheduler avoided.

### Reported loss is current, not cumulative

The loss figure a route publishes is `PathMetrics::loss_ratio` — the smoothed
estimate the scheduler scores with — exposed per path as `lossPercent`.

The client used to compute it instead from the session's lifetime
`probesLost`/`probesReceived` counters, which answer a different question. Those
counters never forget, so one bad minute keeps reading as steady-state loss for
as long as the session runs, decaying only as the session ages around it. A
route that lost 45 probes during a 40-second stall at startup and nothing since
was still reporting about 20% loss several minutes later, while the scheduler's
own view of that route — the number deciding whether it carried traffic — was
0%. Those two should not be able to disagree, so both now read the same
estimate. The raw counters are still reported, as counters.

That estimate is smoothed at `LOSS_SMOOTHING`, deliberately a quarter of the
`SMOOTHING` used for latency and jitter. Being an EWMA over a per-probe 0/1
indicator, its expectation is the path's true loss rate whatever the constant
is; what the constant sets is how far one probe can move it. The original 0.2
moved it the whole way to 20% on a single lost probe, so the published figure
swung between 20% just after a loss and under 1% just before the next one — on
a link whose real loss was about 3%, whoever looked saw whichever extreme they
happened to catch. It was not only cosmetic: at 200 points per unit of loss in
`score`, one lost probe added 40 points, more than the entire 39-point spread
between a 47 ms route and an 86 ms one, so a single lost packet outranked every
latency difference in the route set. A live three-route session changed its
selection 50 times in six minutes because of it.

Slowing the estimate costs nothing in failure detection, because detection is
not its job: a path that has actually died is removed by `consecutive_losses`
reaching `LOSSES_BEFORE_INACTIVE`, an immediate and separate signal. What
`loss_ratio` ranks is paths that are degraded but still working, and for that a
rate measured over roughly twenty probes is the honest input.

### The pick has to resist a tie

Fixing the loss estimate removed the loss-driven half of the flapping above and
exposed the other half. Ranking is memoryless: every probe reply re-sorts the
whole route set and takes the best two, with no notion of which routes are
already carrying traffic. Two routes within measurement noise of each other
therefore trade places on whichever was measured most recently. On a live
three-route session that produced three different selections inside 2.1
seconds — `1+3`, then `1+2`, then `2+3` — with every route at about 52 ms and
no loss, the whole decision turning on one point of score.

`choose_paths_with_incumbent` ranks the routes already carrying traffic
`INCUMBENCY_MARGIN` points better than they score, so a challenger has to be
meaningfully better rather than merely different. The margin is sized from the
gap the decision actually turns on, the second-best route against the third:
across 261 recorded selection changes its median was 1 point and its 90th
percentile 6, while the smallest gap separating genuinely different routes in
the same log was 39 — two 47 ms WireGuard paths against an 86 ms L2TP one. At 8
points the margin sits inside the noise and nowhere near real signal, and
replaying the recorded score sequences it suppresses about 88% of the changes.

It cannot delay a failover, which is the property that makes it affordable. A
path that stops answering scores `f64::INFINITY` through
`LOSSES_BEFORE_INACTIVE`, and no finite margin reaches infinity; a path that
genuinely degrades moves its score by far more than 8. The discount also applies
only to ranking — whether to duplicate at all still reads the paths' true
latency, jitter and loss, because that is a question about the routes and not
about which of them was picked last time. The same margin holds the armed
fallback steady during a total outage, where two equally dead routes could
otherwise alternate on every timeout.

### The deadline floor depends on the transport

The estimator answers "how long should this path take", but not every path can
answer as fast as it is. A datagram transport passes loss straight up: nothing
underneath WireGuard or a SOCKS5 association retries a dropped packet, so a
probe still unanswered after `rtt::MIN_TIMEOUT` really is lost.

A stream transport does the opposite. OpenVPN over TCP hides loss by
retransmitting the segment, and every packet behind it waits in the receive
buffer until it arrives. That recovery has a floor of its own — the operating
system's minimum retransmission timeout, 200 ms on Linux and 300 ms on Windows
— and a sparse game flow rarely supplies the three following segments fast
retransmit needs, so the timer is the ordinary case rather than the rare one.
One recovery therefore costs roughly `RTO_min` plus a round trip before the
probe can possibly be answered.

Measured on a live session, a `tr2` OpenVPN/TCP node whose latency never left
the fifties logged nine failed health checks in five minutes, while the
WireGuard route beside it on the same uplink logged none. The 200 ms deadline
was under the stall it was measuring, so every retransmission read as a dead
path.

So `RelayPath::probe_deadline_floor` lets the transport set its own lower bound:
`rtt::MIN_TIMEOUT` for datagrams, `rtt::STREAMED_MIN_TIMEOUT` for a byte stream.
It is a floor and not an override — a stream path that is genuinely slow still
widens past it on its own measurement, and the ceiling still applies. OpenVPN
answers from the protocol it actually negotiated, which matters because a `udp`
configuration falls back to `tcp` when UDP cannot get through.

The cost is that a dead stream-carried path takes longer to declare, and a test
bounds that at four seconds. That is the correct trade: on a transport that
retransmits underneath us, "stalled" and "dead" genuinely take longer to tell
apart, and reporting the first as the second is the more expensive mistake.

### A probe that times out still measures the path

The deadline is only as good as what the estimator is allowed to see, and it
used to see a biased sample. A reply arriving after its probe had been written
off was discarded: the worker matched replies against the one outstanding
probe, and that slot had already been cleared.

So the estimator learned only from replies that beat the current deadline.
That holds its smoothed round trip and its variation below the truth, which
keeps the deadline near its floor — on exactly the paths whose replies are slow
enough to need it widened, so the next probe times out for the same reason.
Measured on a live L2TP/IPsec route whose round trip doubled under congestion
while two WireGuard routes on the same uplink did not move at all: at a 100 ms
round trip with 24 ms of variation the estimator asks for 196 ms and is given
the 200 ms floor, about two times headroom, where a 48 ms WireGuard path has
four.

A timed-out probe is now remembered for `LATE_REPLY_WINDOW`, and a reply that
turns up inside it feeds its round trip to the estimator. The relay already
echoes the probe's sequence number in its `pong` for precisely this — the engine
warns when a relay is too old to do so, naming "accurate RTT matching after
timeouts" — so the match is exact. An untagged legacy `pong` is refused rather
than guessed at, because it cannot say which probe it answers.

**The probe stays lost.** It missed its deadline; `probes_lost`, the consecutive
failure count and the scheduler's loss score are all untouched, and none of the
health or failover accounting is revisited. What this recovers is the
measurement, not the verdict — so a path cannot talk its way out of being
declared dead by answering late.

### The stream transport keeps its own send queue

The other half of carrying datagrams over TCP is what happens on the way out.

Every path's send queue sheds packets older than `PATH_QUEUE_MAX_AGE`, because a
game packet that has waited 50 ms describes a world that has moved on and the
bandwidth is better spent on the one behind it. On a datagram transport that
rule is the last word: `send` hands the packet to the wire and returns.

On TCP it was not. The link handed the kernel a four-megabyte send buffer and
called a blocking `write_all`, so the moment congestion control slowed down, the
backlog moved somewhere the staleness rule could not reach it. Bytes the kernel
has accepted go out in order, at whatever rate is allowed, and cannot be dropped
or reordered — so a game packet queued behind a megabyte of older data arrives
late no matter what any policy above decides. The queue simply left the building
through the socket.

Two changes put it back:

- **The kernel gets `SEND_BUFFER` (256 KiB) instead of four megabytes**.
  The receive buffer stays large to preserve bursts between reads.
  The send-buffer/RTT throughput estimate is about 35 Mbit/s on a 60 ms path,
  not a measured guarantee. This reduces hidden backlog rather than bounding
  latency: 256 KiB takes about 210 ms to serialize at 10 Mbit/s. Downloads can
  also be affected when their tunneled TCP acknowledgements queue on upload.
- **The rest of the backlog stays in `Link`**, as a queue of framed packets that
  can still be shed, with a 50 ms rule and a `MAX_OUTBOUND_BYTES` backstop.
  Each queue measures its own residence time; this is not an end-to-end
  50 ms delivery guarantee.

Writes are non-blocking, which is what makes the queue safe rather than merely
useful. A blocking write on a stalled socket would hold the worker thread that
also runs the path's health probes and timers, so a congested link would present
as a dead one — the exact failure the deadline floor above exists to prevent.
Non-blocking writes mean short writes are routine, so the offset into the packet
at the head is kept and the next pass continues from there: a `write_all`
interrupted part-way would leave a truncated frame on a length-prefixed stream
and desynchronise the reader permanently. The socket is switched to
non-blocking only around the write and restored afterwards, including on
failure, because reads rely on `SO_RCVTIMEO` and a non-blocking read would spin
the session loop.

Shedding distinguishes two kinds of traffic, which is why `Link::send` takes an
`Urgency`:

- `Realtime` — tunnelled traffic. The overlay already treats loss on a path as
  ordinary, so dropping a stale packet is better than delivering it late.
- `Reliable` — the TLS handshake, rekeys, keepalives and overlay health probes.
  Probes use `RelayPath::send_probe` so local shedding cannot turn a brief TCP
  stall into an unanswered health check. These packets retain stream order.
  If control traffic alone
  ever exceeds the budget the link reports an error, because that much of it
  unsent means the stream is not moving at all.

Two packets are never shed regardless: anything `Reliable`, and the packet at
the head of the queue once part of it is on the wire. Removing a frame the
reader has begun to see would desynchronise a length-prefixed stream for good,
which is far worse than the delay being avoided. Shedding is otherwise
oldest-first, because the newest game packet is the one still worth arriving.

WireGuard and SOCKS5 keep their existing datagram send behavior. They do not
use this application stream queue; a successful send is not proof of delivery.

After a redial, the RTT estimator is recreated using the replacement path's
deadline floor. A UDP-to-TCP fallback must acquire the wider deadline, and a
return to UDP must restore faster failure detection.

### Recovery is not one price

A redial is not a single cost to be paid whenever a path fails. Measured on a
live session, an L2TP route took **21 seconds** to come back: `rasdial.exe` to
hang up, then `RasDialW` negotiating IKE, IPsec, L2TP and PPP from scratch.
Rebuilding the UDP socket pinned to a RAS session that is still perfectly alive
takes microseconds. Most of what takes an L2TP path out is the relay going
quiet, not the adapter dying — so the expensive answer was usually being paid
for a problem it did not solve.

`ReopenEffort` splits the two. `Cheap` keeps whatever is still standing and
rebuilds only the socket; `Full` tears the transport down and builds it again.
A path worker offers `Cheap` once per outage and escalates to `Full` for every
attempt after it, so a rebuild that does not hold costs one probe cycle rather
than becoming a loop, and the offer is renewed only when the path answers a
probe again — proof that the cheap route worked. A transport with nothing cheap
to reuse ignores the distinction; the L2TP path falls through to `Full` by
itself when no RAS session is up, so `Cheap` is never a detour.

The live session's coordinates come from RAS at the moment of the reopen rather
than from the handover the service gave the engine at session start. A redial
renegotiates both address and adapter, so the stored pair describes something
that no longer exists; without asking, the cheap route would work for the first
outage of a session and never again.

Hanging up is native too. `rasdial.exe <profile> /disconnect` cost a process
start before it could act, and most often had nothing to do — the adapter had
already gone, which is generally why a redial is happening. `RasEnumConnectionsW`
answers that without spawning anything, and when there is a session to close,
`RasHangUpW` plus a wait on `RasGetConnectStatusW` closes it: RAS hangs up
asynchronously, and dialling the same entry while the last one is still tearing
down is how a redial races itself.

None of this makes `RasDialW` faster. What it removes is paying for `RasDialW`
when nothing needed it.

### A transport can report itself gone

A path is normally declared down by its probes, and that is the right default:
a failed send usually means one datagram was lost, not that the path is
finished, and reacting to it would take a working route out of service.

An interface-pinned socket breaks that assumption. The L2TP relay socket is
bound to the RAS adapter's address and pinned to its interface with
`IP_UNICAST_IF`; when Windows tears that adapter down — on every redial, and
oftener than that on a flaky provider — the socket outlives it and every send
fails from then on. Waiting for three probes to time out rediscovers something
the socket already knew, and each of those seconds is game traffic handed to
something that cannot carry it. Seen live as `WSAEINVAL`, surfaced to the user
as "L2TP relay send failed: An invalid argument was supplied".

So `RelayPath::transport_failed` lets a transport say that its own failure is
terminal, and the worker then takes the path out of the dispatcher and arms the
redial without waiting. The verdict is the transport's rather than inferred
from an error string, so each one decides with whatever its platform gives it,
and the default is that nothing is terminal — the behaviour every transport had
before.

The classification is deliberately narrow. `WSAECONNRESET`, `WSAEHOSTUNREACH`
and `WSAENETUNREACH` are excluded because Windows raises them from an ICMP
message about a datagram already sent: the socket is fine, the next send may
well succeed, and tearing the path down for one is the more expensive mistake —
the same reasoning that makes the SOCKS5 transport swallow them on receive.

## Relay failover

Multipath survives any path failing, but every path ends at one relay, so the
relay is the one failure it cannot route around. `electron/relay-failover.cjs`
moves a session to a standby relay when that relay is gone. It is off unless
the user turns it on, because a move is not free: every node redials and the
game sees a new public address.

It exists because of a measured failure: a relay VPS on an overloaded host
stopped answering from everywhere — through every node, and to direct pings
from the client — for 3 to 21 seconds at a time, several times an hour, while
the client's own Internet and every node stayed up. Each freeze ended by
itself. So silence is not enough; a move needs every independent witness to
agree, and `RelayFailoverWatch` checks them from the main process's session
poll:

- the session carried traffic first, so a slow start is not a dead relay;
- every path has been down without a break;
- the uplink monitor, which probes outside every node, reported `up` on every
  poll; `down` or `unknown` means the cause may be local and restarts the clock;
- where this machine can reach the relay directly — learned from a direct
  `probe-relay` while the session was healthy, repeated every ten minutes —
  direct probes every 5 s fail at least `DIRECT_FAILURES_REQUIRED` (3) times
  with no answer between. One answer proves the relay alive and restarts the
  clock, since a different relay would not fix the paths to it.

With the direct witness the silence has to last `OUTAGE_WITH_WITNESS_MS` (30 s);
on a network that filters direct traffic to the relay, `OUTAGE_WITHOUT_WITNESS_MS`
(60 s). Both are well past the longest freeze measured.

The standby is the relay the user picked, or the first other relay that is set
up, never one on the main relay's own address. In split mode it must answer a
direct probe first; if it does not, the session stays and the whole wait starts
again. In all-traffic mode only the active relay is routed around the tunnel,
so a direct probe to the standby would enter the dead session and prove
nothing; there the start itself is the check, and a standby that fails to start
sends the session straight back to the main relay, which beats no session at
all.

The move runs through the same `startSession` path as the Start button,
serialised with Start and Stop so they cannot interleave. It happens at most
once per session and never back: the moved session, and a session returning
from a failed move, do not watch for failover. `activeRelayId` is not changed,
so the next session starts on the user's relay again.

A direct answer during an outage settles it for `RELAY_ALIVE_HOLD_MS` (60 s):
the relay is up, nothing is left to decide, and probing on would only add load.

Building this exposed two relay bugs, both fixed in `relay/src/main.rs`:

- **Probe sessions displaced the real one.** `probe-relay` uses a one-off
  session id, and the relay admitted every one as a session. The per-client cap
  evicts the least recently used session, which during an outage is the real
  one, silent while its paths are down; replies also go to the newest session,
  which a probe briefly became. A probe from a session the relay holds no state
  for is now answered without creating any.
- **A re-created session repeated nonces.** A session's key depends only on the
  enrolment key and its id, and the AEAD nonce is the sequence. When the relay
  forgot a session and re-created it for the same id — evicted, expired after
  `SESSION_TTL`, or lost to a relay restart while the client kept going — its
  reply sequence started from zero again. That reused every nonce of the
  previous incarnation under the same key, and the client's replay window, far
  ahead, discarded every reply as stale: connected, and delivering nothing. A
  new session's reply sequence now starts from the wall clock in microseconds,
  which moves faster than any session sends.

## Common-mode failure

Independent providers do not fail in the same second. When every path stops
answering at once the cause is the one thing they share — the machine's own
uplink — and the two reflexes that serve a single failing path both make a local
outage worse:

- **Duplication is suppressed when every path is degraded.** Sending each packet
  twice over a link that is already congested doubles the load that is the
  problem, and it is a feedback loop: congestion raises loss, loss switches
  duplication on, the extra copies deepen the congestion. A degraded path is
  covered by a healthy one; when nothing is healthy the best single path carries
  the traffic alone. `Strategy::Duplicate` still duplicates unconditionally.
- **A path does not redial while no other path is up.** The dial has nowhere to
  go, and for WireGuard it throws away a working tunnel to negotiate a new
  handshake over a link that cannot carry it. Instead the path waits
  `UPLINK_DOWN_BACKOFF` and keeps probing, because paths recover on their own the
  moment the uplink does. A single-path session has nothing to compare against
  and redials as normal, and so does one that has not come up yet: until some
  path has carried traffic, "nothing is up" is a session still starting rather
  than one that collapsed.

### The monitor is too slow to be the only witness

That guard is gated on the uplink verdict, and the verdict is deliberately
unhurried: `uplink::PROBE_INTERVAL` is 2 s and `uplink::FAILURES_BEFORE_DOWN` is
3, so turning `Up` into `Down` takes around eight seconds. A path gives up after
three probes of its own — about one second.

Those two numbers disagreeing is a hole rather than a rounding error. Any shared
stall shorter than the monitor's window — a Wi-Fi hiccup, a router pause, a
congestion burst, which is the ordinary case — kills every path while the
monitor still reports `Up`, and a plain `Up` used to mean "redial". Observed
live: three routes across two unrelated providers went unavailable inside 1.2 s
and all three redialled, one of them an L2TP/IPsec RAS redial, with the monitor
reporting `Up` throughout and recovering every path 2 s later at 500 ms RTT
decaying back to 48.

So the health mask is treated as evidence in its own right. Every path being
down at once, after at least one of them had carried traffic, is the
common-mode signal, and inside `COMMON_MODE_CONFIRM_WINDOW` it outranks a
stale `Up`: the mask moves the moment a path fails, while `Up` can be a probe
interval old.

It is a window and not a veto, which is the other half of the design. Past it
the monitor has had every chance to agree and has not, so the paths are down for
their own reasons and are allowed to redial. Without that expiry a session whose
transports cannot recover without a dial — OpenVPN, SOCKS5, L2TP, none of which
rehandshake on their own — could hold every redial indefinitely on the strength
of an inference the monitor kept contradicting. The window is derived from the
monitor's own constants rather than written down separately, so the two cannot
drift apart.

This is a game client, so recovery is timed to be fast rather than merely safe.
A path that misses a probe switches to `PROBE_INTERVAL_DEGRADED`, so a route
that comes back is noticed in milliseconds instead of at the healthy one-second
cadence. The first redial of a path judged dead waits for nothing at all — by
then it has missed several probes in a row _and_ another path is up, so the
uplink is known good and there is nothing to gain by pausing. Only subsequent
attempts back off, from `RECONNECT_BACKOFF_STEP` up to `RECONNECT_BACKOFF_MAX`.
A test bounds the whole sequence, from the first missed probe to the first dial,
at six seconds.

Neither of these repairs the uplink. What they remove is GamePath's own
contribution to the problem, which was measurable: a local outage used to turn
into several minutes of reconnect churn after the link itself had recovered.

## Route retry

A route is dialled once when the session starts and its transport is then owned
by that route's worker. Three things can go wrong with it, and they are handled
separately:

- **It fails to dial.** The route is recorded in `skippedRoutes` with the reason
  and the session starts on the rest. Only every route failing is a start
  failure, and that error names each one.
- **It dials but never answers.** See _Degraded startup_ below: it stays out of
  the dispatcher's selection and keeps probing.
- **It dies mid-session.** WireGuard recovers by itself, because BoringTun
  re-initiates a handshake from its own timers. A SOCKS5 association and an
  OpenVPN link have no equivalent, so after `RECONNECT_AFTER_FAILURES`
  consecutive failed health checks the worker redials its node, backing off from
  `RECONNECT_BACKOFF_MIN` to `RECONNECT_BACKOFF_MAX` between attempts and
  resetting both the moment a probe is answered.

The dial runs on its own thread and the worker collects the result without
blocking, so a route that is down never delays the probes of its own path or a
session stop. A redialled path reaches the relay from a new source endpoint; the
relay learns endpoints from authenticated frames and expires them after
`ENDPOINT_TTL`, so the old one ages out with nothing to reconcile.

## Degraded startup

A relay session becomes ready when at least one path is usable, not when all of
them are. Paths that have not answered stay out of the dispatcher's selection —
tracked as a health mask separate from the scheduler's latency-based pick — and
keep probing, joining in when they answer. Status reports them as
`degradedRoutes`. A direct session has exactly one path, so it still requires
that path. Every path is given a short settling window first, so a healthy route
set does not start with routes missing.

## Worker timing

Each path worker alternates between draining the outbound queue and waiting on
its socket. An arriving packet wakes that wait immediately, so inbound traffic
is never delayed by it, but a packet handed to the worker while it is waiting is
only sent once the wait ends. Windows schedules waits on a ~15.6 ms timer by
default, which measured at 15.3 ms mean and 16.7 ms worst case on a 1 ms socket
timeout, so an outbound game packet could sit for most of a frame. A session
therefore raises the timer resolution to 1 ms for as long as it runs, which
brings the same measurement to 1.35 ms mean and 2.8 ms worst case, and releases
it when the session stops. Session status reports whether the raise was granted.

A path also returns at most one datagram per read for the same reason: reading
on would mean waiting out the timeout again for a datagram that usually is not
there, delaying the one already in hand. The worker loops instead, so a queued
datagram is taken by the next read with no wait.

## SOCKS5 routes

A SOCKS5 node opens a TCP control connection, authenticates when the proxy asks for a username and password, and issues `UDP ASSOCIATE`. Sealed frames then travel as plain datagrams carrying the ten-byte SOCKS5 UDP request header, so a SOCKS5 path adds less overhead than a WireGuard path rather than more. Replies are accepted only when the header names the relay, and fragmented datagrams are dropped: a GamePath frame is always one datagram.

RFC 1928 ties the association to its TCP control connection, so that stream is held open. Real proxies vary — some close it as soon as they answer and keep relaying — so a closed control stream is recorded as diagnostic context and never by itself marks a path dead. The session's own authenticated probes decide reachability, and the adaptive scheduler stops selecting a path whose probes stop returning.

The relay needs no change to accept these paths. It identifies a client by the authenticated client ID in each frame header and learns source endpoints as they appear, so a path arriving from the proxy's egress address registers itself and receives its share of the reply fan-out.

A SOCKS5 hop is not encrypted. Frames are already sealed and replay protected before they reach any path, so payload confidentiality and integrity do not depend on the transport, but the proxy operator observes the relay address and traffic timing that a WireGuard path hides.

A proxy on the client machine is refused in all-traffic mode. The tunnel would own the default route the proxy needs for its own upstream, so the proxy's forwarded traffic would be captured and fed back into it. Split-tunnel mode captures only the selected targets and has no such loop. A remote proxy's address joins the relay endpoint and the WireGuard endpoints in the bypass route set.

## OpenVPN routes

The client implements OpenVPN in user space rather than driving the reference
implementation, for the same reason it implements WireGuard that way: the
reference client owns an operating system adapter and takes the routing table
with it, which caps a session at one such node and collides with the capture
layer. Speaking the protocol directly gives each node its own socket, so N nodes
run concurrently, the scheduler treats them like any other path, and the
installer gains nothing to install.

A session is brought up in four steps, each of which must complete before the
next: a hard reset, a TLS handshake carried inside numbered control packets, an
exchange of random material under `key-method 2`, and the server's `PUSH_REPLY`.
Data keys come from OpenVPN's own PRF over the exchanged material rather than
from the TLS key exporter, which is what makes the client work with servers of
every vintage. TLS runs on `rustls` with a verifier that checks the chain
against the configuration's `<ca>` and skips only the hostname, which OpenVPN
does not use.

Several wire details are ordered the opposite way from how the documentation
reads, and were settled by trying every combination against a live server rather
than by inference. They are recorded in `engine/src/openvpn/crypto.rs`: the
client sends with key slot 0 and receives with slot 1, the implicit half of an
AEAD nonce is the front of the key's HMAC material, the authentication tag
precedes the ciphertext it covers, the nonce is the packet id followed by the
implicit IV, and the associated data is the header together with that packet id.
`engine/tests/openvpn_live.rs` re-proves all of it against a real provider.

Renegotiation is handled in place. A server asks to rekey roughly once an hour by
sending a soft reset on a new key id; the client runs a fresh handshake there
while the old keys stay live, so packets still in flight on the previous
generation are opened rather than dropped, and the traffic being carried does not
stop. Two generations are kept, which is what the reference implementation does.

Control packets are chunked well below a typical MTU. A handshake packet that
does not fit is dropped silently and retransmitted at the same size forever, so
the extra round trip is worth more than the larger chunk. When a UDP handshake
stalls anyway — which happens on connections that drop large datagrams — the
node is retried over TCP on the same port, where each packet is preceded by its
length. Nothing above the link layer changes between the two.

The tunnel's own address is assigned by the server, so it is not known until the
session is up, and the node list says so rather than inventing one. The server's
public address joins the relay endpoint and the WireGuard endpoints in the bypass
route set. A provider's tunnel also carries its own network's broadcast and
multicast traffic; only packets addressed to this tunnel reach the capture layer.

## WireGuard routes

Each purchased configuration is parsed only in memory for the active session. The private key, peer key, optional pre-shared key, endpoint, and assigned address feed its isolated WireGuard protocol instance. Original encrypted configurations are never modified. A validation-only transformer also proves that adapter-based backends would narrow `AllowedIPs` to the resolved relay address and omit DNS and route side effects.

## Privileged service

The Electron UI remains unprivileged. `GamePathService` runs through Windows Service Control Manager and owns the native engine behind a token-authenticated loopback API on `127.0.0.1`. The installer creates a random 256-bit control token under `%ProgramData%\GamePath`, protects it for Local System, administrators, and the installing user, and installs the signed Wintun and WinDivert runtime files beside the service. A Windows Job Object with `KILL_ON_JOB_CLOSE` prevents the capture engine from surviving a service exit. The client renews a thirty-second session lease from its main process every three seconds; if the client disappears, the service closes the engine and its capture handles automatically. The renewal cannot be driven from the renderer, whose timers Chromium throttles whenever the window is hidden or occluded — see _Session lease_.

## Concurrent sessions

The service runs two independent session slots, `game` and `vpn`, each with its own engine child, Job Object,
lease, rules and lock. Every session command takes an optional `"slot"`; a request without one is for the
game, which is what every client written before the VPN meant. `status` keeps the game's fields at the top
level and reports both slots under `slots`. Validation is pure: checking one slot never writes into the state
of a session that is running.

The slots never wait on each other's lock. A slot's lock is held for its whole start, and an L2TP dial alone
takes several seconds, so if one slot's status request queued behind the other's start, the client would see
three failed polls and tear a healthy session down. Instead each slot publishes a small summary (status,
traffic mode, where its own tunnel traffic goes) under a lock held only for a copy, and cross-slot decisions
read that. Background notifications read the latest summary after acquiring
the receiving slot's lock, so notifications delayed by a dial cannot restore
old bypass addresses or stop a VPN after the game has already stopped. Each
slot also has its own lease watchdog.

**Priority is WinDivert's, not coordination.** The game's capture handles open at priority 0, as they always
did; the VPN engine (`gamepath-engine.exe --role vpn`) opens its handles at −1000. WinDivert diverts a packet
to higher-priority handles first, and a packet one handle reinjects is only seen by handles of lower priority.
So the game takes what it selects before the VPN sees it, what the game reinjects falls through to the VPN,
and what the VPN reinjects goes out normally. Nothing on the packet path crosses processes. The cost is one
extra user-space round trip for unselected traffic when both slots run in the `all-outbound` scope; game
packets are taken by the first handle and pay nothing.

The inject handle that delivers replies runs at priority 1000 in both engines, above every capture
priority. WinDivert diverts an injected packet only to handles below the injecting one, once per level, so a
reply injected at the same priority as the DNS observer was invisible to it. That covered every tunnelled
DNS answer — which is how wildcard and changing hostname targets learn their addresses — even before a
second session existed.

**Each slot keeps the other's tunnel clear.** The service passes the other slot's tunnel addresses (relay,
node endpoint, proxy, L2TP server) as `foreignBypass`. Split capture excludes them in the kernel filter;
all-traffic capture and a native L2TP all-traffic VPN route them around the tunnel as host routes via the
physical gateway. When the game starts, stops or moves relay, the service pushes the new set to the VPN with
`set-foreign-bypass`, in the background, so the game never waits for it. The game is never rebuilt because of
the VPN; for the game the set is only an optimisation, applied at its next start.

**The game wins conflicts.** A game session in all-traffic mode leaves the VPN nothing to carry, and its
default route would swallow the VPN's tunnel, so the client stops the VPN before such a session starts and
resumes it afterwards. The service enforces the same thing: it refuses a VPN start with
`game-all-traffic` and stops a running VPN itself when the game takes all traffic. Both engines tunnel public
DNS; while the game slot has remote DNS on it takes every query first, otherwise the VPN does.

The VPN engine also writes its own log (`engine-vpn.log`), uses its own Wintun adapter (`GamePath VPN`, its
own GUID) and raises its data-plane threads one step less than the game's, to `THREAD_PRIORITY_ABOVE_NORMAL`,
so under a busy CPU the game's packets go first. Every service line about a slot is tagged `[game]` or
`[vpn vpn-3f9a1c]`; the id is the client's and appears in `client.log` too.

### SOCKS5 as the VPN's node

A proxy cannot be handed captured packets, so the VPN engine puts a smoltcp stack in front of it
(`engine/src/tun2socks`). TCP is answered there and replayed with `CONNECT`; UDP is forwarded datagram by
datagram over one `UDP ASSOCIATE` per local socket; UDP lookups to port 53 go over TCP, one lookup at a time
per stream with up to eight streams per resolver and one kept ready, with ids remapped so lookups from
different apps cannot collide. Sharing one stream let a lookup the proxy never answered hold up every lookup
behind it (measured through Throne). sing-box also closes a DNS stream when any lookup on it fails, so a lookup
lost that way is sent once more on a fresh stream and then answered with SERVFAIL, never left to time out.
Lookups to a LAN resolver are redirected whichever process sent them: Chromium-based apps (Chrome, Discord)
resolve with their own DNS client, not the system's. One thread and one `mio` poll
drive all of it.

A connection is answered only once the proxy has opened its far end: the SYN is held, then fed to smoltcp
or refused with a reset. Answering first would make every connection look open while the proxy is down, and
the direct worker treats any packet back from the path as proof it is alive. A TCP reset while that SYN is
held cancels the outstanding proxy stream immediately, rather than letting an abandoned dial finish and
return a SYN/ACK for an application socket that no longer exists. ICMP cannot cross a proxy, so
the worker's echo to the benchmark target is answered by a real `CONNECT` to it on port 53: the session's
health and latency measure the proxy's acceptance of that connection. A local proxy can accept before its
remote connection completes, so this can report a local round trip even while DNS queries time out beyond
the proxy; it is not a measurement of game-server ping or successful DNS delivery.

A stream to the proxy watches writability only while something is waiting to be written. A connected socket
is writable at once, and mio re-arms a socket every time an operation on it would block, so a stream that kept
watching it was woken by its own next read attempt, every turn: a paused video held one core at 100%, measured
as 225,000 writable events a second on one flow. Now it turns about 150 times a second (`turns=` in the
per-minute summary), and a write that would block is retried after 5 ms rather than on every event.

The path worker does not shed stale packets into this stack. Shedding suits a network path, where a packet
that waited 50 ms is worth less than the latency it adds; here the queue waits only on local processing, and a
dropped segment is resent by TCP, adding the load that made it wait. Measured: a busy VPN spiralled to 289,000
packets a minute and stopped answering status requests until the client reconnected it.

Proxy clients built on sing-box, Clash or Xray (Throne, for one) often answer DNS with **fake-IP** addresses
from 198.18.0.0/15 and map each back to its name when a connection to it arrives. Only that proxy can reach
them, so with a SOCKS5 node the VPN carries every packet to that range whichever app sent it, and both
engines treat it as not globally routable. With remote DNS on, this means every app that resolves a name
uses the proxy for it; turn fake DNS off in the proxy for a strict split tunnel.

## Remote DNS and the router's resolver

Windows sends a lookup to every adapter's resolvers at once and takes the first answer (smart multi-homed
name resolution). On a filtered network the router answers first, with the filter's blackhole address
(`10.10.34.36` for `discord.com`, measured), so giving a tunnel adapter resolvers of its own does not help.

- **Split mode** sets no resolvers on any adapter. Lookups Windows sends to a LAN or ISP resolver are
  redirected in the capture loop: rewritten to `TUNNEL_RESOLVER` (8.8.8.8), carried through the tunnel, and
  the reply rewritten to come from the resolver Windows asked. Windows only ever sees its own resolver
  answering, so there is no race. An earlier design pointed a resolver-only Wintun adapter at 8.8.8.8; with
  no route on that adapter its queries never left the machine, and blocking the router to win the race then
  left the machine with no DNS at all. The redirect stops as soon as a tunnelled lookup goes unanswered for
  2 s, and while it is stopped one lookup a second is still sent through the tunnel, so the first answer
  turns it back on; a dead tunnel costs a lookup about two seconds and never leaves the machine unable to
  resolve. Handing the query to the session is no proof: with every path down it is still sent on the last
  one. Names only the LAN can answer (single-label, `.local`, `.lan`, `.home.arpa`, reverse lookups for
  private addresses) are never redirected: elsewhere they go unanswered, and through a proxy that resolves
  them with the system resolver they would loop.
- **All-traffic mode** points the adapter at the relay's resolver (or a public one), reached through the
  tunnel's routes. Lookups to the router are not blocked: a kernel filter cannot tell GamePath's own lookups
  from any other, and the game has to be able to re-resolve its nodes while its tunnel is down.

**While both sessions run, applications' own lookups go to their own session.** Windows' resolver (svchost)
answers for most applications and games and cannot be split by application, so it stays with the game. But
Chromium-based applications (Chrome, Discord) send their own lookups, and the game's capture now leaves those
alone when the sender is installed outside Windows' folder and is not in the game's rules; the VPN then
resolves them if they are its applications, or they go to the local resolver. Without this, a VPN app's names
were resolved from the game route's country, and a route through Turkey, which blocks Discord, could not
resolve Discord at all. The service tells the game when the VPN starts or stops (`set-other-session-active`)
without reopening the game's capture, so the game's traffic is never interrupted for it.

**GamePath's own names are never redirected.** The client sends both sessions `ownHostnames`: every game
node, relay and VPN node hostname. Lookups for them go out as they would with the other session off.
Without this, a game node resolved while a SOCKS5 VPN was on got the proxy's fake-IP answer
(`198.18.0.101:903`, measured), and that game route then ran through the VPN.

This applies to the game and the VPN alike. The resolver cache is flushed whenever this changes, so neither
filtered nor fake-IP answers outlive the switch.

**Name resolution belongs to the game while it runs.** Windows resolves for every application, the game
included, so these lookups cannot be split by app. While the game session is starting or running
(`otherSessionActive`), the VPN redirects only the lookups its own rules select, which are those from
applications with their own DNS client (Chrome, Discord). Everything else follows the game's own setting:
through the game's tunnel with remote DNS on, or the local resolver with it off. Otherwise a game resolved
through a fake-IP proxy got an address only that proxy can reach, and its traffic ended up in the VPN.

**The proxy's own lookups are never redirected.** A local proxy client resolves its upstream server with the
machine's DNS servers, from its own process (sing-box does, `dns/transport/local`). Redirected, that lookup went
into the proxy itself; with fake IP on, Throne answered its own WARP server with `198.18.0.3` after a restart and
nothing went through it again. `proxy_identity` finds the process listening on the proxy's port and leaves its
UDP lookups alone, so it resolves exactly as it would without GamePath.

**Connections already open are ended, not left to hang.** A TCP connection an application opened before the
VPN started (or before a rule selected it) is carried from its next packet on, but from the session's address,
so the server stops answering it and the application only notices when its own timeout fires. When the VPN's
capture opens, `tcp_reset` ends those connections with `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)`, as Windscribe
does, and the applications reconnect through the VPN at once. Connections the session already carries are
kept, and nothing is ended while a game session runs, because the VPN cannot see the game's rules and must never
end a connection the game carries.

On disconnect, capture stops and its routes are removed before Windows' DNS cache
is flushed and its tunnelled TCP connections are ended with `SetTcpEntry`. Split
capture matches the recorded local and remote endpoints and, when known, the PID;
it does not close every connection of a selected application. All-traffic capture
matches its tunnel source address. This lets applications retry over the normal
route instead of waiting for a dead proxy stream to time out. Live capture
replacement transfers these flows without ending them. Applications that cache
proxy fake-IP DNS answers themselves can still need to resolve the name again;
flushing Windows' cache cannot clear an application's private cache.

A capture restart (a live rule edit, or the other session starting or stopping) hands the new capture its
predecessor's reply table, routed-connection list and usage counters (`CarriedFlows`), under the same capture
id. Before, every live connection's replies were dropped until it next sent something: 101 in the ten
seconds after a game session started beside the VPN.

## WireSock option

WireSock Core SDK can replace parts of tunnel lifecycle and per-application filtering for personal or licensed commercial builds. It is not the default because its free license is non-commercial and includes mandatory telemetry, and its ordinary tunnel manager does not implement the GamePath relay's multipath framing or deduplication.

## LAN proxy

The proxy a session offers to consoles lives in the privileged engine (`engine/src/socks/`), on one
event-loop thread using non-blocking sockets throughout. A console opens dozens of connections at once, and
one owner for every socket is also what the user-space stack behind it requires.

**It does not use Windows' networking to reach the tunnel.** In split mode nothing routes to the tunnel at
all, and in all-traffic mode the routes exist but a proxy relying on them would be carried by capture
policy it has no reason to depend on. So the proxy terminates the client's TCP and speaks TCP again itself,
from the session address, in smoltcp (`tunnel_egress`), handing every packet it produces to
`enqueue_data_packet` like a captured one. That is why proxied traffic ignores split rules: it never meets
capture. Direct L2TP/IPsec has no engine data plane to enter, so there the service starts an engine child
for the proxy alone, and its flows are plain sockets pinned to the RAS adapter with `IP_UNICAST_IF`
(`interface_egress`).

Replies come back on the same inbound path as a game's, so the path workers pass each one through
`session::LocalTap` first. The stack claims every local port it uses in an atomic bitmap, one per
protocol, and a reply to a claimed port goes to the stack instead of capture — which would otherwise hand
it to Windows, which has no socket for it and would reset the connection. Each port is taken from Windows
first by binding a real socket with `SO_EXCLUSIVEADDRUSE`, so no application whose traffic capture
carries can ever be given the same one. Later fragments of a diverted datagram carry no port and follow
their first fragment by IP identification. With no proxy running, the tap costs one relaxed load per
packet.

smoltcp is pinned to 0.12, the last release inside the 1.85 MSRV, with its build-time buffers raised: a
full 64 KiB UDP datagram in each direction, four reassembly slots, and 16 out-of-order TCP segments
rather than 4, which matters on the lossy paths this client is used on. Nagle is off and congestion
control is CUBIC. Hostnames are resolved through the same egress, racing every resolver the session can
reach and retrying every 700 ms, with answers cached for their TTL clamped to 30 s–10 min.

The loop is woken by the client sockets, by the egress's own sockets, or by a `mio::Waker` the tap fires
when the first packet of a batch arrives, so a reply reaches its client in the turn it arrives. Packets
the stack produces are flushed to the session under a single lock per turn. The proxy thread takes the
session lock, so it is always stopped before the session is, never while the lock is held.

## Usage accounting

The privileged engine publishes two monotonic per-session counters for IP packets admitted to the session and delivered to its capture receiver. They count a relay packet once even when the scheduler sends copies on several paths. Existing per-path worker counters remain the physical node view, including framing overhead. Split capture attaches atomic sent/received counters to its known application flows and exports them with capture diagnostics; unattributed flows use their own bucket. Capture generations distinguish a live split-policy replacement from counter growth.

Native direct L2TP is routed by Windows outside that engine data plane. The service samples `RasGetConnectionStatistics` for its connection and extends the 32-bit counters across wraparound, resetting the baseline if the connection duration restarts. These totals reflect RAS connection bytes rather than the engine's unique IPv4 packet count.

Electron's main-process lease poll samples these counters without database work on the packet path. It accumulates deltas in memory and flushes daily local-time buckets to SQLite every 15 seconds. The statistics view queries that store only while visible. A reset deletes saved buckets while retaining the current session's counter baseline. This avoids replaying old totals at the next poll.
