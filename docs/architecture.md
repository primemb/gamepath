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

A captured packet is not what leaves the machine, so the tunnel MTU is derived from what the selected transports actually add rather than fixed at a constant. `EffectiveMtu::for_session` costs the outer IPv4/UDP header, the transport's own framing, and — for a relay session — the inner IPv4/UDP datagram, the 40-byte GamePath header and its 16-byte AEAD tag. Relay over WireGuard therefore costs 144 bytes and yields a 1356-byte MTU on a 1500-byte link; direct WireGuard costs 60 and yields 1440. A mixed route set takes the smallest, because the scheduler may move a packet onto any of them. The Wintun adapter is sized from this, and split mode clamps the TCP MSS to `mtu - 40` rather than to a fixed conservative value.

The link MTU is read per endpoint from the route Windows would actually take, because a laptop can have Ethernet, Wi-Fi and a mobile interface up at once.

`MIN_TUNNEL_MTU` (1280) is a hard floor, not a preference: no session is configured below it whatever the link and encapsulation leave room for. 1280 is the minimum every IPv6-capable link must carry, and the size games, engines and middleboxes assume they can send without discovering a path MTU first, so a tunnel advertised under it tends to surface as connection failures rather than as the slower path it ought to be. On a link too narrow to hold the floor plus its encapsulation — a 1280-byte uplink carrying a relay session over L2TP/IPsec, where 200 bytes of encapsulation leave 1080 — the remainder fragments instead. That is the deliberate trade, and it is the less obvious failure of the two, so `EffectiveMtu::below_link_budget` records it and both session-start paths log it rather than letting it appear as unexplained loss.

## Windows network configuration

Interface MTUs, route installation and adapter lookups go through the IP Helper
API in `engine/src/netconfig.rs`, not through the `Net*` PowerShell cmdlets.

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
is ever answered, the engine stops asking after three attempts and stops
counting them as loss — reporting such a node as totally lossy would be wrong —
and the handshake round trip stands in for the route latency. **The cost is
that a node in this state has no liveness signal at all** and stays reported as
up while the tunnel is established. Probe counters stay unpublished until one
echo is answered, so the client never shows probes it could not measure.

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

## WireSock option

WireSock Core SDK can replace parts of tunnel lifecycle and per-application filtering for personal or licensed commercial builds. It is not the default because its free license is non-commercial and includes mandatory telemetry, and its ordinary tunnel manager does not implement the GamePath relay's multipath framing or deduplication.
