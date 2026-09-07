# Client networking architecture

GamePath uses separate components for policy, capture, and transport so the GUI never needs administrator privileges.

## Split-tunnel mode

The privileged Windows service installs filters based on Windows Filtering Platform (WFP) semantics:

1. ALE flow/socket events associate each network five-tuple with its originating process.
2. Application rules match the full executable path. Folder rules match the normalized process-path prefix in the service policy layer.
3. Hostname rules are correlated through the client's DNS policy cache and compiled to current address sets. IP and CIDR rules match destinations directly.
4. Selected UDP and TCP packets are passed to the GamePath transport. Unselected packets continue unchanged.

The current implementation uses the signed WinDivert callout driver as the WFP capture layer. It opens network filters only for selected destination ranges and ports discovered from process-aware socket events. DNS observation is copy-only. Unrelated traffic therefore stays in the kernel and cannot be held by the client. A production-owned WFP callout can replace this backend later without changing the GUI or relay protocol.

## All-traffic mode

All traffic is routed into the signed Wintun adapter. This avoids process correlation overhead when every connection has the same policy. Relay endpoint routes and local-network bypass routes are installed before the default route changes.

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

A **direct session** has no relay, so a node has to do that work itself. Only a
WireGuard node can: its server already routes and NATs whatever comes out of
the tunnel. The captured packet is rewritten to the tunnel's own address and
sent as it stands, with no GamePath framing, no sequence number and no
duplication — WireGuard's own crypto is the only wrapping, and replies come
back as plain inner packets addressed to the tunnel. A SOCKS5 node is refused
before anything is opened, since a proxy has nothing to route with.

The two modes meet at `enqueue_data_packet` and `DataReceiver::receive`, so the
capture layer above them is identical: split-tunnel filters, the Wintun
all-traffic path, the reply injector and the privileged service are unchanged
by the choice.

Health is judged differently because the evidence differs. A relay session
exchanges authenticated control frames with a relay it owns, so a silent path
is a broken path. A direct session's node belongs to a provider and answers
nothing at the application layer, so the engine sends an ICMP echo through the
tunnel to `1.1.1.1` every 500 ms and works from two signals:

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

## Multipath transport

Every node becomes one path behind a common `RelayPath` transport interface, so the scheduler, the sequence allocator, and the session's authenticated framing work the same whichever transport a route uses. Two transports exist today: a user-space WireGuard tunnel and a SOCKS5 UDP association. A session may mix them freely.

Each distinct imported configuration creates an independent user-space WireGuard protocol instance. This allows different provider endpoints to run simultaneously even when their tunnel addresses overlap, a combination Windows rejects as duplicate adapters. The implementation uses BoringTun's portable WireGuard protocol core and ordinary Winsock UDP sockets for the outer provider connections.

The direct ISP path is always available alongside provider routes. If two files resolve to the same endpoint and reuse the same client identity, their WireGuard handshakes would replace one another at the provider. GamePath detects that conflict, keeps one live, and holds the overlap as standby. Distinct endpoint/key pairs become additional live paths.

Authenticated GamePath frames are wrapped in an inner IPv4/UDP packet addressed to the relay, then encrypted independently by each WireGuard instance. Packets receive a session ID and monotonically increasing sequence number before adaptive scheduling sends them on one or two routes. The relay sees two authenticated endpoints and fans replies back across both.

Direct and WireGuard workers share one atomic sequence allocator, so control traffic and data traffic never reuse an authenticated nonce or fall behind the relay replay window. The client sends one encrypted data frame to every selected path and accepts the first authenticated reply; later copies are discarded by sequence number.

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

## WireGuard routes

Each purchased configuration is parsed only in memory for the active session. The private key, peer key, optional pre-shared key, endpoint, and assigned address feed its isolated WireGuard protocol instance. Original encrypted configurations are never modified. A validation-only transformer also proves that adapter-based backends would narrow `AllowedIPs` to the resolved relay address and omit DNS and route side effects.

## Privileged service

The Electron UI remains unprivileged. `GamePathService` runs through Windows Service Control Manager and owns the native engine behind a token-authenticated loopback API on `127.0.0.1`. The installer creates a random 256-bit control token under `%ProgramData%\GamePath`, protects it for Local System, administrators, and the installing user, and installs the signed Wintun and WinDivert runtime files beside the service. A Windows Job Object with `KILL_ON_JOB_CLOSE` prevents the capture engine from surviving a service exit. The GUI's two-second telemetry poll also renews a ten-second session lease; if the GUI disappears, the service closes the engine and its capture handles automatically.

## WireSock option

WireSock Core SDK can replace parts of tunnel lifecycle and per-application filtering for personal or licensed commercial builds. It is not the default because its free license is non-commercial and includes mandatory telemetry, and its ordinary tunnel manager does not implement the GamePath relay's multipath framing or deduplication.
