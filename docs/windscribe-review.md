# GamePath review against Windscribe

Reviewed on 2026-10-02. GamePath version: 0.5.5, starting commit
`ffb20e0b7e5ac395c08d3d6aefc9ec7ea9568b46`. Windscribe source:
`829cd6e609027e76d3ce1c14b1da94ba10d34177`, release 2.25.2 dated 2026-09-29.
The public Windscribe mirror was cloned outside the GamePath repository and
reviewed as source; its client was not installed or run.

## Assessment

GamePath has a substantial gaming data plane and useful safeguards already.
It is still an alpha client, with lifecycle, IPv6 and distribution gaps that
prevent treating it as a mature general VPN. Passing tests is good evidence
of specific behavior, not proof of lower ping or uninterrupted games on real
restricted networks.

The products solve different problems. GamePath's authenticated relay overlay
can duplicate packets, deduplicate replies, repair some losses and preserve
the relay egress address across node failures. Windscribe's desktop client
offers a broader set of VPN protocols, firewall controls and platform
integration. Neither project's source establishes that one has better latency
on a particular ISP, provider or game server.

## Comparison

| Area                          | GamePath now                                                                                                               | Windscribe reference                                                                                            | Assessment                                                                                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Gaming redundancy             | Adaptive path scoring, incumbency margin, duplicate delivery, replay protection and negotiated XOR repair                  | Conventional VPN connection lifecycle and protocol selection                                                    | GamePath has a useful specialized design; its bandwidth cost and shared uplink failures still matter.                                           |
| Queue latency                 | Bounded queues, stale packet shedding, nonblocking OpenVPN TCP writes and transport-aware relay probes                     | Native VPN connectors, including WireGuard and OpenVPN DCO build dependencies                                   | Good GamePath safeguards. Performance superiority needs measurement.                                                                            |
| Network changes               | Physical gateway, bypass routes and uplink source are chosen at activation; no IP Helper network-change subscription found | Windows address, route and interface notifications, with a 250 ms debounce                                      | High-priority GamePath recovery gap.                                                                                                            |
| Sleep/resume                  | VPN gets a resume callback; game session does not have equivalent recovery                                                 | Explicit sleep/wake connection states and reconnect handling                                                    | High-priority game lifecycle gap.                                                                                                               |
| DNS                           | Router/ISP DNS redirection in split mode, tunnel adapter DNS in all mode, deliberate fallback and bootstrap exceptions     | Separate Windows DNS firewall and DNS configurator                                                              | GamePath improves censored DNS access; it does not provide Windscribe-style strict leak prevention.                                             |
| IPv6                          | IPv4 data plane with exposure diagnostics; native direct L2TP may carry IPv6 itself                                        | IPv6 firewall and split-tunnel handling                                                                         | Selected apps can bypass GamePath over IPv6.                                                                                                    |
| Split capture                 | Destination-only kernel filters; app/folder/hostname plans classify broad outbound IPv4 in user space                      | Dedicated Windows split-tunneling implementation                                                                | GamePath's broad scope remains a throughput and compatibility cost, especially with both slots running.                                         |
| Restricted-network transports | WireGuard, OpenVPN UDP/TCP, L2TP/IPsec and external SOCKS5 paths                                                           | Also Stealth, WSTunnel, IKEv2 and AmneziaWG integration in source                                               | Obfuscation is a useful next capability where standard VPN handshakes are blocked. External proxy clients already provide an integration route. |
| Privileges                    | Service owns capture, but packaged Electron executable requests administrator privileges                                   | Helper isolation and runtime executable signature checks; recent release also reduces OpenVPN daemon privileges | GamePath packaging currently contradicts its unprivileged-GUI invariant.                                                                        |
| Release assurance             | Unsigned installer, published checksum, signed upstream capture drivers, automated build/unit checks                       | Signing and runtime signature verification paths                                                                | Improve release signing and real-machine validation before calling GamePath mature.                                                             |

Windscribe evidence: [supported protocols and build dependencies](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/README.md),
[network-change worker](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/client/engine/engine/networkdetectionmanager/networkchangeworkerthread.cpp),
[connection lifecycle](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/client/engine/engine/connectionmanager/connectionmanager.cpp),
[Windows DNS firewall](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/helper/windows/dns_firewall.cpp),
[IPv6 firewall](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/helper/windows/ipv6_firewall.cpp),
[Windows split tunneling](https://github.com/Windscribe/Desktop-App/tree/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/helper/windows/split_tunneling),
[signature verification](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/client/client-common/utils/executable_signature/executable_signature_win.cpp),
and [release fixes](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/CHANGELOG.md).

## Verified fixes made in this review

1. **Old game status replies could affect a new session.** The main-process
   poll previously applied results after Stop, Start or relay replacement and
   could issue failure cleanup outside the session transition queue. It now
   checks the session identity after the request and again after queued cleanup
   starts. Four executable regression tests cover stale success, stale failure,
   queued replacement and ordinary three-failure cleanup.
2. **Cross-slot background notifications could apply stale state.** Tasks
   captured an old bypass list or active flag before waiting on the destination
   slot's potentially long dial. A delayed all-traffic notification could also
   stop a VPN after the game had already stopped. Tasks now reconcile from the
   current summary after taking the destination slot's lock. Tests cover an
   obsolete stop notification and continued enforcement of a current
   all-traffic game.
3. **Direct probes could credit the wrong echo.** Matching used the identifier
   without the sequence, so a late reply could consume a newer probe's timer
   and publish a false RTT. Matching now includes the sequence, accepts IPv4
   header options at their actual offset, and refuses truncated or fragmented
   measurements. The startup benchmark also checks its sequence.
4. **Direct OpenVPN health probes lacked relay-mode TCP safeguards.** They used
   the datagram timeout floor and realtime writes. They now use the negotiated
   transport's deadline floor and reliable writes, so local stale-packet
   shedding cannot discard the health probe. This reduces one source of false
   loss reports; it does not eliminate TCP head-of-line delay.
5. **OpenVPN certificate requirements were silently ignored.** Files naming
   `verify-x509-name`, `peer-fingerprint`, `verify-hash`, `crl-verify` or `tls-verify` were
   accepted without enforcing those extra checks. Import and native validation
   now explicitly refuse them, including prefixed directives and directives
   inside connection blocks, plus inline fingerprints and revocation lists.
   Existing saved configurations containing these
   checks will also fail validation. CA-chain verification remains in use;
   implementing the additional checks is future compatibility work. The
   [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html)
   defines these as certificate verification controls, not cosmetic settings.
6. **Documented connection-block import did not work.** Electron treated
   `<connection>` content as an opaque certificate block and could not find its
   server. It now reads connection directives while keeping certificate and key
   bodies opaque. Regression tests reproduced both this bug and the certificate
   requirement bug before the fixes and passed afterward.
7. **DNS and MTU documentation was stale.** README previously said router DNS
   could not be protected in split mode even though redirection is implemented.
   Architecture examples omitted the 15-byte repair reserve: relay WireGuard
   costs 159 bytes and yields a 1341-byte tunnel MTU on a 1500-byte link.

These are original changes to GamePath. No Windscribe implementation was copied.

## Remaining priorities

### P1: Network handover and game-session recovery

Relevant code: `engine/src/capture.rs`, `engine/src/session/monitors.rs`,
`engine/src/netconfig.rs`, `engine/src/session/direct_worker.rs`,
`electron/main.cjs`, `electron/vpn-session.cjs`.

All-traffic bypass routes retain the gateway/interface selected at activation.
The uplink monitor retains its original source address. Ethernet-to-Wi-Fi,
DHCP address changes or a hotspot handover can therefore leave stale routing
and misleading uplink diagnostics. The MTU invalidation API currently has no
production callers. The VPN's resume handler does not provide an equivalent
restart path for the game if its service slot expired or its transport died.

Add debounced route/address/interface monitoring and reconcile the physical
route, pinned sockets and MTU without restarting usable relay paths. Ignore
GamePath's own adapter/route churn to prevent feedback loops. Use
[Microsoft's IP interface notification API](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)
with bounded callbacks and cancellation outside the callback; Microsoft
specifically documents the cancellation deadlock constraint. A game whose
slot is actually gone needs an explicit recovery state that respects a user
Stop and reports whether existing game connections can survive.

Direct OpenVPN also needs a stronger lifecycle: the direct worker reports
transport errors but has no redial loop equivalent to the relay worker. A
provider that never answers ICMP retains its established-handshake health
signal even if the transport later fails. The separate VPN controller can
restart a degraded session, but that only helps if degradation is detected.
Recovery must account for a provider assigning a different tunnel address;
blindly swapping the path under the existing capture would be unsafe.

### P1: Finish the privilege split

`package.json` sets `requestedExecutionLevel` to `requireAdministrator`, while
`electron/startup.cjs` installs a per-user Run entry. The service installer
already grants its installing user's SID read access to the control directory.
The shipped GUI nevertheless requests elevation and does not meet the stated
architecture invariant.

Move the packaged GUI to `asInvoker`, validate standard-user service access,
and provide writable per-user client/engine logs. Current shared ProgramData
logging and installation under a different administrator account need
verification before changing only the executable manifest. Keep elevation in
the install/repair operation and privileged service.

### P1/P2: Explicit IPv6 and reconnect protection

IPv6 bypass is documented, but it can still make a selected game reach a blocked
server directly. Provide an explicit per-session option to block selected
IPv6 until the IPv6 data plane exists. Preserve unrelated applications and LAN
access. The separate VPN kill switch intentionally has a reconnect gap and
does not block DNS; stronger protection needs service-owned filters that
survive transport replacement, with clear cleanup behavior. This is a product
choice, not something to silently enable during a review.

### P2: Path MTU and capture efficiency

Interface MTU is not the same as the smallest MTU across an Internet path.
GamePath's encapsulation accounting is valuable, but a 1500-byte local link
does not prove the route to a provider can carry that budget. Windscribe has a
[packet-size detector](https://github.com/Windscribe/Desktop-App/blob/829cd6e609027e76d3ce1c14b1da94ba10d34177/src/client/engine/engine/packetsizecontroller.cpp).
Consider optional bounded packet-size discovery and a manual MTU cap; a failed
ICMP probe on a censored network must not be treated as proof of a small MTU.

Benchmark GamePath's `all-outbound` compatibility scope before investing in a
signed WFP callout. Measure game p50/p95/p99 added latency, jitter, CPU and
throughput with unrelated downloads and both session slots active. A large
rewrite is not justified by source comparison alone.

### P2: Distribution, protocol compatibility and regression coverage

Add code signing, runtime provenance checks appropriate to the distribution
model, and a repeatable Windows release test matrix. Windscribe's latest
changelog still fixes WFP coexistence, sleep recovery and reconnect edge cases;
its size and age do not make those problems disappear.

The existing transport, scheduler and session submodules are a good basis for
extensions. `electron/main.cjs` and `engine/src/split_capture.rs` still carry
large amounts of lifecycle and policy logic. Extract a game-session controller
along the VPN controller's lines and separate DNS/flow classification during
functional work, keeping behavior tests at those boundaries. Broad formatting
or file movement alone would not improve connection stability.

For restricted networks, prioritize integration tests with actual censorship
conditions and available external proxies. Additional obfuscated transports
need compatible servers and their own MTU, health and recovery accounting;
adding protocol names alone will not improve connectivity. Expand tests of the
custom OpenVPN implementation against the reference server, including rekeys,
certificate constraints, TCP stalls and provider-pushed settings.

## Validation and limits

Final results:

| Check                                                    | Result                                                                                                    |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `npm run check`                                          | Passed: formatting, 144 JavaScript tests, TypeScript/Vite build, engine and service builds.               |
| `cargo test --locked --manifest-path engine/Cargo.toml`  | Passed: 251 library tests and 131 binary tests; 8 tests requiring live networking/provider setup ignored. |
| `cargo test --locked --manifest-path service/Cargo.toml` | Passed: 33 tests.                                                                                         |
| `cargo test --locked --manifest-path relay/Cargo.toml`   | Passed: 11 tests on Windows.                                                                              |
| `npm run relay:msrv`                                     | Passed with Rust 1.85.0.                                                                                  |
| Rust formatting for changed files and `git diff --check` | Passed.                                                                                                   |

There were 570 passing tests across those suites, including 15 added regression
tests. These checks cover builds, type checking, formatting, unit tests and
local simulated networking. Provider-dependent OpenVPN tests are ignored
unless explicitly supplied with provider configuration.

No real saved VPN configuration, relay credential or elevated integration
harness was used. Windows relay tests exercise the platform-independent
portions; the Linux TUN/NAT runtime remains a Linux CI or VPS integration check.
No claim about actual ping, bandwidth, IPv6 leak behavior or recovery time on
this user's restricted connection was measured here.

Before a production recommendation, test sleep/wake, interface handover,
temporary ISP blackouts, individual node failures, relay restart, dual-stack
DNS, another VPN/WFP client, and a long gaming session with a concurrent
download. Record game reconnects and packet loss alongside throughput and
latency percentiles.
