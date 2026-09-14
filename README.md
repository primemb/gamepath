# GamePath

**Bring your own VPN configs. Choose your apps. Keep your routes working together.**

GamePath is an early-stage Windows gaming tunnel client built with Electron, React,
and Rust. Import WireGuard, OpenVPN (TCP or UDP), L2TP/IPsec, or UDP-capable SOCKS5 nodes and
choose which apps use them. Use one VPN node directly, or
combine paths through an authenticated relay on your own Debian or Ubuntu VPS.

[Download releases](https://github.com/primemb/gamepath/releases) |
[Report a problem](https://github.com/primemb/gamepath/issues) |
[Relay setup](deploy/README.md)

## Get started

1. Install the Windows x64 installer from Releases, when available.
2. Import a WireGuard or OpenVPN config, or add an L2TP/IPsec login. For SOCKS5, use a proxy with working
   `UDP ASSOCIATE` support and select relay mode.
3. Choose **Direct** for one tunnelling node without a VPS, or **Relay** to use
   multiple nodes with a VPS you control.
4. Add the games or programs you want to tunnel, enable your nodes, and connect.

GamePath is alpha software. Multiple routes can help with individual path
failures, but they still share your internet connection. It cannot guarantee
lower ping or prevent interruptions when every available path is affected.

## Requirements

- Windows x64, with administrator access for the network service and packet capture.
- Your own compatible node configurations; VPN subscriptions are not included.
- For relay mode: a Debian 13+ or Ubuntu 22.04+ VPS with root access for setup.
- To build from source: Node.js 24 LTS, npm, stable Rust with the MSVC toolchain,
  and Visual Studio Build Tools with Desktop development with C++ and a Windows SDK.
  CI uses Windows Server 2022 runners.

## Credits

Created by **primemb**. Discord: **prime_lifesoul**.
Project: https://github.com/primemb/gamepath

## Run the client

```powershell
npm ci
npm run dev
```

Build the Windows installer with:

```powershell
npm run package:windows
```

The installer is written to `release\GamePath-Setup-<version>.exe`. It installs
and starts the network service automatically, and the application requests
administrator access at launch. Its uninstaller removes the Windows service,
privileged runtime, control token, routes, and local app data. Settings includes
a manual service reinstall action for repair.

Imported VPN configurations, L2TP/IPsec pre-shared keys and login passwords, and SOCKS5 proxy passwords are encrypted with Electron `safeStorage`, backed by Windows cryptography. Only non-secret metadata is sent to the renderer.

To copy the privileged runtime without starting packet capture, use `deploy\install-windows-service.ps1 -LeaveStopped`. Running the installer from Settings installs and starts the service normally.

## Validate

```powershell
npm run check
cargo test --locked --manifest-path engine/Cargo.toml
cargo test --locked --manifest-path service/Cargo.toml
cargo test --locked --manifest-path relay/Cargo.toml
```

## Current scope

- Import any number of WireGuard `.conf` files.
- Import any number of OpenVPN `.ovpn` files, over UDP or TCP, and run several at once without an adapter or a driver.
- Add L2TP/IPsec nodes backed by the native Windows RAS client, and test the real connection before saving.
- Add any number of SOCKS5 proxy nodes, alone or beside WireGuard routes, and test each one for real UDP support before saving it.
- Enable, disable, and remove individual routes.
- Choose all-system traffic or split-tunnel rules.
- Add split rules for executables, folders, hostnames, and IP ranges.
- Choose relay mode, which adaptively selects paths through a relay you own, or direct mode, which needs no VPS and routes through one WireGuard, OpenVPN or L2TP/IPsec node.
- Configure and test an authenticated relay in a location you choose.
- Add any number of relay locations and enable zero or one at a time.
- Provision or remove a Debian 13+ or Ubuntu 22.04+ VPS over password-authenticated SSH from the client; SSH passwords remain transient and host fingerprints are pinned after first use.
- Start and monitor the Rust engine through private JSON-line IPC.
- Detect the installed WireGuard client and active interfaces.
- Validate complete session plans before any route mutation.
- Compile application, folder, hostname, and IP targets into a process-aware WFP interception plan.
- Compute adaptive route decisions in the Rust engine.
- Load and verify the WinDivert WFP capture runtime before activation.
- Encrypt and send sequenced frames through WireGuard, OpenVPN TCP/UDP, Windows L2TP/IPsec, and UDP-capable SOCKS5 paths.
- Monitor provider routes with authenticated probes and check the local uplink separately.
- Duplicate authenticated IP frames across the live paths and verify the complete Windows-to-relay-TUN return loop.
- Detect configs that resolve to the same WireGuard endpoint and reuse the same client identity, then hold overlaps as standby instead of allowing their handshakes to replace each other.
- Hold a second node pointed at one SOCKS5 proxy as standby, since two associations on the same proxy carry no extra path.
- Install an authenticated Windows network service that owns the Wintun and WinDivert data planes and contains its engine in a kill-on-close Job Object.
- Provision an idempotent Debian 13+ or Ubuntu 22.04+ relay with systemd, nftables NAT, TUN forwarding, per-client enrollment, authenticated probes, replay protection, and multipath reply fan-out.

All-traffic mode captures and reinjects IPv4 through Wintun. IPv6 is not carried: on a dual-stack connection, IPv6 keeps using your normal route while a session runs, and the client warns when it detects one.

Split mode compiles IP and CIDR targets straight into the WinDivert kernel filter, so unrelated traffic never leaves the kernel. Executable, folder and hostname targets cannot be expressed in a filter that is fixed when the handle opens, so those plans admit all outbound IPv4 and classify in user space, reinjecting what was not selected — a compatibility backend with a measurable cost, reported as `captureScope` in capture diagnostics. Exact hostnames resolve at activation; a copy-only DNS observer learns later addresses and wildcard subdomains.

### Name resolution

Both modes send DNS through the tunnel. This is not only about privacy: where DNS answers are filtered by name, a game resolves its own servers to a dead address while the tunnel beside it is perfectly healthy, which looks like the tunnel failing and is not.

All-traffic mode points the tunnel adapter at a resolver reachable through the session. It prefers the relay's own resolver, whose address exists only inside the tunnel and so cannot leak by any route, and falls back to a public resolver reached through the tunnel when the relay has none — a relay installed before this existed keeps working, it just resolves further away. The chosen servers are logged and reported as `dnsServers`. They are cleared when capture stops.

Split mode selects DNS whoever asked for it, over UDP and TCP, counted as `tunnelledDnsQueries` — but only queries already aimed at a public resolver, since a query to your own router means the relay's LAN once it arrives there and tunnelling it would destroy rather than redirect it. If your machine resolves through its router, all-traffic mode is the mode that protects lookups. A rule naming an application cannot do this on its own: Windows applications do not send DNS themselves, they call the resolver, and the DNS Client service inside `svchost.exe` sends the query — so an application rule selects every packet the game sends and still leaves its name lookups going out untunnelled, owned by a process nobody selected. If the session cannot carry a query it takes the normal route, so this can cost a lookup latency but never the ability to resolve.

To resolve inside the relay rather than through a public resolver, reinstall the relay with `deploy/install-relay.sh`; it configures a resolver bound to the tunnel address only, and refuses port 53 on the public interface so the relay never becomes an open resolver.

Targets and rule-group changes made during a connected split session take effect immediately. GamePath replaces only the capture policy and keeps the encrypted relay paths and session keys alive; newly selected TCP applications use the tunnel for new connections, while UDP sockets already open when the rule is added are discovered automatically.

The repository includes the official signed Wintun 0.14.1 AMD64 DLL and its redistribution license under `vendor/wintun`. The downloaded archive is verified against the SHA-256 published by the Wintun project before the binary is copied into the project.

The WFP prototype backend uses the upstream WinDivert 2.2.2-A x64 runtime under `vendor/windivert`. Its signed driver, user-mode DLL, license, package source, and recorded hashes are included.

See `docs/architecture.md` for the WFP, Winsock, Wintun, and optional WireSock backend design.
See `docs/relay-security.md` and `deploy/README.md` for the encrypted overlay and one-command relay installation.

## Connection modes

**Relay mode** keeps eligible enabled nodes connected to a relay you run. The
adaptive scheduler proactively duplicates sealed packets across the two best
suitable routes, so backup copies are already travelling when a path fails.
Latency, jitter, and probe loss affect selection; a severely slower backup or
substantial degradation on both candidates reduces outbound traffic to one
route. The latency and loss shown for a route are current smoothed measures
rather than session averages, so a route that had a bad minute and recovered
reads as recovered. Other enabled paths keep probing and can replace a failed route.
The first authenticated copy wins in each direction, without waiting for the
other paths. Return copies are deduplicated before entering the client queue;
a reply can still rescue a lost packet even if its path is no longer selected
for outgoing traffic. Multiple enabled nodes do not mean every outbound packet
travels through every node. The relay currently sends replies to every recently
authenticated endpoint, including endpoints kept alive by probes. This mode
needs a VPS and adds bandwidth overhead for redundancy.

Failover preserves the relay session and public source address. Its quality
still depends on a usable alternative: a slower backup can increase ping, and
paths sharing an ISP bottleneck or the same relay cannot bypass failure of that
shared segment. Direct mode does not provide multipath failover.

**Direct mode** is for people who have no server to run a relay on. Selected
traffic goes through one WireGuard, OpenVPN or L2TP/IPsec node, which routes it
onward as a normal VPN would. Nothing is duplicated and there is no second path
to fall back on. WireGuard and OpenVPN accept every split selector; native L2TP
split routing accepts IPv4 ranges and exact hostnames, while its all-traffic
mode accepts everything.

Direct mode takes a tunnelling node: WireGuard, OpenVPN or L2TP/IPsec. A SOCKS5 proxy
forwards connections and datagrams; it cannot route the raw packets GamePath
captures, so it needs a relay on the other side to do that. Exactly one node is
used, because combining nodes is the relay's job.

Switching modes needs no provider-side reconfiguration beyond choosing the node.

## L2TP/IPsec nodes

L2TP/IPsec uses the Windows RAS client. GamePath creates a temporary VPN profile,
dials it from the privileged network service, and removes the connection,
profile and routes on disconnect or lease expiry. In relay mode only the relay
host is routed through that adapter. If RAS drops, the privileged engine redials
that profile without restarting the other relay paths. In direct all-traffic
mode Windows owns the VPN default route. Direct split mode installs IPv4 routes
for CIDRs and the current A records of exact hostnames; application, folder,
wildcard-hostname and IPv6 split targets are not supported. Use all-traffic mode
or a WireGuard/OpenVPN node for the application, folder and wildcard-hostname
selectors.

The service derives the L2TP interface MTU from the uplink route before traffic
starts — 1384 bytes on an ordinary 1500-byte link, and never below 1280 — and
uses an interface-pinned DNS probe for live latency and loss. The probe requires
no permanent route of its own, so direct split mode carries only the targets the
user selected. IPv6 diagnostics follow the machine's preferred public IPv6
route and distinguish traffic carried by the VPN from traffic bypassing it.

## OpenVPN nodes

GamePath speaks OpenVPN itself, in user space, the same way it speaks WireGuard.
There is no separate OpenVPN adapter or driver to install and no `openvpn.exe` to
supervise, so several OpenVPN nodes run side by side in one session and mix
freely with WireGuard and SOCKS5 nodes. Import a provider's `.ovpn` file, enter
the username and password it asks for, and it becomes a node like any other.

**A TCP configuration still carries your game's UDP traffic.** This is worth
being clear about, because it is the opposite of how a TCP-only SOCKS5 proxy
behaves. OpenVPN over TCP is a full IP tunnel: whole packets, UDP included,
travel inside the stream. So one WireGuard node on UDP beside one OpenVPN node
on TCP is a working pair, and both deliver UDP frames to the relay.

The trade-off is that TCP retransmits in order, so a lost segment holds up every
packet behind it — which hurts most on exactly the bad networks a TCP
configuration is chosen for. Prefer a UDP configuration where one works.

**A UDP configuration can retry TCP on the same port.** Some connections
drop the large packets an OpenVPN server sends during its handshake; the server
then retransmits the same oversized packet forever and nothing completes. When
that happens GamePath retries the same server over TCP rather than failing, and
the node list says which transport a node settled on. This succeeds only if the
provider also accepts OpenVPN TCP on that port.

What a configuration may contain:

- `remote` lines over UDP or TCP, including several, and `<connection>` blocks.
- Inline `<ca>`, and either `auth-user-pass` or an inline `<cert>` and `<key>`.
- `tls-auth` or `tls-crypt`, inline, with either key direction.
- `AES-256-GCM`, `AES-128-GCM` or `CHACHA20-POLY1305`, negotiated or named.

What is refused, by name and with the reason:

- `dev tap`, which carries Ethernet frames rather than IP packets.
- `ca`, `cert`, `key`, `tls-auth`, `tls-crypt` or `pkcs12` kept in a separate
  file; the block has to be inline, since GamePath stores one self-contained file.
- `tls-crypt-v2`, and `secret` static-key mode.
- Compression of any kind, which leaks information about traffic and adds
  latency. A `no`, `stub` or `stub-v2` stub is accepted.
- `--fragment`, `http-proxy`, `socks-proxy` and `static-challenge`.

The server's certificate is checked against the `<ca>` in the file, inside its
validity dates, and must be marked for server use. The hostname is deliberately
not checked: OpenVPN does not authenticate a server that way, servers are
routinely reached by bare IP, and their certificates routinely carry a name that
matches nothing. Verification itself is never skipped.

The file and its credentials are encrypted by Windows secure storage and are
decrypted only in the privileged process, at the moment the engine needs them.

## SOCKS5 nodes

A relay session can mix WireGuard, OpenVPN, L2TP/IPsec, and SOCKS5 nodes. GamePath carries game TCP _and_ UDP inside its own authenticated UDP
frames, so a SOCKS5 node only has to move datagrams: the proxy must support
`UDP ASSOCIATE`. Proxies that speak only `CONNECT`, including SSH dynamic
forwarding, cannot be used. Accepting the association is not sufficient either,
so **Test UDP** sends an authenticated frame and waits for the relay's reply
through the proxy before the node is saved.

Beware of testing a proxy with a DNS query. Clients built on sing-box and Xray
— Throne, NekoBox, v2rayN and the rest — answer DNS from their own resolver
instead of forwarding the datagram, so a DNS round trip succeeds even when the
proxy relays no UDP at all. Aim a query at `192.0.2.1`, which is reserved and
routes nowhere: a reply can only have come from the proxy intercepting it.
**Test UDP** does exactly this before reporting a result, and says so when it
finds a proxy in that state. Such a proxy usually needs UDP enabled on its
outbound _and_ on the server it connects to, plus no routing rule blocking UDP
other than port 53.

A SOCKS5 hop adds no encryption of its own. Frames stay sealed and replay
protected end to end, so the proxy operator cannot read or forge game traffic,
but it does see the relay address and the traffic timing that WireGuard hides.

A proxy running on this PC is refused in all-traffic mode: the tunnel would own
the default route the proxy itself needs, and its forwarded traffic would be
captured and looped back. Split-tunnel mode captures only the chosen targets, so
a local proxy is fine there.

## CI and tagged releases

[GitHub Actions](.github/workflows/ci.yml) runs on pull requests, pushes to
`main` or `master`, version tags beginning with `v`, and manual runs.

- **Windows:** formatting, JavaScript tests, frontend build, native builds,
  and Rust engine/service tests.
- **Linux:** relay tests and a release build on Ubuntu 22.04.
- **Version tag push:** after both jobs pass, publish a GitHub Release containing
  `GamePath-Setup-<version>.exe` and `SHA256SUMS.txt`, with generated release notes.
  Tags with a prerelease suffix, such as `v0.1.16-beta.1`, create prereleases.

The tag must exactly match `v` plus the version in `package.json`. For example,
from a clean checkout after committing your changes:

```powershell
npm version 0.1.16
git push origin HEAD
git push origin v0.1.16
```

`npm version` updates `package.json` and `package-lock.json`, creates a commit,
and creates the matching tag. Replace the example with the next unused version.
Commit and push the workflow before pushing a release tag. Do not move a
published tag: use a new version instead. Existing releases are never overwritten.

The workflow uses GitHub's automatic `GITHUB_TOKEN`; no personal access token is
required. Repository policy must allow GitHub Actions and the release job's
`contents: write` permission. Pull-request and build jobs have read-only access.
Manual runs validate the code; publication requires a tag push.

Installers are **not code-signed** by this workflow. Bundled upstream drivers
retain their own signatures. Compare the installer SHA-256 against the checksum
in the same release. No VPS credentials are used by CI, and releasing a new
installer does not update a deployed relay automatically. Update your relay
through the client or the [deployment script](deploy/README.md) when required.

Tests that need a real VPN provider, relay, or privileged packet capture are not
run on hosted CI. Test a release with real connections before recommending it
for regular use.
