# GamePath

GamePath is a Windows multipath gaming client with an authenticated Debian relay.

## Run the client

```powershell
npm install
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

Imported WireGuard configuration bodies and SOCKS5 proxy passwords are encrypted with Electron `safeStorage`, backed by Windows cryptography. Only non-secret metadata is sent to the renderer.

To copy the privileged runtime without starting packet capture, use `deploy\install-windows-service.ps1 -LeaveStopped`. Running the installer from Settings installs and starts the service normally.

## Validate

```powershell
npm test
npm run build
cd engine
cargo test
cargo test --manifest-path ..\relay\Cargo.toml
```

## Current scope

- Import any number of WireGuard `.conf` files.
- Add any number of SOCKS5 proxy nodes, alone or beside WireGuard routes, and test each one for real UDP support before saving it.
- Enable, disable, and remove individual routes.
- Choose all-system traffic or split-tunnel rules.
- Add split rules for executables, folders, hostnames, and IP ranges.
- Choose relay mode, which combines every enabled node at a relay you own, or direct mode, which needs no server and routes through a single WireGuard node.
- Configure and test an authenticated Istanbul relay.
- Add any number of relay locations and enable zero or one at a time.
- Provision or remove a Debian VPS over password-authenticated SSH from the client; SSH passwords remain transient and host fingerprints are pinned after first use.
- Start and monitor the Rust engine through private JSON-line IPC.
- Detect the installed WireGuard client and active interfaces.
- Validate complete session plans before any route mutation.
- Compile application, folder, hostname, and IP targets into a process-aware WFP interception plan.
- Compute adaptive route decisions in the Rust engine.
- Load and verify the WinDivert WFP capture runtime before activation.
- Encrypt and send identical sequenced frames over multiple UDP paths.
- Keep a direct ISP path and distinct provider routes alive through persistent authenticated health checks.
- Duplicate authenticated IP frames across the live paths and verify the complete Windows-to-relay-TUN return loop.
- Detect configs that resolve to the same WireGuard endpoint and reuse the same client identity, then hold overlaps as standby instead of allowing their handshakes to replace each other.
- Hold a second node pointed at one SOCKS5 proxy as standby, since two associations on the same proxy carry no extra path.
- Install an authenticated Windows network service that owns the Wintun and WinDivert data planes and contains its engine in a kill-on-close Job Object.
- Provision an idempotent Debian 13 relay with systemd, nftables NAT, TUN forwarding, per-client enrollment, authenticated probes, replay protection, and multipath reply fan-out.

All-traffic mode captures and reinjects IPv4 through Wintun. Split mode uses narrow WinDivert/WFP filters for IP/CIDR targets and dynamically creates port filters from process-aware socket events for executable and folder targets. Exact hostnames resolve at activation; a copy-only DNS observer learns later addresses and wildcard subdomains without diverting unrelated traffic.

The repository includes the official signed Wintun 0.14.1 AMD64 DLL and its redistribution license under `vendor/wintun`. The downloaded archive is verified against the SHA-256 published by the Wintun project before the binary is copied into the project.

The WFP prototype backend uses the upstream WinDivert 2.2.2-A x64 runtime under `vendor/windivert`. Its signed driver, user-mode DLL, license, package source, and recorded hashes are included.

See `docs/architecture.md` for the WFP, Winsock, Wintun, and optional WireSock backend design.
See `docs/relay-security.md` and `deploy/README.md` for the encrypted overlay and one-command relay installation.

## Connection modes

**Relay mode** is what GamePath is for. Every enabled node carries the same
sealed frames to a relay you run, and the scheduler sends latency-sensitive
packets down more than one path at once, so a packet lost on one hop still
arrives by another. It needs a VPS.

**Direct mode** is for people who have no server to run a relay on. Selected
traffic goes through one WireGuard node, which routes it onward exactly as a
normal VPN would — GamePath still decides which applications, folders,
hostnames and addresses enter the tunnel, but nothing is duplicated and there
is no second path to fall back on.

Direct mode takes a WireGuard node and only a WireGuard node. A SOCKS5 proxy
forwards connections and datagrams; it cannot route the raw packets GamePath
captures, so it needs a relay on the other side to do that. Exactly one node is
used, because combining nodes is the relay's job.

Nothing else changes between the modes. Split-tunnel rules, all-traffic mode,
the capture layer and the privileged service work the same either way, and
switching modes needs no reconfiguration beyond choosing the node.

## SOCKS5 nodes

A node may be a WireGuard configuration or a SOCKS5 proxy, and a session can mix
both. GamePath carries game TCP _and_ UDP inside its own authenticated UDP
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
