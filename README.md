# GamePath

GamePath is a Windows multipath gaming client with an authenticated Debian relay.

## Run the client

```powershell
npm install
npm run dev
```

Imported WireGuard configuration bodies are encrypted with Electron `safeStorage`, backed by Windows cryptography. Only non-secret metadata is sent to the renderer.

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
- Enable, disable, and remove individual routes.
- Choose all-system traffic or split-tunnel rules.
- Add split rules for executables, folders, hostnames, and IP ranges.
- Configure and test an authenticated Istanbul relay.
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
- Install an authenticated Windows network service that owns the Wintun and WinDivert data planes and contains its engine in a kill-on-close Job Object.
- Provision an idempotent Debian 13 relay with systemd, nftables NAT, TUN forwarding, per-client enrollment, authenticated probes, replay protection, and multipath reply fan-out.

All-traffic mode captures and reinjects IPv4 through Wintun. Split mode uses narrow WinDivert/WFP filters for IP/CIDR targets and dynamically creates port filters from process-aware socket events for executable and folder targets. Exact hostnames resolve at activation; a copy-only DNS observer learns later addresses and wildcard subdomains without diverting unrelated traffic.

The repository includes the official signed Wintun 0.14.1 AMD64 DLL and its redistribution license under `vendor/wintun`. The downloaded archive is verified against the SHA-256 published by the Wintun project before the binary is copied into the project.

The WFP prototype backend uses the upstream WinDivert 2.2.2-A x64 runtime under `vendor/windivert`. Its signed driver, user-mode DLL, license, package source, and recorded hashes are included.

See `docs/architecture.md` for the WFP, Winsock, Wintun, and optional WireSock backend design.
See `docs/relay-security.md` and `deploy/README.md` for the encrypted overlay and one-command relay installation.
