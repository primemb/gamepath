# GamePath

GamePath is a Windows multipath gaming client with an authenticated Debian relay.

## Run the client

```powershell
npm install
npm run dev
```

Imported WireGuard configuration bodies are encrypted with Electron `safeStorage`, backed by Windows cryptography. Only non-secret metadata is sent to the renderer.

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
- Encrypt and send identical sequenced frames over multiple Winsock UDP sockets bound to distinct interface indexes.
- Provision an idempotent Debian 13 relay with systemd, nftables NAT, TUN forwarding, per-client enrollment, authenticated probes, replay protection, and multipath reply fan-out.

The Windows packet adapter and privileged service boundary are the next implementation milestones. A prepared session does not modify routes until those components are active.

The repository includes the official signed Wintun 0.14.1 AMD64 DLL and its redistribution license under `vendor/wintun`. The downloaded archive is verified against the SHA-256 published by the Wintun project before the binary is copied into the project.

The WFP prototype backend uses the upstream WinDivert 2.2.2-A x64 runtime under `vendor/windivert`. Its signed driver, user-mode DLL, license, package source, and recorded hashes are included.

See `docs/architecture.md` for the WFP, Winsock, Wintun, and optional WireSock backend design.
See `docs/relay-security.md` and `deploy/README.md` for the encrypted overlay and one-command relay installation.
