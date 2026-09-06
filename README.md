# GamePath

GamePath is a Windows multipath gaming client. The current milestone provides the desktop configuration experience and the native route-scheduling foundation.

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
```

## Current scope

- Import any number of WireGuard `.conf` files.
- Enable, disable, and remove individual routes.
- Choose all-system traffic or split-tunnel rules.
- Add split rules for executables, folders, hostnames, and IP ranges.
- Choose the Istanbul relay placeholder.
- Configure the relay host and UDP port.
- Start and monitor the Rust engine through private JSON-line IPC.
- Detect the installed WireGuard client and active interfaces.
- Validate complete session plans before any route mutation.
- Compute adaptive route decisions in the Rust engine.

The Windows packet adapter, privileged service boundary, encrypted client-to-relay transport, and Debian relay are the next implementation milestones. A prepared session does not modify routes until those components are installed and reachable.

The repository includes the official signed Wintun 0.14.1 AMD64 DLL and its redistribution license under `vendor/wintun`. The downloaded archive is verified against the SHA-256 published by the Wintun project before the binary is copied into the project.
