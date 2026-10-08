# Relay security model

GamePath relays authenticate every client packet before it reaches the TUN
interface. Enrollment creates a random 128-bit client ID, random 256-bit
pre-shared key, and unique IPv4 address in the relay subnet.

For every session, the client and relay derive separate client-to-server and
server-to-client keys with HKDF-SHA256. ChaCha20-Poly1305 encrypts the inner IP
packet and authenticates the complete GamePath frame header. Direction-specific
nonces and monotonically increasing 64-bit sequence numbers prevent nonce reuse.

The relay keeps a 64-packet replay window for each client session. It learns an
endpoint only after successful authentication, limits the number of endpoints,
expires inactive paths, rejects packets whose inner source address does not match
the enrolled client address, and duplicates replies only to authenticated active
paths.

Enrollment token files are mode `0600`; server records are `root:gamepath` mode
`0640`. On Windows, Electron `safeStorage` encrypts imported tokens. The renderer
receives only a boolean saying whether a credential exists.

The relay reloads client records once per second without restarting. It validates
the whole snapshot before applying it, rejecting duplicate client IDs, duplicate
addresses, invalid key material, and addresses outside the client subnet. Missing
or unreadable directories and malformed records retain the last valid registry.
Removing a record from a valid snapshot revokes that client; changing its key or
address clears only that client's sessions. Unchanged clients preserve all session
state, including their outbound nonce counters and inbound replay windows.

The Windows sharing flow creates separate enrollment for each recipient. Its
invitation link or `.gprelay` file contains a plaintext credential: send it
privately and treat it like a VPN configuration. Invitation export and clipboard
import happen in Electron's main process; previews contain only endpoint and
recipient metadata, and imported credentials are encrypted with `safeStorage`.

Client listing and revocation require a root or sudo SSH login to the VPS.
Possession of an enrollment token does not grant administration rights.
Lists expose only IDs, labels, and tunnel addresses. Revocation resolves an exact
client ID to its enrolled file and removes only that credential; the Windows
dialog prevents removing the local PC's identified credential. SSH management
sessions stay in the main process, belong to one window, and close on sign-out,
window destruction, or a 15-minute timeout.

Revoked tunnel addresses are permanently reserved by key-free `.revoked` files.
This prevents a new client receiving traffic from a revoked client's surviving
kernel NAT mappings. The subnet has 253 lifetime address allocations including
these reservations. Administrative enrollment and revocation use the same VPS
lock; changing credentials never restarts unrelated sessions.

This pre-shared-key design is appropriate for personal relays. A public service
with account recovery and key rotation should add a mutually authenticated
handshake and short-lived session credentials before accepting third-party users.
