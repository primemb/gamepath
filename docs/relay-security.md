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

This pre-shared-key design is appropriate for personal relays. A public service
with account recovery and key rotation should add a mutually authenticated
handshake and short-lived session credentials before accepting third-party users.
