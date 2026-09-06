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

## Multipath transport

Each distinct imported configuration creates an independent user-space WireGuard protocol instance. This allows different provider endpoints to run simultaneously even when their tunnel addresses overlap, a combination Windows rejects as duplicate adapters. The implementation uses BoringTun's portable WireGuard protocol core and ordinary Winsock UDP sockets for the outer provider connections.

The direct ISP path is always available alongside provider routes. If two files resolve to the same endpoint and reuse the same client identity, their WireGuard handshakes would replace one another at the provider. GamePath detects that conflict, keeps one live, and holds the overlap as standby. Distinct endpoint/key pairs become additional live paths.

Authenticated GamePath frames are wrapped in an inner IPv4/UDP packet addressed to the relay, then encrypted independently by each WireGuard instance. Packets receive a session ID and monotonically increasing sequence number before adaptive scheduling sends them on one or two routes. The relay sees two authenticated endpoints and fans replies back across both.

Direct and WireGuard workers share one atomic sequence allocator, so control traffic and data traffic never reuse an authenticated nonce or fall behind the relay replay window. The client sends one encrypted data frame to every selected path and accepts the first authenticated reply; later copies are discarded by sequence number.

## WireGuard routes

Each purchased configuration is parsed only in memory for the active session. The private key, peer key, optional pre-shared key, endpoint, and assigned address feed its isolated WireGuard protocol instance. Original encrypted configurations are never modified. A validation-only transformer also proves that adapter-based backends would narrow `AllowedIPs` to the resolved relay address and omit DNS and route side effects.

## Privileged service

The Electron UI remains unprivileged. `GamePathService` runs through Windows Service Control Manager and owns the native engine behind a token-authenticated loopback API on `127.0.0.1`. The installer creates a random 256-bit control token under `%ProgramData%\GamePath`, protects it for Local System, administrators, and the installing user, and installs the signed Wintun and WinDivert runtime files beside the service. A Windows Job Object with `KILL_ON_JOB_CLOSE` prevents the capture engine from surviving a service exit.

## WireSock option

WireSock Core SDK can replace parts of tunnel lifecycle and per-application filtering for personal or licensed commercial builds. It is not the default because its free license is non-commercial and includes mandatory telemetry, and its ordinary tunnel manager does not implement the GamePath relay's multipath framing or deduplication.
