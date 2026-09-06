# Client networking architecture

GamePath uses separate components for policy, capture, and transport so the GUI never needs administrator privileges.

## Split-tunnel mode

The privileged Windows service installs filters based on Windows Filtering Platform (WFP) semantics:

1. ALE flow/socket events associate each network five-tuple with its originating process.
2. Application rules match the full executable path. Folder rules match the normalized process-path prefix in the service policy layer.
3. Hostname rules are correlated through the client's DNS policy cache and compiled to current address sets. IP and CIDR rules match destinations directly.
4. Selected UDP and TCP packets are passed to the GamePath transport. Unselected packets continue unchanged.

The first implementation can use the signed WinDivert callout driver as the WFP capture layer. It exposes process identity at the flow layer and packet data at the network layer, so the service maintains a bounded five-tuple map between the two. A production-owned WFP callout can replace this backend later without changing the GUI or relay protocol.

## All-traffic mode

All traffic is routed into the signed Wintun adapter. This avoids process correlation overhead when every connection has the same policy. Relay endpoint routes and local-network bypass routes are installed before the default route changes.

## Multipath transport

Winsock UDP sockets carry GamePath frames to the relay. Each socket is bound to one active WireGuard interface and its source address. Packets receive a session ID and monotonically increasing sequence number before adaptive scheduling sends them on one or two routes.

## WireGuard routes

Each purchased configuration is transformed only in memory for the active session. Its runtime `AllowedIPs` is narrowed to the resolved relay address, and DNS settings are omitted, so multiple providers can run without competing for the system default route. Original encrypted configurations are never modified.

## WireSock option

WireSock Core SDK can replace parts of tunnel lifecycle and per-application filtering for personal or licensed commercial builds. It is not the default because its free license is non-commercial and includes mandatory telemetry, and its ordinary tunnel manager does not implement the GamePath relay's multipath framing or deduplication.
